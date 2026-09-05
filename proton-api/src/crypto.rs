use crate::{ProtonError, Result};
use base64::Engine;
use sequoia_openpgp::{
    crypto::{Password, SessionKey},
    parse::{
        stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
        Parse,
    },
    policy::StandardPolicy,
    types::SymmetricAlgorithm,
    Cert, KeyHandle,
};

pub fn derive_mailbox_password(password: &[u8], key_salt_b64: &str) -> Result<Vec<u8>> {
    let key_salt = base64::engine::general_purpose::STANDARD
        .decode(key_salt_b64)
        .map_err(|e| ProtonError::Crypto(format!("Invalid key salt base64: {e}")))?;

    let encoded_salt = bcrypt_b64_encode(&key_salt);
    let raw_salt_bytes = bcrypt_b64_decode(&encoded_salt[..22])?;

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&raw_salt_bytes[..16]);

    let hash = bcrypt::hash_with_salt(password, 10, salt_arr)
        .map_err(|e| ProtonError::Crypto(format!("bcrypt: {e}")))?;

    let crypted = hash.format_for_version(bcrypt::Version::TwoY);

    let hash_str = crypted.as_bytes();
    let len = hash_str.len();
    if len < 31 {
        return Err(ProtonError::Crypto("bcrypt hash too short".into()));
    }
    Ok(hash_str[len - 31..].to_vec())
}

pub struct UnlockedKey {
    pub keypairs: Vec<sequoia_openpgp::crypto::KeyPair>,
    fingerprints: Vec<sequoia_openpgp::Fingerprint>,
}

impl UnlockedKey {
    pub fn from_armored(armored: &str, passphrase: &[u8]) -> Result<Self> {
        let cert = Cert::from_bytes(armored.as_bytes())
            .map_err(|e| ProtonError::Crypto(format!("Parse key: {e}")))?;

        let mut keypairs = Vec::new();
        let mut fingerprints = Vec::new();

        for ka in cert.keys().secret() {
            let mut key = ka.key().clone();
            let pk_algo = key.pk_algo();
            if key.secret().is_encrypted() {
                if key
                    .secret_mut()
                    .decrypt_in_place(pk_algo, &Password::from(passphrase.to_vec()))
                    .is_err()
                {
                    continue;
                }
            }
            match key.into_keypair() {
                Ok(pair) => {
                    fingerprints.push(ka.fingerprint());
                    keypairs.push(pair);
                }
                Err(_) => continue,
            }
        }

        if keypairs.is_empty() {
            return Err(ProtonError::Crypto(
                "Failed to unlock any key with passphrase".into(),
            ));
        }

        Ok(Self {
            keypairs,
            fingerprints,
        })
    }

    pub fn from_bytes(bytes: &[u8], passphrase: &[u8]) -> Result<Self> {
        let cert =
            Cert::from_bytes(bytes).map_err(|e| ProtonError::Crypto(format!("Parse key: {e}")))?;

        let mut keypairs = Vec::new();
        let mut fingerprints = Vec::new();

        for ka in cert.keys().secret() {
            let mut key = ka.key().clone();
            let pk_algo = key.pk_algo();
            if key.secret().is_encrypted() {
                if key
                    .secret_mut()
                    .decrypt_in_place(pk_algo, &Password::from(passphrase.to_vec()))
                    .is_err()
                {
                    continue;
                }
            }
            match key.into_keypair() {
                Ok(pair) => {
                    fingerprints.push(ka.fingerprint());
                    keypairs.push(pair);
                }
                Err(_) => continue,
            }
        }

        if keypairs.is_empty() {
            return Err(ProtonError::Crypto(
                "Failed to unlock any key with passphrase".into(),
            ));
        }

        Ok(Self {
            keypairs,
            fingerprints,
        })
    }
}

struct Helper<'a> {
    key: &'a mut UnlockedKey,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        for pkesk in pkesks {
            for (i, pair) in self.key.keypairs.iter_mut().enumerate() {
                if let Some((algo, session_key)) = pkesk.decrypt(pair, sym_algo) {
                    decrypt(algo, &session_key);
                    return Ok(Some(self.key.fingerprints[i].clone()));
                }
            }
        }

        Err(sequoia_openpgp::Error::MalformedMessage("No matching key".into()).into())
    }
}

pub fn decrypt_contact_card(
    encrypted_data: &str,
    unlocked_keys: &mut [UnlockedKey],
) -> Result<String> {
    let p = &StandardPolicy::new();

    for key in unlocked_keys.iter_mut() {
        let helper = Helper { key };

        let result = (|| -> Result<String> {
            let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data.as_bytes())
                .map_err(|e| ProtonError::Crypto(format!("Parse message: {e}")))?
                .with_policy(p, None, helper)
                .map_err(|e| ProtonError::Crypto(format!("Decrypt: {e}")))?;

            let mut decrypted = Vec::new();
            std::io::Read::read_to_end(&mut decryptor, &mut decrypted)
                .map_err(|e| ProtonError::Crypto(format!("Read: {e}")))?;

            String::from_utf8(decrypted).map_err(|e| ProtonError::Crypto(format!("UTF-8: {e}")))
        })();

        if result.is_ok() {
            return result;
        }
    }

    Err(ProtonError::Crypto(
        "No key could decrypt the message".into(),
    ))
}

fn bcrypt_b64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((acc >> bits) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((acc << (6 - bits)) & 0x3F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn bcrypt_b64_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for ch in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| ProtonError::Crypto("Invalid bcrypt base64 char".into()))?;
        acc = (acc << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }
    Ok(result)
}
