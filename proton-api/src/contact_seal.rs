// proton-api/src/contact_seal.rs — Contact upsync sealing.
// Whole-message armored encrypt to the USER public key + detached armored
// signature with the USER private key (WebClients `prepareCardsFromVCard`
// via `splitKeys(await getUserKeys())`, researched 2026-09-08 — the
// OPPOSITE of calendar cards, which seal to calendar keys and sign with
// address keys; do NOT "unify" them).
//
// Unlike calendar split packets, contact Type-3 `Data` carries the FULL
// armored message (PKESK + data together); no key packets on the side.
use crate::{ProtonError, Result, UnlockedKey};
use sequoia_openpgp::{
    armor,
    serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message, Recipient, Signer},
};
use std::io::Write;

/// Seal one contact card body for upload → `(Data, Signature)`, both
/// armored strings ready for `ContactCard { Type: 3, .. }`. Encryption
/// and signing need DIFFERENT capabilities (ECDH subkey encrypts, EdDSA
/// primary/subkey signs), so every (encryption, signing) pair combination
/// is tried; the first fully-working combo wins.
pub fn seal_contact_card(plain: &str, user_keys: &mut [UnlockedKey]) -> Result<(String, String)> {
    let pairs: Vec<sequoia_openpgp::crypto::KeyPair> = user_keys
        .iter()
        .flat_map(|k| k.keypairs.iter().cloned())
        .collect();
    if pairs.is_empty() {
        return Err(ProtonError::Crypto("seal: user key has no pairs".into()));
    }
    let mut last_err = String::new();
    for enc in &pairs {
        for sign in &pairs {
            match seal_with_pair(plain, enc, sign) {
                Ok(out) => return Ok(out),
                Err(e) => last_err = format!("seal: {e}"),
            }
        }
    }
    Err(ProtonError::Crypto(last_err))
}

fn seal_with_pair(
    plain: &str,
    enc_pair: &sequoia_openpgp::crypto::KeyPair,
    sign_pair: &sequoia_openpgp::crypto::KeyPair,
) -> Result<(String, String)> {
    let recipient = Recipient::from(enc_pair.public());
    let mut buf = Vec::new();
    let message = Message::new(&mut buf);
    let message = Armorer::new(message)
        .kind(armor::Kind::Message)
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal armorer: {e}")))?;
    let message = Encryptor2::for_recipients(message, vec![recipient])
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal encryptor: {e}")))?;
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal literal: {e}")))?;
    literal
        .write_all(plain.as_bytes())
        .map_err(|e| ProtonError::Crypto(format!("seal write: {e}")))?;
    literal
        .finalize()
        .map_err(|e| ProtonError::Crypto(format!("seal finalize: {e}")))?;
    let data =
        String::from_utf8(buf).map_err(|e| ProtonError::Crypto(format!("seal UTF-8: {e}")))?;
    let signer = sign_pair.clone();
    let mut sig_buf = Vec::new();
    let sig_message = Message::new(&mut sig_buf);
    let sig_message = Armorer::new(sig_message)
        .kind(armor::Kind::Signature)
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal sig armorer: {e}")))?;
    let mut signer = Signer::new(sig_message, signer)
        .detached()
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal signer: {e}")))?;
    signer
        .write_all(plain.as_bytes())
        .map_err(|e| ProtonError::Crypto(format!("seal sign write: {e}")))?;
    signer
        .finalize()
        .map_err(|e| ProtonError::Crypto(format!("seal sign finalize: {e}")))?;
    let sig = String::from_utf8(sig_buf)
        .map_err(|e| ProtonError::Crypto(format!("seal sig UTF-8: {e}")))?;
    Ok((data, sig))
}

/// Detached-sign with the first signing-capable user pair (tries each;
/// ECDH pairs fail and are skipped — same capability reality as seal).
fn detached_sign_any(plain: &str, user_keys: &mut [UnlockedKey]) -> Result<String> {
    let mut last_err = "seal: user key has no pairs".to_string();
    for key in user_keys.iter_mut() {
        for pair in key.keypairs.iter_mut() {
            match crate::calendar_seal::detached_sign(plain.as_bytes(), pair) {
                Ok(sig) => return Ok(sig),
                Err(e) => last_err = format!("seal sign: {e}"),
            }
        }
    }
    Err(ProtonError::Crypto(last_err))
}

/// Decrypt + parse all server cards of one contact for an update rebuild.
/// Returns the parsed cards in order; `None` when a Type-0 cleartext card
/// exists (nothing to merge it into — rebuild would drop it), any card
/// fails to decrypt/parse, or unknown props are present.
fn decrypt_server_cards(
    cards: &[crate::ContactCard],
    user_keys: &mut [UnlockedKey],
) -> Option<Vec<crate::vcard::ParsedContact>> {
    let mut plains = Vec::with_capacity(cards.len());
    for card in cards {
        match card.Type {
            0 => return None,
            2 => plains.push(card.Data.clone()),
            _ => {
                plains.push(crate::crypto::decrypt_contact_card(&card.Data, user_keys).ok()?);
            }
        }
    }
    if crate::vcard::has_unknown_vcard_props(&plains) {
        return None;
    }
    plains
        .iter()
        .map(|plain| crate::vcard::parse_vcard(plain).ok())
        .collect()
}

/// Build sealed update cards for one server contact + full phone snapshot:
/// server photos preserved (phone has no photo upload v1), UID preserved,
/// phone fields win otherwise. Returns `None` (= deferred) on any guard
/// above. Mirrors the calendar whole-object-replace discipline.
pub fn build_contact_update_cards(
    server_cards: &[crate::ContactCard],
    phone: &crate::vcard::ParsedContact,
    contact_uid: &str,
    user_keys: &mut [UnlockedKey],
) -> Result<Option<Vec<crate::ContactCard>>> {
    let Some(server_parsed) = decrypt_server_cards(server_cards, user_keys) else {
        return Ok(None);
    };
    let mut merged = phone.clone();
    merged.photos = server_parsed
        .iter()
        .flat_map(|parsed| parsed.photos.clone())
        .collect();
    let (signed_plain, enc_plain) = crate::vcard::build_vcard(&merged, contact_uid);
    let signed_sig = detached_sign_any(&signed_plain, user_keys)?;
    let (enc_data, enc_sig) = seal_contact_card(&enc_plain, user_keys)?;
    Ok(Some(vec![
        crate::ContactCard {
            Type: 2,
            Data: signed_plain,
            Signature: signed_sig,
        },
        crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        },
    ]))
}

/// Build sealed create cards from a phone snapshot (no server base).
/// Same guards minus the server-dependent ones; UID is fresh from caller.
pub fn build_contact_create_cards(
    phone: &crate::vcard::ParsedContact,
    uid: &str,
    user_keys: &mut [UnlockedKey],
) -> Result<Option<Vec<crate::ContactCard>>> {
    let mut merged = phone.clone();
    merged.photos = Vec::new(); // no photo upload v1 (documented gap)
    let (signed_plain, enc_plain) = crate::vcard::build_vcard(&merged, uid);
    let signed_sig = detached_sign_any(&signed_plain, user_keys)?;
    let (enc_data, enc_sig) = seal_contact_card(&enc_plain, user_keys)?;
    Ok(Some(vec![
        crate::ContactCard {
            Type: 2,
            Data: signed_plain,
            Signature: signed_sig,
        },
        crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        },
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};

    /// Fresh unlocked test identity (primary + signing + transport-encryption
    /// subkeys, no password). Callers split user/address use by position.
    fn test_user_identity() -> UnlockedKey {
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .expect("test key generation");
        let mut armored_bytes = Vec::new();
        cert.as_tsk()
            .armored()
            .export(&mut armored_bytes)
            .expect("test cert armor");
        let armored = armored_bytes
            .into_iter()
            .map(|b| b as char)
            .collect::<String>();
        UnlockedKey::from_armored(&armored, b"").expect("test key unlock")
    }

    #[test]
    fn test_seal_round_trips_through_read_path() {
        // Killer check: sealed output decrypts via the EXISTING
        // `decrypt_contact_card` read path (armored Type-3 model).
        let mut user = test_user_identity();
        let plain = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ada\r\nEND:VCARD";
        let (data, sig) = seal_contact_card(plain, std::slice::from_mut(&mut user)).unwrap();
        assert!(data.starts_with("-----BEGIN PGP MESSAGE-----"), "{data}");
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));
        let card = crate::ContactCard {
            Type: 3,
            Data: data,
            Signature: sig,
        };
        let back = crate::crypto::decrypt_contact_card(&card.Data, std::slice::from_mut(&mut user))
            .unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn test_seal_rejects_wrong_key() {
        let mut user = test_user_identity();
        let mut other = test_user_identity();
        let (data, _) = seal_contact_card("plain", std::slice::from_mut(&mut user)).unwrap();
        assert!(
            crate::crypto::decrypt_contact_card(&data, std::slice::from_mut(&mut other)).is_err()
        );
    }

    #[test]
    fn test_seal_ciphertext_differs_per_seal() {
        let mut user = test_user_identity();
        let (d1, _) = seal_contact_card("same", std::slice::from_mut(&mut user)).unwrap();
        let (d2, _) = seal_contact_card("same", std::slice::from_mut(&mut user)).unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_seal_no_usable_key_fails() {
        let mut empty: Vec<UnlockedKey> = Vec::new();
        assert!(seal_contact_card("x", &mut empty).is_err());
    }

    fn server_cards_fixture(
        user: &mut UnlockedKey,
    ) -> (Vec<crate::ContactCard>, crate::vcard::ParsedContact) {
        // Server state: signed uid/fn/email + sealed name/phone cards.
        let signed = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nFN:Old Name\r\nEMAIL:old@example.com\r\nEND:VCARD";
        let (enc_data, enc_sig) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nN:Old;Name;;;\r\nTEL:+100\r\nEND:VCARD",
            std::slice::from_mut(user),
        )
        .unwrap();
        let cards = vec![
            crate::ContactCard {
                Type: 2,
                Data: signed.to_string(),
                Signature: "sig".into(),
            },
            crate::ContactCard {
                Type: 3,
                Data: enc_data,
                Signature: enc_sig,
            },
        ];
        let phone = crate::vcard::ParsedContact {
            first_name: "New".into(),
            last_name: "Name".into(),
            emails: vec![crate::vcard::ParsedEmail {
                email: "new@example.com".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        };
        (cards, phone)
    }

    fn decrypt_card(
        card: &crate::ContactCard,
        user: &mut UnlockedKey,
    ) -> crate::vcard::ParsedContact {
        let plain = if card.Type == 2 {
            card.Data.clone()
        } else {
            crate::crypto::decrypt_contact_card(&card.Data, std::slice::from_mut(user)).unwrap()
        };
        crate::vcard::parse_vcard(&plain).unwrap()
    }

    #[test]
    fn test_update_rebuilds_and_preserves() {
        let mut user = test_user_identity();
        let (cards, phone) = server_cards_fixture(&mut user);
        let out =
            build_contact_update_cards(&cards, &phone, "c-1", std::slice::from_mut(&mut user))
                .unwrap()
                .expect("update seals");
        assert_eq!(out.len(), 2);
        // Signed card: phone emails + preserved UID.
        assert!(out[0].Data.contains("UID:c-1"));
        let signed = decrypt_card(&out[0], &mut user);
        assert!(signed.emails.iter().any(|e| e.email == "new@example.com"));
        // Encrypted card: phone name edit applied.
        let enc = decrypt_card(&out[1], &mut user);
        assert_eq!(enc.first_name, "New");
    }

    #[test]
    fn test_update_defers_cleartext_and_unknown() {
        let mut user = test_user_identity();
        let phone = crate::vcard::ParsedContact::default();
        // Type-0 cleartext card would be dropped by the rebuild.
        let clear = vec![crate::ContactCard {
            Type: 0,
            Data: "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c\r\nFN:x\r\nCATEGORIES:Friends\r\nEND:VCARD"
                .into(),
            Signature: String::new(),
        }];
        assert!(
            build_contact_update_cards(&clear, &phone, "c", std::slice::from_mut(&mut user))
                .unwrap()
                .is_none()
        );
        // Unknown X- prop likewise defers.
        let (enc_data, enc_sig) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c\r\nX-CUSTOM:1\r\nEND:VCARD",
            std::slice::from_mut(&mut user),
        )
        .unwrap();
        let exotic = vec![crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        }];
        assert!(
            build_contact_update_cards(&exotic, &phone, "c", std::slice::from_mut(&mut user))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_create_cards_shape() {
        let mut user = test_user_identity();
        let phone = crate::vcard::ParsedContact {
            display_name: "Fresh Contact".into(),
            ..Default::default()
        };
        let out = build_contact_create_cards(&phone, "fresh-uid", std::slice::from_mut(&mut user))
            .unwrap()
            .expect("create seals");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].Type, 2);
        assert_eq!(out[1].Type, 3);
        let signed = decrypt_card(&out[0], &mut user);
        assert_eq!(signed.display_name, "Fresh Contact");
    }
}
