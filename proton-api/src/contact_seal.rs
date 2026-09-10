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

/// Decrypt all server cards, split by provenance. `None` on a Type-0
/// cleartext card or any decrypt failure (fail-closed either way).
fn split_server_plains(
    cards: &[crate::ContactCard],
    user_keys: &mut [UnlockedKey],
) -> Option<(Vec<String>, Vec<String>)> {
    let mut signed = Vec::new();
    let mut decrypted = Vec::new();
    for card in cards {
        match card.Type {
            0 => return None,
            2 => signed.push(card.Data.clone()),
            _ => {
                decrypted.push(crate::crypto::decrypt_contact_card(&card.Data, user_keys).ok()?);
            }
        }
    }
    Some((signed, decrypted))
}

/// Guard: unknown props block the rebuild — EXCEPT preservable key
/// groups, and then only on the SIGNED side (their canonical home per
/// WebClients `VCARD_KEY_FIELDS`). Encrypted-side key lines stay
/// blocking: the rebuild never relocates protection domains, so
/// carrying them would silently drop them instead.
fn blocking_unknowns(signed: &[String], decrypted: &[String]) -> Vec<String> {
    let mut out = crate::vcard::unknown_vcard_props_except_keys(signed);
    out.extend(crate::vcard::unknown_vcard_props(decrypted));
    out.sort();
    out.dedup();
    out
}

/// Decrypt + parse all server cards of one contact for an update rebuild.
/// Returns the parsed cards in order plus the carried per-email crypto
/// settings (key groups from the signed cards, regrouped at seal time);
/// `None` when a Type-0 cleartext card exists (nothing to merge it into —
/// rebuild would drop it), any card fails to decrypt/parse, or blocking
/// unknown props are present.
fn decrypt_server_cards(
    cards: &[crate::ContactCard],
    user_keys: &mut [UnlockedKey],
) -> Option<(
    Vec<crate::vcard::ParsedContact>,
    Vec<crate::vcard::KeyGroup>,
)> {
    let (signed, decrypted) = split_server_plains(cards, user_keys)?;
    if !blocking_unknowns(&signed, &decrypted).is_empty() {
        return None;
    }
    let parsed: Vec<crate::vcard::ParsedContact> = signed
        .iter()
        .chain(decrypted.iter())
        .map(|plain| crate::vcard::parse_vcard(plain).ok())
        .collect::<Option<_>>()?;
    let mut groups = Vec::new();
    for plain in &signed {
        groups.extend(crate::vcard::extract_key_groups(plain));
    }
    Some((parsed, groups))
}

/// Diagnose WHY an update rebuild deferred, for the file-log trace
/// (schema/IDs only, never card contents). Best-effort mirror of
/// `decrypt_server_cards` — call it when `build_contact_update_cards`
/// returns `Ok(None)`. First hit wins, in rebuild order.
pub fn diagnose_update_block(
    cards: &[crate::ContactCard],
    user_keys: &mut [UnlockedKey],
) -> String {
    if cards.iter().any(|card| card.Type == 0) {
        return "cleartext-card".to_string();
    }
    let mut signed = Vec::with_capacity(cards.len());
    let mut decrypted = Vec::with_capacity(cards.len());
    for card in cards {
        if card.Type == 2 {
            signed.push(card.Data.clone());
        } else {
            match crate::crypto::decrypt_contact_card(&card.Data, user_keys) {
                Ok(plain) => decrypted.push(plain),
                Err(_) => return "undecryptable-card".to_string(),
            }
        }
    }
    for plain in signed.iter().chain(decrypted.iter()) {
        if crate::vcard::parse_vcard(plain).is_err() {
            return "unparsable-card".to_string();
        }
    }
    let unknown = blocking_unknowns(&signed, &decrypted);
    if !unknown.is_empty() {
        return format!("unknown-props:{}", unknown.join(","));
    }
    "sealable".to_string()
}

/// Build sealed update cards for one server contact + full phone snapshot:
/// server photos preserved (phone has no photo upload v1), UID preserved,
/// per-email crypto settings carried (regrouped onto the rebuilt emails),
/// phone fields win otherwise. Returns `None` (= deferred) on any guard
/// above. Mirrors the calendar whole-object-replace discipline.
pub fn build_contact_update_cards(
    server_cards: &[crate::ContactCard],
    phone: &crate::vcard::ParsedContact,
    contact_uid: &str,
    user_keys: &mut [UnlockedKey],
) -> Result<Option<Vec<crate::ContactCard>>> {
    let Some((server_parsed, key_groups)) = decrypt_server_cards(server_cards, user_keys) else {
        return Ok(None);
    };
    let mut merged = phone.clone();
    merged.photos = server_parsed
        .iter()
        .flat_map(|parsed| parsed.photos.clone())
        .collect();
    let (mut signed_plain, enc_plain) = crate::vcard::build_vcard(&merged, contact_uid);
    // Carry crypto settings: same numbering as the rebuilt emails
    // (`item{i+1}` for the i-th phone email), bodies byte-identical.
    // Addresses dropped from the phone snapshot lose their groups.
    if !key_groups.is_empty() {
        let email_to_group: std::collections::HashMap<String, String> = merged
            .emails
            .iter()
            .enumerate()
            .map(|(i, mail)| (mail.email.clone(), format!("item{}", i + 1)))
            .collect();
        let carried = crate::vcard::render_key_groups(&key_groups, &email_to_group);
        signed_plain = crate::vcard::append_vcard_lines(&signed_plain, &carried);
    }
    let signed_sig = detached_sign_any(&signed_plain, user_keys)?;
    // Mirror `encrypt.ts`: no Type 3 when there is nothing encrypt-side
    // (email-only contact) — order stays [signed, encrypted] like before;
    // the live-verified [Type2, Type3] shape for full contacts is untouched.
    let mut cards = vec![crate::ContactCard {
        Type: 2,
        Data: signed_plain,
        Signature: signed_sig,
    }];
    if let Some(enc_plain) = enc_plain {
        let (enc_data, enc_sig) = seal_contact_card(&enc_plain, user_keys)?;
        cards.push(crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        });
    }
    Ok(Some(cards))
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
    let mut cards = vec![crate::ContactCard {
        Type: 2,
        Data: signed_plain,
        Signature: signed_sig,
    }];
    if let Some(enc_plain) = enc_plain {
        let (enc_data, enc_sig) = seal_contact_card(&enc_plain, user_keys)?;
        cards.push(crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        });
    }
    Ok(Some(cards))
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

    /// Server signed card with per-email crypto settings (WebClients
    /// per-address key groups). Sealed encrypted side via the test key.
    fn keyed_server_cards(user: &mut UnlockedKey) -> Vec<crate::ContactCard> {
        let signed = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nFN:Keyed Contact\r\nitem1.EMAIL;TYPE=HOME:kept@example.com\r\nitem1.KEY:data:;base64,QUJD\r\nitem1.X-PM-SCHEME:pgp-mime\r\nitem1.X-PM-SIGN:true\r\nitem2.EMAIL:plain@example.com\r\nEND:VCARD";
        let (enc_data, enc_sig) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nN:Contact;Keyed;;;\r\nEND:VCARD",
            std::slice::from_mut(user),
        )
        .unwrap();
        vec![
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
        ]
    }

    fn keyed_phone() -> crate::vcard::ParsedContact {
        // Same addresses REORDERED (exercises regrouping) + name edit.
        crate::vcard::ParsedContact {
            first_name: "KeyedEdited".into(),
            emails: vec![
                crate::vcard::ParsedEmail {
                    email: "plain@example.com".into(),
                    types: Vec::new(),
                },
                crate::vcard::ParsedEmail {
                    email: "kept@example.com".into(),
                    types: vec!["HOME".into()],
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_update_carries_key_groups_regrouped() {
        // Previously: `unknown-props:KEY,X-PM-SCHEME,X-PM-SIGN` → deferred
        // forever (contact phone-read-only). Now seals with the groups
        // following their address to its new itemN, bodies byte-identical.
        let mut user = test_user_identity();
        let cards = keyed_server_cards(&mut user);
        let out = build_contact_update_cards(
            &cards,
            &keyed_phone(),
            "c-1",
            std::slice::from_mut(&mut user),
        )
        .unwrap()
        .expect("keyed update seals");
        assert_eq!(out[0].Type, 2);
        assert!(out[0].Data.contains("item2.EMAIL"), "{}", out[0].Data);
        assert!(
            out[0].Data.contains("item2.KEY:data:;base64,QUJD"),
            "{}",
            out[0].Data
        );
        assert!(
            out[0].Data.contains("item2.X-PM-SCHEME:pgp-mime"),
            "{}",
            out[0].Data
        );
        assert!(
            out[0].Data.contains("item2.X-PM-SIGN:true"),
            "{}",
            out[0].Data
        );
        assert!(!out[0].Data.contains("item1.KEY"), "{}", out[0].Data);
        // Name edit applied alongside.
        assert!(!out[1].Data.is_empty());
        let enc = decrypt_card(&out[1], &mut user);
        assert_eq!(enc.first_name, "KeyedEdited");
        // Diagnose agrees it is sealable (no unknown-props deferral).
        assert_eq!(
            diagnose_update_block(&cards, std::slice::from_mut(&mut user)),
            "sealable"
        );
    }

    #[test]
    fn test_update_drops_key_group_of_deleted_email() {
        // Address removed from the phone snapshot: its settings go with it
        // (no orphan KEY lines for a deleted address).
        let mut user = test_user_identity();
        let cards = keyed_server_cards(&mut user);
        let mut phone = keyed_phone();
        phone.emails.truncate(1); // keep only plain@example.com
        let out =
            build_contact_update_cards(&cards, &phone, "c-1", std::slice::from_mut(&mut user))
                .unwrap()
                .expect("update seals");
        assert!(!out[0].Data.contains("KEY:"), "{}", out[0].Data);
        assert!(!out[0].Data.contains("X-PM-"), "{}", out[0].Data);
        assert!(out[0].Data.contains("item1.EMAIL:plain@example.com"));
    }

    #[test]
    fn test_update_defers_encrypted_side_keys() {
        // Key lines in the ENCRYPTED card never relocate: still deferred
        // (protection domains don't move on rebuild).
        let mut user = test_user_identity();
        let (enc_data, enc_sig) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c\r\nN:X;Y;;;\r\nitem1.KEY:abc\r\nEND:VCARD",
            std::slice::from_mut(&mut user),
        )
        .unwrap();
        let cards = vec![crate::ContactCard {
            Type: 3,
            Data: enc_data,
            Signature: enc_sig,
        }];
        assert!(build_contact_update_cards(
            &cards,
            &crate::vcard::ParsedContact::default(),
            "c",
            std::slice::from_mut(&mut user)
        )
        .unwrap()
        .is_none());
        assert_eq!(
            diagnose_update_block(&cards, std::slice::from_mut(&mut user)),
            "unknown-props:KEY"
        );
    }

    #[test]
    fn test_diagnose_names_remaining_unknowns_beside_keys() {
        // Key groups exempt, but a genuinely exotic prop still names itself.
        let mut user = test_user_identity();
        let mut cards = keyed_server_cards(&mut user);
        cards[0].Data = cards[0]
            .Data
            .replace("END:VCARD", "X-CUSTOM:1\r\nEND:VCARD");
        assert!(build_contact_update_cards(
            &cards,
            &keyed_phone(),
            "c-1",
            std::slice::from_mut(&mut user)
        )
        .unwrap()
        .is_none());
        assert_eq!(
            diagnose_update_block(&cards, std::slice::from_mut(&mut user)),
            "unknown-props:X-CUSTOM"
        );
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
            phones: vec![crate::vcard::ParsedPhone {
                number: "+3902000000".into(),
                types: Vec::new(),
            }],
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
        let enc = decrypt_card(&out[1], &mut user);
        assert_eq!(enc.phones.len(), 1);
    }

    #[test]
    fn test_create_email_only_seals_single_signed_card() {
        // WebClients `encrypt.ts` gate: no encrypt-side properties → no
        // Type-3 card at all (an empty wrapper was never live-tested).
        let mut user = test_user_identity();
        let phone = crate::vcard::ParsedContact {
            display_name: "Solo".into(),
            emails: vec![crate::vcard::ParsedEmail {
                email: "solo@example.com".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        };
        let out = build_contact_create_cards(&phone, "solo-uid", std::slice::from_mut(&mut user))
            .unwrap()
            .expect("create seals");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].Type, 2);
        assert!(out[0].Data.contains("item1.EMAIL:solo@example.com"));
        let back = decrypt_card(&out[0], &mut user);
        assert_eq!(back.display_name, "Solo");
        assert_eq!(back.emails.len(), 1);
    }

    #[test]
    fn test_update_email_only_snapshot_drops_encrypted_card() {
        // Phone stripped every encrypt-side field: the rebuilt update is a
        // single signed card (deterministic split, like the web) — the old
        // server Type 3 is intentionally replaced away.
        let mut user = test_user_identity();
        let (cards, _) = server_cards_fixture(&mut user);
        let phone = crate::vcard::ParsedContact {
            display_name: "Stripped".into(),
            emails: vec![crate::vcard::ParsedEmail {
                email: "s@example.com".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        };
        let out =
            build_contact_update_cards(&cards, &phone, "c-1", std::slice::from_mut(&mut user))
                .unwrap()
                .expect("update seals");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].Type, 2);
    }

    #[test]
    fn test_grouped_email_updates_and_diagnoses() {
        // Live 2026-09-09: Proton web groups emails (`item1.EMAIL`), which
        // the pre-fix guard treated as unknown → every plain edit deferred.
        // Grouped standard props must seal; genuinely exotic ones must name
        // themselves via `diagnose_update_block` (schema only, safe to log).
        let mut user = test_user_identity();
        let signed_grouped = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nFN:Old Name\r\nitem1.EMAIL;TYPE=HOME:old@example.com\r\nEND:VCARD";
        let (enc_data, enc_sig) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c-1\r\nN:Old;Name;;;\r\nEND:VCARD",
            std::slice::from_mut(&mut user),
        )
        .unwrap();
        let cards = vec![
            crate::ContactCard {
                Type: 2,
                Data: signed_grouped.to_string(),
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
            ..Default::default()
        };
        assert!(
            build_contact_update_cards(&cards, &phone, "c-1", std::slice::from_mut(&mut user))
                .unwrap()
                .is_some(),
            "grouped EMAIL seals"
        );
        assert_eq!(
            diagnose_update_block(&cards, std::slice::from_mut(&mut user)),
            "sealable"
        );
        // Exotic prop still defers, and names itself.
        let (enc2, sig2) = seal_contact_card(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c\r\nX-CUSTOM:1\r\nEND:VCARD",
            std::slice::from_mut(&mut user),
        )
        .unwrap();
        let exotic = vec![crate::ContactCard {
            Type: 3,
            Data: enc2,
            Signature: sig2,
        }];
        assert!(build_contact_update_cards(
            &exotic,
            &crate::vcard::ParsedContact::default(),
            "c",
            std::slice::from_mut(&mut user)
        )
        .unwrap()
        .is_none());
        assert_eq!(
            diagnose_update_block(&exotic, std::slice::from_mut(&mut user)),
            "unknown-props:X-CUSTOM"
        );
    }
}
