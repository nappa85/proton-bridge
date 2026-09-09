// proton-api/src/calendar_seal.rs — Calendar upsync sealing primitives.
// Encrypt + detached-sign for the sync write path (proton-cal
// `pkg/event/write.go` `sealCards`/`resealCard` + `pkg/pgp`, researched
// 2026-09-07, see FINDINGS_CALENDAR.md §12).
//
// Split-packet model (mirrors `CalendarEventPart::Decode` in reverse):
// - encrypted card → `SharedKeyPacket`/`CalendarKeyPacket` = base64 PKESK
//   (session key encrypted to the calendar public key) and `Data` =
//   base64 bare SEIP data packet (symmetric encryption with that session
//   key, NO key packet inside). Our read path concatenates both back.
// - `Signature` on every part = armored DETACHED signature of the
//   PLAINTEXT by an address key (verified leniently on read).
//
// Creates use FRESH session keys; updates REUSE the stored ones
// (decrypted from the kept packets — the update body carries none).
#![allow(non_snake_case)]

use crate::{ProtonError, Result, UnlockedKey};
use sequoia_openpgp::{
    armor,
    crypto::{KeyPair, SessionKey},
    packet::{pkesk::PKESK3, Packet},
    parse::Parse,
    serialize::{
        stream::{Armorer, Encryptor2, LiteralWriter, Message, Signer},
        Serialize,
    },
    types::SymmetricAlgorithm,
    PacketPile,
};
use std::io::Write;

/// Symmetric cipher for fresh event session keys (Proton standard).
pub const SEAL_CIPHER: SymmetricAlgorithm = SymmetricAlgorithm::AES256;

/// Extract the session key from a stored base64 key packet with any pair
/// of any given key (proton-cal `DecryptSessionKey`). Returns the cipher +
/// key for `encrypt_with_session_key`.
pub fn extract_session_key(
    key_packet_b64: &str,
    cal_keys: &mut [UnlockedKey],
) -> Result<(SymmetricAlgorithm, SessionKey)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(key_packet_b64.trim())
        .map_err(|e| ProtonError::Crypto(format!("key packet base64: {e}")))?;
    let pile = PacketPile::from_bytes(&raw)
        .map_err(|e| ProtonError::Crypto(format!("key packet: {e}")))?;
    for packet in pile.descendants() {
        let Packet::PKESK(pkesk) = packet else {
            continue;
        };
        for cal_key in cal_keys.iter_mut() {
            for pair in cal_key.keypairs.iter_mut() {
                if let Some((algo, sk)) = pkesk.decrypt(pair, None) {
                    return Ok((algo, sk));
                }
            }
        }
    }
    Err(ProtonError::Crypto(
        "key packet: no pair could decrypt".into(),
    ))
}

/// Symmetric-encrypt plaintext with an EXPLICIT session key, emitting the
/// bare SEIP data packet only (no PKESK inside — sequoia omits key packets
/// when `with_session_key` is used without recipients, exactly the split
/// model). Pair with `fresh_key_packet` (create) or the stored packet
/// (update, same key reused).
pub fn encrypt_with_session_key(
    plain: &[u8],
    algo: SymmetricAlgorithm,
    session_key: &SessionKey,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let message = Message::new(&mut buf);
    let message = Encryptor2::with_session_key(message, algo, session_key.clone())
        .map_err(|e| ProtonError::Crypto(format!("seal encryptor: {e}")))?;
    let message = message
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal encryptor build: {e}")))?;
    let mut literal = LiteralWriter::new(message)
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal literal: {e}")))?;
    literal
        .write_all(plain)
        .map_err(|e| ProtonError::Crypto(format!("seal write: {e}")))?;
    // One finalize cascades through the whole stack (1.22 API).
    literal
        .finalize()
        .map_err(|e| ProtonError::Crypto(format!("seal finalize: {e}")))?;
    Ok(buf)
}

/// Fresh random session key of `SEAL_CIPHER` size (create path).
pub fn fresh_session_key() -> Result<SessionKey> {
    let size = SEAL_CIPHER
        .key_size()
        .map_err(|e| ProtonError::Crypto(format!("cipher key size: {e}")))?;
    Ok(SessionKey::new(size))
}

/// Encrypt a session key to the calendar public key → bare PKESK bytes
/// (base64 this for `SharedKeyPacket`/`CalendarKeyPacket`). Tries every
/// pair's public part until one accepts encryption (the primary is usually
/// sign/certify-only — EdDSA — while a transport subkey encrypts).
pub fn fresh_key_packet(session_key: &SessionKey, cal_keys: &[UnlockedKey]) -> Result<Vec<u8>> {
    let mut last_err = "seal: calendar key has no pairs".to_string();
    let mut pkesk_opt = None;
    'outer: for cal_key in cal_keys {
        for pair in &cal_key.keypairs {
            match PKESK3::for_recipient(SEAL_CIPHER, session_key, pair.public()) {
                Ok(pkesk) => {
                    pkesk_opt = Some(pkesk);
                    break 'outer;
                }
                Err(e) => last_err = format!("seal key packet: {e}"),
            }
        }
    }
    let pkesk = pkesk_opt.ok_or_else(|| ProtonError::Crypto(std::mem::take(&mut last_err)))?;
    let mut buf = Vec::new();
    Packet::PKESK(pkesk.into())
        .serialize(&mut buf)
        .map_err(|e| ProtonError::Crypto(format!("seal key packet serialize: {e}")))?;
    Ok(buf)
}

/// Armored detached signature of plaintext by an address key (every sync
/// part carries one; Type 3 signs the PLAINTEXT, api.md).
pub fn detached_sign(plain: &[u8], signer: &mut KeyPair) -> Result<String> {
    let mut buf = Vec::new();
    let message = Message::new(&mut buf);
    let message = Armorer::new(message)
        .kind(armor::Kind::Signature)
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal armorer: {e}")))?;
    let pair = signer.clone();
    let mut signer = Signer::new(message, pair)
        .detached()
        .build()
        .map_err(|e| ProtonError::Crypto(format!("seal signer: {e}")))?;
    signer
        .write_all(plain)
        .map_err(|e| ProtonError::Crypto(format!("seal sign write: {e}")))?;
    signer
        .finalize()
        .map_err(|e| ProtonError::Crypto(format!("seal sign finalize: {e}")))?;
    String::from_utf8(buf).map_err(|e| ProtonError::Crypto(format!("seal sig UTF-8: {e}")))
}

/// Seal one encrypted card for a CREATE: fresh session key → `(key_packet,
// data, signature)` with both halves raw bytes (base64 them into
// `SharedKeyPacket` + `Data`) and an armored detached plaintext
// signature. Mirrors proton-cal `sealCards` per-card half.
pub fn seal_card(
    plain: &str,
    cal_keys: &mut [UnlockedKey],
    addr_keys: &mut [UnlockedKey],
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let sk = fresh_session_key()?;
    let data = encrypt_with_session_key(plain.as_bytes(), SEAL_CIPHER, &sk)?;
    let kp = fresh_key_packet(&sk, cal_keys)?;
    let signer = addr_keys
        .first_mut()
        .and_then(|k| k.keypairs.first_mut())
        .ok_or_else(|| ProtonError::Crypto("seal: address key has no pairs".into()))?;
    let sig = detached_sign(plain.as_bytes(), signer)?;
    Ok((kp, data, sig))
}

use crate::calendar_write::{
    escape_ical_text, format_ical_date_end_exclusive, format_ical_dt, marshal_color,
    marshal_notifications, next_sequence, patch_card, CardPatch, LocalFields, SyncContentPart,
    SyncEventBody,
};
use crate::{CalendarEvent, CalendarEventPart};
use base64::Engine;

/// Largest `SEQUENCE` found in signed plaintext cards (0 when absent).
fn max_sequence(plaintexts: &[String]) -> i64 {
    plaintexts
        .iter()
        .filter_map(|plain| {
            crate::calendar::parse_ical(plain)
                .ok()
                .and_then(|parsed| parsed.sequence.trim().parse::<i64>().ok())
        })
        .max()
        .unwrap_or(0)
}

/// Decrypt one card group, returning `(is_encrypted, plaintext)` per part
/// in order. `None` when any encrypted part fails (verbatim requirement).
fn decrypt_group(
    parts: &[CalendarEventPart],
    key_packet_b64: &str,
    cal_keys: &mut [UnlockedKey],
    addr_keys: &mut [UnlockedKey],
) -> Option<Vec<(bool, String)>> {
    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        if (part.Type & 1) == 0 {
            out.push((false, part.Data.clone()));
            continue;
        }
        if key_packet_b64.is_empty() {
            return None;
        }
        let plain =
            crate::calendar::decrypt_calendar_part(part, cal_keys, addr_keys, Some(key_packet_b64))
                .ok()?;
        out.push((true, plain));
    }
    Some(out)
}

/// Reseal one decrypted group: encrypted entries re-encrypted with the
/// SAME session key, every entry freshly detached-signed (mirrors
/// proton-cal `resealCard`; output types normalize to 2 = signed,
/// 3 = encrypted+signed).
fn reseal_group(
    decrypted: &[(bool, String)],
    patches: Vec<CardPatch>,
    session_key: Option<(&SessionKey, SymmetricAlgorithm)>,
    addr_keys: &mut [UnlockedKey],
) -> Result<Vec<SyncContentPart>> {
    let signer = addr_keys
        .first_mut()
        .and_then(|k| k.keypairs.first_mut())
        .ok_or_else(|| ProtonError::Crypto("reseal: address key has no pairs".into()))?;
    let mut out = Vec::with_capacity(decrypted.len());
    for (i, (encrypted, plain)) in decrypted.iter().enumerate() {
        let patched = match patches.get(i) {
            Some(p) => patch_card(plain, p),
            None => plain.clone(),
        };
        if *encrypted {
            let (sk, algo) = session_key.ok_or_else(|| {
                ProtonError::Crypto("reseal: encrypted part without session key".into())
            })?;
            let data = encrypt_with_session_key(patched.as_bytes(), algo, sk)?;
            let sig = detached_sign(patched.as_bytes(), signer)?;
            out.push(SyncContentPart {
                Type: 3,
                Data: base64::engine::general_purpose::STANDARD.encode(data),
                Signature: sig,
            });
        } else {
            let sig = detached_sign(patched.as_bytes(), signer)?;
            out.push(SyncContentPart {
                Type: 2,
                Data: patched,
                Signature: sig,
            });
        }
    }
    Ok(out)
}

/// TEXT patch entry: `None` = keep, `Some("")` = delete, `Some(v)` = set
/// (escaped) — mirrors proton-cal `applyText`.
fn apply_text(patch: &mut CardPatch, name: &str, value: Option<&str>) {
    let Some(v) = value else { return };
    if v.is_empty() {
        patch.delete.insert(name.to_string());
    } else {
        patch.set.insert(
            name.to_string(),
            format!(":{v}", v = crate::calendar_write::escape_ical_text(v)),
        );
    }
}

/// Build the sealed update body for one GET-fresh row + local fields.
/// Returns `None` (= deferred, engine logs + skips) when the row carries
/// member `PersonalEvents` (never decrypted — must not drop) or has
/// undecryptable cards (can't seal what we can't read; never fail the
/// phase for one bad row). Attendee data is SAFE: cards reseal verbatim
/// and clear `Attendees` token rows re-send verbatim (wiping them would
/// destroy RSVP state — the pre-token guard is gone).
///
/// Patch scope (v1): TEXT (SUMMARY/DESCRIPTION/LOCATION) + times + RRULE.
/// Notifications/Color re-send verbatim unless `overrides` says otherwise;
/// calendar + attendees cards reseal verbatim. Phone-side attendee-identity
/// edits are NOT exported (download-wins, documented).
#[allow(clippy::too_many_lines)]
pub fn build_update_body(
    row: &CalendarEvent,
    fields: &LocalFields,
    overrides: Option<&crate::calendar_write::UpdateOverrides>,
    cal_keys: &mut [UnlockedKey],
    addr_keys: &mut [UnlockedKey],
) -> Result<Option<SyncEventBody>> {
    if !row.PersonalEvents.is_empty() {
        return Ok(None);
    }
    // Session keys (update carries no packets — all reuse). Present exactly
    // when the group has encrypted parts; extraction failure defers the row
    // (log + skip) instead of failing the whole upload phase.
    let mut shared_sk: Option<(SymmetricAlgorithm, SessionKey)> = None;
    if row.SharedEvents.iter().any(|p| (p.Type & 1) != 0) {
        if row.SharedKeyPacket.is_empty() {
            return Ok(None);
        }
        match extract_session_key(&row.SharedKeyPacket, cal_keys) {
            Ok(sk) => shared_sk = Some(sk),
            Err(_) => return Ok(None),
        }
    }
    let mut cal_sk: Option<(SymmetricAlgorithm, SessionKey)> = None;
    if row.CalendarEvents.iter().any(|p| (p.Type & 1) != 0) {
        if row.CalendarKeyPacket.is_empty() {
            return Ok(None);
        }
        match extract_session_key(&row.CalendarKeyPacket, cal_keys) {
            Ok(sk) => cal_sk = Some(sk),
            Err(_) => return Ok(None),
        }
    }
    // Undecryptable groups defer the row (log + skip) instead of failing
    // the whole upload phase — we can't seal what we can't read.
    let Some(shared) = decrypt_group(&row.SharedEvents, &row.SharedKeyPacket, cal_keys, addr_keys)
    else {
        return Ok(None);
    };
    let Some(calendar) = decrypt_group(
        &row.CalendarEvents,
        &row.CalendarKeyPacket,
        cal_keys,
        addr_keys,
    ) else {
        return Ok(None);
    };
    let Some(attendees) = decrypt_group(
        &row.AttendeesEvents,
        &row.SharedKeyPacket,
        cal_keys,
        addr_keys,
    ) else {
        return Ok(None);
    };

    let all_day = fields.all_day.unwrap_or(row.FullDay.unwrap_or(false));
    let mut signed_patch = CardPatch::default();
    let mut enc_patch = CardPatch::default();
    // Server-sent VERSION/PRODID lines are read-tolerated but never
    // written: proton-cal's builder never emits them, so whole-object
    // replaces must not echo them back (live 2011 lesson 2026-09-08).
    for patch in [&mut signed_patch, &mut enc_patch] {
        patch.delete.insert("VERSION".into());
        patch.delete.insert("PRODID".into());
    }
    let mut strip_patch = CardPatch::default();
    strip_patch.delete.insert("VERSION".into());
    strip_patch.delete.insert("PRODID".into());
    // Times (signed card). Phone all-day end is inclusive → exclusive.
    if let Some(start) = fields.start_unix {
        if let Some(v) = format_ical_dt(start, all_day) {
            signed_patch.set.insert("DTSTART".into(), v);
        }
    }
    if let Some(end) = fields.end_unix {
        let v = if all_day {
            format_ical_date_end_exclusive(end)
        } else {
            format_ical_dt(end, false)
        };
        if let Some(v) = v {
            signed_patch.set.insert("DTEND".into(), v);
        }
    }
    // Significance vs the plaintext row columns (no decrypt needed).
    let times_changed = fields.start_unix.is_some_and(|s| s != row.StartTime)
        || fields.end_unix.is_some_and(|e| {
            // All-day phone end is inclusive; row EndTime is exclusive.
            if all_day {
                e.saturating_add(86400) != row.EndTime
            } else {
                e != row.EndTime
            }
        })
        || fields
            .all_day
            .is_some_and(|a| a != row.FullDay.unwrap_or(false));
    // RRULE (signed card). None = keep; Some(None) = delete rule (+ its
    // EXDATEs) — EXCEPT with has_recurrence (unserializable phone rule:
    // keep the server rule; the phone edit reverts on download); Some
    // with a string = set it.
    let mut rrule_changed = false;
    match &fields.rrule {
        None => {}
        Some(None) if fields.has_recurrence => {}
        Some(None) => {
            signed_patch.delete.insert("RRULE".into());
            signed_patch.delete.insert("EXDATE".into());
            rrule_changed = row.RRule.as_ref().is_some_and(|r| !r.is_empty());
        }
        Some(Some(r)) => {
            signed_patch.set.insert("RRULE".into(), format!(":{r}"));
            rrule_changed = row.RRule.as_deref() != Some(r.as_str());
        }
    }
    if times_changed || rrule_changed {
        let seq = max_sequence(
            &shared
                .iter()
                .map(|(_, plain)| plain.clone())
                .collect::<Vec<_>>(),
        );
        signed_patch
            .set
            .insert("SEQUENCE".into(), format!(":{}", next_sequence(seq, true)));
    }
    // Text (encrypted card).
    apply_text(&mut enc_patch, "SUMMARY", fields.summary.as_deref());
    apply_text(&mut enc_patch, "DESCRIPTION", fields.description.as_deref());
    apply_text(&mut enc_patch, "LOCATION", fields.location.as_deref());

    // Per-card patch assignment: shared cards split by group — signed
    // entries take the structural patch, encrypted entries the text patch.
    let mut shared_patches = Vec::with_capacity(shared.len());
    for (encrypted, _) in &shared {
        shared_patches.push(if *encrypted {
            enc_patch.clone()
        } else {
            signed_patch.clone()
        });
    }
    let shared_parts = reseal_group(
        &shared,
        shared_patches,
        shared_sk.as_ref().map(|(algo, sk)| (sk, *algo)),
        addr_keys,
    )?;
    let calendar_parts = reseal_group(
        &calendar,
        vec![strip_patch.clone(); calendar.len()],
        cal_sk.as_ref().map(|(algo, sk)| (sk, *algo)),
        addr_keys,
    )?;
    let attendees_parts = reseal_group(
        &attendees,
        vec![strip_patch.clone(); attendees.len()],
        shared_sk.as_ref().map(|(algo, sk)| (sk, *algo)),
        addr_keys,
    )?;
    // Re-send row metadata verbatim (whole-object replace must not reset
    // reminders/color; phone edits to those stay download-wins in v1).
    // Clear attendee token rows re-send verbatim (wiping them would
    // destroy server-side RSVP state); `[]` exactly when the row has none.
    let attendees_value = if row.Attendees.is_empty() {
        serde_json::Value::Array(Vec::new())
    } else {
        crate::calendar_write::marshal_attendees(
            &row.Attendees
                .iter()
                .map(|t| (t.Token.clone(), t.Status))
                .collect::<Vec<_>>(),
        )
    };
    let no_overrides = crate::calendar_write::UpdateOverrides::default();
    let applied = overrides.unwrap_or(&no_overrides);
    let notifications = match &applied.notifications {
        None => marshal_notifications(
            row.Notifications.is_some(),
            &row.Notifications.clone().unwrap_or_default(),
        ),
        Some(None) => serde_json::Value::Null,
        Some(Some(list)) => marshal_notifications(true, list),
    };
    let color = match &applied.color {
        None => marshal_color(row.Color.as_deref().unwrap_or("")),
        Some(hex) => marshal_color(hex),
    };
    Ok(Some(SyncEventBody {
        Permissions: 1,
        SharedKeyPacket: None,
        CalendarKeyPacket: None,
        SharedEventContent: shared_parts,
        CalendarEventContent: calendar_parts,
        AttendeesEventContent: attendees_parts,
        Attendees: attendees_value,
        Notifications: notifications,
        Color: color,
    }))
}

/// Re-seal one encrypted card for an UPDATE with the SAME session key
/// (decrypted from the stored packet via `extract_session_key`): fresh
/// data bytes + fresh plaintext signature, NO new key packet (the update
/// body reuses the stored one). Mirrors proton-cal `resealCard`.
pub fn reseal_card(
    plain: &str,
    session_key: &SessionKey,
    algo: SymmetricAlgorithm,
    addr_key: &mut UnlockedKey,
) -> Result<(Vec<u8>, String)> {
    let data = encrypt_with_session_key(plain.as_bytes(), algo, session_key)?;
    let signer = addr_key
        .keypairs
        .first_mut()
        .ok_or_else(|| ProtonError::Crypto("reseal: address key has no pairs".into()))?;
    let sig = detached_sign(plain.as_bytes(), signer)?;
    Ok((data, sig))
}

/// Normalize inner VEVENT lines into a wrapped, folded fragment (the
/// create path builds cards from fields; updates reuse decrypted text).
fn wrap_fragment(inner_lines: &[String]) -> String {
    patch_card(&inner_lines.join("\n"), &CardPatch::default())
}

/// Build the sealed create body from local fields. Returns `None` (=
/// deferred) when times are missing or the phone recurrence is
/// unserializable (`has_recurrence` without a rule string) — a flattened
/// single event must never silently replace a series. Notifications/Color
/// stay `null` (inherit calendar defaults — v1 has no reminder/color
/// export); attendees start empty.
pub fn build_create_body(
    fields: &LocalFields,
    uid: &str,
    cal_keys: &mut [UnlockedKey],
    addr_keys: &mut [UnlockedKey],
) -> Result<Option<SyncEventBody>> {
    let rule: Option<String> = match (&fields.rrule, fields.has_recurrence) {
        (None, false) | (Some(None), false) => None,
        (Some(Some(r)), _) => Some(r.clone()),
        (None, true) | (Some(None), true) => return Ok(None),
    };
    let (Some(start), Some(end)) = (fields.start_unix, fields.end_unix) else {
        return Ok(None);
    };
    let all_day = fields.all_day.unwrap_or(false);
    let now = chrono::Utc::now().timestamp();
    let Some(dtstamp) = format_ical_dt(now, false) else {
        return Ok(None);
    };
    let Some(dtstart) = format_ical_dt(start, all_day) else {
        return Ok(None);
    };
    let Some(dtend) = (if all_day {
        format_ical_date_end_exclusive(end)
    } else {
        format_ical_dt(end, false)
    }) else {
        return Ok(None);
    };
    let mut signed_inner = vec![
        format!("UID:{uid}"),
        format!("DTSTAMP{dtstamp}"),
        format!("DTSTART{dtstart}"),
        format!("DTEND{dtend}"),
    ];
    if let Some(r) = rule {
        signed_inner.push(format!("RRULE:{r}"));
    }
    signed_inner.push("SEQUENCE:0".into());
    let mut enc_inner = vec![format!("UID:{uid}")];
    if let Some(s) = fields.summary.as_deref().filter(|s| !s.is_empty()) {
        enc_inner.push(format!("SUMMARY:{}", escape_ical_text(s)));
    }
    if let Some(s) = fields.description.as_deref().filter(|s| !s.is_empty()) {
        enc_inner.push(format!("DESCRIPTION:{}", escape_ical_text(s)));
    }
    if let Some(s) = fields.location.as_deref().filter(|s| !s.is_empty()) {
        enc_inner.push(format!("LOCATION:{}", escape_ical_text(s)));
    }
    let cal_signed_inner = vec![format!("UID:{uid}"), format!("DTSTAMP{dtstamp}")];
    let cal_enc_inner = vec![format!("UID:{uid}")];

    let shared_signed = wrap_fragment(&signed_inner);
    let shared_encrypted = wrap_fragment(&enc_inner);
    let cal_signed = wrap_fragment(&cal_signed_inner);
    let cal_encrypted = wrap_fragment(&cal_enc_inner);

    let shared_signed_sig = detached_sign(
        shared_signed.as_bytes(),
        addr_keys
            .first_mut()
            .and_then(|k| k.keypairs.first_mut())
            .ok_or_else(|| ProtonError::Crypto("create: address key has no pairs".into()))?,
    )?;
    let cal_signed_sig = detached_sign(
        cal_signed.as_bytes(),
        addr_keys
            .first_mut()
            .and_then(|k| k.keypairs.first_mut())
            .ok_or_else(|| ProtonError::Crypto("create: address key has no pairs".into()))?,
    )?;
    let (shared_kp, shared_data, shared_sig) = seal_card(&shared_encrypted, cal_keys, addr_keys)?;
    let (cal_kp, cal_data, cal_sig) = seal_card(&cal_encrypted, cal_keys, addr_keys)?;

    Ok(Some(SyncEventBody {
        Permissions: 1,
        SharedKeyPacket: Some(base64::engine::general_purpose::STANDARD.encode(shared_kp)),
        CalendarKeyPacket: Some(base64::engine::general_purpose::STANDARD.encode(cal_kp)),
        SharedEventContent: vec![
            SyncContentPart {
                Type: 2,
                Data: shared_signed,
                Signature: shared_signed_sig,
            },
            SyncContentPart {
                Type: 3,
                Data: base64::engine::general_purpose::STANDARD.encode(shared_data),
                Signature: shared_sig,
            },
        ],
        CalendarEventContent: vec![
            SyncContentPart {
                Type: 2,
                Data: cal_signed,
                Signature: cal_signed_sig,
            },
            SyncContentPart {
                Type: 3,
                Data: base64::engine::general_purpose::STANDARD.encode(cal_data),
                Signature: cal_sig,
            },
        ],
        AttendeesEventContent: Vec::new(),
        Attendees: serde_json::Value::Array(Vec::new()),
        Notifications: serde_json::Value::Null,
        Color: serde_json::Value::Null,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sequoia_openpgp::{cert::CertBuilder, parse::stream::DetachedVerifierBuilder};

    /// Fresh test identity: public cert + unlocked key (primary + signing
    /// subkey + transport encryption subkey, no password). Pure-Rust
    /// backend: no fixtures.
    fn test_identity() -> (sequoia_openpgp::Cert, UnlockedKey) {
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .expect("test key generation");
        // NB: `armored()` exports public-only; secret material needs `as_tsk()`.
        let mut armored_bytes = Vec::new();
        cert.as_tsk()
            .armored()
            .export(&mut armored_bytes)
            .expect("test cert armor");
        let armored = armored_bytes
            .into_iter()
            .map(|b| b as char)
            .collect::<String>();
        let unlocked = UnlockedKey::from_armored(&armored, b"").expect("test key unlock");
        (cert, unlocked)
    }

    fn b64(raw: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    #[test]
    fn test_detached_sign_is_armored() {
        let (_, mut addr) = test_identity();
        let sig = detached_sign(b"UID:u1", addr.keypairs.first_mut().unwrap()).unwrap();
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"), "{sig}");
        assert!(sig.contains("-----END PGP SIGNATURE-----"), "{sig}");
    }

    #[test]
    fn test_detached_sign_verifies_against_public_key() {
        let (cert, mut addr) = test_identity();
        let sig = detached_sign(b"Hello", addr.keypairs.first_mut().unwrap()).unwrap();
        struct H(sequoia_openpgp::Cert);
        impl sequoia_openpgp::parse::stream::VerificationHelper for H {
            fn get_certs(
                &mut self,
                _ids: &[sequoia_openpgp::KeyHandle],
            ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
                Ok(vec![self.0.clone()])
            }
            fn check(
                &mut self,
                s: sequoia_openpgp::parse::stream::MessageStructure,
            ) -> sequoia_openpgp::Result<()> {
                s.iter().next().unwrap();
                Ok(())
            }
        }
        let policy = sequoia_openpgp::policy::StandardPolicy::new();
        let mut verifier = DetachedVerifierBuilder::from_bytes(sig.as_bytes())
            .unwrap()
            .with_policy(&policy, None, H(cert))
            .unwrap();
        verifier.verify_bytes(b"Hello").unwrap();
    }

    #[test]
    fn test_seal_round_trips_through_read_path() {
        // The killer self-consistency check: our sealed output must decrypt
        // through the EXISTING engine read path (`decrypt_calendar_part`
        // split-packet branch with kp+data).
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        let plain = "BEGIN:VEVENT\r\nUID:seal-1\r\nSUMMARY:Sealed\r\nEND:VEVENT";
        let (kp, data, sig) = seal_card(
            plain,
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        assert!(!kp.is_empty() && !data.is_empty());
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----"));

        let part = crate::CalendarEventPart {
            MemberID: String::new(),
            Type: 3, // encrypted (+ signed bit not required for decrypt)
            Data: b64(&data),
            Signature: sig,
            Author: String::new(),
        };
        let kp_b64 = b64(&kp);
        let back = crate::calendar::decrypt_calendar_part(
            &part,
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
            Some(&kp_b64),
        )
        .unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn test_extract_and_reseal_reuses_packet() {
        // Update-path invariant: extract SK from the STORED packet, seal new
        // plaintext with it, combine ORIGINAL kp + NEW data → decrypts.
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        let (kp, _data, _sig) = seal_card(
            "BEGIN:VEVENT\r\nUID:r1\r\nSUMMARY:v1\r\nEND:VEVENT",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        let kp_b64 = b64(&kp);
        let (algo, sk) = extract_session_key(&kp_b64, std::slice::from_mut(&mut cal)).unwrap();
        let patched = "BEGIN:VEVENT\r\nUID:r1\r\nSUMMARY:v2 edited\r\nEND:VEVENT";
        let (new_data, _new_sig) = reseal_card(patched, &sk, algo, &mut addr).unwrap();
        // Same packet, new data → the update body shape (no new key packet).
        let part = crate::CalendarEventPart {
            MemberID: String::new(),
            Type: 3,
            Data: b64(&new_data),
            Signature: String::new(),
            Author: String::new(),
        };
        let back = crate::calendar::decrypt_calendar_part(
            &part,
            std::slice::from_mut(&mut cal),
            &mut [],
            Some(&kp_b64),
        )
        .unwrap();
        assert_eq!(back, patched);
    }

    #[test]
    fn test_extract_rejects_wrong_key() {
        let (_, mut cal) = test_identity();
        let (_, mut other) = test_identity();
        let (_, mut addr) = test_identity();
        let (kp, _, _) = seal_card(
            "plain",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        assert!(extract_session_key(&b64(&kp), std::slice::from_mut(&mut other)).is_err());
    }

    /// Decrypt one Type-3 body part with an explicit packet through the
    /// engine read path (mirrors update/download symmetry).
    fn decrypt_body(
        data_b64: &str,
        sig: &str,
        kp_b64: &str,
        cal: &mut UnlockedKey,
        addr: &mut UnlockedKey,
    ) -> String {
        let part = CalendarEventPart {
            MemberID: String::new(),
            Type: 3,
            Data: data_b64.to_string(),
            Signature: sig.to_string(),
            Author: String::new(),
        };
        crate::calendar::decrypt_calendar_part(
            &part,
            std::slice::from_mut(cal),
            std::slice::from_mut(addr),
            Some(kp_b64),
        )
        .unwrap()
    }

    struct UpdateFixture {
        row: CalendarEvent,
        shared_kp_b64: String,
        cal: UnlockedKey,
        addr: UnlockedKey,
    }

    /// Signed structural + sealed text cards (SEQUENCE:3), no attendees,
    /// no personal parts — the updatable shape.
    fn update_fixture() -> UpdateFixture {
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        let shared_signed =
            "BEGIN:VEVENT\r\nUID:fx-1\r\nDTSTART:20260914T200000Z\r\nDTEND:20260914T210000Z\r\nSEQUENCE:3\r\nEND:VEVENT";
        let shared_plain =
            "BEGIN:VEVENT\r\nUID:fx-1\r\nSUMMARY:Old title\r\nDESCRIPTION:Keep me\r\nEND:VEVENT";
        let cal_signed = "BEGIN:VEVENT\r\nUID:fx-1\r\nSTATUS:CONFIRMED\r\nEND:VEVENT";
        let (skp, sdata, ssig) = seal_card(
            shared_plain,
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        let shared_kp_b64 = b64(&skp);
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-09-14T20:00:00Z")
            .unwrap()
            .timestamp();
        let row = CalendarEvent {
            ID: "fx-1".into(),
            UID: "fx-1".into(),
            CalendarID: "c1".into(),
            StartTime: t0,
            EndTime: t0 + 3600,
            FullDay: Some(false),
            RRule: None,
            Notifications: Some(vec![serde_json::json!({"Trigger": "-PT15M", "Type": 1})]),
            Color: None,
            SharedKeyPacket: shared_kp_b64.clone(),
            CalendarKeyPacket: String::new(),
            SharedEvents: vec![
                CalendarEventPart {
                    MemberID: String::new(),
                    Type: 2,
                    Data: shared_signed.to_string(),
                    Signature: "ssig".into(),
                    Author: String::new(),
                },
                CalendarEventPart {
                    MemberID: String::new(),
                    Type: 3,
                    Data: b64(&sdata),
                    Signature: ssig,
                    Author: String::new(),
                },
            ],
            CalendarEvents: vec![CalendarEventPart {
                MemberID: String::new(),
                Type: 2,
                Data: cal_signed.to_string(),
                Signature: "csig".into(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        UpdateFixture {
            row,
            shared_kp_b64,
            cal,
            addr,
        }
    }

    #[test]
    fn test_update_text_edit_preserves_rest() {
        let mut fx = update_fixture();
        let fields = LocalFields {
            summary: Some("New title".into()),
            ..Default::default()
        };
        let body = build_update_body(
            &fx.row,
            &fields,
            None,
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("text edit seals");
        // No key packets on update; notifications verbatim.
        assert!(body.SharedKeyPacket.is_none());
        assert_eq!(
            body.Notifications,
            serde_json::json!([{"Trigger": "-PT15M", "Type": 1}])
        );
        // Encrypted part decrypts (ORIGINAL packet) to edited text + kept text.
        let enc = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 3)
            .expect("encrypted part");
        let plain = decrypt_body(
            &enc.Data,
            &enc.Signature,
            &fx.shared_kp_b64,
            &mut fx.cal,
            &mut fx.addr,
        );
        let parsed = crate::calendar::parse_ical(&plain).unwrap();
        assert_eq!(parsed.summary, "New title");
        assert_eq!(parsed.description, "Keep me");
        // Structural untouched, SEQUENCE unbumped (not significant).
        let signed = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 2)
            .expect("signed part");
        assert!(signed.Data.contains("DTSTART:20260914T200000Z"));
        assert!(signed.Data.contains("SEQUENCE:3"));
        // Calendar card resealed verbatim (re-signed).
        assert_eq!(body.CalendarEventContent.len(), 1);
        assert!(body.CalendarEventContent[0]
            .Data
            .contains("STATUS:CONFIRMED"));
    }

    #[test]
    fn test_update_time_edit_bumps_sequence() {
        let mut fx = update_fixture();
        let t0 = fx.row.StartTime;
        let fields = LocalFields {
            start_unix: Some(t0 + 3600),
            end_unix: Some(t0 + 7200),
            ..Default::default()
        };
        let body = build_update_body(
            &fx.row,
            &fields,
            None,
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("time edit seals");
        let signed = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 2)
            .unwrap();
        assert!(
            signed.Data.contains("DTSTART:20260914T210000Z"),
            "{}",
            signed.Data
        );
        assert!(
            signed.Data.contains("DTEND:20260914T220000Z"),
            "{}",
            signed.Data
        );
        assert!(signed.Data.contains("SEQUENCE:4"), "{}", signed.Data);
    }

    #[test]
    fn test_update_strips_version_prodid() {
        // Live 2011 lesson: server-sent VERSION/PRODID are read-tolerated
        // but never re-emitted (proton-cal's builder never emits them).
        let mut fx = update_fixture();
        fx.row.SharedEvents[0].Data = format!(
            "BEGIN:VEVENT\r\nVERSION:2.0\r\nPRODID:-//Proton AG//web-calendar//EN\r\n{}",
            fx.row.SharedEvents[0].Data
        );
        let fields = LocalFields {
            summary: Some("Stripped".into()),
            ..Default::default()
        };
        let body = build_update_body(
            &fx.row,
            &fields,
            None,
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("strips and seals");
        for part in body
            .SharedEventContent
            .iter()
            .chain(body.CalendarEventContent.iter())
        {
            if (part.Type & 1) != 0 {
                continue; // ciphertext opaque; signed parts carry the check
            }
            assert!(!part.Data.contains("VERSION:"), "{}", part.Data);
            assert!(!part.Data.contains("PRODID:"), "{}", part.Data);
        }
    }

    #[test]
    fn test_update_preserves_attendee_tokens() {
        // Attendee data is now SAFE (not deferred): cards reseal verbatim
        // and clear token rows re-send verbatim — wiping them would destroy
        // server-side RSVP state. Only PersonalEvents still defers.
        let mut fx = update_fixture();
        fx.row.CalendarEvents[0].Data += "\r\nATTENDEE:mailto:a@b.c";
        fx.row.Attendees = vec![crate::AttendeeToken {
            Token: "tok-1".into(),
            Status: 3,
        }];
        let fields = LocalFields {
            summary: Some("x".into()),
            ..Default::default()
        };
        let body = build_update_body(
            &fx.row,
            &fields,
            None,
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("attendee rows proceed");
        assert_eq!(
            body.Attendees,
            serde_json::json!([{"Token": "tok-1", "Status": 3, "Comment": null}])
        );
    }

    #[test]
    fn test_update_overrides_notifications_and_color() {
        let mut fx = update_fixture();
        // Row carries one custom reminder; override replaces it, null
        // forces inherit, color swaps the row value.
        let fields = LocalFields::default();
        let overrides = crate::calendar_write::UpdateOverrides {
            notifications: Some(Some(vec![
                serde_json::json!({"Trigger": "-PT1H", "Type": 1}),
            ])),
            color: Some("#EC3E7C".into()),
        };
        let body = build_update_body(
            &fx.row,
            &fields,
            Some(&overrides),
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("overrides seal");
        assert_eq!(
            body.Notifications,
            serde_json::json!([{"Trigger": "-PT1H", "Type": 1}])
        );
        assert_eq!(body.Color, serde_json::json!("#EC3E7C"));
        let null_over = crate::calendar_write::UpdateOverrides {
            notifications: Some(None),
            color: None,
        };
        let body2 = build_update_body(
            &fx.row,
            &fields,
            Some(&null_over),
            std::slice::from_mut(&mut fx.cal),
            std::slice::from_mut(&mut fx.addr),
        )
        .unwrap()
        .expect("null override seals");
        assert_eq!(body2.Notifications, serde_json::Value::Null);
        // No overrides → verbatim row values (prove with the fixture's row).
        assert_eq!(
            fx.row.Notifications,
            Some(vec![serde_json::json!({"Trigger": "-PT15M", "Type": 1})])
        );
    }

    #[test]
    fn test_update_defers_personal_events() {
        // PersonalEvents card → never decrypted, must not drop.
        let fields = LocalFields {
            summary: Some("x".into()),
            ..Default::default()
        };
        let mut fx2 = update_fixture();
        fx2.row.PersonalEvents = vec![CalendarEventPart {
            MemberID: String::new(),
            Type: 2,
            Data: "BEGIN:VEVENT\r\nUID:fx-1\r\nX-PERSONAL:y\r\nEND:VEVENT".into(),
            Signature: "s".into(),
            Author: String::new(),
        }];
        assert!(
            build_update_body(&fx2.row, &fields, None, &mut [fx2.cal], &mut [fx2.addr])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_create_body_round_trips() {
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-09-14T20:00:00Z")
            .unwrap()
            .timestamp();
        let fields = LocalFields {
            summary: Some("Fresh".into()),
            description: Some("Hello".into()),
            location: None,
            start_unix: Some(t0),
            end_unix: Some(t0 + 1800),
            all_day: Some(false),
            rrule: None,
            has_recurrence: false,
            notifications: None,
            color: None,
        };
        let body = build_create_body(
            &fields,
            "fresh-uid",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap()
        .expect("create seals");
        let (skp, ckp) = (
            body.SharedKeyPacket.clone().unwrap(),
            body.CalendarKeyPacket.clone().unwrap(),
        );
        assert_ne!(skp, ckp, "separate session keys per card");
        // Shared encrypted decrypts to the entered text.
        let enc = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 3)
            .unwrap();
        let plain = decrypt_body(&enc.Data, &enc.Signature, &skp, &mut cal, &mut addr);
        let parsed = crate::calendar::parse_ical(&plain).unwrap();
        assert_eq!(parsed.summary, "Fresh");
        assert_eq!(parsed.description, "Hello");
        // Signed carries structure + SEQUENCE:0 + UID.
        let signed = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 2)
            .unwrap();
        assert!(signed.Data.contains("UID:fresh-uid"));
        assert!(signed.Data.contains("DTSTART:20260914T200000Z"));
        assert!(signed.Data.contains("SEQUENCE:0"));
        // Calendar encrypted decrypts with ITS packet.
        let cinc = body
            .CalendarEventContent
            .iter()
            .find(|p| p.Type == 3)
            .unwrap();
        let cplain = decrypt_body(&cinc.Data, &cinc.Signature, &ckp, &mut cal, &mut addr);
        assert!(cplain.contains("UID:fresh-uid"));
        // Inherit-by-default rows.
        assert_eq!(body.Notifications, serde_json::Value::Null);
        assert_eq!(body.Color, serde_json::Value::Null);
        assert!(body.AttendeesEventContent.is_empty());
    }

    #[test]
    fn test_create_all_day_exclusive_end_rolls_month() {
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        // Phone-inclusive 2026-01-31 → exclusive 2026-02-01 (rollover!).
        let end_incl = chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
            .unwrap()
            .timestamp();
        let fields = LocalFields {
            summary: Some("Holiday".into()),
            start_unix: Some(end_incl),
            end_unix: Some(end_incl),
            all_day: Some(true),
            ..Default::default()
        };
        let body = build_create_body(
            &fields,
            "u-ad",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap()
        .expect("all-day create seals");
        let signed = body
            .SharedEventContent
            .iter()
            .find(|p| p.Type == 2)
            .unwrap();
        assert!(
            signed.Data.contains("DTSTART;VALUE=DATE:20260131"),
            "{}",
            signed.Data
        );
        assert!(
            signed.Data.contains("DTEND;VALUE=DATE:20260201"),
            "{}",
            signed.Data
        );
    }

    #[test]
    fn test_create_defers_without_times_or_rule() {
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        // No times → cannot fabricate.
        let bare = LocalFields {
            summary: Some("x".into()),
            ..Default::default()
        };
        assert!(build_create_body(
            &bare,
            "u",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr)
        )
        .unwrap()
        .is_none());
        // Unserializable phone recurrence → never flatten a series.
        let t0 = chrono::Utc::now().timestamp();
        let recur = LocalFields {
            start_unix: Some(t0),
            end_unix: Some(t0 + 60),
            has_recurrence: true,
            rrule: None,
            ..Default::default()
        };
        assert!(build_create_body(
            &recur,
            "u",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr)
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn test_format_ical_dt_shapes() {
        assert_eq!(
            format_ical_dt(0, false).as_deref(),
            Some(":19700101T000000Z")
        );
        assert_eq!(
            format_ical_dt(0, true).as_deref(),
            Some(";VALUE=DATE:19700101")
        );
        // Phone-inclusive 2026-01-31 → exclusive 2026-02-01.
        let end_incl = chrono::DateTime::parse_from_rfc3339("2026-01-31T00:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(
            format_ical_date_end_exclusive(end_incl).as_deref(),
            Some(";VALUE=DATE:20260201")
        );
        assert!(format_ical_dt(i64::MAX, false).is_none());
    }

    #[test]
    fn test_seal_ciphertext_differs_per_seal() {
        // Fresh session keys: same plaintext seals differently (no key reuse
        // on create), yet both decrypt.
        let (_, mut cal) = test_identity();
        let (_, mut addr) = test_identity();
        let (kp1, data1, _) = seal_card(
            "same",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        let (kp2, data2, _) = seal_card(
            "same",
            std::slice::from_mut(&mut cal),
            std::slice::from_mut(&mut addr),
        )
        .unwrap();
        assert_ne!(kp1, kp2);
        assert_ne!(data1, data2);
    }
}
