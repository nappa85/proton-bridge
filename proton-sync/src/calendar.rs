use crate::{config::SyncConfig, status::SyncStatus};
use base64::Engine;
use proton_api::{
    calendar as cal_api, CalendarClient, CalendarEvent, KeysClient, TokenManager, UnlockedKey,
};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// JSON shape consumed by the C++ mKCal shim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CalEventJson {
    pub id: String,
    pub uid: String,
    pub calendar_id: String,
    pub calendar_name: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub dtstart: String,
    pub dtend: String,
    pub dtstamp: String,
    pub rrule: String,
    pub exdates: Vec<String>,
    pub sequence: String,
    pub status: String,
    pub transp: String,
    pub organizer: String,
    pub attendees: Vec<String>,
    pub start_time: i64,
    pub end_time: i64,
    pub start_timezone: String,
    pub end_timezone: String,
    pub full_day: bool,
    pub color: Option<String>,
    pub recurrence_id: Option<i64>,
}

use serde::Deserialize;

pub struct CalendarSyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
    events_json: Arc<Mutex<Option<String>>>,
    keys_debug: Arc<Mutex<Option<String>>>,
}

impl CalendarSyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let mut tm = TokenManager::new();
        if let (Some(rt), Some(uid)) = (&config.refresh_token, &config.uid) {
            if !rt.is_empty() && !uid.is_empty() {
                let at = config.access_token.as_deref().unwrap_or("");
                tm.restore_tokens(proton_api::AuthTokens {
                    access_token: at.to_string(),
                    refresh_token: rt.clone(),
                    uid: uid.clone(),
                });
                if !at.is_empty() {
                    tm.set_expiry(3600);
                }
            }
        }
        Self {
            config: Arc::new(Mutex::new(config)),
            status: Arc::new(Mutex::new(SyncStatus::default())),
            token_manager: Arc::new(Mutex::new(tm)),
            events_json: Arc::new(Mutex::new(None)),
            keys_debug: Arc::new(Mutex::new(None)),
        }
    }

    pub fn config(&self) -> SyncConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *self.config.lock().unwrap() = config.clone();
        *self.events_json.lock().unwrap() = None;
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.0,
            ..Default::default()
        });
        match self.run_sync(&config) {
            Ok(evts) => {
                let json = serde_json::to_string(&evts).unwrap_or_else(|_| "[]".into());
                *self.events_json.lock().unwrap() = Some(json);
                self.set_status(SyncStatus {
                    state: "complete".into(),
                    progress: 1.0,
                    total_contacts: evts.len() as u32,
                    synced_contacts: evts.len() as u32,
                    ..Default::default()
                });
            }
            Err(e) => {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!("Calendar sync failed: {e}")),
                    ..Default::default()
                });
            }
        }
    }

    fn run_sync(&self, config: &SyncConfig) -> Result<Vec<CalEventJson>, proton_api::ProtonError> {
        let mut tm = self.token_manager.lock().unwrap();
        if tm.refresh_token().is_none()
            && config.password.is_empty()
            && config.derived_passwords.is_none()
        {
            return Err(proton_api::ProtonError::Auth("No auth".into()));
        }
        let access_token = if tm.refresh_token().is_some() {
            tm.access_token()?
        } else {
            return Err(proton_api::ProtonError::Auth(
                "Calendar needs refresh token".into(),
            ));
        };
        let uid = tm.uid().unwrap_or(&config.username).to_string();
        drop(tm);
        if std::env::var("LIVE_TRACE").is_ok() {
            eprintln!(
                "engine token={} uid={uid}",
                &access_token[..6.min(access_token.len())]
            );
        }

        // Phase 1: fetch event rows FIRST, before any key/salt/bootstrap
        // calls. Live-verified 2026-09-06 (FINDINGS_CALENDAR.md §7): in a
        // session, untyped listing returns rows when called before
        // get_user/get_key_salts/get_addresses/bootstrap, and null Events
        // afterwards — same token, same params. Cause unknown (server-side
        // read-state); ordering around it is the reliable path.
        let cal_client = CalendarClient::new(access_token.clone(), uid.clone());
        let cals = cal_client.list_calendars().unwrap_or_default();
        let mut out = Vec::new();
        let mut query_errors: Vec<String> = Vec::new();
        let mut fetched: Vec<(proton_api::Calendar, Vec<CalendarEvent>)> = Vec::new();
        for cal in &cals {
            match cal_client.list_all_events(&cal.ID) {
                Ok(evs) => fetched.push((cal.clone(), evs)),
                Err(e) => {
                    query_errors.push(format!("{}:{e}", &cal.ID[..8.min(cal.ID.len())]));
                }
            }
        }
        // Unlock user + address keys (same Token-aware logic as contacts engine).
        let mut address_keys = self.unlock_address_keys(&access_token, &uid, config)?;
        for (cal, events) in &fetched {
            // Bootstrap: members + keys + passphrase in one call (v2, fallback v1).
            let bootstrap =
                cal_client
                    .get_bootstrap(&cal.ID)
                    .unwrap_or(proton_api::CalendarBootstrap {
                        Members: Vec::new(),
                        Keys: Vec::new(),
                        Passphrase: None,
                    });
            // Display metadata lives on the member entry (api.md drift),
            // top-level Name is a legacy fallback.
            let cal_name = bootstrap
                .Members
                .first()
                .map(|m| {
                    if m.Name.is_empty() {
                        m.Email.clone()
                    } else {
                        m.Name.clone()
                    }
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    if cal.Name.is_empty() {
                        cal.ID.clone()
                    } else {
                        cal.Name.clone()
                    }
                });
            let member_id = pick_member_id(&bootstrap.Members, &config.username);
            let mut cal_keys: Vec<UnlockedKey> = Vec::new();
            if let (Some(pp), Some(mid)) = (bootstrap.Passphrase.as_ref(), member_id.as_ref()) {
                if let Ok(uks) =
                    cal_api::decrypt_calendar_keys(&bootstrap.Keys, pp, &mut address_keys, mid)
                {
                    cal_keys = uks;
                }
            }
            // Fallback: try passphrase entries for any member when our pick fails
            // (shared calendars, email mismatch).
            if cal_keys.is_empty() {
                if let Some(pp) = bootstrap.Passphrase.as_ref() {
                    for mp in &pp.MemberPassphrases {
                        if let Ok(uks) = cal_api::decrypt_calendar_keys(
                            &bootstrap.Keys,
                            pp,
                            &mut address_keys,
                            &mp.MemberID,
                        ) {
                            cal_keys = uks;
                            break;
                        }
                    }
                }
            }
            self.set_debug(format!(
                "cal={} members={} calkeys={} addrkeys={}",
                &cal.ID[..8.min(cal.ID.len())],
                bootstrap.Members.len(),
                cal_keys.len(),
                address_keys.len()
            ));
            for ev in events {
                if let Some(json) =
                    Self::process_event(ev, &cal.ID, &cal_name, &mut cal_keys, &mut address_keys)
                {
                    out.push(json);
                }
            }
        }
        // Never report a silent empty success when every query failed.
        if out.is_empty() && !query_errors.is_empty() {
            return Err(proton_api::ProtonError::Api {
                code: 0,
                message: format!("Calendar event queries failed: {}", query_errors.join("; ")),
            });
        }
        Ok(out)
    }

    fn process_event(
        ev: &CalendarEvent,
        cal_id: &str,
        cal_name: &str,
        cal_keys: &mut [UnlockedKey],
        addr_keys: &mut [UnlockedKey],
    ) -> Option<CalEventJson> {
        let mut fragments: Vec<String> = Vec::new();
        // Shared-signed first (structural wins in merge), then shared-encrypted,
        // calendar parts, attendees. Key packets per Go Decode: shared cards use
        // SharedKeyPacket, calendar cards use CalendarKeyPacket.
        for part in &ev.SharedEvents {
            let is_cal = false;
            let _ = is_cal;
            // Heuristic: shared group → SharedKeyPacket.
            let kp = if ev.SharedKeyPacket.is_empty() {
                None
            } else {
                Some(ev.SharedKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            } else if (part.Type & 1) == 0 {
                fragments.push(part.Data.clone());
            }
        }
        for part in &ev.CalendarEvents {
            let kp = if ev.CalendarKeyPacket.is_empty() {
                None
            } else {
                Some(ev.CalendarKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            } else if (part.Type & 1) == 0 {
                fragments.push(part.Data.clone());
            }
        }
        for part in &ev.AttendeesEvents {
            let kp = if ev.SharedKeyPacket.is_empty() {
                None
            } else {
                Some(ev.SharedKeyPacket.as_str())
            };
            if let Ok(plain) = cal_api::decrypt_calendar_part(part, cal_keys, addr_keys, kp) {
                fragments.push(plain);
            }
        }
        // PersonalEvents carry member reminders; Notifications row is source of
        // truth (api.md) – skip decrypt, do not fail on them.
        let parsed = if fragments.is_empty() {
            cal_api::ParsedCalendarEvent::default()
        } else {
            cal_api::merge_ical_fragments(&fragments).unwrap_or_default()
        };
        // UID fallback to row UID (signed-only rows still listable).
        let uid = if parsed.uid.is_empty() {
            ev.UID.clone()
        } else {
            parsed.uid.clone()
        };
        if uid.is_empty() && parsed.summary.is_empty() {
            return None;
        }
        Some(CalEventJson {
            id: ev.ID.clone(),
            uid,
            calendar_id: cal_id.to_string(),
            calendar_name: cal_name.to_string(),
            summary: parsed.summary.clone(),
            description: parsed.description.clone(),
            location: parsed.location.clone(),
            dtstart: parsed.dtstart.clone(),
            dtend: parsed.dtend.clone(),
            dtstamp: parsed.dtstamp.clone(),
            rrule: parsed.rrule.clone(),
            exdates: parsed.exdates.clone(),
            sequence: parsed.sequence.clone(),
            status: parsed.status.clone(),
            transp: parsed.transp.clone(),
            organizer: parsed.organizer.clone(),
            attendees: parsed.attendees.clone(),
            start_time: ev.StartTime,
            end_time: ev.EndTime,
            start_timezone: ev.StartTimezone.clone(),
            end_timezone: ev.EndTimezone.clone(),
            full_day: ev.FullDay.unwrap_or(false),
            color: ev.Color.clone(),
            recurrence_id: ev.RecurrenceID,
        })
    }

    /// Unlock user keys via derived/salted passphrase, then address keys via
    /// Token (go-proton-api) with salt fallback. Returns address-capable keys
    /// (user keys + unlocked address keys – both can decrypt passphrase cards
    /// since passphrase may be encrypted to any account address key).
    fn unlock_address_keys(
        &self,
        access_token: &str,
        uid: &str,
        config: &SyncConfig,
    ) -> Result<Vec<UnlockedKey>, proton_api::ProtonError> {
        let keys_client = KeysClient::new(access_token.to_string(), uid.to_string());
        let user = keys_client.get_user()?;
        // Best-effort: restored sessions lack the elevated ("locked") scope
        // for /keys/salts (403/9101, verified live). Derived passwords and
        // Token-decrypt paths don't need salts, so continue without them.
        let salts = match keys_client.get_key_salts() {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("{e}");
                let short: String = msg.chars().take(80).collect();
                self.set_debug(format!("salts_unavailable:{short}"));
                Vec::new()
            }
        };
        let addresses = keys_client.get_addresses().unwrap_or_default();
        let mut unlocked: Vec<UnlockedKey> = Vec::new();
        let mut debug_parts: Vec<String> = Vec::new();
        // User keys.
        for key in &user.Keys {
            if key.PrivateKey.is_empty() {
                continue;
            }
            if let Some(pp) = Self::passphrase_for(
                &key.ID,
                &config.password,
                config.derived_passwords.as_ref(),
                salts.iter().find(|s| s.ID == key.ID),
            ) {
                if let Ok(uk) = UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                    debug_parts.push(format!("u_{}_ok", &key.ID[..8.min(key.ID.len())]));
                    unlocked.push(uk);
                }
            }
        }
        // Address keys: Token first, then salt fallback.
        for addr in &addresses {
            for key in &addr.Keys {
                if key.PrivateKey.is_empty() {
                    continue;
                }
                if !key.Token.is_empty() && !unlocked.is_empty() {
                    let mut found: Option<Vec<u8>> = None;
                    for uk in unlocked.iter_mut() {
                        if let Ok(secret) = proton_api::crypto::decrypt_raw_with_key(&key.Token, uk)
                        {
                            if !secret.is_empty() {
                                found = Some(secret);
                                break;
                            }
                        }
                    }
                    if let Some(secret) = found {
                        if let Ok(ak) = UnlockedKey::from_armored(&key.PrivateKey, &secret) {
                            debug_parts
                                .push(format!("a_{}_tok_ok", &key.ID[..8.min(key.ID.len())]));
                            unlocked.push(ak);
                            continue;
                        }
                    }
                }
                if let Some(pp) = Self::passphrase_for(
                    &key.ID,
                    &config.password,
                    config.derived_passwords.as_ref(),
                    salts.iter().find(|s| s.ID == key.ID),
                ) {
                    if let Ok(ak) = UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                        debug_parts.push(format!("a_{}_salt_ok", &key.ID[..8.min(key.ID.len())]));
                        unlocked.push(ak);
                    }
                }
            }
        }
        debug_parts.push(format!("total={}", unlocked.len()));
        self.set_debug(debug_parts.join(";"));
        Ok(unlocked)
    }

    fn passphrase_for(
        key_id: &str,
        password: &str,
        derived: Option<&std::collections::HashMap<String, String>>,
        salt: Option<&proton_api::KeySalt>,
    ) -> Option<Vec<u8>> {
        if let Some(map) = derived {
            if let Some(b64) = map.get(key_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return Some(bytes);
                }
            }
        }
        if password.is_empty() {
            return None;
        }
        let salt = salt?;
        let ks = salt.KeySalt.as_ref()?;
        if ks.is_empty() {
            return Some(password.as_bytes().to_vec());
        }
        proton_api::derive_mailbox_password(password.as_bytes(), ks).ok()
    }

    fn set_debug(&self, s: String) {
        let mut prev = self.keys_debug.lock().unwrap();
        let combined = match prev.clone() {
            Some(p) if !p.is_empty() => format!("{p}|{s}"),
            _ => s,
        };
        *prev = Some(combined);
    }

    pub fn status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn get_events_json(&self) -> String {
        self.events_json
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "[]".into())
    }

    pub fn get_keys_debug(&self) -> Option<String> {
        self.keys_debug.lock().unwrap().clone()
    }

    pub fn get_refresh_token(&self) -> Option<String> {
        self.token_manager
            .lock()
            .unwrap()
            .refresh_token()
            .map(str::to_string)
    }

    pub fn get_uid(&self) -> Option<String> {
        self.token_manager.lock().unwrap().uid().map(str::to_string)
    }

    fn set_status(&self, s: SyncStatus) {
        *self.status.lock().unwrap() = s;
    }
}

fn pick_member_id(members: &[proton_api::CalendarMember], _username: &str) -> Option<String> {
    // Prefer the first member (list endpoint returns only our own member,
    // api.md response drift). Email matching could refine shared calendars.
    members.first().map(|m| m.ID.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SyncConfig {
        SyncConfig {
            username: "u".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_process_event_signed_only_no_keys() {
        let ev = CalendarEvent {
            ID: "e1".into(),
            UID: "uid-1".into(),
            CalendarID: "c1".into(),
            StartTime: 100,
            EndTime: 200,
            StartTimezone: "UTC".into(),
            EndTimezone: "UTC".into(),
            FullDay: Some(false),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 2,
                Data: "BEGIN:VEVENT\nUID:uid-1\nSUMMARY:Standup\nDTSTART:20260602T090000Z\nDTEND:20260602T093000Z\nEND:VEVENT".into(),
                Signature: "sig".into(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        // Manual Default (CalendarEvent has no Default derive – build via serde).
        let got = CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut []);
        assert!(got.is_some());
        let g = got.unwrap();
        assert_eq!(g.uid, "uid-1");
        assert_eq!(g.summary, "Standup");
        assert_eq!(g.dtstart, "20260602T090000Z");
    }

    #[test]
    fn test_process_event_skips_fully_encrypted_without_keys() {
        let ev = CalendarEvent {
            ID: "e2".into(),
            UID: String::new(),
            CalendarID: "c1".into(),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 3,
                Data: "-----BEGIN PGP MESSAGE-----".into(),
                Signature: String::new(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        let got = CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut []);
        assert!(got.is_none());
    }

    #[test]
    fn test_pick_member_id_first() {
        let m = vec![
            proton_api::CalendarMember {
                ID: "m1".into(),
                ..Default::default()
            },
            proton_api::CalendarMember {
                ID: "m2".into(),
                ..Default::default()
            },
        ];
        assert_eq!(pick_member_id(&m, "u"), Some("m1".into()));
        let empty: Vec<proton_api::CalendarMember> = Vec::new();
        assert_eq!(pick_member_id(&empty, "u"), None);
    }

    #[test]
    fn test_engine_new_restores_tokens() {
        let mut c = cfg();
        c.refresh_token = Some("rt".into());
        c.uid = Some("uid".into());
        c.access_token = Some("at".into());
        let e = CalendarSyncEngine::new(c);
        assert_eq!(e.get_uid(), Some("uid".into()));
        assert_eq!(e.get_refresh_token(), Some("rt".into()));
        assert_eq!(e.get_events_json(), "[]");
    }
}
