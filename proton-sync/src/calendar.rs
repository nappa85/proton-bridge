use crate::{config::SyncConfig, status::SyncStatus};
use base64::Engine;
use proton_api::{
    calendar as cal_api, CalendarClient, CalendarEvent, KeysClient, TokenManager, UnlockedKey,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// JSON shape consumed by the C++ mKCal shim.
///
/// New fields are `#[serde(default)]` so old phone builds ignore them and
/// new builds accept old cached JSON: `organizer` stays the bare email,
/// `organizer_name` carries CN; `attendees` stays the legacy email list,
/// `attendees_full` carries CN/RSVP/PARTSTAT/ROLE; `recurrence_id_ical`
/// is the in-fragment RECURRENCE-ID value (row `recurrence_id` unix stays
/// authoritative for exception linkage).
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
    pub notifications: Vec<proton_api::CalNotification>,
    #[serde(default)]
    pub organizer_name: String,
    #[serde(default)]
    pub attendees_full: Vec<proton_api::CalAttendee>,
    #[serde(default)]
    pub recurrence_id_ical: String,
    #[serde(default)]
    pub recurrence_id_range: String,
}

use serde::Deserialize;

pub struct CalendarSyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
    events_json: Arc<Mutex<Option<String>>>,
    keys_debug: Arc<Mutex<Option<String>>>,
    // Last-seen non-empty per-calendar reminder defaults (this run). The
    // shim persists them via get_defaults_json so restored sessions (whose
    // live settings come back empty) can seed the same fallbacks.
    last_defaults: Arc<Mutex<HashMap<String, crate::config::CalendarDefaults>>>,
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
            last_defaults: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Serialized last-seen non-empty per-calendar defaults (`{}` when none
    /// this run — caller must not overwrite a good cache with it).
    pub fn defaults_json(&self) -> String {
        let map = self.last_defaults.lock().unwrap();
        if map.is_empty() {
            return String::new();
        }
        serde_json::to_string(&*map).unwrap_or_default()
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
        let refresh_scopes = tm.last_refresh_scopes();
        drop(tm);
        if let Some(rs) = refresh_scopes {
            self.set_debug(format!("refresh_scopes={rs}"));
        }
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
            let mut bootstrap =
                cal_client
                    .get_bootstrap(&cal.ID)
                    .unwrap_or(proton_api::CalendarBootstrap {
                        Members: Vec::new(),
                        Keys: Vec::new(),
                        Passphrase: None,
                        Settings: None,
                    });
            // Standalone settings top-up with visible outcome: a single
            // fetch whose shape is always reported, so empty results stay
            // attributable (server-sent-nothing vs unparsed-shape).
            if bootstrap.Settings.as_ref().is_none_or(|s| s.is_empty()) {
                match cal_client.get_settings_verbose(&cal.ID) {
                    Ok((s, _)) if !s.is_empty() => {
                        bootstrap.Settings = Some(s);
                    }
                    Ok((_, shape)) => {
                        self.set_debug(format!(
                            "cal={} settings_empty {shape}",
                            &cal.ID[..8.min(cal.ID.len())]
                        ));
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        let short: String = msg.chars().take(90).collect();
                        self.set_debug(format!(
                            "cal={} settings_err:{short}",
                            &cal.ID[..8.min(cal.ID.len())]
                        ));
                    }
                }
            }
            // Remember non-empty live defaults so the shim can cache them
            // for restored sessions (whose live settings come back empty).
            if let Some(s) = bootstrap.Settings.as_ref().filter(|s| !s.is_empty()) {
                let part = s
                    .DefaultPartDayNotifications
                    .as_deref()
                    .map_or_else(Vec::new, Self::parse_notification_list);
                let full = s
                    .DefaultFullDayNotifications
                    .as_deref()
                    .map_or_else(Vec::new, Self::parse_notification_list);
                if !part.is_empty() || !full.is_empty() {
                    self.last_defaults.lock().unwrap().insert(
                        cal.ID.clone(),
                        crate::config::CalendarDefaults { part, full },
                    );
                }
            }
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
                "cal={} members={} calkeys={} addrkeys={} settings={}",
                &cal.ID[..8.min(cal.ID.len())],
                bootstrap.Members.len(),
                cal_keys.len(),
                address_keys.len(),
                if bootstrap.Settings.is_some() {
                    "1"
                } else {
                    "0"
                }
            ));
            for ev in events {
                let cached = config
                    .calendar_defaults
                    .as_ref()
                    .and_then(|m| m.get(&cal.ID));
                if let Some(json) = Self::process_event(
                    ev,
                    &cal.ID,
                    &cal_name,
                    &mut cal_keys,
                    &mut address_keys,
                    bootstrap.Settings.as_ref(),
                    cached,
                ) {
                    out.push(json);
                }
            }
        }
        // Account-level calendar settings in full (default reminder sets
        // may live here rather than per-calendar — one small call/sync).
        match cal_client.fetch_account_calendar_settings_raw() {
            Ok((v, status)) => self.set_debug(format!(
                "account_calendar_settings http{status} {}",
                proton_api::diag::diag_body(&v)
            )),
            Err(e) => {
                let msg = format!("{e}");
                self.set_debug(format!(
                    "account_calendar_settings err:{}",
                    msg.chars().take(80).collect::<String>()
                ));
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
        settings: Option<&proton_api::CalendarSettings>,
        cached: Option<&crate::config::CalendarDefaults>,
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
            notifications: Self::resolve_notifications(ev, settings, cached),
            organizer_name: parsed.organizer_name.clone(),
            attendees_full: parsed.attendee_details.clone(),
            recurrence_id_ical: parsed.recurrence_id.clone(),
            recurrence_id_range: parsed.recurrence_id_range.clone(),
        })
    }

    /// Effective reminders for one event: explicit array (even empty =
    /// none) wins; `null`/absent falls back to live calendar defaults, then
    /// to cached defaults (same precedence); nothing anywhere means none.
    fn resolve_notifications(
        ev: &CalendarEvent,
        settings: Option<&proton_api::CalendarSettings>,
        cached: Option<&crate::config::CalendarDefaults>,
    ) -> Vec<proton_api::CalNotification> {
        if let Some(list) = ev.Notifications.as_ref() {
            return Self::parse_notification_list(list);
        }
        let live = settings.and_then(|s| {
            if ev.FullDay.unwrap_or(false) {
                s.DefaultFullDayNotifications.as_ref()
            } else {
                s.DefaultPartDayNotifications.as_ref()
            }
        });
        if let Some(list) = live {
            if !list.is_empty() {
                return Self::parse_notification_list(list);
            }
        }
        let fallback = cached.map(|c| {
            if ev.FullDay.unwrap_or(false) {
                &c.full
            } else {
                &c.part
            }
        });
        fallback.cloned().unwrap_or_default()
    }

    fn parse_notification_list(list: &[serde_json::Value]) -> Vec<proton_api::CalNotification> {
        list.iter()
            .filter_map(|n| {
                let kind = n.get("Type").and_then(|v| v.as_i64()).unwrap_or(1);
                // Email reminders (Type 0) are sent by the Proton server —
                // only on-device (display) alarms belong in mKCal.
                if kind == 0 {
                    return None;
                }
                let trigger = n.get("Trigger").and_then(|v| v.as_str())?;
                let offset_secs = proton_api::parse_notification_trigger(trigger)?;
                Some(proton_api::CalNotification {
                    action: "display".into(),
                    offset_secs,
                })
            })
            .collect()
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
        debug_parts.push(format!(
            "derived_keys={}",
            config
                .derived_passwords
                .as_ref()
                .map(|m| m.len())
                .unwrap_or(0)
        ));
        // User keys.
        for key in &user.Keys {
            if key.PrivateKey.is_empty() {
                continue;
            }
            match Self::passphrase_for(
                &key.ID,
                &config.password,
                config.derived_passwords.as_ref(),
                salts.iter().find(|s| s.ID == key.ID),
            ) {
                Some((pp, src)) => match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                    Ok(uk) => {
                        debug_parts.push(format!("u_{}_{src}", &key.ID[..8.min(key.ID.len())]));
                        unlocked.push(uk);
                    }
                    Err(_) => {
                        debug_parts.push(format!(
                            "u_{}_unlock_err_{src}",
                            &key.ID[..8.min(key.ID.len())]
                        ));
                    }
                },
                None => {
                    debug_parts.push(format!("u_{}_no_pp", &key.ID[..8.min(key.ID.len())]));
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
                match Self::passphrase_for(
                    &key.ID,
                    &config.password,
                    config.derived_passwords.as_ref(),
                    salts.iter().find(|s| s.ID == key.ID),
                ) {
                    Some((pp, src)) => match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                        Ok(ak) => {
                            debug_parts.push(format!("a_{}_{src}", &key.ID[..8.min(key.ID.len())]));
                            unlocked.push(ak);
                        }
                        Err(_) => {
                            debug_parts.push(format!(
                                "a_{}_unlock_err_{src}",
                                &key.ID[..8.min(key.ID.len())]
                            ));
                        }
                    },
                    None => {
                        debug_parts.push(format!("a_{}_no_pp", &key.ID[..8.min(key.ID.len())]));
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
    ) -> Option<(Vec<u8>, &'static str)> {
        if let Some(map) = derived {
            if let Some(b64) = map.get(key_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return Some((bytes, "derived"));
                }
            }
        }
        if password.is_empty() {
            return None;
        }
        let salt = salt?;
        let ks = salt.KeySalt.as_ref()?;
        if ks.is_empty() {
            return Some((password.as_bytes().to_vec(), "plain"));
        }
        proton_api::derive_mailbox_password(password.as_bytes(), ks)
            .ok()
            .map(|pp| (pp, "salt"))
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
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None);
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
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None);
        assert!(got.is_none());
    }

    fn notif_json() -> serde_json::Value {
        serde_json::from_str(
            r#"[{"Type":1,"Trigger":"-PT15M"},{"Type":0,"Trigger":"-P1D"},{"Type":9,"Trigger":"garbage"}]"#,
        )
        .unwrap()
    }

    #[test]
    fn test_resolve_notifications_explicit_wins() {
        let ev = CalendarEvent {
            Notifications: Some(notif_json().as_array().unwrap().clone()),
            ..Default::default()
        };
        let out = CalendarSyncEngine::resolve_notifications(&ev, None, None);
        // Garbage entry skipped, email entry skipped (server-sent), no
        // defaults consulted.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].action, "display");
        assert_eq!(out[0].offset_secs, -900);
    }

    #[test]
    fn test_calendar_settings_is_empty() {
        assert!(proton_api::CalendarSettings::default().is_empty());
        let empty_obj = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(vec![]),
            ..Default::default()
        };
        assert!(empty_obj.is_empty());
        let full = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(
                    r#"[{"Type":1,"Trigger":"-PT15M"}]"#,
                )
                .unwrap(),
            ),
            ..Default::default()
        };
        assert!(!full.is_empty());
    }

    #[test]
    fn test_resolve_notifications_explicit_empty_means_none() {
        let ev = CalendarEvent {
            Notifications: Some(vec![]),
            ..Default::default()
        };
        let settings = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(notif_json().as_array().unwrap().clone()),
            ..Default::default()
        };
        assert!(CalendarSyncEngine::resolve_notifications(&ev, Some(&settings), None).is_empty());
    }

    #[test]
    fn test_resolve_notifications_inherits_calendar_defaults() {
        let timed = CalendarEvent {
            FullDay: Some(false),
            ..Default::default()
        };
        let allday = CalendarEvent {
            FullDay: Some(true),
            ..Default::default()
        };
        let settings = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(
                    r#"[{"Type":1,"Trigger":"-PT15M"}]"#,
                )
                .unwrap(),
            ),
            DefaultFullDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(r#"[{"Type":1,"Trigger":"-P1D"}]"#)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let t = CalendarSyncEngine::resolve_notifications(&timed, Some(&settings), None);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].offset_secs, -900);
        let a = CalendarSyncEngine::resolve_notifications(&allday, Some(&settings), None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].offset_secs, -86400);
        // No settings at all: nothing.
        let n = CalendarSyncEngine::resolve_notifications(&timed, None, None);
        assert!(n.is_empty());
    }

    #[test]
    fn test_resolve_notifications_cached_fallback() {
        use crate::config::CalendarDefaults;
        // Live settings empty (v2 `{}` on restored sessions) + cache hit.
        let timed = CalendarEvent {
            FullDay: Some(false),
            ..Default::default()
        };
        let empty_live = proton_api::CalendarSettings::default();
        let cached = CalendarDefaults {
            part: vec![proton_api::CalNotification {
                action: "display".into(),
                offset_secs: -900,
            }],
            full: vec![],
        };
        let out =
            CalendarSyncEngine::resolve_notifications(&timed, Some(&empty_live), Some(&cached));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset_secs, -900);
        // Live non-empty wins over cache.
        let live = proton_api::CalendarSettings {
            DefaultPartDayNotifications: Some(
                serde_json::from_str::<Vec<serde_json::Value>>(r#"[{"Type":1,"Trigger":"-PT1H"}]"#)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let out2 = CalendarSyncEngine::resolve_notifications(&timed, Some(&live), Some(&cached));
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].offset_secs, -3600);
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

    #[test]
    fn test_process_event_carries_attendee_details_and_rrule() {
        let ev = CalendarEvent {
            ID: "e9".into(),
            UID: "uid-9".into(),
            CalendarID: "c1".into(),
            StartTime: 100,
            EndTime: 200,
            StartTimezone: "Europe/Rome".into(),
            EndTimezone: "Europe/Rome".into(),
            FullDay: Some(false),
            SharedEvents: vec![proton_api::CalendarEventPart {
                MemberID: String::new(),
                Type: 2,
                Data: "BEGIN:VEVENT\nUID:uid-9\nSUMMARY:Sync\nORGANIZER;CN=Boss:mailto:boss@example.com\nATTENDEE;CN=Alice;RSVP=TRUE;PARTSTAT=ACCEPTED:mailto:alice@example.com\nRRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH\nRECURRENCE-ID:20260915T200000Z\nEND:VEVENT"
                    .into(),
                Signature: "sig".into(),
                Author: String::new(),
            }],
            ..Default::default()
        };
        let got =
            CalendarSyncEngine::process_event(&ev, "c1", "Work", &mut [], &mut [], None, None)
                .expect("signed-only event processes");
        assert_eq!(got.organizer, "boss@example.com");
        assert_eq!(got.organizer_name, "Boss");
        assert_eq!(got.attendees_full.len(), 1);
        assert_eq!(got.attendees_full[0].email, "alice@example.com");
        assert!(got.attendees_full[0].rsvp);
        assert_eq!(got.attendees_full[0].partstat, "ACCEPTED");
        assert_eq!(got.rrule, "FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH");
        assert_eq!(got.recurrence_id_ical, "20260915T200000Z");
        // JSON round-trips the new fields (shim contract) and stays
        // backward compatible with old JSON missing them.
        let json = serde_json::to_string(&vec![got]).unwrap();
        assert!(json.contains("attendees_full"));
        assert!(json.contains("organizer_name"));
        let old: Vec<CalEventJson> =
            serde_json::from_str(r#"[{"id":"x","uid":"u","calendar_id":"c","calendar_name":"n","summary":"s","description":"","location":"","dtstart":"","dtend":"","dtstamp":"","rrule":"","exdates":[],"sequence":"","status":"","transp":"","organizer":"a@b","attendees":[],"start_time":0,"end_time":0,"start_timezone":"","end_timezone":"","full_day":false,"color":null,"recurrence_id":null,"notifications":[]}]"#)
                .unwrap();
        assert!(old[0].attendees_full.is_empty());
        assert!(old[0].organizer_name.is_empty());
    }
}
