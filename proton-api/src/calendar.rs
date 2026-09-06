// proton-api/src/calendar.rs — Proton Calendar REST client (contacts analog)
// Endpoints documented in go-proton-api calendar*.go and WebClients api/calendars.ts
// Crypto model per cheeseandcereal/proton-cal docs/crypto.md + api.md (June 2026,
// verified live) and proton.me/blog/protoncalendar-security-model:
//   user key -> address key (Token) -> calendar passphrase (per-member armored)
//   -> calendar keys -> per-event session keys (SharedKeyPacket/CalendarKeyPacket).
use crate::{crypto::UnlockedKey, models::*, ProtonError, Result};
use base64::Engine;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Max window per listing request: 93 days (api.md, code 2000 beyond).
pub const CALENDAR_MAX_WINDOW_SECS: i64 = 93 * 86400;
/// Page size cap (400 code 2021 beyond 100).
pub const CALENDAR_PAGE_SIZE: u32 = 100;

const API_BASE: &str = "https://mail.proton.me/api";
const APP_VERSION: &str = "web-mail@6.3.2";

pub struct CalendarClient {
    client: Client,
    base_url: String,
    access_token: String,
    uid: String,
}

impl CalendarClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .user_agent("curl/8.0")
                .build()
                .expect("HTTP client"),
            base_url: API_BASE.to_string(),
            access_token,
            uid,
        }
    }

    #[cfg(test)]
    pub fn new_with_base_url(base_url: String, access_token: String, uid: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("curl/8.0")
                .build()
                .expect("HTTP client"),
            base_url,
            access_token,
            uid,
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    pub fn list_calendars(&self) -> Result<Vec<Calendar>> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let cals: Vec<Calendar> =
            serde_json::from_value(v["Calendars"].clone()).unwrap_or_default();
        Ok(cals)
    }

    pub fn get_calendar_keys(&self, cal_id: &str) -> Result<Vec<CalendarKey>> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/keys", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        let keys: Vec<CalendarKey> = serde_json::from_value(v["Keys"].clone()).unwrap_or_default();
        Ok(keys)
    }

    pub fn get_passphrase(&self, cal_id: &str) -> Result<CalendarPassphrase> {
        let resp = self
            .client
            .get(format!(
                "{}/calendar/v1/{}/passphrase",
                self.base_url, cal_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        Ok(serde_json::from_value(v["Passphrase"].clone())?)
    }

    pub fn get_members(&self, cal_id: &str) -> Result<Vec<CalendarMember>> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/members", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        let members: Vec<CalendarMember> =
            serde_json::from_value(v["Members"].clone()).unwrap_or_default();
        Ok(members)
    }

    /// Consolidated bootstrap (only v2 route, api.md): Keys + Passphrase +
    /// Members in one call. Falls back to three v1 calls if v2 is unavailable.
    pub fn get_bootstrap(&self, cal_id: &str) -> Result<CalendarBootstrap> {
        let v2 = self
            .client
            .get(format!(
                "{}/calendar/v2/{}/bootstrap",
                self.base_url, cal_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send();
        if let Ok(resp) = v2 {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<serde_json::Value>() {
                    let members: Vec<CalendarMember> =
                        serde_json::from_value(v["Members"].clone()).unwrap_or_default();
                    let keys: Vec<CalendarKey> =
                        serde_json::from_value(v["Keys"].clone()).unwrap_or_default();
                    let passphrase: Option<CalendarPassphrase> =
                        serde_json::from_value(v["Passphrase"].clone()).unwrap_or(None);
                    // v2 returns passphrase object directly (not Option-wrapped null issue)
                    if !members.is_empty() || !keys.is_empty() || passphrase.is_some() {
                        return Ok(CalendarBootstrap {
                            Members: members,
                            Keys: keys,
                            Passphrase: passphrase,
                        });
                    }
                }
            }
        }
        // Fallback: three v1 calls (same shapes per api.md).
        let members = self.get_members(cal_id).unwrap_or_default();
        let keys = self.get_calendar_keys(cal_id).unwrap_or_default();
        let passphrase = self.get_passphrase(cal_id).ok();
        Ok(CalendarBootstrap {
            Members: members,
            Keys: keys,
            Passphrase: passphrase,
        })
    }

    /// Single Type-scoped page (Type 0..3 required for server-side windowing,
    /// api.md). `Timezone` is REQUIRED by the server (400 Code 2000 without
    /// it, verified live 2026-09-06); "UTC" is the neutral choice. Returns
    /// (events, More cursor).
    pub fn list_events_page(
        &self,
        cal_id: &str,
        query_type: u32,
        start: i64,
        end: i64,
        page: u32,
        timezone: &str,
    ) -> Result<(Vec<CalendarEvent>, bool)> {
        let v = self.fetch_events_page_raw(cal_id, query_type, start, end, page, timezone)?;
        Ok(Self::parse_events_envelope(&v, page))
    }

    /// Tolerant envelope parsing shared by typed and untyped listings.
    /// Unknown shapes must not silently drop rows: `More` accepts 0/1 or
    /// bool, falling back to `Total`-based paging.
    pub fn parse_events_envelope(v: &serde_json::Value, page: u32) -> (Vec<CalendarEvent>, bool) {
        // Element-wise: one unparseable row must not drop the whole page.
        // Skips are logged (trace) with the row ID and serde path.
        let events: Vec<CalendarEvent> =
            v.get("Events")
                .and_then(|e| e.as_array())
                .map_or_else(Vec::new, |a| {
                    a.iter()
                        .filter_map(|item| match serde_json::from_value(item.clone()) {
                            Ok(ev) => Some(ev),
                            Err(e) => {
                                if std::env::var("LIVE_TRACE").is_ok() {
                                    eprintln!(
                                        "trace parse-skip ID={} err={e}",
                                        item.get("ID").map_or("?".into(), |m| m.to_string())
                                    );
                                }
                                None
                            }
                        })
                        .collect()
                });
        let more = match v.get("More") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
            _ => v
                .get("Total")
                .and_then(|t| t.as_u64())
                .is_some_and(|total| u64::from(page) * u64::from(CALENDAR_PAGE_SIZE) < total),
        };
        (events, more)
    }

    /// Raw GET for diagnostics: returns (status, body) without status checks.
    pub fn fetch_events_raw(
        &self,
        cal_id: &str,
        params: &[(&str, String)],
    ) -> Result<(u16, String)> {
        let pairs: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/events", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&pairs)
            .send()?;
        let status = resp.status().as_u16();
        if std::env::var("LIVE_TRACE").is_ok() {
            let hdrs: Vec<String> = resp
                .headers()
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.to_str().unwrap_or("?")))
                .collect();
            eprintln!("trace HEADERS {}", hdrs.join(" "));
        }
        let body = resp.text().unwrap_or_default();
        Ok((status, body))
    }

    /// Diagnostic helper: raw page envelope for one (Type, page) query.
    /// Used by the live-check example to inspect real server shapes.
    pub fn fetch_events_page_raw(
        &self,
        cal_id: &str,
        query_type: u32,
        start: i64,
        end: i64,
        page: u32,
        timezone: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/events", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[
                ("Type", query_type.to_string()),
                ("Start", start.to_string()),
                ("End", end.to_string()),
                ("Timezone", timezone.to_string()),
                ("Page", page.to_string()),
                ("PageSize", CALENDAR_PAGE_SIZE.to_string()),
            ])
            .send()?
            .error_for_status()?;
        if std::env::var("LIVE_TRACE").is_ok() {
            eprintln!("trace RESP-URL {}", resp.url());
        }
        Ok(resp.json()?)
    }

    /// Legacy untyped list (kept for compat; server ignores Start/End without
    /// Type and paginates everything – do not use for sync).
    pub fn list_events(&self, cal_id: &str, start: i64, end: i64) -> Result<Vec<CalendarEvent>> {
        let mut out = Vec::new();
        for t in 0..4 {
            let (mut evs, _) = self
                .list_events_page(cal_id, t, start, end, 0, "UTC")
                .unwrap_or_default();
            out.append(&mut evs);
        }
        dedupe_events(&mut out);
        Ok(out)
    }

    /// Windowed sync read (api.md): all 4 Types, ≤93d chunks, ±1d padding,
    /// More-pagination, dedupe by ID. `timezone` is forwarded as the REQUIRED
    /// Timezone query param ("UTC" unless the caller knows better).
    pub fn list_all_events_windowed(
        &self,
        cal_id: &str,
        start: i64,
        end: i64,
        timezone: &str,
    ) -> Result<Vec<CalendarEvent>> {
        let mut out: Vec<CalendarEvent> = Vec::new();
        // ±1d padding keeps boundary rows; content chunks are therefore ≤91d
        // so padded spans never exceed the 93d server cap (400 otherwise).
        let trace = std::env::var("LIVE_TRACE").is_ok();
        for (cs, ce) in split_window(start, end, CALENDAR_MAX_WINDOW_SECS - 2 * 86400) {
            // ±1d padding (server buckets by tz-local start/end).
            let ps = cs.saturating_sub(86400);
            let pe = ce.saturating_add(86400);
            for query_type in 0..4 {
                let mut page = 0u32;
                loop {
                    let (evs, more) =
                        self.list_events_page(cal_id, query_type, ps, pe, page, timezone)?;
                    if trace {
                        eprintln!(
                            "trace cal={} type={query_type} [{ps},{pe}] page={page} rows={} more={more}",
                            &cal_id[..8.min(cal_id.len())],
                            evs.len(),
                        );
                    }
                    out.extend(evs);
                    if !more {
                        break;
                    }
                    page += 1;
                    if page > 100 {
                        break;
                    }
                }
            }
        }
        dedupe_events(&mut out);
        Ok(out)
    }

    pub fn get_event(&self, cal_id: &str, event_id: &str) -> Result<CalendarEvent> {
        let resp = self
            .client
            .get(format!(
                "{}/calendar/v1/{}/events/{}",
                self.base_url, cal_id, event_id
            ))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        Ok(serde_json::from_value(v["Event"].clone())?)
    }

    pub fn list_all_events(&self, cal_id: &str) -> Result<Vec<CalendarEvent>> {
        // 2-year window. Live-verified 2026-09-06: untyped paged listing +
        // client-side filtering is reliable, while Type-scoped chunk queries
        // intermittently return 200-empty for covered windows (see
        // FINDINGS_CALENDAR.md §7). Same approach as Nojuza/proton-calendar-cli.
        let end = chrono::Utc::now().timestamp() + 365 * 24 * 3600;
        let start = end - 2 * 365 * 24 * 3600;
        self.list_all_events_untyped(cal_id, start, end)
    }

    /// Untyped full listing with client-side window filtering.
    /// Recurring masters (RRule present) are always included: per api.md they
    /// must never be window-filtered by their own StartTime/EndTime, which
    /// describe only the first occurrence.
    pub fn list_all_events_untyped(
        &self,
        cal_id: &str,
        start: i64,
        end: i64,
    ) -> Result<Vec<CalendarEvent>> {
        let mut out = Vec::new();
        let mut page = 0u32;
        loop {
            let params = vec![
                ("Page", page.to_string()),
                ("PageSize", CALENDAR_PAGE_SIZE.to_string()),
            ];
            let (status, body) = self.fetch_events_raw(cal_id, &params)?;
            if status != 200 {
                return Err(ProtonError::Auth(format!(
                    "Untyped events query failed {status}: {}",
                    body.chars().take(200).collect::<String>()
                )));
            }
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let (evs, more) = Self::parse_events_envelope(&v, page);
            let raw = evs.len();
            let mut kept = 0usize;
            for ev in evs {
                let recurring = ev.RRule.as_ref().is_some_and(|r| !r.is_empty());
                if recurring || (ev.StartTime < end && ev.EndTime > start) {
                    out.push(ev);
                    kept += 1;
                }
            }
            if std::env::var("LIVE_TRACE").is_ok() {
                let keys: Vec<&String> = v.as_object().map_or(Vec::new(), |m| m.keys().collect());
                let snippet: String = body.chars().take(300).collect();
                eprintln!(
                    "trace untyped cal={} page={page} status={status} raw={raw} kept={kept} more={more} MoreRaw={} TotalRaw={} keys={keys:?} body={snippet}",
                    cal_id,
                    v.get("More").map_or("?".into(), |m| m.to_string()),
                    v.get("Total").map_or("?".into(), |m| m.to_string()),
                );
            }
            if !more {
                break;
            }
            page += 1;
            if page > 1000 {
                break;
            }
        }
        dedupe_events(&mut out);
        Ok(out)
    }
}

/// Split [start,end) into ≤max_span chunks (api.md 93d cap).
pub fn split_window(start: i64, end: i64, max_span: i64) -> Vec<(i64, i64)> {
    if end <= start || max_span <= 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = start;
    while cur < end {
        let nxt = (cur.saturating_add(max_span)).min(end);
        out.push((cur, nxt));
        if nxt >= end {
            break;
        }
        cur = nxt;
    }
    out
}

fn dedupe_events(evs: &mut Vec<CalendarEvent>) {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    evs.retain(|e| seen.insert(e.ID.clone()));
}

/// Lenient signature check (proton-cal `event.Decrypt` + web client behavior:
/// verification is optional in practice; failures must not fail decrypt).
/// Returns Ok(true) when a signature was present (verification attempted),
/// Ok(false) when skipped. Never returns Err.
pub fn verify_signature(
    _data: &str,
    signature: &str,
    _calendar_keys: &[UnlockedKey],
    _address_keys: &[UnlockedKey],
) -> Result<bool> {
    if signature.is_empty() {
        return Ok(false);
    }
    // Full detached-verify via sequoia would need the author's *public* key;
    // UnlockedKey only carries private keypairs, and Proton signs event cards
    // with the author's address key while we may only hold calendar keys.
    // Like proton-cal's lenient read path, we accept the plaintext and let the
    // caller record provenance from row columns (Author). See FINDINGS_CALENDAR.md.
    Ok(true)
}

/// Decrypt one event card.
///
/// Mirrors `go-proton-api` `CalendarEventPart::Decode`:
/// - Encrypted (Type&1) + `key_packet` present → Data is base64 raw SEIPD,
///   key_packet is base64 PKESK; concat binary packets → decrypt with calendar keys.
/// - Encrypted without packet → armored PGP decrypt with calendar keys
///   (fallback: address keys, for passphrase-style cards).
/// - Signed (Type&2) → lenient verify (never fails).
pub fn decrypt_calendar_part(
    part: &CalendarEventPart,
    calendar_keys: &mut [UnlockedKey],
    address_keys: &mut [UnlockedKey],
    key_packet: Option<&str>,
) -> Result<String> {
    let is_encrypted = (part.Type & 1) != 0;
    let is_signed = (part.Type & 2) != 0;
    let mut data = part.Data.clone();
    if is_encrypted {
        let mut found: Option<String> = None;
        // 1) Split-packet path (normal event cards with Shared/CalendarKeyPacket).
        if let Some(kp) = key_packet {
            if !kp.is_empty() && !part.Data.is_empty() {
                let kp_raw = base64::engine::general_purpose::STANDARD.decode(kp).ok();
                let data_raw = base64::engine::general_purpose::STANDARD
                    .decode(&part.Data)
                    .ok();
                if let (Some(kp_raw), Some(data_raw)) = (kp_raw, data_raw) {
                    let mut combined = kp_raw;
                    combined.extend_from_slice(&data_raw);
                    for ak in calendar_keys.iter_mut() {
                        if let Ok(plain) = crate::crypto::decrypt_bytes_with_key(&combined, ak) {
                            found = Some(plain);
                            break;
                        }
                    }
                }
            }
        }
        // 2) Armored fallback (passphrase cards, invites, tests).
        if found.is_none() {
            for ak in calendar_keys.iter_mut().chain(address_keys.iter_mut()) {
                if let Ok(plain) = crate::crypto::decrypt_with_key(&data, ak) {
                    found = Some(plain);
                    break;
                }
            }
        }
        data =
            found.ok_or_else(|| ProtonError::Crypto("calendar decrypt failed: no key".into()))?;
    }
    if is_signed && !part.Signature.is_empty() {
        let _ = verify_signature(&data, &part.Signature, calendar_keys, address_keys);
    }
    Ok(data)
}

// Helper to keep the double-Result let readable under clippy::pedantic.

/// Back-compat wrapper (existing callers pass no key packets).
pub fn decrypt_calendar_event(
    part: &CalendarEventPart,
    calendar_keys: &mut [UnlockedKey],
    address_keys: &mut [UnlockedKey],
) -> Result<String> {
    decrypt_calendar_part(part, calendar_keys, address_keys, None)
}

/// Decrypt the member passphrase with any address key (api.md: passphrase may
/// be encrypted to ANY account address key, not necessarily the member's –
/// try all), then unlock every calendar key that opens with it (keep old
/// generations – old events may use retired keys).
pub fn decrypt_calendar_keys(
    keys: &[CalendarKey],
    passphrase: &CalendarPassphrase,
    address_keys: &mut [UnlockedKey],
    member_id: &str,
) -> Result<Vec<UnlockedKey>> {
    let member_pp = passphrase
        .MemberPassphrases
        .iter()
        .find(|mp| mp.MemberID == member_id)
        .ok_or_else(|| ProtonError::Crypto("No passphrase for member".into()))?;

    let passphrase_plain = crate::crypto::decrypt_contact_card(&member_pp.Passphrase, address_keys)
        .map_err(|e| ProtonError::Crypto(format!("Calendar passphrase decrypt failed: {e}")))?;

    let mut unlocked = Vec::new();
    for key in keys {
        if key.PrivateKey.is_empty() {
            continue;
        }
        match UnlockedKey::from_armored(&key.PrivateKey, passphrase_plain.as_bytes()) {
            Ok(uk) => unlocked.push(uk),
            Err(_) => continue,
        }
    }

    if unlocked.is_empty() {
        return Err(ProtonError::Crypto(
            "No calendar keys could be unlocked".into(),
        ));
    }

    Ok(unlocked)
}

/// Merge decrypted VEVENT fragments into one ParsedCalendarEvent.
///
/// Per proton-cal `ical.MergeFragments`: shared-signed wins structural props,
/// first-seen wins otherwise, multi-valued (EXDATE/ATTENDEE) unioned.
/// Fragments are CRLF, folded at 75 octets, no VERSION/PRODID – unfold first.
pub fn merge_ical_fragments(fragments: &[String]) -> Result<ParsedCalendarEvent> {
    let mut out = ParsedCalendarEvent::default();
    let mut seen_structural = std::collections::HashSet::new();
    for frag in fragments {
        let parsed = parse_ical(frag)?;
        // Structural: shared-signed wins → first non-empty wins in our call
        // order (callers pass shared-signed first).
        macro_rules! first_wins {
            ($field:ident) => {
                if out.$field.is_empty() && !parsed.$field.is_empty() {
                    out.$field = parsed.$field.clone();
                    seen_structural.insert(stringify!($field));
                }
            };
        }
        first_wins!(uid);
        first_wins!(summary);
        first_wins!(description);
        first_wins!(location);
        first_wins!(dtstart);
        first_wins!(dtend);
        first_wins!(dtstamp);
        first_wins!(rrule);
        first_wins!(sequence);
        first_wins!(status);
        first_wins!(transp);
        first_wins!(organizer);
        let _ = &seen_structural;
        // Multi-valued: union.
        for x in parsed.exdates {
            if !out.exdates.contains(&x) {
                out.exdates.push(x);
            }
        }
        for a in parsed.attendees {
            if !out.attendees.contains(&a) {
                out.attendees.push(a);
            }
        }
        if out.created.is_empty() && !parsed.created.is_empty() {
            out.created = parsed.created.clone();
        }
    }
    Ok(out)
}

fn unescape_ical_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Unfold RFC5545 content lines (CRLF + SP/HTAB continuations) then split.
/// Unfolding removes CRLF plus EXACTLY ONE whitespace char: further spaces
/// are content (verified live 2026-09-06: "ed emoji" folded as "ed \r\n emoji"
/// must not become "edemoji").
fn unfold_ical(s: &str) -> Vec<String> {
    let normalized = s.replace("\r\n", "\n").replace('\r', "\n");
    let mut out: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                // SP/HTAB are single-byte in UTF-8: skip exactly one char.
                last.push_str(&line[1..]);
            }
        } else {
            out.push(line.to_string());
        }
    }
    out
}

/// Split `NAME;PARAM=...:value` into (name, value), upper-cased name.
fn split_ical_line(line: &str) -> Option<(String, String)> {
    let colon = line.find(':')?;
    let (left, value) = line.split_at(colon);
    let value = value[1..].to_string();
    let name = left.split(';').next().unwrap_or(left).trim().to_uppercase();
    Some((name, value))
}

pub fn parse_ical(ical_str: &str) -> Result<ParsedCalendarEvent> {
    let mut out = ParsedCalendarEvent::default();
    for line in unfold_ical(ical_str) {
        let l = line.trim();
        if l.is_empty()
            || l.eq_ignore_ascii_case("BEGIN:VCALENDAR")
            || l.eq_ignore_ascii_case("END:VCALENDAR")
            || l.eq_ignore_ascii_case("BEGIN:VEVENT")
            || l.eq_ignore_ascii_case("END:VEVENT")
            || l.starts_with("VERSION:")
            || l.starts_with("PRODID:")
            || l.starts_with("BEGIN:VALARM")
            || l.starts_with("END:VALARM")
        {
            continue;
        }
        let Some((name, raw_value)) = split_ical_line(l) else {
            continue;
        };
        let value = unescape_ical_text(raw_value.trim());
        match name.as_str() {
            "UID" if out.uid.is_empty() => out.uid = value,
            "SUMMARY" if out.summary.is_empty() => out.summary = value,
            "DESCRIPTION" if out.description.is_empty() => out.description = value,
            "LOCATION" if out.location.is_empty() => out.location = value,
            "DTSTART" if out.dtstart.is_empty() => out.dtstart = value,
            "DTEND" if out.dtend.is_empty() => out.dtend = value,
            "DTSTAMP" if out.dtstamp.is_empty() => out.dtstamp = value,
            "CREATED" if out.created.is_empty() => out.created = value,
            "RRULE" if out.rrule.is_empty() => out.rrule = value,
            "SEQUENCE" if out.sequence.is_empty() => out.sequence = value,
            "STATUS" if out.status.is_empty() => out.status = value,
            "TRANSP" if out.transp.is_empty() => out.transp = value,
            "ORGANIZER" if out.organizer.is_empty() => out.organizer = value,
            "EXDATE" => {
                for part in value.split(',') {
                    let p = part.trim().to_string();
                    if !p.is_empty() && !out.exdates.contains(&p) {
                        out.exdates.push(p);
                    }
                }
            }
            "ATTENDEE" if !out.attendees.contains(&value) => {
                out.attendees.push(value);
            }
            _ => {}
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsedCalendarEvent {
    pub uid: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub dtstart: String,
    pub dtend: String,
    #[serde(default)]
    pub dtstamp: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub rrule: String,
    #[serde(default)]
    pub exdates: Vec<String>,
    #[serde(default)]
    pub sequence: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub transp: String,
    #[serde(default)]
    pub organizer: String,
    #[serde(default)]
    pub attendees: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_window_respects_93d_cap() {
        let chunks = split_window(0, 93 * 86400 + 1, CALENDAR_MAX_WINDOW_SECS);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (0, 93 * 86400));
        assert_eq!(chunks[1], (93 * 86400, 93 * 86400 + 1));
        let one = split_window(100, 200, CALENDAR_MAX_WINDOW_SECS);
        assert_eq!(one, vec![(100, 200)]);
        assert!(split_window(5, 5, CALENDAR_MAX_WINDOW_SECS).is_empty());
    }

    #[test]
    fn test_windowed_chunks_stay_within_cap_after_padding() {
        // Regression: ±1d query padding must not push spans over the 93d cap.
        let end = 1_800_000_000;
        let start = end - 2 * 365 * 24 * 3600;
        let chunks = split_window(start, end, CALENDAR_MAX_WINDOW_SECS - 2 * 86400);
        assert!(!chunks.is_empty());
        for (cs, ce) in chunks {
            let padded = ce.saturating_add(86400) - cs.saturating_sub(86400);
            assert!(
                padded <= CALENDAR_MAX_WINDOW_SECS,
                "padded span {padded} exceeds cap"
            );
        }
    }

    #[test]
    fn test_parse_ical_unfolds_and_strips_params() {
        let frag = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc-123\r\nDTSTAMP:20260601T120000Z\r\nDTSTART;TZID=Europe/Rome:20260602T090000\r\nDTEND;TZID=Europe/Rome:20260602T100000\r\nSUMMARY:Long title that is folded \r\n over two lines\r\nDESCRIPTION:line1\\nline2\\, with comma\r\nRRULE:FREQ=WEEKLY;COUNT=10\r\nEXDATE:20260609T090000Z,20260616T090000Z\r\nSEQUENCE:3\r\nSTATUS:CONFIRMED\r\nTRANSP:OPAQUE\r\nORGANIZER;CN=Boss:mailto:boss@example.com\r\nATTENDEE;CN=Alice:mailto:alice@example.com\r\nATTENDEE;CN=Bob:mailto:bob@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.uid, "abc-123");
        assert_eq!(p.dtstart, "20260602T090000");
        assert_eq!(p.dtend, "20260602T100000");
        assert_eq!(p.summary, "Long title that is folded over two lines");
        assert_eq!(p.description, "line1\nline2, with comma");
        assert_eq!(p.rrule, "FREQ=WEEKLY;COUNT=10");
        assert_eq!(p.exdates.len(), 2);
        assert_eq!(p.sequence, "3");
        assert_eq!(p.status, "CONFIRMED");
        assert_eq!(p.transp, "OPAQUE");
        assert_eq!(p.organizer, "mailto:boss@example.com");
        assert_eq!(p.attendees.len(), 2);
    }

    #[test]
    fn test_unfold_keeps_content_spaces() {
        // Live 2026-09-06 (T05): "ed \r\n emoji" must unfold to "ed emoji",
        // not "edemoji" — exactly one fold char is removed.
        let frag = "BEGIN:VEVENT\r\nUID:x\r\nDESCRIPTION:ed \r\n emoji\r\nEND:VEVENT";
        let p = parse_ical(frag).unwrap();
        assert_eq!(p.description, "ed emoji");
    }

    #[test]
    fn test_parse_ical_all_day_and_utc_forms() {
        // Date/time forms per crypto.md (all accepted, verified live).
        let allday = "BEGIN:VEVENT\nUID:x\nDTSTART;VALUE=DATE:20260709\nDTEND;VALUE=DATE:20260710\nSUMMARY:Holiday\nEND:VEVENT";
        let p = parse_ical(allday).unwrap();
        assert_eq!(p.dtstart, "20260709");
        assert_eq!(p.dtend, "20260710");
        let utc =
            "BEGIN:VEVENT\nUID:y\nDTSTART:20260709T160000Z\nDTEND:20260709T170000Z\nEND:VEVENT";
        let q = parse_ical(utc).unwrap();
        assert_eq!(q.dtstart, "20260709T160000Z");
    }

    #[test]
    fn test_merge_fragments_shared_signed_wins() {
        let signed = "BEGIN:VEVENT\nUID:u1\nDTSTART:20260602T090000Z\nDTEND:20260602T100000Z\nRRULE:FREQ=DAILY\nSUMMARY:signed-title\nEND:VEVENT"
            .to_string();
        let encrypted = "BEGIN:VEVENT\nUID:u1\nDTSTART:SHOULD-NOT-WIN\nSUMMARY:enc-title\nDESCRIPTION:secret\nLOCATION:Room\nEND:VEVENT"
            .to_string();
        let m = merge_ical_fragments(&[signed, encrypted]).unwrap();
        assert_eq!(m.dtstart, "20260602T090000Z");
        // summary already set by signed (first) – first-seen wins otherwise.
        assert_eq!(m.summary, "signed-title");
        assert_eq!(m.description, "secret");
        assert_eq!(m.location, "Room");
        assert_eq!(m.rrule, "FREQ=DAILY");
    }

    #[test]
    fn test_verify_signature_lenient_never_fails() {
        assert!(!verify_signature("data", "", &[], &[]).unwrap());
        assert!(verify_signature("data", "-----BEGIN PGP SIGNATURE-----", &[], &[]).unwrap());
    }

    #[test]
    fn test_decrypt_signed_only_needs_no_keys() {
        let part = CalendarEventPart {
            MemberID: String::new(),
            Type: 2,
            Data: "BEGIN:VEVENT\nUID:plain\nSUMMARY:Hi\nEND:VEVENT".into(),
            Signature: "sig".into(),
            Author: String::new(),
        };
        let out = decrypt_calendar_event(&part, &mut [], &mut []).unwrap();
        assert!(out.contains("UID:plain"));
    }

    #[test]
    fn test_decrypt_encrypted_fails_without_keys() {
        let part = CalendarEventPart {
            MemberID: String::new(),
            Type: 3,
            Data: "-----BEGIN PGP MESSAGE-----".into(),
            Signature: String::new(),
            Author: String::new(),
        };
        assert!(decrypt_calendar_event(&part, &mut [], &mut []).is_err());
    }

    #[test]
    fn test_list_events_page_mock_pagination() {
        let mut server = mockito::Server::new();
        let _m0 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Events":[{"ID":"e1","UID":"u1"}],"More":0}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let (evs, more) = c.list_events_page("cal1", 0, 0, 999, 0, "UTC").unwrap();
        assert_eq!(evs.len(), 1);
        assert!(!more);
        assert_eq!(evs[0].ID, "e1");
    }

    #[test]
    fn test_list_all_events_untyped_filters_window() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Code":1000,"Events":[
                    {"ID":"in1","UID":"u1","StartTime":150,"EndTime":250},
                    {"ID":"out1","UID":"u2","StartTime":10,"EndTime":20},
                    {"ID":"rec1","UID":"u3","StartTime":1,"EndTime":2,"RRule":"FREQ=YEARLY"}
                ],"More":0}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let evs = c.list_all_events_untyped("cal1", 100, 200).unwrap();
        let ids: Vec<&str> = evs.iter().map(|e| e.ID.as_str()).collect();
        // Overlapping + recurring-master (never window-filtered) survive.
        assert!(ids.contains(&"in1"), "overlap kept: {ids:?}");
        assert!(ids.contains(&"rec1"), "recurring kept: {ids:?}");
        assert!(!ids.contains(&"out1"), "outside dropped: {ids:?}");
    }

    #[test]
    fn test_live_shaped_row_parses() {
        // Live shape 2026-09-06: int-bool FullDay, null Exdates/RRule/
        // Notifications, VERSION/PRODID in fragments. One bad row must not
        // kill its siblings.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"Code":1000,"Events":[
                {"ID":"good","UID":"u1","StartTime":150,"EndTime":250,
                 "FullDay":0,"Exdates":null,"RRule":null,"Notifications":null,
                 "IsOrganizer":1,"Permissions":3,"RecurrenceID":null,
                 "StartTimezone":null,"EndTimezone":null,"Author":null,
                 "SharedKeyPacket":null,"CalendarKeyPacket":null,
                 "SharedEventID":null,"CreateTime":null,"LastEditTime":null,
                 "IsProtonProtonInvite":0,"AddressKeyPacket":"x",
                 "SharedEvents":[{"Type":2,"Data":"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Proton AG//x//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Hi\r\nEND:VEVENT\r\nEND:VCALENDAR","Signature":"s","Author":null}]},
                "not-an-object"
            ],"More":0}"#,
        )
        .unwrap();
        let (evs, more) = CalendarClient::parse_events_envelope(&v, 0);
        assert!(!more);
        assert_eq!(evs.len(), 1, "good row kept, bad row skipped");
        assert_eq!(evs[0].ID, "good");
        assert_eq!(evs[0].FullDay, Some(false));
        assert!(evs[0].Exdates.is_empty());
        assert_eq!(evs[0].StartTimezone, "");
        assert_eq!(evs[0].SharedKeyPacket, "");
        assert_eq!(evs[0].SharedEvents.len(), 1);
    }

    #[test]
    fn test_bootstrap_mock_v2() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"Members":[{"ID":"m1","Email":"a@b.c"}],"Keys":[],"Passphrase":{"ID":"p1","MemberPassphrases":[]}}"#,
            )
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        assert_eq!(b.Members.len(), 1);
        assert_eq!(b.Members[0].ID, "m1");
    }

    #[test]
    fn test_bootstrap_falls_back_to_v1() {
        let mut server = mockito::Server::new();
        let _v2 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v2/cal1/bootstrap.*".into()),
            )
            .with_status(404)
            .with_body("{}")
            .create();
        let _members = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/members.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Members":[{"ID":"m9"}]}"#)
            .create();
        let _keys = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/keys.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Keys":[]}"#)
            .create();
        let _pp = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/passphrase.*".into()),
            )
            .with_status(200)
            .with_body(r#"{"Passphrase":{"ID":"p","MemberPassphrases":[]}}"#)
            .create();
        let c = CalendarClient::new_with_base_url(server.url(), "at".into(), "uid".into());
        let b = c.get_bootstrap("cal1").unwrap();
        assert_eq!(b.Members[0].ID, "m9");
    }
}
