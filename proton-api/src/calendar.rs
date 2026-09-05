// proton-api/src/calendar.rs — Proton Calendar REST client (contacts analog)
// Endpoints documented in go-proton-api calendar*.go and WebClients api/calendars.ts
use crate::{crypto::UnlockedKey, models::*, ProtonError, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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

    pub fn list_events(&self, cal_id: &str, start: i64, end: i64) -> Result<Vec<CalendarEvent>> {
        let resp = self
            .client
            .get(format!("{}/calendar/v1/{}/events", self.base_url, cal_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[("Start", start.to_string()), ("End", end.to_string())])
            .send()?
            .error_for_status()?;
        let v: serde_json::Value = resp.json()?;
        let evs: Vec<CalendarEvent> =
            serde_json::from_value(v["Events"].clone()).unwrap_or_default();
        Ok(evs)
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
        // Simple 1-year window, similar to proton-sync engine's fetch
        let end = chrono::Utc::now().timestamp() + 365 * 24 * 3600;
        let start = end - 2 * 365 * 24 * 3600;
        self.list_events(cal_id, start, end)
    }
}

pub fn decrypt_calendar_event(
    part: &CalendarEventPart,
    calendar_keys: &mut [UnlockedKey],
    address_keys: &mut [UnlockedKey],
) -> Result<String> {
    let is_encrypted = (part.Type & 1) != 0;
    let is_signed = (part.Type & 2) != 0;
    let mut data = part.Data.clone();
    if is_encrypted {
        let mut found = None;
        for ak in calendar_keys.iter_mut().chain(address_keys.iter_mut()) {
            if let Ok(plain) = crate::crypto::decrypt_with_key(&data, ak) {
                found = Some(plain);
                break;
            }
        }
        data =
            found.ok_or_else(|| ProtonError::Crypto("calendar decrypt failed: no key".into()))?;
    }
    if is_signed && !part.Signature.is_empty() {
        let _ = part.Signature.len();
    }
    Ok(data)
}

pub fn decrypt_calendar_keys(
    _keys: &[CalendarKey],
    _passphrase: &CalendarPassphrase,
    _address_keys: &[UnlockedKey],
    _member_id: &str,
) -> Result<Vec<UnlockedKey>> {
    // Stub: full impl would decrypt MemberPassphrase.Passphrase with addrKR and Unlock CalendarKeys
    Err(ProtonError::Crypto(
        "calendar key decrypt not yet fully implemented".into(),
    ))
}

pub fn parse_ical(ical_str: &str) -> Result<ParsedCalendarEvent> {
    // Minimal VEVENT parser — reuse vcard.rs style but for VEVENT
    // For now just extract SUMMARY, DTSTART, DTEND, UID, DESCRIPTION, LOCATION
    let mut out = ParsedCalendarEvent::default();
    for line in ical_str.lines() {
        let l = line.trim();
        if let Some(stripped) = l.strip_prefix("SUMMARY:") {
            out.summary = stripped.to_string();
        } else if let Some(stripped) = l.strip_prefix("DESCRIPTION:") {
            out.description = stripped.to_string();
        } else if let Some(stripped) = l.strip_prefix("LOCATION:") {
            out.location = stripped.to_string();
        } else if let Some(stripped) = l.strip_prefix("UID:") {
            out.uid = stripped.to_string();
        } else if let Some(stripped) = l.strip_prefix("DTSTART:") {
            out.dtstart = stripped.to_string();
        } else if let Some(stripped) = l.strip_prefix("DTEND:") {
            out.dtend = stripped.to_string();
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
}
