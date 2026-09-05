use crate::{config::SyncConfig, status::SyncStatus};
use proton_api::{CalendarClient, CalendarEvent, TokenManager};
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct CalEventJson {
    uid: String,
    summary: String,
    description: String,
    location: String,
    dtstart: String,
    dtend: String,
    calendar_id: String,
}

pub struct CalendarSyncEngineFull {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
}

impl CalendarSyncEngineFull {
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
        }
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *self.config.lock().unwrap() = config.clone();
        self.set_status(SyncStatus {
            state: "syncing".into(),
            ..Default::default()
        });
        match self.run_sync(&config) {
            Ok(evts) => {
                let json = serde_json::to_string(&evts).unwrap_or_else(|_| "[]".into());
                // store json in status? For now just complete
                self.set_status(SyncStatus {
                    state: "complete".into(),
                    progress: 1.0,
                    total_contacts: evts.len() as u32,
                    synced_contacts: evs_len(&json),
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
        let at = tm.access_token()?;
        let uid = tm.uid().unwrap_or(&config.username).to_string();
        drop(tm);
        let client = CalendarClient::new(at, uid);
        let cals = client.list_calendars().unwrap_or_default();
        let mut out = Vec::new();
        for cal in cals {
            if let Ok(evs) = client.list_all_events(&cal.ID) {
                for ev in evs {
                    if let Some(json) = self.process_event(&ev) {
                        out.push(json);
                    }
                }
            }
        }
        Ok(out)
    }

    fn process_event(&self, ev: &CalendarEvent) -> Option<CalEventJson> {
        // For now just take the first CalendarEvents part if any, decrypt would happen here
        // Stub: just use the event's UID and times
        Some(CalEventJson {
            uid: ev.UID.clone(),
            summary: format!("Proton Event {}", ev.UID),
            description: String::new(),
            location: String::new(),
            dtstart: ev.StartTime.to_string(),
            dtend: ev.EndTime.to_string(),
            calendar_id: ev.CalendarID.clone(),
        })
    }

    pub fn status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }
    fn set_status(&self, s: SyncStatus) {
        *self.status.lock().unwrap() = s;
    }
}

fn evs_len(json: &str) -> u32 {
    serde_json::from_str::<Vec<serde_json::Value>>(json)
        .map(|v| v.len() as u32)
        .unwrap_or(0)
}
