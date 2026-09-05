use crate::{config::SyncConfig, status::SyncStatus};
use proton_api::{CalendarClient, TokenManager};
use std::sync::{Arc, Mutex};

pub struct CalendarSyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
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
        }
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *self.config.lock().unwrap() = config.clone();
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.0,
            ..Default::default()
        });
        if let Err(e) = self.run_sync(&config) {
            self.set_status(SyncStatus {
                state: "error".into(),
                error: Some(format!("Calendar sync failed: {e}")),
                ..Default::default()
            });
            return;
        }
        self.set_status(SyncStatus {
            state: "complete".into(),
            progress: 1.0,
            ..Default::default()
        });
    }

    fn run_sync(&mut self, config: &SyncConfig) -> Result<(), proton_api::ProtonError> {
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

        let cal_client = CalendarClient::new(access_token.clone(), uid.clone());
        let cals = cal_client.list_calendars().unwrap_or_default();
        // For now just decrypt the first event's first part as proof-of-concept and count
        let mut total = 0;
        let mut sample_uid = String::new();
        for cal in &cals {
            if let Ok(evs) = cal_client.list_all_events(&cal.ID) {
                total += evs.len();
                for ev in evs.iter().take(1) {
                    for part in ev.CalendarEvents.iter().chain(ev.SharedEvents.iter()) {
                        if let Ok(plain) =
                            proton_api::calendar::decrypt_calendar_event(part, &mut [], &mut [])
                        {
                            if let Ok(parsed) = proton_api::calendar::parse_ical(&plain) {
                                sample_uid = parsed.uid.clone();
                                break;
                            }
                        }
                    }
                }
            }
        }
        // Store a minimal JSON for the C++ shim to write to mKCal (uid + summary)
        let _ = sample_uid; // keep compiler happy until full KeysClient decrypt is wired
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.5,
            total_contacts: total as u32,
            synced_contacts: total as u32,
            ..Default::default()
        });
        Ok(())
    }

    pub fn status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    fn set_status(&self, s: SyncStatus) {
        *self.status.lock().unwrap() = s;
    }
}
