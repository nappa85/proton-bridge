//! Back-compat wrapper: the real implementation lives in [`crate::calendar`].
//! `CalendarSyncEngineFull` is kept for API compat and delegates to
//! [`crate::calendar::CalendarSyncEngine`] (previously this file fabricated
//! `summary="Proton Event <UID>"` without decrypting – see FINDINGS_CALENDAR.md).
use crate::{config::SyncConfig, status::SyncStatus};
use serde::Serialize;

#[derive(Serialize)]
pub struct CalEventJsonCompat {
    pub uid: String,
    pub summary: String,
    pub description: String,
    pub location: String,
    pub dtstart: String,
    pub dtend: String,
    pub calendar_id: String,
}

pub struct CalendarSyncEngineFull {
    inner: crate::calendar::CalendarSyncEngine,
}

impl CalendarSyncEngineFull {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            inner: crate::calendar::CalendarSyncEngine::new(config),
        }
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        self.inner.start_sync(config);
    }

    pub fn status(&self) -> SyncStatus {
        self.inner.status()
    }

    pub fn get_events_json(&self) -> String {
        self.inner.get_events_json()
    }
}
