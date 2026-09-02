// proton-sync/src/status.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncStatus {
    pub state: String, // "idle", "syncing", "error", "complete"
    pub progress: f32, // 0.0 - 1.0
    pub total_contacts: u32,
    pub synced_contacts: u32,
    pub error: Option<String>,
    pub last_sync: Option<String>,
}
