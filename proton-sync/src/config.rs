use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CalendarDefaults {
    #[serde(default)]
    pub part: Vec<proton_api::CalNotification>,
    #[serde(default)]
    pub full: Vec<proton_api::CalNotification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncConfig {
    pub account_id: String,
    pub username: String,
    pub password: String,
    pub derived_passwords: Option<HashMap<String, String>>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub uid: Option<String>,
    pub sync_token: Option<String>,
    pub two_way: bool,
    pub last_sync: Option<String>,
    pub collection_remote_uid: Option<String>,
    pub custom_fields: HashMap<String, String>,
    pub totp_code: Option<String>,
    /// Cached per-calendar reminder defaults (`calendar_id -> sets`),
    /// seeded with fresh scope (v1 settings degrade on restored sessions).
    /// Live fetch always wins when non-empty.
    #[serde(default)]
    pub calendar_defaults: Option<HashMap<String, CalendarDefaults>>,
    /// Local inventory exported by the shim for the upsync cycle
    /// (`upsync::LocalItem` JSON). `None` (or empty) = download-only,
    /// byte-identical behavior to before wiring.
    #[serde(default)]
    pub local_inventory: Option<Vec<crate::upsync::LocalItem>>,
    /// Per-row sync anchors (`upsync::AnchorMap`): Proton row ID →
    /// server `LastEditTime` at the last successful sync.
    #[serde(default)]
    pub anchor_map: Option<HashMap<String, i64>>,
    /// API base override for tests (mockito). `None` = production.
    #[serde(default)]
    pub api_base_url: Option<String>,
}
