use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncConfig {
    pub account_id: String,
    pub username: String,
    pub password: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub uid: Option<String>,
    pub sync_token: Option<String>,
    pub two_way: bool,
    pub last_sync: Option<String>,
    pub collection_remote_uid: Option<String>,
    pub custom_fields: HashMap<String, String>,
}
