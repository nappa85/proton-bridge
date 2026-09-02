#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod bridge;

pub use bridge::{
    proton_bridge_abort_sync, proton_bridge_create_engine, proton_bridge_destroy_engine,
    proton_bridge_free_string, proton_bridge_get_refresh_token, proton_bridge_get_status,
    proton_bridge_get_synced_contacts_json, proton_bridge_get_uid, proton_bridge_start_sync,
    ProtonBridgeStatus,
};
