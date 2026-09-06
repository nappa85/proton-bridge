#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod auth;
pub mod bridge;

pub use auth::{
    proton_auth_free_result, proton_auth_login, proton_auth_refresh, proton_auth_submit_2fa,
    ProtonAuthResult,
};
pub use bridge::{
    proton_bridge_abort_sync, proton_bridge_create_engine, proton_bridge_destroy_engine,
    proton_bridge_free_string, proton_bridge_get_derived_passwords_json,
    proton_bridge_get_keys_debug, proton_bridge_get_refresh_token, proton_bridge_get_status,
    proton_bridge_get_synced_contacts_json, proton_bridge_get_uid, proton_bridge_start_sync,
    proton_calendar_create_engine, proton_calendar_create_engine_with_derived,
    proton_calendar_destroy_engine, proton_calendar_get_events_json,
    proton_calendar_get_keys_debug, proton_calendar_get_refresh_token, proton_calendar_get_status,
    proton_calendar_get_uid, proton_calendar_start_sync, ProtonBridgeStatus,
};
