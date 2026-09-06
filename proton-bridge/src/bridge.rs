use proton_sync::{calendar::CalendarSyncEngine, SyncConfig, SyncEngine, SyncStatus};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

pub struct ProtonSyncEngine {
    inner: Arc<Mutex<Option<SyncEngine>>>,
    synced_contacts_json: Arc<Mutex<Option<String>>>,
}

#[repr(C)]
pub struct ProtonBridgeStatus {
    pub state: [u8; 16],
    pub progress: f32,
    pub total_contacts: u32,
    pub synced_contacts: u32,
    pub error: [u8; 256],
}

impl Default for ProtonBridgeStatus {
    fn default() -> Self {
        Self {
            state: [0; 16],
            progress: 0.0,
            total_contacts: 0,
            synced_contacts: 0,
            error: [0; 256],
        }
    }
}

impl ProtonBridgeStatus {
    fn from_sync_status(s: &SyncStatus) -> Self {
        let mut status = Self::default();
        let state_bytes = s.state.as_bytes();
        let copy_len = state_bytes.len().min(status.state.len() - 1);
        status.state[..copy_len].copy_from_slice(&state_bytes[..copy_len]);
        status.progress = s.progress;
        status.total_contacts = s.total_contacts;
        status.synced_contacts = s.synced_contacts;
        if let Some(ref err) = s.error {
            let err_bytes = err.as_bytes();
            let copy_len = err_bytes.len().min(status.error.len() - 1);
            status.error[..copy_len].copy_from_slice(&err_bytes[..copy_len]);
        }
        status
    }
}

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[no_mangle]
pub extern "C" fn proton_bridge_create_engine(
    username: *const c_char,
    password: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
) -> *mut ProtonSyncEngine {
    proton_bridge_create_engine_with_derived(
        username,
        password,
        access_token,
        refresh_token,
        uid,
        totp_code,
        std::ptr::null(),
    )
}

#[no_mangle]
pub extern "C" fn proton_bridge_create_engine_with_derived(
    username: *const c_char,
    password: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
    derived_passwords_json: *const c_char,
) -> *mut ProtonSyncEngine {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };
    let access_token_str = unsafe { cstr_to_string(access_token) };
    let refresh_token_str = unsafe { cstr_to_string(refresh_token) };
    let uid_str = unsafe { cstr_to_string(uid) };
    let totp_code_str = unsafe { cstr_to_string(totp_code) };
    let derived_json_str = unsafe { cstr_to_string(derived_passwords_json) };

    let derived_passwords = if derived_json_str.is_empty() {
        None
    } else {
        serde_json::from_str(&derived_json_str).ok()
    };

    let config = SyncConfig {
        username,
        password,
        derived_passwords,
        access_token: if access_token_str.is_empty() {
            None
        } else {
            Some(access_token_str)
        },
        refresh_token: if refresh_token_str.is_empty() {
            None
        } else {
            Some(refresh_token_str)
        },
        uid: if uid_str.is_empty() {
            None
        } else {
            Some(uid_str)
        },
        totp_code: if totp_code_str.is_empty() {
            None
        } else {
            Some(totp_code_str)
        },
        ..Default::default()
    };

    let engine = SyncEngine::new(config);
    Box::into_raw(Box::new(ProtonSyncEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_contacts_json: Arc::new(Mutex::new(None)),
    }))
}

#[no_mangle]
pub extern "C" fn proton_bridge_destroy_engine(engine: *mut ProtonSyncEngine) {
    if !engine.is_null() {
        unsafe {
            drop(Box::from_raw(engine));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_start_sync(engine: *mut ProtonSyncEngine) -> bool {
    if engine.is_null() {
        return false;
    }
    let engine_ref = unsafe { &*engine };

    if let Some(mut inner_engine) = engine_ref.inner.lock().unwrap().take() {
        let config = inner_engine.config().clone();
        let json_arc = Arc::clone(&engine_ref.synced_contacts_json);
        let inner_arc = Arc::clone(&engine_ref.inner);

        std::thread::spawn(move || {
            inner_engine.start_sync(config);
            let status = inner_engine.status();
            if status.state == "complete" {
                let json = inner_engine.get_contacts_json();
                *json_arc.lock().unwrap() = Some(json);
            }
            *inner_arc.lock().unwrap() = Some(inner_engine);
        });

        true
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_abort_sync(engine: *mut ProtonSyncEngine) {
    if engine.is_null() {
        return;
    }
    let engine_ref = unsafe { &*engine };
    if let Some(mut inner_engine) = engine_ref.inner.lock().unwrap().take() {
        inner_engine.abort();
        *engine_ref.inner.lock().unwrap() = Some(inner_engine);
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_status(
    engine: *mut ProtonSyncEngine,
    status: *mut ProtonBridgeStatus,
) {
    if engine.is_null() || status.is_null() {
        return;
    }
    let engine_ref = unsafe { &*engine };
    let s = engine_ref
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .map(|e| e.status())
        .unwrap_or_default();

    let bridge_status = ProtonBridgeStatus::from_sync_status(&s);
    unsafe {
        *status = bridge_status;
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_synced_contacts_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let json = engine_ref.synced_contacts_json.lock().unwrap().clone();
    match json {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_refresh_token(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = engine_ref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(e) => match e.get_refresh_token() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_uid(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = engine_ref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(e) => match e.get_uid() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_derived_passwords_json(
    engine: *mut ProtonSyncEngine,
) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = engine_ref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(e) => match e.get_derived_passwords_json() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_bridge_get_keys_debug(engine: *mut ProtonSyncEngine) -> *mut c_char {
    if engine.is_null() {
        return std::ptr::null_mut();
    }
    let engine_ref = unsafe { &*engine };
    let guard = engine_ref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(e) => match e.get_keys_debug() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

// ---- Calendar engine FFI (single .so, separate engine) ----
// Mirrors the contacts engine: derived passwords in, events JSON out.
pub struct ProtonCalendarEngine {
    inner: Arc<Mutex<Option<CalendarSyncEngine>>>,
    synced_events_json: Arc<Mutex<Option<String>>>,
}

fn calendar_config_from_parts(
    username: String,
    access_token: String,
    refresh_token: String,
    uid: String,
    derived_json: String,
) -> SyncConfig {
    let derived_passwords = if derived_json.is_empty() {
        None
    } else {
        serde_json::from_str(&derived_json).ok()
    };
    SyncConfig {
        username,
        password: String::new(),
        derived_passwords,
        access_token: if access_token.is_empty() {
            None
        } else {
            Some(access_token)
        },
        refresh_token: if refresh_token.is_empty() {
            None
        } else {
            Some(refresh_token)
        },
        uid: if uid.is_empty() { None } else { Some(uid) },
        ..Default::default()
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_create_engine(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
) -> *mut ProtonCalendarEngine {
    proton_calendar_create_engine_with_derived(
        username,
        access_token,
        refresh_token,
        uid,
        std::ptr::null(),
    )
}
#[no_mangle]
pub extern "C" fn proton_calendar_create_engine_with_derived(
    username: *const c_char,
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    derived_passwords_json: *const c_char,
) -> *mut ProtonCalendarEngine {
    let username = unsafe { cstr_to_string(username) };
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let derived_json = unsafe { cstr_to_string(derived_passwords_json) };
    let config =
        calendar_config_from_parts(username, access_token, refresh_token, uid, derived_json);
    let engine = CalendarSyncEngine::new(config);
    Box::into_raw(Box::new(ProtonCalendarEngine {
        inner: Arc::new(Mutex::new(Some(engine))),
        synced_events_json: Arc::new(Mutex::new(None)),
    }))
}
#[no_mangle]
pub extern "C" fn proton_calendar_destroy_engine(e: *mut ProtonCalendarEngine) {
    if !e.is_null() {
        unsafe {
            drop(Box::from_raw(e));
        }
    }
}
#[no_mangle]
pub extern "C" fn proton_calendar_start_sync(e: *mut ProtonCalendarEngine) -> bool {
    if e.is_null() {
        return false;
    }
    let eref = unsafe { &*e };
    if let Some(mut eng) = eref.inner.lock().unwrap().take() {
        let config = eng.config();
        let json_arc = Arc::clone(&eref.synced_events_json);
        let inner = Arc::clone(&eref.inner);
        std::thread::spawn(move || {
            eng.start_sync(config);
            let status = eng.status();
            if status.state == "complete" {
                *json_arc.lock().unwrap() = Some(eng.get_events_json());
            }
            *inner.lock().unwrap() = Some(eng);
        });
        true
    } else {
        false
    }
}
#[no_mangle]
pub extern "C" fn proton_calendar_get_status(
    e: *mut ProtonCalendarEngine,
    s: *mut ProtonBridgeStatus,
) {
    if e.is_null() || s.is_null() {
        return;
    }
    let eref = unsafe { &*e };
    let st = eref
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .map(|x| x.status())
        .unwrap_or_default();
    unsafe {
        *s = ProtonBridgeStatus::from_sync_status(&st);
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_events_json(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    // Prefer the snapshot taken at completion; fall back to the live engine.
    if let Some(s) = eref.synced_events_json.lock().unwrap().clone() {
        return CString::new(s).unwrap().into_raw();
    }
    let guard = eref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(eng) => CString::new(eng.get_events_json()).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_keys_debug(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = eref.inner.lock().unwrap();
    match guard.as_ref() {
        Some(eng) => match eng.get_keys_debug() {
            Some(s) => CString::new(s).unwrap().into_raw(),
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_refresh_token(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = eref.inner.lock().unwrap();
    match guard.as_ref().and_then(|eng| eng.get_refresh_token()) {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn proton_calendar_get_uid(e: *mut ProtonCalendarEngine) -> *mut c_char {
    if e.is_null() {
        return std::ptr::null_mut();
    }
    let eref = unsafe { &*e };
    let guard = eref.inner.lock().unwrap();
    match guard.as_ref().and_then(|eng| eng.get_uid()) {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_state(status: &ProtonBridgeStatus) -> String {
        let len = status
            .state
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(status.state.len());
        String::from_utf8_lossy(&status.state[..len]).into_owned()
    }

    fn decode_error(status: &ProtonBridgeStatus) -> String {
        let len = status
            .error
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(status.error.len());
        String::from_utf8_lossy(&status.error[..len]).into_owned()
    }

    #[test]
    fn test_status_needs_2fa_round_trips_over_ffi() {
        // The C++ shim branches on the literal "needs_2fa": it must survive
        // the fixed-size FFI buffers intact (state has 16 bytes, it needs 9).
        let sync = SyncStatus {
            state: "needs_2fa".into(),
            error: Some("2FA verification required".into()),
            ..Default::default()
        };
        let bridge = ProtonBridgeStatus::from_sync_status(&sync);
        assert_eq!(decode_state(&bridge), "needs_2fa");
        assert_eq!(decode_error(&bridge), "2FA verification required");
    }

    #[test]
    fn test_status_error_round_trips_over_ffi() {
        let sync = SyncStatus {
            state: "error".into(),
            error: Some("Auth failed: bad password".into()),
            ..Default::default()
        };
        let bridge = ProtonBridgeStatus::from_sync_status(&sync);
        assert_eq!(decode_state(&bridge), "error");
        assert!(decode_error(&bridge).contains("bad password"));
    }
}
