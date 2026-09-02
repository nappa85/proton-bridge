use proton_sync::{SyncConfig, SyncEngine, SyncStatus};
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
) -> *mut ProtonSyncEngine {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };
    let access_token_str = unsafe { cstr_to_string(access_token) };
    let refresh_token_str = unsafe { cstr_to_string(refresh_token) };
    let uid_str = unsafe { cstr_to_string(uid) };

    let config = SyncConfig {
        username,
        password,
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
