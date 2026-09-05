use proton_api::{AuthClient, AuthTokens, LoginState};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)]
pub struct ProtonAuthResult {
    pub status: i32,
    pub access_token: *mut c_char,
    pub refresh_token: *mut c_char,
    pub uid: *mut c_char,
    pub error: *mut c_char,
}

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn ok_result(tokens: AuthTokens) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 0,
        access_token: CString::new(tokens.access_token).unwrap().into_raw(),
        refresh_token: CString::new(tokens.refresh_token).unwrap().into_raw(),
        uid: CString::new(tokens.uid).unwrap().into_raw(),
        error: std::ptr::null_mut(),
    }
}

fn needs_2fa_result(access_token: String, refresh_token: String, uid: String) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 1,
        access_token: CString::new(access_token).unwrap().into_raw(),
        refresh_token: CString::new(refresh_token).unwrap().into_raw(),
        uid: CString::new(uid).unwrap().into_raw(),
        error: std::ptr::null_mut(),
    }
}

fn error_result(msg: &str) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 2,
        access_token: std::ptr::null_mut(),
        refresh_token: std::ptr::null_mut(),
        uid: std::ptr::null_mut(),
        error: CString::new(msg).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_login(
    username: *const c_char,
    password: *const c_char,
) -> ProtonAuthResult {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };

    let client = AuthClient::new();
    match client.login(&username, &password) {
        Ok(LoginState::Authenticated { tokens, .. }) => ok_result(tokens),
        Ok(LoginState::Requires2FA {
            access_token,
            refresh_token,
            uid,
            ..
        }) => needs_2fa_result(access_token, refresh_token, uid),
        Err(e) => error_result(&format!("{e}")),
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_submit_2fa(
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
) -> ProtonAuthResult {
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let totp_code = unsafe { cstr_to_string(totp_code) };

    let client = AuthClient::new();
    match client.submit_2fa(&totp_code, &access_token, &refresh_token, &uid) {
        Ok(tokens) => ok_result(tokens),
        Err(e) => error_result(&format!("{e}")),
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_refresh(
    refresh_token: *const c_char,
    uid: *const c_char,
) -> ProtonAuthResult {
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };

    let client = AuthClient::new();
    match client.refresh(&refresh_token, &uid) {
        Ok(tokens) => ok_result(tokens),
        Err(e) => error_result(&format!("{e}")),
    }
}

#[no_mangle]
pub extern "C" fn proton_derive_passwords(
    password: *const c_char,
    access_token: *const c_char,
    uid: *const c_char,
) -> *mut c_char {
    let password = unsafe { cstr_to_string(password) };
    let access_token = unsafe { cstr_to_string(access_token) };
    let uid = unsafe { cstr_to_string(uid) };
    match proton_api::keys::derive_all_passwords(&password, &access_token, &uid) {
        Ok(map) if !map.is_empty() => {
            let json = serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string());
            CString::new(json).unwrap().into_raw()
        }
        Ok(_) => std::ptr::null_mut(),
        Err(e) => {
            eprintln!("derive_all_passwords failed: {e}");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_free_result(result: *mut ProtonAuthResult) {
    if result.is_null() {
        return;
    }
    unsafe {
        let r = &mut *result;
        if !r.access_token.is_null() {
            drop(CString::from_raw(r.access_token));
        }
        if !r.refresh_token.is_null() {
            drop(CString::from_raw(r.refresh_token));
        }
        if !r.uid.is_null() {
            drop(CString::from_raw(r.uid));
        }
        if !r.error.is_null() {
            drop(CString::from_raw(r.error));
        }
    }
}
