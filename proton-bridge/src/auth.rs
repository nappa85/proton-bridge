use crate::ffi_utils::cstr_to_string;
use proton_api::{AuthClient, AuthTokens, LoginState, ProtonError};
use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
pub struct ProtonAuthResult {
    pub status: i32,
    pub access_token: *mut c_char,
    pub refresh_token: *mut c_char,
    pub uid: *mut c_char,
    pub error: *mut c_char,
    /// Set only when `status == 3` (human-verification challenge):
    /// challenge URL for the verification UI (embeds the token).
    pub captcha_url: *mut c_char,
    /// Comma-joined verification methods (`"captcha, email, sms"`),
    /// set only when `status == 3`.
    pub captcha_methods: *mut c_char,
    /// Human-verification token (set only when `status == 3`). Must be
    /// sent back as `x-pm-humanverification` header on retry after the
    /// user solves the challenge in the browser.
    pub captcha_token: *mut c_char,
}

fn ok_result(tokens: AuthTokens) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 0,
        access_token: CString::new(tokens.access_token).unwrap().into_raw(),
        refresh_token: CString::new(tokens.refresh_token).unwrap().into_raw(),
        uid: CString::new(tokens.uid).unwrap().into_raw(),
        error: std::ptr::null_mut(),
        captcha_url: std::ptr::null_mut(),
        captcha_methods: std::ptr::null_mut(),
        captcha_token: std::ptr::null_mut(),
    }
}

fn needs_2fa_result(access_token: String, refresh_token: String, uid: String) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 1,
        access_token: CString::new(access_token).unwrap().into_raw(),
        refresh_token: CString::new(refresh_token).unwrap().into_raw(),
        uid: CString::new(uid).unwrap().into_raw(),
        error: std::ptr::null_mut(),
        captcha_url: std::ptr::null_mut(),
        captcha_methods: std::ptr::null_mut(),
        captcha_token: std::ptr::null_mut(),
    }
}

fn error_result(msg: &str) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 2,
        access_token: std::ptr::null_mut(),
        refresh_token: std::ptr::null_mut(),
        uid: std::ptr::null_mut(),
        error: CString::new(msg).unwrap().into_raw(),
        captcha_url: std::ptr::null_mut(),
        captcha_methods: std::ptr::null_mut(),
        captcha_token: std::ptr::null_mut(),
    }
}

/// Human-verification challenge (API 9001): status 3 carries the
/// challenge URL, methods, and the HV token for retry.
fn captcha_result(challenge: &proton_api::CaptchaChallenge) -> ProtonAuthResult {
    ProtonAuthResult {
        status: 3,
        access_token: std::ptr::null_mut(),
        refresh_token: std::ptr::null_mut(),
        uid: std::ptr::null_mut(),
        error: std::ptr::null_mut(),
        captcha_url: CString::new(challenge.web_url.clone()).unwrap().into_raw(),
        captcha_methods: CString::new(challenge.methods_display())
            .unwrap()
            .into_raw(),
        captcha_token: CString::new(challenge.token.clone()).unwrap().into_raw(),
    }
}

/// Shared error mapping: structured 9001 → status 3, everything else →
/// status 2 with the (token-redacted for Captcha) message.
fn auth_error_result(e: &ProtonError) -> ProtonAuthResult {
    match e {
        ProtonError::Captcha(c) => captcha_result(c),
        _ => error_result(&format!("{e}")),
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_login(
    username: *const c_char,
    password: *const c_char,
    hv_token: *const c_char,
) -> ProtonAuthResult {
    let username = unsafe { cstr_to_string(username) };
    let password = unsafe { cstr_to_string(password) };
    let hv = unsafe { cstr_to_string(hv_token) };
    let hv_opt = if hv.is_empty() {
        None
    } else {
        Some(hv.as_str())
    };

    let client = AuthClient::new();
    match client.login(&username, &password, hv_opt) {
        Ok(LoginState::Authenticated { tokens, .. }) => ok_result(tokens),
        Ok(LoginState::Requires2FA {
            access_token,
            refresh_token,
            uid,
            ..
        }) => needs_2fa_result(access_token, refresh_token, uid),
        Err(e) => auth_error_result(&e),
    }
}

#[no_mangle]
pub extern "C" fn proton_auth_submit_2fa(
    access_token: *const c_char,
    refresh_token: *const c_char,
    uid: *const c_char,
    totp_code: *const c_char,
    hv_token: *const c_char,
) -> ProtonAuthResult {
    let access_token = unsafe { cstr_to_string(access_token) };
    let refresh_token = unsafe { cstr_to_string(refresh_token) };
    let uid = unsafe { cstr_to_string(uid) };
    let totp_code = unsafe { cstr_to_string(totp_code) };
    let hv = unsafe { cstr_to_string(hv_token) };
    let hv_opt = if hv.is_empty() {
        None
    } else {
        Some(hv.as_str())
    };

    let client = AuthClient::new();
    match client.submit_2fa(&totp_code, &access_token, &refresh_token, &uid, hv_opt) {
        Ok(tokens) => ok_result(tokens),
        Err(e) => auth_error_result(&e),
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
            r.access_token = std::ptr::null_mut();
        }
        if !r.refresh_token.is_null() {
            drop(CString::from_raw(r.refresh_token));
            r.refresh_token = std::ptr::null_mut();
        }
        if !r.uid.is_null() {
            drop(CString::from_raw(r.uid));
            r.uid = std::ptr::null_mut();
        }
        if !r.error.is_null() {
            drop(CString::from_raw(r.error));
            r.error = std::ptr::null_mut();
        }
        if !r.captcha_url.is_null() {
            drop(CString::from_raw(r.captcha_url));
            r.captcha_url = std::ptr::null_mut();
        }
        if !r.captcha_methods.is_null() {
            drop(CString::from_raw(r.captcha_methods));
            r.captcha_methods = std::ptr::null_mut();
        }
        if !r.captcha_token.is_null() {
            drop(CString::from_raw(r.captcha_token));
            r.captcha_token = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv_error() -> ProtonError {
        ProtonError::Captcha(proton_api::CaptchaChallenge {
            methods: vec!["captcha".into(), "email".into()],
            token: "secret-token".into(),
            web_url: "https://verify.proton.me/?methods=captcha&token=secret-token".into(),
        })
    }

    #[test]
    fn test_captcha_maps_to_status_3_with_url_and_methods() {
        let mut r = auth_error_result(&hv_error());
        assert_eq!(r.status, 3);
        assert!(r.error.is_null());
        let url = unsafe { cstr_to_string(r.captcha_url) };
        let methods = unsafe { cstr_to_string(r.captcha_methods) };
        let token = unsafe { cstr_to_string(r.captcha_token) };
        assert!(url.starts_with("https://verify.proton.me/"), "{url}");
        assert_eq!(methods, "captcha, email");
        assert_eq!(token, "secret-token");
        proton_auth_free_result(&mut r);
    }

    #[test]
    fn test_generic_error_stays_status_2_without_captcha_fields() {
        let mut r = auth_error_result(&ProtonError::Auth("bad password".into()));
        assert_eq!(r.status, 2);
        assert!(r.captcha_url.is_null());
        assert!(r.captcha_methods.is_null());
        assert!(r.captcha_token.is_null());
        let msg = unsafe { cstr_to_string(r.error) };
        assert!(msg.contains("bad password"), "{msg}");
        proton_auth_free_result(&mut r);
    }
}
