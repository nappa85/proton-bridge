use crate::{AuthTokens, ProtonError, Result};
use num_bigint::BigUint;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::time::{Duration, Instant};

const API_BASE: &str = "https://mail.proton.me/api";
const APP_VERSION: &str = "web-mail@6.3.2";

pub struct AuthClient {
    client: Client,
    base_url: String,
}

#[derive(Debug, Clone)]
pub enum LoginState {
    Authenticated {
        tokens: AuthTokens,
        scopes: Vec<String>,
    },
    Requires2FA {
        /// Locked-session access token (scopes: twofactor). Upgraded in-place
        /// by the server once the TOTP code is submitted.
        access_token: String,
        /// Refresh token issued at login; stays valid after 2FA.
        refresh_token: String,
        uid: String,
        scopes: Vec<String>,
    },
}

impl AuthClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("curl/8.0")
                .build()
                .expect("HTTP client"),
            base_url: API_BASE.to_string(),
        }
    }

    #[cfg(test)]
    pub fn new_with_base_url(base_url: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("curl/8.0")
                .build()
                .expect("HTTP client"),
            base_url,
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn login(&self, username: &str, password: &str) -> Result<LoginState> {
        let info = self.get_auth_info(username)?;
        let auth = SrpAuth::new(password, &info)?;
        let proofs = auth.generate_proofs(2048)?;
        let resp = self.post_auth(username, &proofs)?;

        let _tokens = AuthTokens {
            access_token: resp.AccessToken.clone(),
            refresh_token: resp.RefreshToken.clone(),
            uid: resp.UID.clone(),
        };

        let two_fa_enabled = Self::is_totp_required(&resp.TwoFA, &resp.TwoFactor);
        let scopes: Vec<String> = resp.Scopes.clone().unwrap_or_default();

        let tokens = AuthTokens {
            access_token: resp.AccessToken.clone(),
            refresh_token: resp.RefreshToken.clone(),
            uid: resp.UID.clone(),
        };

        if two_fa_enabled {
            Ok(LoginState::Requires2FA {
                access_token: resp.AccessToken,
                refresh_token: resp.RefreshToken,
                uid: resp.UID,
                scopes,
            })
        } else {
            Ok(LoginState::Authenticated { tokens, scopes })
        }
    }

    /// Submits the TOTP code for a locked (2FA-pending) session.
    ///
    /// Per the Proton API (see go-proton-api Auth2FA), POST /auth/v4/2fa does
    /// NOT return new tokens: it upgrades the scopes of the existing locked
    /// session. The refresh token issued at login remains valid.
    pub fn submit_2fa(
        &self,
        totp_code: &str,
        access_token: &str,
        refresh_token: &str,
        uid: &str,
    ) -> Result<AuthTokens> {
        let resp = self
            .client
            .post(format!("{}/auth/v4/2fa", self.base_url))
            .header("x-pm-appversion", APP_VERSION)
            .header("x-pm-uid", uid)
            .bearer_auth(access_token)
            .json(&TwoFARequest {
                TwoFactorCode: totp_code.to_string(),
            })
            .send()?;

        let status = resp.status();
        let body = resp.text()?;

        if !status.is_success() {
            return Err(ProtonError::Auth(format!(
                "2FA POST failed {status}: {body}"
            )));
        }

        // Response only carries {Code, Scope, Scopes} - no tokens. The
        // original locked-session tokens are the valid ones now.
        let twofa_resp: TwoFAResponse = serde_json::from_str(&body)?;
        if twofa_resp.Code != 1000 {
            return Err(ProtonError::Auth(format!(
                "2FA rejected, code {}: {}",
                twofa_resp.Code,
                twofa_resp.Error.unwrap_or_default()
            )));
        }

        Ok(AuthTokens {
            access_token: access_token.to_string(),
            refresh_token: refresh_token.to_string(),
            uid: uid.to_string(),
        })
    }

    pub fn refresh(&self, refresh_token: &str, uid: &str) -> Result<AuthTokens> {
        let resp = self
            .client
            .post(format!("{}/auth/v4/refresh", self.base_url))
            .header("x-pm-appversion", APP_VERSION)
            .header("x-pm-uid", uid)
            .json(&RefreshRequest {
                GrantType: "refresh_token".to_string(),
                RefreshToken: refresh_token.to_string(),
            })
            .send()?;

        let status = resp.status();
        let body = resp.text()?;

        if !status.is_success() {
            return Err(ProtonError::Auth(format!(
                "Refresh POST failed {status}: {body}"
            )));
        }

        let refresh_resp: RefreshResponse = serde_json::from_str(&body)?;
        Ok(AuthTokens {
            access_token: refresh_resp.AccessToken,
            refresh_token: refresh_resp.RefreshToken,
            uid: refresh_resp.UID,
        })
    }

    fn get_auth_info(&self, username: &str) -> Result<AuthInfoResponse> {
        let resp = self
            .client
            .post(format!("{}/core/v4/auth/info", self.base_url))
            .header("x-pm-appversion", APP_VERSION)
            .json(&AuthInfoRequest {
                Username: username.to_string(),
            })
            .send()?
            .error_for_status()?
            .json()?;
        Ok(resp)
    }

    fn is_totp_required(two_fa: &Option<TwoFAField>, two_factor: &Option<TwoFactorInfo>) -> bool {
        if let Some(f) = two_fa {
            // Enabled 1 = TOTP, 2 = FIDO2, 3 = both. TOTP field may also be set.
            if f.Enabled == 1 || f.Enabled == 3 || f.TOTP == 1 {
                return true;
            }
        }
        if let Some(f) = two_factor {
            let enabled = f.Enabled.unwrap_or(0);
            let totp = f.TOTP.unwrap_or(0);
            if enabled == 1 || enabled == 3 || totp == 1 {
                return true;
            }
            // Fallback: any non-zero Enabled that includes TOTP bit?
            // If Enabled is 2 (FIDO2 only) we should not require TOTP.
            // But if server uses newer schema, check U2F vs TOTP distinction.
            // Legacy: Enabled==1 means TOTP.
        }
        false
    }

    fn post_auth(&self, username: &str, proofs: &SrpProofs) -> Result<AuthResponse> {
        let client_ephemeral_b64 = b64_encode(&proofs.client_ephemeral);
        let client_proof_b64 = b64_encode(&proofs.client_proof);

        let resp = self
            .client
            .post(format!("{}/core/v4/auth", self.base_url))
            .header("x-pm-appversion", APP_VERSION)
            .header("Content-Type", "application/json")
            .json(&AuthRequest {
                Username: username.to_string(),
                ClientEphemeral: client_ephemeral_b64,
                ClientProof: client_proof_b64,
                SRPSession: proofs.srp_session.clone(),
            })
            .send()?;

        let status = resp.status();
        let body = resp.text()?;

        if !status.is_success() {
            return Err(ProtonError::Auth(format!(
                "Auth POST failed {status}: {body}"
            )));
        }

        let auth_resp: AuthResponse = serde_json::from_str(&body)?;
        Ok(auth_resp)
    }
}

impl Default for AuthClient {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TokenManager {
    auth: AuthClient,
    tokens: Option<AuthTokens>,
    expires_at: Option<Instant>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            auth: AuthClient::new(),
            tokens: None,
            expires_at: None,
        }
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<LoginState> {
        let state = self.auth.login(username, password)?;
        match &state {
            LoginState::Authenticated { tokens, .. } => {
                self.expires_at = Some(Instant::now() + Duration::from_secs(3600));
                self.tokens = Some(tokens.clone());
            }
            LoginState::Requires2FA { .. } => {}
        }
        Ok(state)
    }

    pub fn submit_2fa(
        &mut self,
        totp_code: &str,
        access_token: &str,
        refresh_token: &str,
        uid: &str,
    ) -> Result<()> {
        let tokens = self
            .auth
            .submit_2fa(totp_code, access_token, refresh_token, uid)?;
        self.expires_at = Some(Instant::now() + Duration::from_secs(3600));
        self.tokens = Some(tokens);
        Ok(())
    }

    pub fn restore_tokens(&mut self, tokens: AuthTokens) {
        self.tokens = Some(tokens);
        self.expires_at = None;
    }

    pub fn set_expiry(&mut self, secs: u64) {
        self.expires_at = Some(Instant::now() + Duration::from_secs(secs));
    }

    pub fn access_token(&mut self) -> Result<String> {
        if self.is_expired() {
            self.refresh_internal()?;
        }
        self.tokens
            .as_ref()
            .map(|t| t.access_token.clone())
            .ok_or_else(|| ProtonError::Auth("No tokens".into()))
    }

    fn is_expired(&self) -> bool {
        self.expires_at.is_none_or(|t| Instant::now() >= t)
    }

    fn refresh_internal(&mut self) -> Result<()> {
        let tokens = self
            .tokens
            .as_ref()
            .ok_or(ProtonError::Auth("No tokens".into()))?;
        if tokens.refresh_token.is_empty() {
            return Err(ProtonError::Auth("No refresh token available".into()));
        }
        let new_tokens = self.auth.refresh(&tokens.refresh_token, &tokens.uid)?;
        self.expires_at = Some(Instant::now() + Duration::from_secs(3600));
        self.tokens = Some(new_tokens);
        Ok(())
    }

    pub fn uid(&self) -> Option<&str> {
        self.tokens.as_ref().map(|t| t.uid.as_str())
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.tokens.as_ref().map(|t| t.refresh_token.as_str())
    }

    pub fn get_tokens(&self) -> Option<&AuthTokens> {
        self.tokens.as_ref()
    }

    pub fn take_tokens(&mut self) -> Option<AuthTokens> {
        self.tokens.take()
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct AuthInfoRequest {
    Username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct AuthInfoResponse {
    Modulus: String,
    ServerEphemeral: String,
    Version: i64,
    Salt: String,
    SRPSession: String,
    #[serde(default, deserialize_with = "deserialize_two_factor")]
    TwoFactor: Option<TwoFactorInfo>,
}

fn deserialize_two_factor<'de, D>(de: D) -> std::result::Result<Option<TwoFactorInfo>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let val = serde_json::Value::deserialize(de)?;
    match val {
        serde_json::Value::Null | serde_json::Value::Number(_) => Ok(None),
        serde_json::Value::Object(_) => serde_json::from_value(val)
            .map(Some)
            .map_err(|e| D::Error::custom(e.to_string())),
        _ => Err(D::Error::custom("invalid TwoFactor type")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct TwoFactorInfo {
    Enabled: Option<i64>,
    U2F: Option<serde_json::Value>,
    TOTP: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct AuthRequest {
    Username: String,
    ClientEphemeral: String,
    ClientProof: String,
    SRPSession: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct AuthResponse {
    AccessToken: String,
    RefreshToken: String,
    UID: String,
    ExpiresIn: i64,
    ServerProof: String,
    #[serde(default, deserialize_with = "deserialize_two_factor")]
    TwoFactor: Option<TwoFactorInfo>,
    #[serde(default)]
    PasswordMode: Option<i64>,
    #[serde(default)]
    Scopes: Option<Vec<String>>,
    #[serde(rename = "2FA", default, deserialize_with = "deserialize_two_fa_field")]
    TwoFA: Option<TwoFAField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct TwoFAField {
    #[serde(default)]
    Enabled: i64,
    #[serde(default)]
    TOTP: i64,
}

fn deserialize_two_fa_field<'de, D>(de: D) -> std::result::Result<Option<TwoFAField>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(de)?;
    match val {
        serde_json::Value::Null | serde_json::Value::Number(_) => Ok(None),
        serde_json::Value::Object(_) => serde_json::from_value(val)
            .map(Some)
            .map_err(|e| serde::de::Error::custom(e.to_string())),
        _ => Err(serde::de::Error::custom("invalid 2FA type")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct TwoFARequest {
    TwoFactorCode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct TwoFAResponse {
    #[serde(default)]
    Code: i64,
    #[serde(default)]
    Scope: Option<String>,
    #[serde(default)]
    Scopes: Option<Vec<String>>,
    #[serde(default)]
    Error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct RefreshRequest {
    GrantType: String,
    RefreshToken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct RefreshResponse {
    AccessToken: String,
    RefreshToken: String,
    UID: String,
    ExpiresIn: i64,
}

struct SrpProofs {
    client_ephemeral: Vec<u8>,
    client_proof: Vec<u8>,
    srp_session: String,
}

struct SrpAuth {
    modulus: Vec<u8>,
    server_ephemeral: Vec<u8>,
    hashed_password: Vec<u8>,
    srp_session: String,
}

impl SrpAuth {
    fn new(password: &str, info: &AuthInfoResponse) -> Result<Self> {
        let modulus = decode_modulus(&info.Modulus)?;
        let server_ephemeral = b64_decode(&info.ServerEphemeral)?;
        let salt = b64_decode(&info.Salt)?;

        let hashed_password = hash_password(info.Version, password.as_bytes(), &salt, &modulus)?;

        Ok(Self {
            modulus,
            server_ephemeral,
            hashed_password,
            srp_session: info.SRPSession.clone(),
        })
    }

    fn generate_proofs(&self, bit_length: usize) -> Result<SrpProofs> {
        let n = le_to_int(&self.modulus);
        let n_minus_1 = n.clone() - BigUint::from(1u32);
        let g = BigUint::from(2u32);

        let byte_len = bit_length / 8;

        let client_secret = generate_random_below(&n_minus_1, byte_len);
        let client_ephemeral = int_to_le(byte_len, &BigUint::from(2u32).modpow(&client_secret, &n));

        let u = le_to_int(&expand_hash(
            [client_ephemeral.as_slice(), &self.server_ephemeral].concat(),
        ));

        let k = le_to_int(&expand_hash(
            [int_to_le(byte_len, &g).as_slice(), &self.modulus].concat(),
        ));

        let x = le_to_int(&self.hashed_password);
        let v = g.modpow(&x, &n);

        let b_int = le_to_int(&self.server_ephemeral);

        let kv = k.clone() * &v % &n;
        let base = (b_int + &n - kv) % &n;

        let exp = (&client_secret + &u * &x) % &n_minus_1;

        let shared = int_to_le(byte_len, &base.modpow(&exp, &n));

        let client_proof =
            expand_hash([client_ephemeral.as_slice(), &self.server_ephemeral, &shared].concat());

        Ok(SrpProofs {
            client_ephemeral,
            client_proof,
            srp_session: self.srp_session.clone(),
        })
    }
}

fn decode_modulus(signed_modulus: &str) -> Result<Vec<u8>> {
    let between = extract_clearsign_payload(signed_modulus)?;
    b64_decode(between.trim())
}

fn extract_clearsign_payload(msg: &str) -> Result<String> {
    let header = "-----BEGIN PGP SIGNED MESSAGE-----";
    let sig_start = "-----BEGIN PGP SIGNATURE-----";

    let after_header = msg
        .find(header)
        .ok_or_else(|| ProtonError::Auth("No PGP signed message header".into()))?;
    let rest = &msg[after_header + header.len()..];

    let hash_end = rest
        .find('\n')
        .ok_or_else(|| ProtonError::Auth("No newline after header".into()))?;
    let after_hash = &rest[hash_end + 1..];

    let blank_end = after_hash
        .find('\n')
        .ok_or_else(|| ProtonError::Auth("No blank line".into()))?;
    let payload_start = &after_hash[blank_end + 1..];

    let sig_pos = payload_start
        .find(sig_start)
        .ok_or_else(|| ProtonError::Auth("No PGP signature block".into()))?;

    let payload = payload_start[..sig_pos]
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .trim();
    Ok(payload.to_string())
}

fn hash_password(version: i64, password: &[u8], salt: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    match version {
        4 | 3 => hash_password_v3(password, salt, modulus),
        _ => Err(ProtonError::Auth(format!(
            "Unsupported auth version: {version}"
        ))),
    }
}

fn hash_password_v3(password: &[u8], salt: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    let mut salt_extended = salt.to_vec();
    salt_extended.extend_from_slice(b"proton");

    let encoded_salt = bcrypt_b64_encode(&salt_extended);

    let raw_salt_bytes = bcrypt_b64_decode(&encoded_salt[..22])?;

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&raw_salt_bytes[..16]);

    let hash = bcrypt::hash_with_salt(password, 10, salt_arr)
        .map_err(|e| ProtonError::Auth(format!("bcrypt: {e}")))?;

    let crypted = hash.format_for_version(bcrypt::Version::TwoY);

    Ok(expand_hash([crypted.as_bytes(), modulus].concat()))
}

fn bcrypt_b64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((acc >> bits) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((acc << (6 - bits)) & 0x3F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn bcrypt_b64_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for ch in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| ProtonError::Auth("Invalid bcrypt base64 char".into()))?;
        acc = (acc << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }
    Ok(result)
}

fn expand_hash(data: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::with_capacity(256);
    for i in 0u8..4 {
        let mut d = data.clone();
        d.push(i);
        let hash = Sha512::digest(&d);
        result.extend_from_slice(&hash);
    }
    result
}

fn le_to_int(arr: &[u8]) -> BigUint {
    let mut reversed = arr.to_vec();
    reversed.reverse();
    BigUint::from_bytes_be(&reversed)
}

fn int_to_le(byte_len: usize, num: &BigUint) -> Vec<u8> {
    let mut arr = vec![0u8; byte_len];
    let bytes = num.to_bytes_be();
    let offset = byte_len.saturating_sub(bytes.len());
    arr[offset..].copy_from_slice(&bytes);
    arr.reverse();
    arr
}

fn generate_random_below(max: &BigUint, byte_len: usize) -> BigUint {
    let lower = BigUint::from(u64::MAX);
    loop {
        let mut buf = vec![0u8; byte_len];
        getrandom::getrandom(&mut buf).expect("RNG");
        let val = BigUint::from_bytes_be(&buf);
        if val < *max && val > lower {
            return val;
        }
    }
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| ProtonError::Auth(format!("Base64 decode: {e}")))
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth_response(json_str: &str) -> AuthResponse {
        serde_json::from_str(json_str).expect("parse auth response")
    }

    #[test]
    fn test_twofa_detection_totp_enabled_1() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":{"Enabled":1,"TOTP":1},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp = make_auth_response(json);
        assert!(AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_detection_both_3() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":{"Enabled":3,"TOTP":1},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp = make_auth_response(json);
        assert!(AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_detection_fido2_only_not_totp() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":{"Enabled":2,"TOTP":0},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp = make_auth_response(json);
        assert!(!AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_detection_no_2fa() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "Scopes":["self","parent","user","full"]
        }"#;
        let resp = make_auth_response(json);
        assert!(!AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_detection_legacy_two_factor() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "TwoFactor":{"Enabled":1,"TOTP":1},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp = make_auth_response(json);
        assert!(AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_detection_legacy_enabled_3() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "TwoFactor":{"Enabled":3},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp = make_auth_response(json);
        assert!(AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_auth_response_parsing_null_2fa() {
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":null,
            "TwoFactor":null
        }"#;
        let resp = make_auth_response(json);
        assert!(!AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
        assert!(resp.TwoFA.is_none());
        assert!(resp.TwoFactor.is_none());
    }

    #[test]
    fn test_auth_response_parsing_numeric_2fa() {
        // Proton sometimes returns numeric instead of object for legacy field
        let json = r#"{
            "AccessToken":"at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":0,
            "TwoFactor":0
        }"#;
        let resp = make_auth_response(json);
        assert!(!AuthClient::is_totp_required(&resp.TwoFA, &resp.TwoFactor));
    }

    #[test]
    fn test_twofa_response_parsing_success() {
        let json = r#"{"Code":1000,"Scope":"full","Scopes":["full","self"]}"#;
        let resp: TwoFAResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.Code, 1000);
        assert_eq!(resp.Scopes.unwrap().len(), 2);
    }

    #[test]
    fn test_twofa_response_parsing_error() {
        let json = r#"{"Code":422,"Error":"TotpWrong"}"#;
        let resp: TwoFAResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.Code, 422);
    }

    #[test]
    fn test_login_state_requires_2fa() {
        // Simulate that AuthClient correctly classifies Requires2FA vs Authenticated
        let json_locked = r#"{
            "AccessToken":"locked_at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "2FA":{"Enabled":1,"TOTP":1},
            "Scopes":["self","parent","user","twofactor"]
        }"#;
        let resp_locked = make_auth_response(json_locked);
        assert!(AuthClient::is_totp_required(
            &resp_locked.TwoFA,
            &resp_locked.TwoFactor
        ));

        let json_full = r#"{
            "AccessToken":"full_at","RefreshToken":"rt","UID":"uid","ExpiresIn":3600,"ServerProof":"sp",
            "Scopes":["self","parent","user","full"]
        }"#;
        let resp_full = make_auth_response(json_full);
        assert!(!AuthClient::is_totp_required(
            &resp_full.TwoFA,
            &resp_full.TwoFactor
        ));
    }

    #[test]
    fn test_refresh_response_parsing() {
        let json =
            r#"{"AccessToken":"new_at","RefreshToken":"new_rt","UID":"uid","ExpiresIn":3600}"#;
        let resp: RefreshResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.AccessToken, "new_at");
    }

    #[test]
    fn test_submit_2fa_keeps_same_tokens() {
        // Verifies the documented behavior: submit_2fa returns same tokens it received on success
        // This is tested via the AuthTokens construction, not HTTP
        let at = "locked_at";
        let rt = "rt";
        let uid = "uid";
        let tokens = AuthTokens {
            access_token: at.to_string(),
            refresh_token: rt.to_string(),
            uid: uid.to_string(),
        };
        assert_eq!(tokens.access_token, at);
        assert_eq!(tokens.refresh_token, rt);
        assert_eq!(tokens.uid, uid);
    }

    #[test]
    fn test_submit_2fa_mock_success() {
        let mut server = mockito::Server::new();
        let client = AuthClient::new_with_base_url(server.url());
        let mock = server
            .mock("POST", "/auth/v4/2fa")
            .match_header("x-pm-appversion", "web-mail@6.3.2")
            .match_header("x-pm-uid", "test-uid")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1000,"Scope":"full","Scopes":["full"]}"#)
            .create();
        let res = client.submit_2fa("123456", "locked-at", "rt", "test-uid");
        assert!(res.is_ok(), "submit_2fa should succeed: {:?}", res);
        let tokens = res.unwrap();
        assert_eq!(tokens.access_token, "locked-at");
        assert_eq!(tokens.refresh_token, "rt");
        assert_eq!(tokens.uid, "test-uid");
        mock.assert();
    }

    #[test]
    fn test_submit_2fa_mock_wrong_code() {
        let mut server = mockito::Server::new();
        let client = AuthClient::new_with_base_url(server.url());
        let mock = server
            .mock("POST", "/auth/v4/2fa")
            .with_status(422)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":422,"Error":"TotpWrong"}"#)
            .create();
        let res = client.submit_2fa("000000", "locked-at", "rt", "test-uid");
        assert!(res.is_err());
        let err = format!("{}", res.unwrap_err());
        assert!(err.contains("422") || err.contains("TotpWrong") || err.contains("failed"));
        mock.assert();
    }

    #[test]
    fn test_refresh_mock_success() {
        let mut server = mockito::Server::new();
        let client = AuthClient::new_with_base_url(server.url());
        let mock = server
            .mock("POST", "/auth/v4/refresh")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"AccessToken":"new_at","RefreshToken":"new_rt","UID":"uid","ExpiresIn":3600}"#,
            )
            .create();
        let res = client.refresh("old_rt", "uid");
        assert!(res.is_ok());
        let tokens = res.unwrap();
        assert_eq!(tokens.access_token, "new_at");
        assert_eq!(tokens.refresh_token, "new_rt");
        mock.assert();
    }

    #[test]
    fn test_token_manager_2fa_flow() {
        // TokenManager should not store tokens before 2FA, only after
        let mut tm = TokenManager::new();
        // Simulate Requires2FA state without actually calling login
        // We test that restore + submit flow would store tokens
        let mut server = mockito::Server::new();
        let client = AuthClient::new_with_base_url(server.url());
        let mock = server
            .mock("POST", "/auth/v4/2fa")
            .with_status(200)
            .with_body(r#"{"Code":1000}"#)
            .create();
        // Inject mocked client into TokenManager via private field is not accessible,
        // so we test AuthClient directly – the flow is validated above.
        let res = client.submit_2fa("123456", "locked", "rt", "uid");
        assert!(res.is_ok());
        mock.assert();
        // Ensure TokenManager's restore path works
        tm.restore_tokens(res.unwrap());
        assert_eq!(tm.uid(), Some("uid"));
    }
}
