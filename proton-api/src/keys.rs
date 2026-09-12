use crate::client::{build_client, API_BASE, APP_VERSION};
use crate::{models::*, Result};
use base64::Engine;
use std::collections::HashMap;
use std::time::Duration;

pub struct KeysClient {
    client: reqwest::blocking::Client,
    base_url: String,
    access_token: String,
    uid: String,
}

impl KeysClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(30)),
            base_url: API_BASE.to_string(),
            access_token,
            uid,
        }
    }

    pub fn new_with_base_url(base_url: String, access_token: String, uid: String) -> Self {
        Self {
            client: build_client(Duration::from_secs(30)),
            base_url,
            access_token,
            uid,
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    pub fn get_user(&self) -> Result<User> {
        let resp = self
            .client
            .get(format!("{}/core/v4/users", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let user: User =
            serde_json::from_value(parsed["User"].clone()).map_err(crate::ProtonError::Serde)?;
        Ok(user)
    }

    pub fn get_addresses(&self) -> Result<Vec<Address>> {
        let resp = self
            .client
            .get(format!("{}/core/v4/addresses", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let addr_resp: AddressesResponse =
            serde_json::from_value(parsed).map_err(crate::ProtonError::Serde)?;
        Ok(addr_resp.Addresses)
    }

    pub fn get_key_salts(&self) -> Result<Vec<KeySalt>> {
        let resp = self
            .client
            .get(format!("{}/core/v4/keys/salts", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?;
        let status = resp.status();
        let text = resp.text()?;
        if !status.is_success() {
            return Err(crate::ProtonError::Auth(format!(
                "get_key_salts {status} token_prefix={} uid={} body: {}",
                self.access_token.chars().take(6).collect::<String>(),
                self.uid,
                text
            )));
        }
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let salts_resp: KeySaltsResponse =
            serde_json::from_value(parsed).map_err(crate::ProtonError::Serde)?;
        Ok(salts_resp.KeySalts)
    }
}

/// Derives mailbox passwords for all user/address keys and returns a map
/// `keyID -> base64(mailboxPassword)` suitable for `DerivedPasswords` blob.
/// This is used by the SignOn plugin to avoid persisting the raw login
/// password: the derived map is stored, the raw password is discarded.
pub fn derive_all_passwords(
    password: &str,
    access_token: &str,
    uid: &str,
) -> Result<HashMap<String, String>> {
    if password.is_empty() {
        return Ok(HashMap::new());
    }
    let client = KeysClient::new(access_token.to_string(), uid.to_string());
    let user = client.get_user()?;
    let salts = client.get_key_salts()?;
    let addresses = client.get_addresses().unwrap_or_default();

    let mut out = HashMap::new();
    for key in &user.Keys {
        if key.PrivateKey.is_empty() {
            continue;
        }
        if let Some(salt) = salts.iter().find(|s| s.ID == key.ID) {
            if let Some(derived) = derive_for_salt(password, salt) {
                // Verify it actually unlocks the key before storing
                if crate::crypto::UnlockedKey::from_armored(&key.PrivateKey, &derived).is_ok() {
                    out.insert(
                        key.ID.clone(),
                        base64::engine::general_purpose::STANDARD.encode(&derived),
                    );
                }
            }
        }
    }
    for addr in &addresses {
        for key in &addr.Keys {
            if key.PrivateKey.is_empty() {
                continue;
            }
            if let Some(salt) = salts.iter().find(|s| s.ID == key.ID) {
                if let Some(derived) = derive_for_salt(password, salt) {
                    if crate::crypto::UnlockedKey::from_armored(&key.PrivateKey, &derived).is_ok() {
                        out.insert(
                            key.ID.clone(),
                            base64::engine::general_purpose::STANDARD.encode(&derived),
                        );
                    }
                }
            }
        }
    }
    Ok(out)
}

fn derive_for_salt(password: &str, salt: &KeySalt) -> Option<Vec<u8>> {
    let key_salt_str = salt.KeySalt.as_ref()?;
    if key_salt_str.is_empty() {
        return Some(password.as_bytes().to_vec());
    }
    crate::crypto::derive_mailbox_password(password.as_bytes(), key_salt_str).ok()
}
