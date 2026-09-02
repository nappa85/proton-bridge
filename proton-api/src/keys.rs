use crate::{models::*, Result};
use reqwest::blocking::Client;
use std::time::Duration;

const API_BASE: &str = "https://mail.proton.me/api";
const APP_VERSION: &str = "web-mail@6.3.2";

pub struct KeysClient {
    client: Client,
    base_url: String,
    access_token: String,
    uid: String,
}

impl KeysClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("curl/8.0")
                .build()
                .expect("HTTP client"),
            base_url: API_BASE.to_string(),
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
        let user: User = serde_json::from_value(parsed["User"].clone())
            .map_err(|e| crate::ProtonError::Serde(e))?;
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
        let addr_resp: AddressesResponse = serde_json::from_value(parsed)
            .map_err(|e| crate::ProtonError::Serde(e))?;
        Ok(addr_resp.Addresses)
    }

    pub fn get_key_salts(&self) -> Result<Vec<KeySalt>> {
        let resp = self
            .client
            .get(format!("{}/core/v4/keys/salts", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let salts_resp: KeySaltsResponse = serde_json::from_value(parsed)
            .map_err(|e| crate::ProtonError::Serde(e))?;
        Ok(salts_resp.KeySalts)
    }
}
