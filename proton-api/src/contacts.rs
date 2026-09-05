// proton-api/src/contacts.rs
use crate::{models::*, ProtonError, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use std::time::Duration;

const API_BASE: &str = "https://mail.proton.me/api";
const APP_VERSION: &str = "web-mail@6.3.2";

pub struct ContactsClient {
    client: Client,
    base_url: String,
    access_token: String,
    uid: String,
}

impl ContactsClient {
    pub fn new(access_token: String, uid: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
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

    /// List contacts with pagination
    pub fn list(&self, page: u32, page_size: u32) -> Result<ContactsListResponse> {
        let resp = self
            .client
            .get(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[
                ("Page", page.to_string()),
                ("PageSize", page_size.to_string()),
            ])
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        let parsed: ContactsListResponse = serde_json::from_str(&text)?;
        Ok(parsed)
    }

    /// Get all contacts (auto-paginates, fetches full data for each)
    pub fn list_all(&self) -> Result<Vec<Contact>> {
        let mut summaries = Vec::new();
        let page_size = 100;
        let mut page = 0;

        loop {
            let resp = self.list(page, page_size)?;
            let total = resp.Total as usize;
            let contacts_len = resp.Contacts.len();
            summaries.extend(resp.Contacts);

            if summaries.len() >= total || contacts_len < page_size as usize {
                break;
            }
            page += 1;
        }

        let mut full_contacts = Vec::new();
        for summary in &summaries {
            match self.get(&summary.ID) {
                Ok(full) => full_contacts.push(full),
                Err(e) => {
                    eprintln!(
                        "Failed to fetch contact {}: {}, using summary",
                        summary.ID, e
                    );
                    full_contacts.push(summary.clone());
                }
            }
        }

        Ok(full_contacts)
    }

    /// Get single contact by ID
    pub fn get(&self, contact_id: &str) -> Result<Contact> {
        let resp = self
            .client
            .get(format!("{}/contacts/v4/{}", self.base_url, contact_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .send()?
            .error_for_status()?;
        let text = resp.text()?;
        if let Ok(mut f) = std::fs::File::create("/tmp/proton-contact-raw.json") {
            use std::io::Write;
            let _ = f.write_all(text.as_bytes());
        }
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        let contact: Contact =
            serde_json::from_value(parsed["Contact"].clone()).map_err(|e| ProtonError::Serde(e))?;
        Ok(contact)
    }

    /// Count contacts
    pub fn count(&self) -> Result<u32> {
        let resp = self
            .client
            .get(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .query(&[("Count", "1")])
            .send()?
            .error_for_status()?
            .json::<serde_json::Value>()?;

        Ok(resp["Total"].as_u64().unwrap_or(0) as u32)
    }

    /// Create contacts (batch)
    pub fn create(&self, req: CreateContactsRequest) -> Result<CreateContactsResponse> {
        let resp = self
            .client
            .post(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .json(&req)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(resp)
    }

    /// Update contact
    pub fn update(&self, contact_id: &str, req: UpdateContactRequest) -> Result<Contact> {
        let resp = self
            .client
            .put(format!("{}/contacts/v4/{}", self.base_url, contact_id))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .json(&req)
            .send()?
            .error_for_status()?
            .json::<serde_json::Value>()?;

        serde_json::from_value(resp["Contact"].clone()).map_err(ProtonError::Serde)
    }

    /// Delete contacts (batch)
    pub fn delete(&self, ids: &[String]) -> Result<()> {
        #[allow(non_snake_case)]
        #[derive(Serialize)]
        struct DeleteReq {
            IDs: Vec<String>,
        }

        self.client
            .delete(format!("{}/contacts/v4", self.base_url))
            .header("Authorization", self.auth_header())
            .header("x-pm-uid", &self.uid)
            .header("x-pm-appversion", APP_VERSION)
            .json(&DeleteReq { IDs: ids.to_vec() })
            .send()?
            .error_for_status()?;
        Ok(())
    }
}
