// proton-api/src/models.rs
// Proton API uses PascalCase JSON keys; allow non-snake-case field names to match wire format.
#![allow(non_snake_case)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub Username: String,
    pub Password: String,
    pub Remember: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub AccessToken: String,
    pub RefreshToken: String,
    pub UID: String,
    pub ExpiresIn: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub uid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub ID: String,
    pub Name: String,
    #[serde(default)]
    pub UID: String,
    #[serde(default)]
    pub Size: i64,
    #[serde(default)]
    pub CreateTime: i64,
    #[serde(default)]
    pub ModifyTime: i64,
    #[serde(default)]
    pub ContactEmails: Vec<ContactEmail>,
    #[serde(default)]
    pub LabelIDs: Vec<String>,
    #[serde(default)]
    pub Cards: Option<Vec<ContactCard>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEmail {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Email: String,
    #[serde(rename = "Type", default)]
    pub Type: Vec<String>,
    #[serde(default)]
    pub ContactID: String,
    #[serde(default)]
    pub LabelIDs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    #[serde(deserialize_with = "deserialize_card_type")]
    pub Type: i32,
    pub Data: String,
    #[serde(default)]
    pub Signature: String,
}

fn deserialize_card_type<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<i32, D::Error> {
    use serde::de;
    let val = serde_json::Value::deserialize(d)?;
    match val {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|v| v as i32)
            .ok_or_else(|| de::Error::custom("invalid number")),
        serde_json::Value::String(s) => s
            .parse::<i32>()
            .map_err(|_| de::Error::custom("invalid string number")),
        _ => Err(de::Error::custom("expected number or string")),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSettings {
    pub Scheme: Option<String>,   // "pgp-inline" or "pgp-mime"
    pub MIMEType: Option<String>, // "text/plain" or "multipart/encrypted"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactsListResponse {
    pub Contacts: Vec<Contact>,
    pub Total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactsRequest {
    pub Contacts: Vec<Vec<ContactCard>>,
    pub Overwrite: i32,
    pub Labels: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactsResponse {
    pub Responses: Vec<CreateContactResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactResponse {
    pub Index: i32,
    pub Response: CreateContactResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactResult {
    #[serde(flatten)]
    pub Contact: Contact,
    pub Code: i32,
    pub Error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContactRequest {
    pub Cards: Vec<ContactCard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKey {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Version: i64,
    #[serde(default)]
    pub PrivateKey: String,
    #[serde(default)]
    pub Token: String,
    #[serde(default)]
    pub Signature: String,
    #[serde(default)]
    pub Primary: i64,
    #[serde(default)]
    pub Active: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub User: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Name: String,
    #[serde(default)]
    pub Keys: Vec<UserKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressKey {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Version: i64,
    #[serde(default)]
    pub PrivateKey: String,
    #[serde(default)]
    pub Token: String,
    #[serde(default)]
    pub Signature: String,
    #[serde(default)]
    pub Primary: i64,
    #[serde(default)]
    pub Active: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub Email: String,
    #[serde(default)]
    pub Keys: Vec<AddressKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressesResponse {
    pub Addresses: Vec<Address>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySalt {
    #[serde(default)]
    pub ID: String,
    #[serde(default)]
    pub KeySalt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySaltsResponse {
    pub KeySalts: Vec<KeySalt>,
}
