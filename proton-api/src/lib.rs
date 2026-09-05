pub mod auth;
pub mod contacts;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod models;
pub mod vcard;

pub use auth::{AuthClient, LoginState, TokenManager};
pub use contacts::ContactsClient;
pub use crypto::{decrypt_contact_card, derive_mailbox_password, UnlockedKey};
pub use error::{ProtonError, Result};
pub use keys::KeysClient;
pub use models::*;
pub use vcard::{
    download_url_photos, format_bday, parse_vcard, ParsedAddress, ParsedContact, ParsedEmail,
    ParsedPhone,
};
