pub mod auth;
pub mod contacts;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod models;
pub mod vcard;

pub use auth::{AuthClient, LoginState, TokenManager};
pub use contacts::ContactsClient;
pub use error::{ProtonError, Result};
pub use keys::KeysClient;
pub use models::*;
pub use crypto::{UnlockedKey, derive_mailbox_password, decrypt_contact_card};
pub use vcard::{ParsedContact, ParsedEmail, ParsedPhone, ParsedAddress, parse_vcard, format_bday, download_url_photos};

