pub mod auth;
pub mod calendar;
pub mod calendar_seal;
pub mod calendar_write;
pub mod contact_seal;
pub mod contacts;
pub mod crypto;
pub mod diag;
pub mod error;
pub mod keys;
pub mod models;
pub mod vcard;

pub use auth::{AuthClient, LoginState, TokenManager};
pub use calendar::{
    parse_notification_trigger, parse_rrule, CalAttendee, CalNotification, CalendarClient,
    RecurrenceSpec, RruleByDay,
};
pub use calendar_write::{
    exception_sequence_ok, format_ical_date_end_exclusive, format_ical_dt, marshal_attendees,
    marshal_color, marshal_notifications, next_sequence, patch_card, resolve_color, valid_color,
    AttendeeClear, CardPatch, LocalFields, SyncBatchRequest, SyncBatchResponse, SyncContentPart,
    SyncEventBody, SyncEventOp, SyncOpResponse, SyncOpResult, COLOR_DEFAULT_SENTINEL,
    SYNC_CODE_SUCCESS, SYNC_CODE_SUCCESS_MULTI,
};
pub use contacts::{generate_contact_uid, ContactsClient};
pub use crypto::{decrypt_contact_card, derive_mailbox_password, UnlockedKey};
pub use error::{ProtonError, Result};
pub use keys::KeysClient;
pub use models::*;
pub use vcard::{
    download_url_photos, format_bday, parse_vcard, ParsedAddress, ParsedContact, ParsedEmail,
    ParsedPhone,
};
