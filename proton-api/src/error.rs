// proton-api/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtonError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error {code}: {message}")]
    Api { code: i32, message: String },

    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Proton human-verification challenge (API code 9001). The Display
    /// deliberately carries NO token and NO verify URL (the URL embeds the
    /// token as a query param — hydroxide precedent: error strings must
    /// not leak it into UI or logs). The full challenge travels in the
    /// variant for the verification UI.
    #[error("Proton human verification required (methods: {})", .0.methods_display())]
    Captcha(CaptchaChallenge),

    #[error("Token expired")]
    TokenExpired,

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A parsed 9001 human-verification challenge. `token` is the API
/// challenge handle (NOT the solved proof — retrying with it unchanged
/// yields 12087; the proof only comes from an embedded verification
/// callback, see FINDINGS_CONTACTS_UPSYNC.md §8/PLAN CAPTCHA TODO).
/// `web_url` opens the challenge; `methods` names the alternatives
/// (e.g. captcha, email, sms) the user can complete on the web.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaChallenge {
    pub methods: Vec<String>,
    pub token: String,
    pub web_url: String,
}

impl CaptchaChallenge {
    /// Comma-joined method list for display/FFI (`"captcha, email"`).
    pub fn methods_display(&self) -> String {
        self.methods.join(", ")
    }
}

impl ProtonError {
    /// Structured challenge when `self` is a [`ProtonError::Captcha`].
    pub fn captcha_challenge(&self) -> Option<&CaptchaChallenge> {
        match self {
            ProtonError::Captcha(c) => Some(c),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProtonError>;
