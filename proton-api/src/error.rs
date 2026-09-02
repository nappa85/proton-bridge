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

    #[error("Token expired")]
    TokenExpired,

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ProtonError>;
