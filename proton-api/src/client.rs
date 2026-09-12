pub const API_BASE: &str = "https://mail.proton.me/api";
pub const APP_VERSION: &str = "web-mail@6.3.2";

use reqwest::blocking::Client;
use std::time::Duration;

pub fn build_client(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .user_agent("curl/8.0")
        .build()
        .expect("HTTP client")
}
