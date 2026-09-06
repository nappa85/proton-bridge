//! Diagnostic response logging: full response text with secrets redacted.
//!
//! Debug logs land in world-readable files, so bodies are scrubbed
//! (sensitive keys replaced) and capped in size. Use for small,
//! shape-questionable endpoints (settings, bootstrap metadata) — never
//! for key material or bulk event listings.

use serde_json::Value;

const MAX_BODY_CHARS: usize = 8000;
const MAX_STRING_CHARS: usize = 500;

/// Case-insensitive substrings marking a JSON key as sensitive.
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "privatekey",
    "passphrase",
    "accesstoken",
    "refreshtoken",
    "twofactorcode",
    "password",
    "secret",
    "signature",
    "token",
];

fn is_sensitive(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_SUBSTRINGS.iter().any(|s| lower.contains(s))
}

/// Deep-clone with sensitive values replaced and long strings shortened.
pub fn scrub(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if is_sensitive(k) {
                        (k.clone(), Value::String("***".into()))
                    } else {
                        (k.clone(), scrub(v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(scrub).collect()),
        Value::String(s) if s.chars().count() > MAX_STRING_CHARS => {
            let head: String = s.chars().take(MAX_STRING_CHARS).collect();
            Value::String(format!(
                "{head}…[+{} chars]",
                s.chars().count() - MAX_STRING_CHARS
            ))
        }
        other => other.clone(),
    }
}

/// Full scrubbed body as pretty JSON, capped with an explicit marker.
pub fn diag_body(value: &Value) -> String {
    let pretty = serde_json::to_string_pretty(&scrub(value)).unwrap_or_default();
    if pretty.chars().count() <= MAX_BODY_CHARS {
        return pretty;
    }
    let head: String = pretty.chars().take(MAX_BODY_CHARS).collect();
    format!("{head}…[truncated, {} chars total]", pretty.chars().count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_scrub_redacts_nested_secrets() {
        let v = json!({
            "Code": 1000,
            "Keys": [{"PrivateKey": "abc", "ID": "k1"}],
            "Passphrase": "hunter2",
            "Name": "Work",
        });
        let s = scrub(&v);
        assert_eq!(s["Code"], json!(1000));
        assert_eq!(s["Keys"][0]["PrivateKey"], json!("***"));
        assert_eq!(s["Keys"][0]["ID"], json!("k1"));
        assert_eq!(s["Passphrase"], json!("***"));
        assert_eq!(s["Name"], json!("Work"));
    }

    #[test]
    fn test_scrub_shortens_long_strings_and_caps_body() {
        let big = "x".repeat(20000);
        let body = diag_body(&json!({"blob": big}));
        assert!(body.contains("[+"));
        assert!(body.contains("chars]"));
        // Many medium keys: no single string trips the shortener, but the
        // whole body trips the cap.
        let mut map = serde_json::Map::new();
        for i in 0..200 {
            map.insert(format!("k{i:03}"), json!("y".repeat(100)));
        }
        let capped = diag_body(&Value::Object(map));
        assert!(capped.contains("truncated"));
        assert!(capped.chars().count() <= MAX_BODY_CHARS + 100);
    }
}
