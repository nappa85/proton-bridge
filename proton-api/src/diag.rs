//! Diagnostic response logging: full response text with secrets redacted.
//!
//! Debug logs land in world-readable files, so bodies are scrubbed
//! (sensitive keys replaced) and capped in size. Use for small,
//! shape-questionable endpoints (settings, bootstrap metadata) — never
//! for key material or bulk event listings.
//!
//! Verbosity (2026-09-09): routine progress traces go through [`vlog!`]
//! and only reach stderr when [`verbose()`] holds — `PROTON_VERBOSE` set
//! to a non-empty value other than `"0"`. Genuine error lines use plain
//! `eprintln!` and always show. Rationale: on device, stderr lands in the
//! root-only volatile journal while the world-readable file log gets the
//! curated `keys_debug` summary — routine duplicates in the journal only
//! cost space. On device, flip verbose without root via
//! `systemctl --user set-environment PROTON_VERBOSE=1` + msyncd restart
//! (the oopp-runner inherits msyncd's environment).

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

/// Routine-trace gate: true only when `PROTON_VERBOSE` is set to a
/// non-empty value other than `"0"`. Read live on every call (no cache):
/// call sites are per-sync/per-op, never hot loops, and uncached reads
/// keep unit tests hermetic.
pub fn verbose() -> bool {
    std::env::var("PROTON_VERBOSE").is_ok_and(|v| !v.trim().is_empty() && v.trim() != "0")
}

/// Gated `eprintln!` for routine progress traces (uploads ran, defer
/// notices, per-op skips). The same facts already reach the file log via
/// the `keys_debug` trace — the journal copy is verbose-only.
#[macro_export]
macro_rules! vlog {
    ($($t:tt)*) => {
        if $crate::diag::verbose() {
            eprintln!($($t)*);
        }
    };
}

/// Truncate-rotate a debug log file: when `path` exceeds `max_bytes`,
/// rewrite it keeping roughly the last `keep_bytes` (cut on a line
/// boundary when one exists past the cut, then advanced past any split
/// UTF-8 sequence), prefixed with a rotation marker line. Returns
/// `Ok(true)` only when a rotation happened; a missing file is `Ok(false)`
/// (first sync run — nothing to rotate).
pub fn rotate_log_if_needed(
    path: &std::path::Path,
    max_bytes: u64,
    keep_bytes: u64,
) -> std::io::Result<bool> {
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if len <= max_bytes {
        return Ok(false);
    }
    let data = std::fs::read(path)?;
    let cut = data.len().saturating_sub(keep_bytes as usize);
    // Prefer a whole-line cut: first `\n` at/after the cut point.
    let mut start = data
        .iter()
        .skip(cut)
        .position(|&b| b == b'\n')
        .map_or(data.len().min(cut), |p| cut + p + 1)
        .min(data.len());
    // Never split a UTF-8 sequence (`\n` itself is ASCII, so this only
    // matters for the no-newline fallback).
    while start < data.len() && (data[start] & 0xC0) == 0x80 {
        start += 1;
    }
    let marker = format!(
        "[proton] log rotated: exceeded {max_bytes} bytes, kept last {} bytes\n",
        data.len() - start
    );
    let mut out = marker.into_bytes();
    out.extend_from_slice(&data[start..]);
    std::fs::write(path, out)?;
    Ok(true)
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

    /// PROTON_VERBOSE is process-global: save/restore around each case so
    /// parallel tests never observe a leaked value.
    fn with_verbose_env(value: Option<&str>, f: impl FnOnce()) {
        let prev = std::env::var("PROTON_VERBOSE").ok();
        match value {
            Some(v) => std::env::set_var("PROTON_VERBOSE", v),
            None => std::env::remove_var("PROTON_VERBOSE"),
        }
        f();
        match prev {
            Some(v) => std::env::set_var("PROTON_VERBOSE", v),
            None => std::env::remove_var("PROTON_VERBOSE"),
        }
    }

    #[test]
    fn test_verbose_defaults_off() {
        with_verbose_env(None, || assert!(!verbose()));
        with_verbose_env(Some(""), || assert!(!verbose()));
        with_verbose_env(Some("0"), || assert!(!verbose()));
        with_verbose_env(Some("1"), || assert!(verbose()));
        with_verbose_env(Some("yes"), || assert!(verbose()));
    }

    #[test]
    fn test_vlog_macro_compiles_and_runs() {
        // Output goes to stderr (not captured here) — this locks the call
        // shape used at every gated site. Run quiet…
        with_verbose_env(None, || vlog!("quiet {}", 1));
        // …and loud.
        with_verbose_env(Some("1"), || vlog!("loud {}", 1));
    }

    #[test]
    fn test_rotate_missing_and_small_files() {
        let dir =
            std::env::temp_dir().join(format!("proton-diag-test-{}-missing", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.log");
        assert!(!rotate_log_if_needed(&missing, 100, 50).unwrap());
        let small = dir.join("small.log");
        std::fs::write(&small, "short log\n").unwrap();
        assert!(!rotate_log_if_needed(&small, 100, 50).unwrap());
        assert_eq!(std::fs::read_to_string(&small).unwrap(), "short log\n");
        // Exactly at the cap: no rotation (`<= max`).
        let exact = dir.join("exact.log");
        std::fs::write(&exact, "x".repeat(100)).unwrap();
        assert!(!rotate_log_if_needed(&exact, 100, 50).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rotate_keeps_tail_on_line_boundary() {
        let dir =
            std::env::temp_dir().join(format!("proton-diag-test-{}-tail", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        // 200 numbered lines (~900 bytes): cut lands mid-file.
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!("line {i:03} padding-pad\n"));
        }
        std::fs::write(&path, &body).unwrap();
        assert!(body.len() as u64 > 400);
        assert!(rotate_log_if_needed(&path, 400, 200).unwrap());
        let out = std::fs::read_to_string(&path).unwrap();
        let mut lines = out.lines();
        assert!(lines.next().unwrap_or("").contains("log rotated"));
        // Tail intact: last original line survives, kept whole lines only.
        assert!(out.ends_with("line 199 padding-pad\n"));
        assert!(out.len() < 200 + 120, "len={}", out.len());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
