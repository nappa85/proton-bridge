// proton-api/src/calendar_write.rs — Calendar upsync write-path payload builders.
// Offline logic only (no network, no crypto): wire types, Notifications
// tri-state, palette validation, in-place card patching, SEQUENCE rules,
// batch builders, and sync-response interpretation.
//
// Contract (researched 2026-09-07, see FINDINGS_CALENDAR.md §12):
// - proton-cal `docs/api.md` "The sync endpoint (write path)":
//   `PUT /calendar/v1/{calID}/events/sync` batch `{MemberID, IsImport?,
//   Events[]}`; create `{Overwrite: 0, Event}` (+ key packets, `IsImport:
//   0`); update `{ID, Event}` (NO key packets — server keeps originals);
//   delete `{ID}`. Whole-object REPLACE on update: omitted fields reset.
// - proton-cal `pkg/event/{wire,write}.go`: `eventBody` field presence
//   (`[]` never `null` for content arrays), `marshalNotifications`
//   tri-state, `marshalAttendees` clear rows, `resealCard` patch-in-place,
//   `sharedCardPatches` (signed = structural, encrypted = text).
// - proton-cal `pkg/ical/patch.go`: `CardPatch`/`PatchCard` semantics
//   mirrored by `patch_card` below.
// - proton-cal `pkg/calcolor`: 20-entry accent palette + resolve rules.
//
// Deliberately NOT here (next step): sealing (fresh session keys to the
// calendar public key, detached-sign with the address key) and resealing
// (session-key extract + re-encrypt with the SAME keys). `crypto.rs` is
// decrypt-only today; those need new sequoia encrypt/session-key/sign ops.
#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Top-level batch success (single-op echo) — proton-cal `papi.CodeSuccess`.
pub const SYNC_CODE_SUCCESS: i64 = 1000;
/// Batch-accepted top-level code — proton-cal `papi.CodeSuccessMulti`.
pub const SYNC_CODE_SUCCESS_MULTI: i64 = 1001;

/// Proton accent palette (canonical uppercase hex), in proton-cal
/// `pkg/calcolor` display order (web client `ACCENT_COLORS_MAP`). The API
/// rejects anything else with 400 code 2011 ("Not a valid Proton color").
pub const ACCENT_PALETTE: &[(&str, &str)] = &[
    ("purple", "#8080FF"),
    ("pink", "#DB60D6"),
    ("strawberry", "#EC3E7C"),
    ("carrot", "#F78400"),
    ("sahara", "#936D58"),
    ("enzian", "#5252CC"),
    ("plum", "#A839A4"),
    ("cerise", "#BA1E55"),
    ("copper", "#C44800"),
    ("soil", "#54473F"),
    ("slateblue", "#415DF0"),
    ("pacific", "#179FD9"),
    ("reef", "#1DA583"),
    ("fern", "#3CBB3A"),
    ("olive", "#B4A40E"),
    ("cobalt", "#273EB2"),
    ("ocean", "#0A77A6"),
    ("pine", "#0F735A"),
    ("forest", "#258723"),
    ("pickle", "#807304"),
];

/// Sentinel meaning "use the calendar's own color": Proton has no per-event
/// "no color" state, so reverting sets the calendar color explicitly (what
/// the web client does; `Color: null` on update is ignored server-side).
pub const COLOR_DEFAULT_SENTINEL: &str = "default";

/// True when `hex` (`#RRGGBB`, case-insensitive) is a palette color.
pub fn valid_color(hex: &str) -> bool {
    let upper = hex.to_uppercase();
    ACCENT_PALETTE.iter().any(|(_, h)| *h == upper)
}

/// Friendly palette name for `hex`, or `None` when not in the palette.
pub fn color_name(hex: &str) -> Option<&'static str> {
    let upper = hex.to_uppercase();
    ACCENT_PALETTE
        .iter()
        .find(|(_, h)| *h == upper)
        .map(|(n, _)| *n)
}

/// Resolve a friendly name or hex (case-insensitive, `#` optional) to
/// canonical uppercase hex. The `default` sentinel and unknown specs are
/// `Err` (callers handle revert-to-calendar-color separately).
pub fn resolve_color(spec: &str) -> Result<String, String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("invalid color: empty color".into());
    }
    if s.eq_ignore_ascii_case(COLOR_DEFAULT_SENTINEL) {
        return Err(
            "invalid color: \"default\" means the calendar color, not a palette entry".into(),
        );
    }
    if let Some((_, hex)) = ACCENT_PALETTE
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(s))
    {
        return Ok((*hex).to_string());
    }
    let mut hex = s.to_uppercase();
    if !hex.starts_with('#') {
        hex.insert(0, '#');
    }
    if valid_color(&hex) {
        Ok(hex)
    } else {
        Err(format!("invalid color {spec:?}; use a palette hex or name"))
    }
}

/// Render a `Notifications` row value preserving the wire tri-state
/// (proton-cal `marshalNotifications`): not-set → `null` (inherit calendar
/// defaults), set-but-empty → `[]` (explicitly none), else the array.
pub fn marshal_notifications(set: bool, list: &[serde_json::Value]) -> serde_json::Value {
    if !set {
        serde_json::Value::Null
    } else if list.is_empty() {
        serde_json::Value::Array(Vec::new())
    } else {
        serde_json::Value::Array(list.to_vec())
    }
}

/// Render a `Color` row value: empty (inherit) → `null`, else the hex string.
/// Callers validate non-empty values with `resolve_color` first.
pub fn marshal_color(color: &str) -> serde_json::Value {
    if color.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(color.to_string())
    }
}

/// One clear `Attendees` row on an update body: token + live RSVP status
/// (proton-cal `attendeeClear`; `Comment` preserved verbatim, null absent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttendeeClear {
    pub Token: String,
    pub Status: i64,
    #[serde(default)]
    pub Comment: serde_json::Value,
}

/// Render clear `Attendees` rows (`[]` when no attendees).
pub fn marshal_attendees(tokens: &[(String, i64)]) -> serde_json::Value {
    if tokens.is_empty() {
        return serde_json::Value::Array(Vec::new());
    }
    let rows: Vec<AttendeeClear> = tokens
        .iter()
        .map(|(token, status)| AttendeeClear {
            Token: token.clone(),
            Status: *status,
            Comment: serde_json::Value::Null,
        })
        .collect();
    serde_json::to_value(&rows).unwrap_or(serde_json::Value::Array(Vec::new()))
}

/// One content part in a sync body: exactly `{Type, Data, Signature}`
/// (a minimal shape — NOT `CalendarEventPart`, whose extra `MemberID` /
/// `Author` keys must not leak onto the wire).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncContentPart {
    pub Type: i64,
    pub Data: String,
    pub Signature: String,
}

/// The `Event` object of a sync payload (proton-cal `eventBody`). Field
/// presence is significant: content arrays serialize as `[]` (never
/// `null`); key packets are `Some` on create, `None` on update (server
/// keeps the originals); `Notifications`/`Color` carry existing values on
/// update so untouched reminders/colors survive the whole-object replace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEventBody {
    pub Permissions: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub SharedKeyPacket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub CalendarKeyPacket: Option<String>,
    #[serde(default)]
    pub SharedEventContent: Vec<SyncContentPart>,
    #[serde(default)]
    pub CalendarEventContent: Vec<SyncContentPart>,
    #[serde(default)]
    pub AttendeesEventContent: Vec<SyncContentPart>,
    #[serde(default)]
    pub Attendees: serde_json::Value,
    #[serde(default)]
    pub Notifications: serde_json::Value,
    #[serde(default)]
    pub Color: serde_json::Value,
}

/// One entry of the sync `Events` array (proton-cal `syncEventReq`):
/// create (`Overwrite` + `Event`), update (`ID` + `Event`), or delete
/// (`ID` only — `Event`/`Overwrite` absent, NOT null).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEventOp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ID: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Overwrite: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Event: Option<SyncEventBody>,
}

impl SyncEventOp {
    /// Delete op: `{ID}` only.
    pub fn delete(event_id: &str) -> Self {
        Self {
            ID: Some(event_id.to_string()),
            Overwrite: None,
            Event: None,
        }
    }

    /// Update op: `{ID, Event}` (body carries NO key packets).
    pub fn update(event_id: &str, body: SyncEventBody) -> Self {
        Self {
            ID: Some(event_id.to_string()),
            Overwrite: None,
            Event: Some(body),
        }
    }

    /// Create op: `{Overwrite: 0, Event}` (body carries fresh key packets).
    pub fn create(body: SyncEventBody) -> Self {
        Self {
            ID: None,
            Overwrite: Some(0),
            Event: Some(body),
        }
    }
}

/// `PUT /calendar/v1/{calID}/events/sync` payload (proton-cal `syncReq`).
/// `IsImport` is present (`0`) on creates only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncBatchRequest {
    pub MemberID: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub IsImport: Option<i32>,
    pub Events: Vec<SyncEventOp>,
}

impl SyncBatchRequest {
    /// Delete batch: master + same-UID rows in ONE call (deleting a master
    /// ORPHANS its exception rows — no server cascade, api.md).
    pub fn delete_batch(member_id: &str, event_ids: &[String]) -> Self {
        Self {
            MemberID: member_id.to_string(),
            IsImport: None,
            Events: event_ids.iter().map(|id| SyncEventOp::delete(id)).collect(),
        }
    }
}

/// Sync endpoint response (proton-cal `syncResp`). Deletes return only the
/// top-level code (no `Responses`); creates echo the stored row; updates
/// may omit it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncBatchResponse {
    #[serde(default)]
    pub Code: i64,
    #[serde(default)]
    pub Responses: Vec<SyncOpResponse>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncOpResponse {
    #[serde(default)]
    pub Index: i64,
    #[serde(default)]
    pub Response: SyncOpResult,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncOpResult {
    #[serde(default)]
    pub Code: i64,
    #[serde(default)]
    pub Error: String,
    #[serde(default)]
    pub Event: Option<serde_json::Value>,
}

impl SyncBatchResponse {
    /// First failure: the first per-op error, else the top-level code
    /// (proton-cal `firstError`). `None` on success.
    pub fn first_error(&self) -> Option<String> {
        if self.Responses.is_empty() {
            if self.Code == SYNC_CODE_SUCCESS || self.Code == SYNC_CODE_SUCCESS_MULTI {
                return None;
            }
            return Some(format!("sync failed: code {}", self.Code));
        }
        let resp = &self.Responses[0].Response;
        if resp.Code != SYNC_CODE_SUCCESS {
            if resp.Error.is_empty() {
                return Some(format!("sync failed: code {}", resp.Code));
            }
            return Some(format!("sync failed: code {}: {}", resp.Code, resp.Error));
        }
        None
    }

    /// Echoed event of the first op on success (`None` when the server
    /// omits it, as updates may), or the failure from `first_error`.
    pub fn first_event(&self) -> Result<Option<serde_json::Value>, String> {
        if let Some(err) = self.first_error() {
            return Err(err);
        }
        if self.Responses.is_empty() {
            return Ok(None);
        }
        Ok(self.Responses[0].Response.Event.clone())
    }
}

/// Property-level edits to a decrypted VEVENT card, preserving every other
/// line verbatim (proton-cal `ical.CardPatch`): conferencing
/// (`X-PM-CONFERENCE-*`), `ORGANIZER`, attendees, third-party `X-` props
/// and nested components (VALARM) survive — rebuilding from known fields
/// would silently drop them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardPatch {
    /// Replace-or-insert single-valued property: NAME → line after NAME
    /// (e.g. `":new value"` or `";TZID=Europe/Rome:20260914T200000"`).
    pub set: HashMap<String, String>,
    /// Remove EVERY line with NAME (single- or multi-valued). Applied
    /// before `set`/`append`.
    pub delete: HashSet<String>,
    /// Add verbatim unfolded lines (e.g. extra EXDATEs); exact duplicates
    /// already in the card are skipped.
    pub append: Vec<String>,
}

/// RFC5545 §3.3.11 TEXT escaping for `set` values of TEXT properties
/// (SUMMARY/DESCRIPTION/LOCATION). Inverse of `unescape_ical_text`.
/// Mirrors proton-cal `escapeText`: bare CR is dropped (a CRLF's CR goes
/// with it; LF becomes `\n`), so escaped values never inject raw line
/// breaks into a content line.
pub fn escape_ical_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Fold one logical line per RFC5545 §3.1 (CRLF + single space), never
/// mid-rune. Mirrors proton-cal `foldLine`: the first chunk gets 75
/// octets, continuation lines start with a space leaving 74.
fn fold_line(line: &str) -> String {
    if line.len() <= 75 {
        return line.to_string();
    }
    let mut out = String::new();
    let mut rest = line;
    let mut budget = 75usize;
    while rest.len() > budget {
        let mut cut = budget;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            cut = rest.chars().next().map_or(1, |c| c.len_utf8());
        }
        out.push_str(&rest[..cut]);
        out.push_str("\r\n ");
        rest = &rest[cut..];
        budget = 74;
    }
    out.push_str(rest);
    out
}

/// Upper-cased property NAME of an unfolded content line (`None` when the
/// line has no colon outside quotes).
fn prop_name(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            in_quotes = !in_quotes;
        } else if b == b':' && !in_quotes {
            let left = &line[..i];
            let name = left.split(';').next().unwrap_or(left).trim().to_uppercase();
            if name.is_empty() {
                return None;
            }
            return Some(name);
        }
    }
    None
}

/// Apply a `CardPatch`, returning re-wrapped card text (no VERSION/PRODID
/// added, no trailing CRLF) ready to re-sign/re-encrypt. Mirrors
/// proton-cal `PatchCard`: unfold → Delete, then Set replaces in place
/// (EVERY occurrence of a Set NAME is replaced — a multi-valued property
/// plus Set collapses to one value), absent Set NAMEs appended sorted by
/// name (deterministic), Append skips exact duplicates, nested component
/// blocks (`VALARM`, …) and wrapper lines pass through verbatim, output
/// folded at 75 octets.
///
/// One deliberate divergence: `VERSION`/`PRODID` lines the server sent us
/// are kept verbatim (proton-cal strips them as its builder never emits
/// them). For a whole-object replace, preserving server-sent bytes is the
/// safer default; the server accepts them since it produced them.
pub fn patch_card(card: &str, patch: &CardPatch) -> String {
    let delete: HashSet<String> = patch.delete.iter().map(|n| n.to_uppercase()).collect();
    let set: HashMap<String, &str> = patch
        .set
        .iter()
        .map(|(k, v)| (k.to_uppercase(), v.as_str()))
        .collect();

    // Unfold (mirror `unfold_ical`: CRLF + exactly one char), tracking
    // nested-component blocks to pass through verbatim.
    let normalized = card.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if (line.starts_with(' ') || line.starts_with('\t')) && !lines.is_empty() {
            if let Some(last) = lines.last_mut() {
                last.push_str(&line[1..]);
            }
        } else {
            lines.push(line.to_string());
        }
    }

    let mut props: Vec<String> = Vec::new();
    let mut blocks: Vec<String> = Vec::new();
    let mut in_block = false;
    for line in lines {
        let upper = line.to_uppercase();
        if !in_block
            && (upper.starts_with("BEGIN:VCALENDAR")
                || upper.starts_with("BEGIN:VEVENT")
                || upper.starts_with("END:VEVENT")
                || upper.starts_with("END:VCALENDAR"))
        {
            continue; // wrapper rebuilt below
        }
        if upper.starts_with("BEGIN:") {
            in_block = true;
            blocks.push(line);
            continue;
        }
        if in_block {
            blocks.push(line);
            if upper.starts_with("END:") {
                in_block = false;
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        props.push(line);
    }

    let mut out: Vec<String> = Vec::with_capacity(props.len() + patch.append.len());
    let mut existing: HashSet<String> = HashSet::new();
    for line in props {
        let Some(name) = prop_name(&line) else {
            out.push(line);
            continue;
        };
        if delete.contains(&name) {
            continue;
        }
        if let Some(repl) = set.get(&name) {
            out.push(format!("{name}{repl}"));
            existing.insert(name);
            continue;
        }
        existing.insert(name);
        out.push(line);
    }
    let mut missing: Vec<(&String, &str)> = set
        .iter()
        .filter(|(name, _)| {
            let upper = name.to_uppercase();
            !existing.contains(&upper) && !delete.contains(&upper)
        })
        .map(|(name, repl)| (name, *repl))
        .collect();
    missing.sort_by(|a, b| a.0.cmp(b.0));
    for (name, repl) in missing {
        out.push(format!("{}{repl}", name.to_uppercase()));
    }
    let mut present: HashSet<String> = out.iter().cloned().collect();
    for line in &patch.append {
        if present.contains(line) {
            continue;
        }
        present.insert(line.clone());
        out.push(line.clone());
    }

    let mut wrapped = vec!["BEGIN:VCALENDAR".to_string(), "BEGIN:VEVENT".to_string()];
    for line in out {
        wrapped.push(fold_line(&line));
    }
    for block in blocks {
        wrapped.push(fold_line(&block));
    }
    wrapped.push("END:VEVENT".to_string());
    wrapped.push("END:VCALENDAR".to_string());
    wrapped.join("\r\n")
}

/// Local field snapshot for one dirty/never-synced row, exported by the
/// shim from the mKCal incidence (exact inventory-JSON contract keys).
/// `None` = field not exported (clean rows omit the whole snapshot).
/// Times are unix seconds (phone semantics: all-day `end_unix` is
/// INCLUSIVE — the sealer converts to exclusive DATE DTEND).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalFields {
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub start_unix: Option<i64>,
    #[serde(default)]
    pub end_unix: Option<i64>,
    #[serde(default)]
    pub all_day: Option<bool>,
    /// Recurrence rule state: absent/`None` = keep server rule (update) or
    /// no rule (create); `Some(Some(r))` = set it; `Some(None)` = delete
    /// the rule — UNLESS `has_recurrence` is set (unserializable phone
    /// rule: keep the server rule instead; the phone edit reverts on
    /// download, documented).
    #[serde(default)]
    pub rrule: Option<Option<String>>,
    /// Phone incidence carries recurrence the shim could NOT serialize
    /// (hourly-or-finer FREQ, BYHOUR/MINUTE/SECOND, exotic BYxxx): updates
    /// keep the server rule, creates defer (never flatten a series).
    #[serde(default)]
    pub has_recurrence: bool,
    /// Phone reminder state for dirty rows: alarm list as `{Trigger, Type}`
    /// row-shaped entries (Type 1 display). `None` = untouched (verbatim
    /// re-send). Explicit `[]` = user cleared all. The engine merges back
    /// the row's server-sent (Type 0) entries and forces inherit (`null`)
    /// when the result equals the effective calendar defaults.
    #[serde(default)]
    pub notifications: Option<Vec<serde_json::Value>>,
    /// Phone event color (`#RRGGBB`, `""` when the phone has none set).
    /// `None` = untouched. Empty reverts to the calendar's own color
    /// (web-client behavior); off-palette values keep the server value.
    #[serde(default)]
    pub color: Option<String>,
}

/// Format a DATE-TIME (UTC `…Z`) or DATE (all-day) property body AFTER the
/// NAME (`":20260914T180000Z"` / `";VALUE=DATE:20260709"`). DATE values
/// carry the explicit `VALUE=DATE` parameter (what the server sends us and
/// proton-cal emits — a bare dateless value is not valid DATE-TIME).
/// All-day end input is the phone-INCLUSIVE unix; output DTEND is
/// exclusive (+1 day), per RFC 5545 and our shim's read-side inverse.
/// Returns `None` for out-of-range input.
pub fn format_ical_dt(unix: i64, all_day: bool) -> Option<String> {
    let dt = chrono::DateTime::from_timestamp(unix, 0)?;
    if all_day {
        Some(format!("{}", dt.format(";VALUE=DATE:%Y%m%d")))
    } else {
        Some(format!("{}", dt.format(":%Y%m%dT%H%M%SZ")))
    }
}

/// Exclusive-end DATE body for a phone-inclusive all-day end unix
/// (`";VALUE=DATE:…"` — see `format_ical_dt`).
pub fn format_ical_date_end_exclusive(inclusive_unix: i64) -> Option<String> {
    let dt = chrono::DateTime::from_timestamp(inclusive_unix, 0)? + chrono::Duration::days(1);
    Some(format!("{}", dt.format(";VALUE=DATE:%Y%m%d")))
}

/// Engine-resolved overrides for an update body. `None` struct = verbatim
/// re-send of the row values (no phone edits to these fields).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateOverrides {
    /// `None` = re-send row tri-state; `Some(None)` = force `null`
    /// (inherit); `Some(Some(list))` = force the array (explicit none when
    /// empty). The engine merges phone display alarms with the row's
    /// server-sent (Type 0) entries and nulls out unchanged defaults.
    pub notifications: Option<Option<Vec<serde_json::Value>>>,
    /// Canonical palette hex replacing the row color (`None` = re-send).
    /// Reverting to the calendar color is an explicit hex, never null
    /// (server ignores null on update — api.md).
    pub color: Option<String>,
}

/// Next `SEQUENCE` after an edit (RFC 5546 + api.md): bump only on
/// significant changes (date/time/recurrence); field-only edits keep the
/// number, or a master edit would leapfrog its exceptions. Never decreases.
pub fn next_sequence(current: i64, significant_change: bool) -> i64 {
    if significant_change {
        current.saturating_add(1).max(1)
    } else {
        current.max(0)
    }
}

/// Server-enforced exception rule (api.md, code 2001 otherwise): an
/// exception row's `SEQUENCE` must be `>=` the master's.
pub fn exception_sequence_ok(master_sequence: i64, exception_sequence: i64) -> bool {
    exception_sequence >= master_sequence
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_palette_shape_and_lookup() {
        assert_eq!(ACCENT_PALETTE.len(), 20);
        assert!(valid_color("#EC3E7C"));
        assert!(valid_color("#ec3e7c"));
        assert!(!valid_color("#FFFFFF"));
        assert!(!valid_color("not-a-color"));
        assert_eq!(color_name("#EC3E7C"), Some("strawberry"));
        assert_eq!(color_name("#ffffff"), None);
        assert_eq!(resolve_color("strawberry").unwrap(), "#EC3E7C");
        assert_eq!(resolve_color("StrawBerry").unwrap(), "#EC3E7C");
        assert_eq!(resolve_color("#ec3e7c").unwrap(), "#EC3E7C");
        assert_eq!(resolve_color("ec3e7c").unwrap(), "#EC3E7C");
        assert!(resolve_color("").is_err());
        assert!(resolve_color("default").is_err());
        assert!(resolve_color("#FFFFFF").is_err());
    }

    #[test]
    fn test_marshal_notifications_tristate() {
        // Inherit → null.
        assert_eq!(marshal_notifications(false, &[]), serde_json::Value::Null);
        // Explicit none → [] (NOT null — null would re-inherit).
        assert_eq!(marshal_notifications(true, &[]), json!([]));
        // Custom array passes through.
        let list = vec![json!({"Trigger": "-PT15M", "Type": 1})];
        assert_eq!(
            marshal_notifications(true, &list),
            json!([{"Trigger": "-PT15M", "Type": 1}])
        );
        // Unset with a stale list still → null (set flag rules).
        assert_eq!(marshal_notifications(false, &list), serde_json::Value::Null);
    }

    #[test]
    fn test_marshal_color_null_when_empty() {
        assert_eq!(marshal_color(""), serde_json::Value::Null);
        assert_eq!(marshal_color("#EC3E7C"), json!("#EC3E7C"));
    }

    #[test]
    fn test_marshal_attendees_empty_array() {
        assert_eq!(marshal_attendees(&[]), json!([]));
        let out = marshal_attendees(&[("tok1".to_string(), 1)]);
        assert_eq!(
            out,
            json!([{"Token": "tok1", "Status": 1, "Comment": null}])
        );
    }

    #[test]
    fn test_delete_batch_wire_shape() {
        let batch = SyncBatchRequest::delete_batch("m1", &["e1".to_string(), "e2".to_string()]);
        let v = serde_json::to_value(&batch).unwrap();
        // Delete ops are ID-only: no Event/Overwrite keys, no IsImport.
        assert_eq!(
            v,
            json!({
                "MemberID": "m1",
                "Events": [{"ID": "e1"}, {"ID": "e2"}]
            })
        );
    }

    #[test]
    fn test_update_op_has_no_key_packets() {
        let body = SyncEventBody {
            Permissions: 1,
            SharedKeyPacket: None,
            CalendarKeyPacket: None,
            SharedEventContent: vec![SyncContentPart {
                Type: 2,
                Data: "BEGIN:VEVENT".into(),
                Signature: "sig".into(),
            }],
            CalendarEventContent: Vec::new(),
            AttendeesEventContent: Vec::new(),
            Attendees: json!([]),
            Notifications: serde_json::Value::Null,
            Color: serde_json::Value::Null,
        };
        let op = SyncEventOp::update("ev9", body);
        let v = serde_json::to_value(&op).unwrap();
        assert_eq!(v.get("ID").unwrap(), "ev9");
        assert!(v.get("Overwrite").is_none());
        let event = v.get("Event").unwrap();
        assert!(event.get("SharedKeyPacket").is_none());
        assert!(event.get("CalendarKeyPacket").is_none());
        // Content arrays serialize as [] (never null).
        assert_eq!(event.get("CalendarEventContent").unwrap(), &json!([]));
    }

    #[test]
    fn test_create_op_carries_packets_and_import_flags() {
        let body = SyncEventBody {
            Permissions: 1,
            SharedKeyPacket: Some("skp".into()),
            CalendarKeyPacket: Some("ckp".into()),
            SharedEventContent: Vec::new(),
            CalendarEventContent: Vec::new(),
            AttendeesEventContent: Vec::new(),
            Attendees: json!([]),
            Notifications: serde_json::Value::Null,
            Color: serde_json::Value::Null,
        };
        let batch = SyncBatchRequest {
            MemberID: "m1".into(),
            IsImport: Some(0),
            Events: vec![SyncEventOp::create(body)],
        };
        let v = serde_json::to_value(&batch).unwrap();
        assert_eq!(v.get("IsImport").unwrap(), 0);
        assert_eq!(v["Events"][0].get("Overwrite").unwrap(), 0);
        assert!(v["Events"][0].get("ID").is_none());
        assert_eq!(v["Events"][0]["Event"]["SharedKeyPacket"], json!("skp"));
    }

    #[test]
    fn test_sync_response_interpretation() {
        // Batch-accepted with per-op success (updates may omit the echo).
        let ok: SyncBatchResponse = serde_json::from_str(
            r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":1000}}]}"#,
        )
        .unwrap();
        assert!(ok.first_error().is_none());
        assert_eq!(ok.first_event().unwrap(), None);
        // Per-op failure surfaces code + message.
        let fail: SyncBatchResponse = serde_json::from_str(
            r#"{"Code":1001,"Responses":[{"Index":0,"Response":{"Code":2001,"Error":"Single edits should have a Sequence greater or equal to main event"}}]}"#,
        )
        .unwrap();
        let err = fail.first_error().unwrap();
        assert!(
            err.contains("2001") && err.contains("Sequence"),
            "err={err}"
        );
        assert!(fail.first_event().is_err());
        // Pure delete: top-level code only.
        let del: SyncBatchResponse = serde_json::from_str(r#"{"Code":1000}"#).unwrap();
        assert!(del.first_error().is_none());
        // Top-level failure with no responses.
        let top: SyncBatchResponse = serde_json::from_str(r#"{"Code":400}"#).unwrap();
        assert!(top.first_error().unwrap().contains("400"));
    }

    #[test]
    fn test_patch_card_set_delete_append() {
        let card = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u1\r\nDTSTART:20260914T200000Z\r\nSUMMARY:Old title\r\nDESCRIPTION:Keep me\r\nX-PM-CONFERENCE-ID:abc\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let mut patch = CardPatch::default();
        patch.set.insert("SUMMARY".into(), ":New title".into());
        patch.delete.insert("DESCRIPTION".into());
        patch.append.push("EXDATE:20260915T200000Z".into());
        patch.append.push("EXDATE:20260915T200000Z".into()); // dup skipped
        let out = patch_card(card, &patch);
        assert!(out.contains("SUMMARY:New title"), "{out}");
        assert!(!out.contains("DESCRIPTION"), "{out}");
        assert!(!out.contains("Old title"), "{out}");
        // Untouched lines survive verbatim (the rebuild-from-fields trap).
        assert!(out.contains("X-PM-CONFERENCE-ID:abc"), "{out}");
        assert!(out.contains("UID:u1"), "{out}");
        // Append added exactly once.
        assert_eq!(out.matches("EXDATE:20260915T200000Z").count(), 1);
        // Wrapper shape: no trailing CRLF.
        assert!(!out.ends_with("\r\n"));
        assert!(out.starts_with("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n"));
    }

    #[test]
    fn test_patch_card_inserts_missing_sorted_and_keeps_valarm() {
        let card = "BEGIN:VEVENT\nUID:u1\nBEGIN:VALARM\nTRIGGER:-PT15M\nEND:VALARM\nEND:VEVENT";
        let mut patch = CardPatch::default();
        patch.set.insert("SUMMARY".into(), ":Hi".into());
        patch
            .set
            .insert("DTSTART".into(), ":20260914T200000Z".into());
        let out = patch_card(card, &patch);
        // Missing props inserted in sorted NAME order (deterministic).
        let dt = out.find("DTSTART").unwrap();
        let sum = out.find("SUMMARY").unwrap();
        assert!(dt < sum, "{out}");
        // Nested VALARM block preserved verbatim.
        assert!(
            out.contains("BEGIN:VALARM\r\nTRIGGER:-PT15M\r\nEND:VALARM"),
            "{out}"
        );
    }

    #[test]
    fn test_patch_card_unfolds_then_folds() {
        // Folded input ("Long " + "title") unfolds before patching.
        let card = "BEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Long \r\n title\r\nEND:VEVENT";
        let patch = CardPatch::default();
        let out = patch_card(card, &patch);
        assert!(out.contains("SUMMARY:Long title"), "{out}");
        // Long lines refold at 75 octets with CRLF+space.
        let long = format!("DESCRIPTION:{}", "x".repeat(200));
        let card2 = format!("BEGIN:VEVENT\r\nUID:u1\r\n{long}\r\nEND:VEVENT");
        let out2 = patch_card(&card2, &patch);
        assert!(out2.contains("\r\n "), "{out2}");
        // Every PHYSICAL line (folded) fits 75 octets; the logical line
        // reassembles to the full 200-x value.
        for line in out2.split("\r\n") {
            assert!(line.len() <= 75, "overlong: {line}");
        }
        assert!(out2.replace("\r\n ", "").contains(&long), "{out2}");
    }

    #[test]
    fn test_escape_round_trips_through_parse() {
        let raw = "Meet, discuss; plan\\next";
        let escaped = escape_ical_text(raw);
        assert_eq!(escaped, "Meet\\, discuss\\; plan\\\\next");
        // parse_ical unescapes back to the original.
        let frag = format!("BEGIN:VEVENT\nUID:u1\nSUMMARY:{escaped}\nEND:VEVENT");
        let parsed = crate::calendar::parse_ical(&frag).unwrap();
        assert_eq!(parsed.summary, raw);
    }

    #[test]
    fn test_put_sync_delete_batch_mock() {
        // Transport check (mockito, no live server): the batch serializes
        // ID-only ops and the 1001 envelope parses with per-op success.
        let mut server = mockito::Server::new();
        let mock = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .match_body(mockito::Matcher::JsonString(
                r#"{"MemberID":"m1","Events":[{"ID":"e1"},{"ID":"e2"}]}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":1001,"Responses":[]}"#)
            .create();
        let client = crate::calendar::CalendarClient::new_with_base_url(
            server.url(),
            "at".into(),
            "uid".into(),
        );
        let batch = SyncBatchRequest::delete_batch("m1", &["e1".to_string(), "e2".to_string()]);
        let resp = client.put_sync("cal1", &batch).unwrap();
        assert_eq!(resp.Code, SYNC_CODE_SUCCESS_MULTI);
        assert!(resp.first_error().is_none());
        mock.assert();
    }

    #[test]
    fn test_put_sync_surfaces_http_errors() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"/calendar/v1/cal1/events/sync.*".into()),
            )
            .with_status(422)
            .with_header("content-type", "application/json")
            .with_body(r#"{"Code":2001,"Error":"bad"}"#)
            .create();
        let client = crate::calendar::CalendarClient::new_with_base_url(
            server.url(),
            "at".into(),
            "uid".into(),
        );
        let batch = SyncBatchRequest::delete_batch("m1", &["e1".to_string()]);
        assert!(client.put_sync("cal1", &batch).is_err());
    }

    #[test]
    fn test_sequence_rules() {
        assert_eq!(next_sequence(3, true), 4);
        assert_eq!(next_sequence(3, false), 3);
        assert_eq!(next_sequence(0, true), 1);
        assert!(exception_sequence_ok(3, 3));
        assert!(exception_sequence_ok(3, 5));
        assert!(!exception_sequence_ok(3, 2));
    }
}
