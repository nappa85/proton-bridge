use serde::{Deserialize, Serialize};
use std::io::BufReader;

/// Phone field snapshot for one contact. EVERY field carries
/// `#[serde(default)]`: this struct is the exact shim↔engine JSON contract
/// (`contact_plan::ContactItem.fields`), and the shim omits keys it has
/// nothing for (`photos` — no photo upload v1 — and any future key). A
/// single missing key must never fail the whole inventory parse: on
/// 2026-09-09 exactly that (`missing field photos`) silently degraded the
/// engine to inventory=None and the known-diff planner wiped the server
/// contact the user had just edited.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedContact {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub emails: Vec<ParsedEmail>,
    #[serde(default)]
    pub phones: Vec<ParsedPhone>,
    #[serde(default)]
    pub addresses: Vec<ParsedAddress>,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub birthday: String,
    #[serde(default)]
    pub anniversary: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub gender: String,
    #[serde(default)]
    pub photos: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedEmail {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPhone {
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedAddress {
    #[serde(default)]
    pub street: String,
    #[serde(default)]
    pub locality: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub types: Vec<String>,
}

fn get_param_values(cl: &ical_vcard::Contentline, param_name: &str) -> Vec<String> {
    cl.params()
        .iter()
        .filter(|p| p.name().eq_ignore_ascii_case(param_name))
        .flat_map(|p| p.values().iter().map(|v| v.to_string()))
        .collect()
}

fn unescape_vcard(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => result.push('\n'),
                Some(',') => result.push(','),
                Some(';') => result.push(';'),
                Some('\\') => result.push('\\'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub fn parse_vcard(data: &str) -> Result<ParsedContact, String> {
    let reader = BufReader::new(data.as_bytes());
    let mut parser = ical_vcard::Parser::new(reader);
    let mut lines: Vec<ical_vcard::Contentline> = Vec::new();
    let mut in_vcard = false;

    loop {
        match parser.next() {
            Some(Ok(cl)) => {
                if cl.name().eq_ignore_ascii_case("BEGIN")
                    && cl.value().eq_ignore_ascii_case("VCARD")
                {
                    in_vcard = true;
                    lines.clear();
                }
                if in_vcard {
                    lines.push(cl);
                }
            }
            Some(Err(e)) => return Err(format!("ical_vcard parse error: {e}")),
            None => break,
        }
    }

    let mut contact = ParsedContact::default();

    for cl in &lines {
        let name = cl.name();
        let value = unescape_vcard(cl.value());

        match name.to_uppercase().as_str() {
            "FN" if contact.display_name.is_empty() => {
                contact.display_name = value;
            }
            "N" => {
                let parts: Vec<&str> = value.split(';').collect();
                if !parts.is_empty() {
                    contact.last_name = parts[0].to_string();
                }
                if parts.len() > 1 {
                    contact.first_name = parts[1].to_string();
                }
            }
            "EMAIL" => {
                let types = get_param_values(cl, "TYPE");
                contact.emails.push(ParsedEmail {
                    email: value,
                    types,
                });
            }
            "TEL" => {
                let types = get_param_values(cl, "TYPE");
                contact.phones.push(ParsedPhone {
                    number: value,
                    types,
                });
            }
            "ADR" => {
                let parts: Vec<&str> = value.split(';').collect();
                let types = get_param_values(cl, "TYPE");
                contact.addresses.push(ParsedAddress {
                    street: parts.get(2).unwrap_or(&"").to_string(),
                    locality: parts.get(3).unwrap_or(&"").to_string(),
                    region: parts.get(4).unwrap_or(&"").to_string(),
                    postal_code: parts.get(5).unwrap_or(&"").to_string(),
                    country: parts.get(6).unwrap_or(&"").to_string(),
                    types,
                });
            }
            "ORG" if contact.organization.is_empty() => {
                contact.organization = value;
            }
            "TITLE" if contact.title.is_empty() => {
                contact.title = value;
            }
            "ROLE" if contact.role.is_empty() => {
                contact.role = value;
            }
            "NOTE" => {
                contact.notes.push(value);
            }
            "URL" if contact.url.is_empty() => {
                contact.url = value;
            }
            "BDAY" if contact.birthday.is_empty() => {
                contact.birthday = format_bday(value);
            }
            "ANNIVERSARY" | "X-ANNIVERSARY" if contact.anniversary.is_empty() => {
                contact.anniversary = format_bday(value);
            }
            "NICKNAME" if contact.nickname.is_empty() => {
                contact.nickname = value;
            }
            "GENDER" if contact.gender.is_empty() => {
                let v = value.to_uppercase();
                if v.starts_with('M') {
                    contact.gender = "Male".to_string();
                } else if v.starts_with('F') {
                    contact.gender = "Female".to_string();
                } else if v.starts_with('O') {
                    contact.gender = "Other".to_string();
                } else if v.starts_with('N') {
                    contact.gender = "N/A".to_string();
                } else if v.starts_with('U') {
                    contact.gender = "Unknown".to_string();
                } else if !value.is_empty() {
                    contact.gender = value;
                }
            }
            "PHOTO" | "LOGO" if !value.is_empty() => {
                contact.photos.push(value);
            }
            _ => {}
        }
    }

    Ok(contact)
}

pub fn download_url_photos(photos: &mut [String]) {
    let mut replacements: Vec<(usize, String)> = Vec::new();
    for (i, photo) in photos.iter().enumerate() {
        if photo.starts_with("http://") || photo.starts_with("https://") {
            match reqwest::blocking::Client::builder()
                .user_agent("curl/8.0")
                .timeout(std::time::Duration::from_secs(10))
                .build()
            {
                Ok(client) => match client.get(photo.as_str()).send() {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            let ct = resp
                                .headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("image/jpeg")
                                .to_string();
                            let bytes = resp.bytes();
                            match bytes {
                                Ok(b) => {
                                    let b64 = base64::Engine::encode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &b,
                                    );
                                    let data_uri = format!("data:{ct};base64,{b64}");
                                    replacements.push((i, data_uri));
                                }
                                Err(e) => {
                                    eprintln!("Failed to read photo bytes from {}: {e}", photo)
                                }
                            }
                        } else {
                            eprintln!("Photo download failed {} status={}", photo, resp.status());
                        }
                    }
                    Err(e) => eprintln!("Photo download request failed {}: {e}", photo),
                },
                Err(e) => eprintln!("Failed to build HTTP client for photo: {e}"),
            }
        }
    }
    for (i, data_uri) in replacements {
        photos[i] = data_uri;
    }
}

/// vCard TEXT escaping (inverse of `unescape_vcard`).
pub fn escape_vcard(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            _ => out.push(c),
        }
    }
    out
}

/// `TYPE=` parameter suffix from parsed type list (`vec!["HOME"]` →
/// `";TYPE=HOME"`, empty → `""`). Values pass through verbatim.
fn type_param(types: &[String]) -> String {
    if types.is_empty() {
        return String::new();
    }
    format!(";TYPE={}", types.join(","))
}

/// Fold one content line to ≤75 octets (CRLF + single space), never
/// mid-rune. Mirrors the calendar `fold_line` (75 first, 74 after).
fn fold_vcard_line(line: &str) -> String {
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

/// Wrap unfolded content lines into a folded vCard fragment (no trailing
/// CRLF), mirroring the shapes the server sends us.
fn wrap_vcard(lines: &[String]) -> String {
    let mut out = vec!["BEGIN:VCARD".to_string(), "VERSION:4.0".to_string()];
    out.extend(lines.iter().cloned());
    out.push("END:VCARD".to_string());
    out.iter()
        .map(|l| fold_vcard_line(l))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// The writable card bodies for one contact (WebClients
/// `prepareCardsFromVCard` split): `signed` carries uid/fn/emails (+
/// version), `encrypted` (`None` when the contact has no encrypt-side
/// properties) carries everything else. No cleartext part —
/// our model has no categories (the only Type 0 trigger). `uid` is the
/// contact UID (freshly generated on create, preserved on update).
/// Display-name fallback mirrors the web client: explicit FN, else
/// `first last`, else the first email, else `Unknown` (`getFallbackFNValue`
/// — the server expects a non-empty FN). No PRODID is emitted: fresh web
/// contacts carry none (only VERSION, forced by the wrapper); PRODID on
/// server cards comes from imports and stays read-tolerated (see
/// `is_known_vcard_prop` — server cards carrying anything outside the
/// known set defer updates instead of dropping data).
/// Emails are grouped (`item1.EMAIL`, `item2.EMAIL`, …) exactly like
/// WebClients `prepareForSaving` (which refuses ungrouped emails — live
/// 2026-09-09 the server 400-rejected our ungrouped update). Other props
/// stay ungrouped, matching the web shape for key-less contacts.
/// The `Option` mirrors `encrypt.ts` exactly: the Type-3 promise is only
/// pushed `if (toEncryptAndSign.length > 0)` — an email-only contact seals
/// to a single Type-2 card, and sending an empty BEGIN/VERSION/END wrapper
/// as Type 3 risks a 400 (never live-tested either way, so match the web).
pub fn build_vcard(contact: &ParsedContact, uid: &str) -> (String, Option<String>) {
    let display = if !contact.display_name.is_empty() {
        contact.display_name.clone()
    } else {
        let full = format!("{} {}", contact.first_name, contact.last_name);
        let full = full.trim().to_string();
        if !full.is_empty() {
            full
        } else {
            contact
                .emails
                .first()
                .map(|e| e.email.clone())
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| "Unknown".to_string())
        }
    };
    let mut signed = vec![
        format!("UID:{uid}"),
        format!("FN:{}", escape_vcard(&display)),
    ];
    for (i, mail) in contact.emails.iter().enumerate() {
        signed.push(format!(
            "item{}.EMAIL{}:{}",
            i + 1,
            type_param(&mail.types),
            escape_vcard(&mail.email)
        ));
    }
    let mut encrypted = Vec::new();
    if !contact.first_name.is_empty() || !contact.last_name.is_empty() {
        encrypted.push(format!(
            "N:{};{};;;",
            escape_vcard(&contact.last_name),
            escape_vcard(&contact.first_name)
        ));
    }
    for phone in &contact.phones {
        encrypted.push(format!(
            "TEL{}:{}",
            type_param(&phone.types),
            escape_vcard(&phone.number)
        ));
    }
    for addr in &contact.addresses {
        encrypted.push(format!(
            "ADR{}:;;{};{};{};{};{}",
            type_param(&addr.types),
            escape_vcard(&addr.street),
            escape_vcard(&addr.locality),
            escape_vcard(&addr.region),
            escape_vcard(&addr.postal_code),
            escape_vcard(&addr.country),
        ));
    }
    if !contact.organization.is_empty() {
        encrypted.push(format!("ORG:{}", escape_vcard(&contact.organization)));
    }
    if !contact.title.is_empty() {
        encrypted.push(format!("TITLE:{}", escape_vcard(&contact.title)));
    }
    if !contact.role.is_empty() {
        encrypted.push(format!("ROLE:{}", escape_vcard(&contact.role)));
    }
    for note in &contact.notes {
        encrypted.push(format!("NOTE:{}", escape_vcard(note)));
    }
    if !contact.url.is_empty() {
        encrypted.push(format!("URL:{}", escape_vcard(&contact.url)));
    }
    if !contact.birthday.is_empty() {
        encrypted.push(format!("BDAY:{}", escape_vcard(&contact.birthday)));
    }
    if !contact.anniversary.is_empty() {
        encrypted.push(format!(
            "ANNIVERSARY:{}",
            escape_vcard(&contact.anniversary)
        ));
    }
    if !contact.nickname.is_empty() {
        encrypted.push(format!("NICKNAME:{}", escape_vcard(&contact.nickname)));
    }
    if !contact.gender.is_empty() {
        encrypted.push(format!(
            "GENDER:{}",
            escape_vcard(&gender_letter(&contact.gender))
        ));
    }
    for photo in &contact.photos {
        encrypted.push(format!("PHOTO:{}", escape_vcard(photo)));
    }
    let signed = wrap_vcard(&signed);
    // WebClients omits the encrypted card when there is nothing to seal
    // (`toEncryptAndSign.length > 0` gate in `encrypt.ts`).
    let encrypted = if encrypted.is_empty() {
        None
    } else {
        Some(wrap_vcard(&encrypted))
    };
    (signed, encrypted)
}

/// Back to single-letter GENDER (inverse of the parse mapping).
fn gender_letter(gender: &str) -> String {
    match gender.to_uppercase().as_str() {
        "MALE" => "M".into(),
        "FEMALE" => "F".into(),
        "OTHER" => "O".into(),
        "N/A" => "N".into(),
        "UNKNOWN" => "U".into(),
        other => other.to_string(),
    }
}

/// Property names the update path understands (everything `build_vcard`
/// round-trips). A decrypted server card carrying anything else (X-*
/// props, key fields, LABELs…) defers the update — rebuilding would
/// silently drop it (calendar patch-in-place lesson). `LOGO` counts as
/// known (folds into photos, re-emitted as `PHOTO`).
pub fn is_known_vcard_prop(name: &str) -> bool {
    matches!(
        name.to_uppercase().as_str(),
        "BEGIN"
            | "END"
            | "VERSION"
            | "PRODID"
            | "UID"
            | "FN"
            | "N"
            | "EMAIL"
            | "TEL"
            | "ADR"
            | "ORG"
            | "TITLE"
            | "ROLE"
            | "NOTE"
            | "URL"
            | "BDAY"
            | "ANNIVERSARY"
            | "X-ANNIVERSARY"
            | "NICKNAME"
            | "GENDER"
            | "PHOTO"
            | "LOGO"
    )
}

/// Upper-cased property names of one card's content lines (unfolded),
/// for the update guard. Group prefixes (`ITEM1.EMAIL` — which Proton web
/// ALWAYS emits for emails, see `prepareForSaving`) are stripped: only the
/// base name matters, and `.` is not a valid property-name character so
/// anything before the last dot can only be a group. `None` when the text
/// doesn't parse as lines.
fn card_prop_names(card: &str) -> Vec<String> {
    unfold_ical_lines(card)
        .iter()
        .filter_map(|line| {
            let name = line.split([';', ':']).next()?.trim().to_uppercase();
            // Strip `GROUP.` prefix (`ITEM1.EMAIL` → `EMAIL`).
            let base = name.rsplit('.').next().unwrap_or_default();
            if base.is_empty() {
                None
            } else {
                Some(base.to_string())
            }
        })
        .collect()
}

/// Unfold folded content lines (a CRLF followed by a single space/tab
/// continues the previous line). Shared by the guard and the key-group
/// preservation below — one unfolding rule everywhere.
fn unfold_ical_lines(card: &str) -> Vec<String> {
    let normalized = card.replace("\r\n", "\n").replace('\r', "\n");
    let mut unfolded: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if (line.starts_with(' ') || line.starts_with('\t')) && !unfolded.is_empty() {
            if let Some(last) = unfolded.last_mut() {
                last.push_str(&line[1..]);
            }
        } else {
            unfolded.push(line.to_string());
        }
    }
    unfolded
}

/// Per-email crypto-setting fields (WebClients `VCARD_KEY_FIELDS`): they
/// live GROUPED with their address (`item3.EMAIL` + `item3.KEY`,
/// `item3.X-PM-SCHEME`, …) in the signed card (see go-proton-api
/// `contact_card.go` `GetGroup`). Ungrouped occurrences are NOT settings
/// (unknown placement — still defer).
pub const VCARD_KEY_FIELDS: &[&str] = &[
    "KEY",
    "X-PM-MIMETYPE",
    "X-PM-ENCRYPT",
    "X-PM-ENCRYPT-UNTRUSTED",
    "X-PM-SIGN",
    "X-PM-SCHEME",
    "X-PM-TLS",
];

/// One address's carried crypto settings: unfolded raw lines, verbatim
/// (re-emitted byte-identical except for the regrouped prefix).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyGroup {
    /// The group's email address (from its `EMAIL` line).
    pub email: String,
    /// Raw `GROUP.BASE;params:value` lines (unfolded, verbatim).
    pub lines: Vec<String>,
}

/// Split one unfolded line into (group, BASE name). `None` when the line
/// has no content name at all.
fn split_grouped_name(line: &str) -> Option<(Option<String>, String)> {
    let name = line.split([';', ':']).next()?.trim();
    if name.is_empty() {
        return None;
    }
    match name.rsplit_once('.') {
        Some((group, base)) if !group.is_empty() && !base.is_empty() => {
            Some((Some(group.to_string()), base.to_uppercase()))
        }
        _ => Some((None, name.to_uppercase())),
    }
}

/// Extract preservable per-email crypto settings from one decrypted card:
/// grouped key-field lines whose group also carries an `EMAIL` line.
/// Orphan key lines (no address in their group) and ungrouped ones are
/// NOT returned — they stay unknown and keep deferring the update.
pub fn extract_key_groups(card: &str) -> Vec<KeyGroup> {
    // group (upper-cased for matching) → (original group spelling, emails, key lines)
    let mut groups: std::collections::HashMap<String, (String, Vec<String>, Vec<String>)> =
        std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in unfold_ical_lines(card) {
        let Some((group, base)) = split_grouped_name(&line) else {
            continue;
        };
        let Some(group) = group else { continue };
        if !VCARD_KEY_FIELDS.contains(&base.as_str()) && base != "EMAIL" {
            continue;
        }
        let key = group.to_uppercase();
        let entry = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (group, Vec::new(), Vec::new())
        });
        if base == "EMAIL" {
            if let Some(value) = line.split_once(':').map(|x| x.1) {
                entry.1.push(value.trim().to_string());
            }
        } else {
            entry.2.push(line);
        }
    }
    let mut out = Vec::new();
    for key in order {
        let (_, emails, lines) = &groups[&key];
        let Some(email) = emails.first().filter(|e| !e.is_empty()) else {
            continue;
        };
        if lines.is_empty() {
            continue;
        }
        out.push(KeyGroup {
            email: email.clone(),
            lines: lines.clone(),
        });
    }
    out
}

/// Unknown props IGNORING preservable key groups: the update rebuild
/// carries those verbatim (see `render_key_groups`), so they no longer
/// block it. Everything else unknown still defers. Encrypted-card key
/// lines are deliberately NOT exempt (WebClients never emits them there;
/// keep deferring rather than relocating protection domains).
pub fn unknown_vcard_props_except_keys(cards: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for card in cards {
        let key_lines: std::collections::HashSet<String> = extract_key_groups(card)
            .into_iter()
            .flat_map(|g| g.lines)
            .collect();
        for line in unfold_ical_lines(card) {
            if key_lines.contains(&line) {
                continue;
            }
            let Some((_, base)) = split_grouped_name(&line) else {
                continue;
            };
            if !base.is_empty() && !is_known_vcard_prop(&base) {
                out.push(base);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Re-emit carried groups under the rebuilt numbering: `email_to_group`
/// maps address → new `itemN` (our `build_vcard` order). Only the group
/// prefix changes — line bodies pass through byte-identical. Groups whose
/// address vanished from the phone snapshot drop (address deleted; its
/// settings are moot). Email lookup is case-insensitive (RFC 5321
/// local-part reality + web-client mixed-case exports).
pub fn render_key_groups(
    groups: &[KeyGroup],
    email_to_group: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let lower: std::collections::HashMap<String, &String> = email_to_group
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    let mut out = Vec::new();
    for group in groups {
        let Some(new_group) = lower.get(&group.email.to_lowercase()) else {
            continue;
        };
        for line in &group.lines {
            match line.split_once('.') {
                Some((_, rest)) => out.push(format!("{new_group}.{rest}")),
                None => out.push(line.clone()),
            }
        }
    }
    out
}

/// Append unfolded lines to a folded card (before `END:VCARD`), folding
/// them to the 75-octet rule. Used for carried key groups (signed before
/// sending — the detached signature must cover the final text).
pub fn append_vcard_lines(card: &str, lines: &[String]) -> String {
    if lines.is_empty() {
        return card.to_string();
    }
    let mut out: Vec<String> = card.split("\r\n").map(str::to_string).collect();
    if out.last().is_some_and(|l| l == "END:VCARD") {
        out.pop();
    }
    out.extend(lines.iter().map(|l| fold_vcard_line(l)));
    out.push("END:VCARD".to_string());
    out.join("\r\n")
}

/// True when any decrypted server card carries properties outside the
/// known set (the update rebuild would silently drop them — defer).
pub fn has_unknown_vcard_props(cards: &[String]) -> bool {
    !unknown_vcard_props(cards).is_empty()
}

/// Sorted unique unknown property names across cards (schema only, never
/// values — safe to log for deferral diagnosis). Group prefixes are already
/// stripped, so `ITEM1.FOO` surfaces as `FOO`: a genuine rebuild hazard,
/// not a grouping artifact.
pub fn unknown_vcard_props(cards: &[String]) -> Vec<String> {
    let mut out: Vec<String> = cards
        .iter()
        .flat_map(|card| card_prop_names(card))
        .filter(|name| !is_known_vcard_prop(name))
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn format_bday(raw: String) -> String {
    if raw.len() == 8 && raw.chars().all(|c| c.is_ascii_digit()) {
        format!("{}-{}-{}", &raw[0..4], &raw[4..6], &raw[6..8])
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rich_contact() -> ParsedContact {
        ParsedContact {
            first_name: "Ada, the".into(),
            last_name: "Lovelace".into(),
            display_name: String::new(), // exercises first+last fallback
            emails: vec![ParsedEmail {
                email: "ada@example.com".into(),
                types: vec!["HOME".into()],
            }],
            phones: vec![ParsedPhone {
                number: "+39 02 123".into(),
                types: vec!["CELL".into(), "VOICE".into()],
            }],
            addresses: vec![ParsedAddress {
                street: "Via Roma 1".into(),
                locality: "Milano".into(),
                region: "MI".into(),
                postal_code: "20100".into(),
                country: "Italy".into(),
                types: vec!["HOME".into()],
            }],
            organization: "Analytical Engines;Dept".into(),
            title: "Mathematician".into(),
            role: String::new(),
            notes: vec!["line1\nline2".into(), "second".into()],
            url: "https://example.com".into(),
            birthday: "1815-12-10".into(),
            anniversary: String::new(),
            nickname: "Queen of Numbers".into(),
            gender: "Female".into(),
            photos: vec!["data:image/jpeg;base64,/9j/".into()],
        }
    }

    #[test]
    fn test_build_vcard_round_trips() {
        let contact = rich_contact();
        let (signed, encrypted) = build_vcard(&contact, "uid-9");
        let encrypted = encrypted.expect("rich contact seals an encrypted card");
        // Split contract: uid/fn/emails signed, everything else encrypted.
        assert!(signed.contains("UID:uid-9"));
        assert!(signed.contains("FN:Ada\\, the Lovelace"));
        assert!(signed.contains("item1.EMAIL;TYPE=HOME:ada@example.com"));
        assert!(!signed.contains("TEL"));
        assert!(encrypted.contains("TEL;TYPE=CELL,VOICE:+39 02 123"));
        assert!(encrypted.contains("N:Lovelace;Ada\\, the;;;"));
        assert!(encrypted.contains("ORG:Analytical Engines\\;Dept"));
        assert!(encrypted.contains("NOTE:line1\\nline2"));
        assert!(encrypted.contains("BDAY:1815-12-10"));
        assert!(encrypted.contains("GENDER:F"));
        // `;` and `,` escaped (correct vCard TEXT escaping for data URIs).
        assert!(encrypted.contains("PHOTO:data:image/jpeg\\;base64\\,/9j/"));
        // No cleartext part without categories.
        assert!(!signed.contains("TEL") || signed.contains("EMAIL"));
        // Re-parse both cards: union recovers the contact.
        let mut back = parse_vcard(&signed).unwrap();
        let enc = parse_vcard(&encrypted).unwrap();
        if back.display_name.is_empty() {
            back.display_name = enc.display_name.clone();
        }
        if back.first_name.is_empty() {
            back.first_name = enc.first_name.clone();
            back.last_name = enc.last_name.clone();
        }
        back.phones = enc.phones.clone();
        back.addresses = enc.addresses.clone();
        back.organization = enc.organization.clone();
        back.title = enc.title.clone();
        back.notes = enc.notes.clone();
        back.url = enc.url.clone();
        back.birthday = enc.birthday.clone();
        back.nickname = enc.nickname.clone();
        back.gender = enc.gender.clone();
        back.photos = enc.photos.clone();
        assert_eq!(back.display_name, "Ada, the Lovelace");
        assert_eq!(back.first_name, "Ada, the");
        assert_eq!(back.last_name, "Lovelace");
        assert_eq!(back.emails.len(), 1);
        assert_eq!(back.phones[0].types, vec!["CELL", "VOICE"]);
        assert_eq!(back.addresses[0].locality, "Milano");
        assert_eq!(back.organization, "Analytical Engines;Dept");
        assert_eq!(back.notes.len(), 2);
        assert_eq!(back.notes[0], "line1\nline2");
        assert_eq!(back.gender, "Female");
    }

    #[test]
    fn test_build_vcard_fn_fallbacks() {
        // Explicit FN wins.
        let c = ParsedContact {
            display_name: "Shown Name".into(),
            ..Default::default()
        };
        let (signed, _) = build_vcard(&c, "u");
        assert!(signed.contains("FN:Shown Name"));
        // Else first email.
        let c2 = ParsedContact {
            emails: vec![ParsedEmail {
                email: "solo@example.com".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        };
        let (signed2, _) = build_vcard(&c2, "u");
        assert!(signed2.contains("FN:solo@example.com"));
        // Else `Unknown` (WebClients `getFallbackFNValue` — never empty).
        let (signed3, _) = build_vcard(&ParsedContact::default(), "u");
        assert!(signed3.contains("FN:Unknown"), "{signed3}");
    }

    #[test]
    fn test_build_vcard_emits_no_prodid() {
        // Fresh web contacts carry VERSION (forced) but no PRODID; the old
        // always-emit risked a calendar-style 2011 property rejection.
        let (signed, encrypted) = build_vcard(&rich_contact(), "u");
        let encrypted = encrypted.expect("rich contact seals an encrypted card");
        assert!(!signed.contains("PRODID"), "{signed}");
        assert!(!encrypted.contains("PRODID"), "{encrypted}");
        assert!(signed.contains("VERSION:4.0"), "{signed}");
    }

    #[test]
    fn test_build_vcard_email_only_omits_encrypted() {
        // `encrypt.ts` only pushes the Type-3 promise
        // `if (toEncryptAndSign.length > 0)`: an email-only contact seals to
        // a single signed card. Emitting an empty BEGIN/VERSION/END wrapper
        // as Type 3 was never live-tested and risks a 400.
        let c = ParsedContact {
            display_name: "Solo".into(),
            emails: vec![ParsedEmail {
                email: "solo@example.com".into(),
                types: Vec::new(),
            }],
            ..Default::default()
        };
        let (signed, encrypted) = build_vcard(&c, "u-solo");
        assert!(signed.contains("UID:u-solo"));
        assert!(signed.contains("FN:Solo"));
        assert!(signed.contains("item1.EMAIL:solo@example.com"));
        assert!(encrypted.is_none(), "{encrypted:?}");
        // Nameless + phoneless + addressless is the same shape.
        let (signed2, encrypted2) = build_vcard(&ParsedContact::default(), "u-empty");
        assert!(signed2.contains("FN:Unknown"));
        assert!(encrypted2.is_none(), "{encrypted2:?}");
    }

    #[test]
    fn test_build_vcard_folds_long_lines() {
        let c = ParsedContact {
            notes: vec!["x".repeat(200)],
            ..Default::default()
        };
        let (_, encrypted) = build_vcard(&c, "u");
        let encrypted = encrypted.expect("note seals an encrypted card");
        for line in encrypted.split("\r\n") {
            assert!(line.len() <= 75, "overlong: {line}");
        }
        // Folded NOTE re-parses whole.
        let back = parse_vcard(&encrypted).unwrap();
        assert_eq!(back.notes, vec!["x".repeat(200)]);
    }

    #[test]
    fn test_grouped_props_dont_trip_guard() {
        // Proton web groups emails (`prepareForSaving` adds itemN groups),
        // so every real-world signed card carries `item1.EMAIL`. The update
        // guard must see the base name, or every web-created contact defers
        // (live 2026-09-09: `update:<uid>:unsealable` for a plain edit).
        let grouped = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Old\r\nitem1.EMAIL;TYPE=HOME:old@example.com\r\nEND:VCARD";
        assert!(!has_unknown_vcard_props(&[grouped.to_string()]));
        assert!(unknown_vcard_props(&[grouped.to_string()]).is_empty());
        // …while a genuinely unknown base name still trips, group or not.
        let exotic = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nX-CUSTOM:1\r\nEND:VCARD";
        assert_eq!(unknown_vcard_props(&[exotic.to_string()]), vec!["X-CUSTOM"]);
        let grouped_exotic =
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nitem1.X-CUSTOM:1\r\nEND:VCARD";
        assert_eq!(
            unknown_vcard_props(&[grouped_exotic.to_string()]),
            vec!["X-CUSTOM"]
        );
    }

    /// WebClients per-email crypto settings shape (go-proton-api
    /// `contact_card.go` GetGroup model): key fields share the address's
    /// group in the signed card.
    const KEYED_SIGNED: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u1\r\nFN:Keyed\r\nitem1.EMAIL;TYPE=HOME:kept@example.com\r\nitem1.KEY:data:;base64,QUJD\r\nitem1.X-PM-SCHEME:pgp-mime\r\nitem1.X-PM-SIGN:true\r\nitem2.EMAIL:plain@example.com\r\nEND:VCARD";

    #[test]
    fn test_extract_key_groups_by_email() {
        let groups = extract_key_groups(KEYED_SIGNED);
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0].email, "kept@example.com");
        assert_eq!(groups[0].lines.len(), 3);
        // Bodies byte-identical (only regrouped at render).
        assert!(groups[0]
            .lines
            .iter()
            .any(|l| l == "item1.KEY:data:;base64,QUJD"));
        assert!(groups[0]
            .lines
            .iter()
            .any(|l| l == "item1.X-PM-SCHEME:pgp-mime"));
        // `plain@example.com` has no key lines → no group.
        assert!(!groups.iter().any(|g| g.email == "plain@example.com"));
    }

    #[test]
    fn test_extract_key_groups_ignores_orphans_and_bare() {
        // Orphan group (no EMAIL) + ungrouped KEY: neither is preservable.
        let card =
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u\r\nFN:x\r\nitem9.KEY:abc\r\nKEY:bare\r\nEND:VCARD";
        assert!(extract_key_groups(card).is_empty());
        assert_eq!(
            unknown_vcard_props_except_keys(&[card.to_string()]),
            vec!["KEY"]
        );
    }

    #[test]
    fn test_key_groups_dont_trip_guard_but_exotic_does() {
        assert!(unknown_vcard_props_except_keys(&[KEYED_SIGNED.to_string()]).is_empty());
        // …while a genuinely unknown prop alongside still trips (and the
        // key lines stay exempt from the report).
        let mixed = KEYED_SIGNED.replace("END:VCARD", "X-CUSTOM:1\r\nEND:VCARD");
        assert_eq!(unknown_vcard_props_except_keys(&[mixed]), vec!["X-CUSTOM"]);
        // The strict guard still trips on key props (only the except-keys
        // path — applied per-card-side at seal time — exempts them).
        assert!(has_unknown_vcard_props(&[KEYED_SIGNED.to_string()]));
    }

    #[test]
    fn test_render_key_groups_regroups_and_drops() {
        let groups = extract_key_groups(KEYED_SIGNED);
        // Rebuilt numbering differs (emails reordered): groups follow the
        // address, bodies byte-identical.
        let mut map = std::collections::HashMap::new();
        map.insert("plain@example.com".to_string(), "item1".to_string());
        map.insert("kept@example.com".to_string(), "item2".to_string());
        let rendered = render_key_groups(&groups, &map);
        assert_eq!(rendered.len(), 3);
        assert!(rendered.iter().any(|l| l == "item2.KEY:data:;base64,QUJD"));
        assert!(rendered.iter().any(|l| l == "item2.X-PM-SIGN:true"));
        assert!(!rendered.iter().any(|l| l.starts_with("item1.KEY")));
        // Address deleted from the phone snapshot → group dropped.
        let mut dropped = std::collections::HashMap::new();
        dropped.insert("plain@example.com".to_string(), "item1".to_string());
        assert!(render_key_groups(&groups, &dropped).is_empty());
        // Case-insensitive email match (mixed-case web exports).
        let mut upper = std::collections::HashMap::new();
        upper.insert("KEPT@example.com".to_string(), "item1".to_string());
        assert_eq!(render_key_groups(&groups, &upper).len(), 3);
    }

    #[test]
    fn test_append_vcard_lines_folds_and_closes() {
        let (signed, _) = build_vcard(&ParsedContact::default(), "u");
        let long_key = format!("item1.KEY:{}", "Q".repeat(200));
        let out = append_vcard_lines(&signed, &[long_key]);
        assert!(out.contains("UID:u"));
        assert!(out.ends_with("END:VCARD"));
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "overlong: {line}");
        }
        // Empty append is identity (no rebuild churn when nothing carried).
        assert_eq!(append_vcard_lines(&signed, &[]), signed);
    }
}
