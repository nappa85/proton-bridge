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
}
