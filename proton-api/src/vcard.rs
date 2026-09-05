use std::io::BufReader;

#[derive(Debug, Clone, Default)]
pub struct ParsedContact {
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub emails: Vec<ParsedEmail>,
    pub phones: Vec<ParsedPhone>,
    pub addresses: Vec<ParsedAddress>,
    pub organization: String,
    pub title: String,
    pub role: String,
    pub notes: Vec<String>,
    pub url: String,
    pub birthday: String,
    pub anniversary: String,
    pub nickname: String,
    pub gender: String,
    pub photos: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedEmail {
    pub email: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPhone {
    pub number: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedAddress {
    pub street: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
    pub types: Vec<String>,
}

fn get_param_values<'a>(cl: &'a ical_vcard::Contentline, param_name: &str) -> Vec<String> {
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
            "FN" => {
                if contact.display_name.is_empty() {
                    contact.display_name = value;
                }
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
            "ORG" => {
                if contact.organization.is_empty() {
                    contact.organization = value;
                }
            }
            "TITLE" => {
                if contact.title.is_empty() {
                    contact.title = value;
                }
            }
            "ROLE" => {
                if contact.role.is_empty() {
                    contact.role = value;
                }
            }
            "NOTE" => {
                contact.notes.push(value);
            }
            "URL" => {
                if contact.url.is_empty() {
                    contact.url = value;
                }
            }
            "BDAY" => {
                if contact.birthday.is_empty() {
                    contact.birthday = format_bday(value);
                }
            }
            "ANNIVERSARY" | "X-ANNIVERSARY" => {
                if contact.anniversary.is_empty() {
                    contact.anniversary = format_bday(value);
                }
            }
            "NICKNAME" => {
                if contact.nickname.is_empty() {
                    contact.nickname = value;
                }
            }
            "GENDER" => {
                if contact.gender.is_empty() {
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
            }
            "PHOTO" | "LOGO" => {
                if value.starts_with("data:")
                    || value.starts_with("http://")
                    || value.starts_with("https://")
                {
                    contact.photos.push(value);
                } else if !value.is_empty() {
                    contact.photos.push(value);
                }
            }
            _ => {}
        }
    }

    Ok(contact)
}

pub fn download_url_photos(photos: &mut Vec<String>) {
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

pub fn format_bday(raw: String) -> String {
    if raw.len() == 8 && raw.chars().all(|c| c.is_ascii_digit()) {
        format!("{}-{}-{}", &raw[0..4], &raw[4..6], &raw[6..8])
    } else {
        raw
    }
}
