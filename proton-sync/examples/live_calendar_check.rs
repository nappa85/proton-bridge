// Live verification against the real Proton API (test account ONLY).
//
// Runs the production engine path headlessly: SRP login -> TOTP 2FA submit ->
// Token-aware address unlock -> calendar bootstrap -> windowed event decrypt.
// Read-only: never creates, modifies, prints tokens, or stores the password.
//
// Usage:
//   PROTON_TEST_PASSWORD='...' cargo run -p proton-sync --example live_calendar_check -- <username> <otp>
use proton_api::{AuthClient, LoginState};
use proton_sync::{calendar::CalendarSyncEngine, SyncConfig};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: live_calendar_check <username> <otp>");
        std::process::exit(2);
    }
    let username = args[1].clone();
    let otp = args[2].clone();
    let password = std::env::var("PROTON_TEST_PASSWORD").unwrap_or_else(|_| {
        eprintln!("PROTON_TEST_PASSWORD env var required");
        std::process::exit(2);
    });

    let auth = AuthClient::new();
    let tokens = match auth.login(&username, &password) {
        Ok(LoginState::Authenticated { tokens, .. }) => {
            eprintln!("login: authenticated without 2FA");
            tokens
        }
        Ok(LoginState::Requires2FA {
            access_token,
            refresh_token,
            uid,
            ..
        }) => {
            eprintln!("login: locked session, submitting TOTP...");
            match auth.submit_2fa(&otp, &access_token, &refresh_token, &uid) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("submit_2fa failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("login failed: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("auth OK (tokens withheld from output)");

    if std::env::var("LIVE_SCOPE_PROBE").is_ok() {
        run_scope_probe(
            &auth,
            &tokens.access_token,
            &tokens.refresh_token,
            &tokens.uid,
        );
        // Stop here: the probe's refresh rotates the server-side token,
        // which would 401 the engine run below and muddy the results.
        return;
    }

    if std::env::var("LIVE_DIAG").is_ok() {
        run_diag(&tokens.access_token, &tokens.uid);
    }

    let config = SyncConfig {
        username: username.clone(),
        // In-memory only: derives mailbox passphrases, never persisted.
        password: password.clone(),
        access_token: Some(tokens.access_token),
        refresh_token: Some(tokens.refresh_token),
        uid: Some(tokens.uid),
        ..Default::default()
    };
    let mut engine = CalendarSyncEngine::new(config.clone());
    engine.start_sync(config);
    let status = engine.status();
    eprintln!(
        "engine status: {} total={}",
        status.state, status.total_contacts
    );
    if let Some(err) = status.error {
        eprintln!("engine error: {err}");
    }
    if let Some(dbg) = engine.get_keys_debug() {
        eprintln!("keys_debug: {dbg}");
    }
    /// Diagnostic: dump calendar list + raw envelope shapes (no secrets).
    /// Scope-narrowing probe: compares /settings + key salts on the fresh
    /// post-2FA token vs the refreshed token. Answers whether refresh
    /// drops scopes (e.g. `locked`), which would explain empty settings
    /// and salts 403 on every phone sync (the engines always refresh
    /// first, since restored tokens carry no expiry).
    fn run_scope_probe(
        auth: &proton_api::AuthClient,
        access_token: &str,
        refresh_token: &str,
        uid: &str,
    ) {
        fn probe(tag: &str, access_token: &str, uid: &str) {
            let cal_client =
                proton_api::CalendarClient::new(access_token.to_string(), uid.to_string());
            let cals = cal_client.list_calendars().unwrap_or_default();
            for cal in &cals {
                match cal_client.get_settings_verbose(&cal.ID) {
                    Ok((s, body)) => eprintln!(
                        "scope_probe[{tag}] cal={} settings_empty={}\n{body}",
                        &cal.ID[..8.min(cal.ID.len())],
                        s.is_empty(),
                    ),
                    Err(e) => {
                        let msg = format!("{e}");
                        let short: String = msg.chars().take(80).collect();
                        eprintln!(
                            "scope_probe[{tag}] cal={} settings_err:{short}",
                            &cal.ID[..8.min(cal.ID.len())]
                        );
                    }
                }
            }
            let keys_client =
                proton_api::KeysClient::new(access_token.to_string(), uid.to_string());
            match keys_client.get_key_salts() {
                Ok(salts) => eprintln!("scope_probe[{tag}] salts_ok n={}", salts.len()),
                Err(e) => {
                    let msg = format!("{e}");
                    let short: String = msg.chars().take(80).collect();
                    eprintln!("scope_probe[{tag}] salts_err:{short}");
                }
            }
        }
        probe("fresh", access_token, uid);
        match auth.refresh_verbose(refresh_token, uid) {
            Ok((new_tokens, scope, scopes)) => {
                eprintln!("scope_probe[refresh] Scope={scope:?} Scopes={scopes:?}");
                probe("refreshed", &new_tokens.access_token, &new_tokens.uid);
            }
            Err(e) => eprintln!("scope_probe[refresh] failed: {e}"),
        }
    }
    fn run_diag(access_token: &str, uid: &str) {
        eprintln!(
            "diag token={} uid={uid}",
            &access_token[..6.min(access_token.len())]
        );
        let client = proton_api::CalendarClient::new(access_token.to_string(), uid.to_string());
        let cals = client.list_calendars().unwrap_or_default();
        eprintln!("diag calendars: {}", cals.len());
        for cal in &cals {
            eprintln!(
                "diag cal id={} name={:?} type={} flags={}",
                &cal.ID[..8.min(cal.ID.len())],
                cal.Name,
                cal.Type,
                cal.Flags
            );
            let end = chrono::Utc::now().timestamp() + 365 * 24 * 3600;
            // Param-combo probe on the first calendar only: pinpoints 400 causes.
            if cal.ID == cals.first().map(|c| c.ID.clone()).unwrap_or_default() {
                // Span probe: same Type=0 + Timezone=UTC query, only the span
                // varies (end fixed where a row is known to live). Finds the
                // real server window cap (93d returns empty, 30d returns rows).
                for span_days in [7u32, 14, 31, 62, 91, 93] {
                    let span = i64::from(span_days) * 86400;
                    let params = vec![
                        ("Type", "0".into()),
                        ("Start", (end - span).to_string()),
                        ("End", end.to_string()),
                        ("Timezone", "UTC".into()),
                        ("Page", "0".into()),
                        ("PageSize", "100".into()),
                    ];
                    match client.fetch_events_raw(&cal.ID, &params) {
                        Ok((st, body)) => {
                            let v: serde_json::Value =
                                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                            let n = v
                                .get("Events")
                                .and_then(|e| e.as_array())
                                .map_or(0, Vec::len);
                            eprintln!(
                                "diag spanprobe {span_days}d: {st} rows={n} Code={}",
                                v.get("Code").map_or("?".into(), |m| m.to_string())
                            );
                        }
                        Err(e) => {
                            eprintln!("diag spanprobe {span_days}d TRANSPORT-ERROR: {e}");
                        }
                    }
                }
            }
            for t in 0..4 {
                // Same 7d window as the spanprobe: head-to-head comparison of
                // fetch_events_page_raw (engine path) vs fetch_events_raw.
                match client.fetch_events_page_raw(&cal.ID, t, end - 7 * 86400, end, 0, "UTC") {
                    Ok(v) => {
                        let keys: Vec<&String> =
                            v.as_object().map_or(Vec::new(), |m| m.keys().collect());
                        let n = v
                            .get("Events")
                            .and_then(|e| e.as_array())
                            .map_or(0, Vec::len);
                        eprintln!(
                            "diag cal={} type={t} keys={keys:?} events={n} More={} Total={}",
                            &cal.ID[..8.min(cal.ID.len())],
                            v.get("More").map_or("?".into(), |m| m.to_string()),
                            v.get("Total").map_or("?".into(), |m| m.to_string())
                        );
                        if let Some(first) = v
                            .get("Events")
                            .and_then(|e| e.as_array())
                            .and_then(|a| a.first())
                        {
                            let fkeys: Vec<&String> =
                                first.as_object().map_or(Vec::new(), |m| m.keys().collect());
                            eprintln!("diag first event keys={fkeys:?} StartTime={} SharedEvents={} CalendarEvents={}",
                            first.get("StartTime").map_or("?".into(), |m| m.to_string()),
                            first.get("SharedEvents").and_then(|e| e.as_array()).map_or(0, Vec::len),
                            first.get("CalendarEvents").and_then(|e| e.as_array()).map_or(0, Vec::len));
                        }
                    }
                    Err(e) => eprintln!(
                        "diag cal={} type={t} ERROR: {e}",
                        &cal.ID[..8.min(cal.ID.len())]
                    ),
                }
            }
        }
        // Bootstrap settings + per-event raw Notifications (reminder forensics).
        if std::env::var("LIVE_CALSET").is_ok() {
            for cal in &cals {
                match client.get_bootstrap(&cal.ID) {
                    Ok(b) => eprintln!(
                        "diag bootstrap cal={} settings={}",
                        &cal.ID[..8.min(cal.ID.len())],
                        serde_json::to_value(&b.Settings).unwrap_or_default()
                    ),
                    Err(e) => eprintln!(
                        "diag bootstrap cal={} ERROR: {e}",
                        &cal.ID[..8.min(cal.ID.len())]
                    ),
                }
                match client.fetch_settings_raw(&cal.ID) {
                    Ok((v, st)) => {
                        let snippet: String = v.to_string().chars().take(400).collect();
                        eprintln!(
                            "diag v1settings cal={} status={st} {snippet}",
                            &cal.ID[..8.min(cal.ID.len())]
                        );
                    }
                    Err(e) => eprintln!("diag v1settings TRANSPORT-ERROR: {e}"),
                }
            }
            match client.fetch_account_calendar_settings_raw() {
                Ok((v, st)) => {
                    let snippet: String = v.to_string().chars().take(600).collect();
                    eprintln!("diag acctsettings status={st} {snippet}");
                }
                Err(e) => eprintln!("diag acctsettings TRANSPORT-ERROR: {e}"),
            }
            for cal in &cals {
                let rows = client
                    .list_all_events_untyped(
                        &cal.ID,
                        chrono::Utc::now().timestamp() - 365 * 24 * 3600,
                        chrono::Utc::now().timestamp() + 365 * 24 * 3600,
                    )
                    .unwrap_or_default();
                for ev in &rows {
                    let v = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
                    eprintln!(
                        "diag row cal={} uid={} notif={} fullday={}",
                        &cal.ID[..8.min(cal.ID.len())],
                        v.get("UID").and_then(|u| u.as_str()).unwrap_or("?"),
                        v.get("Notifications").map_or("?".into(), |n| n.to_string()),
                        v.get("FullDay").map_or("?".into(), |n| n.to_string()),
                    );
                }
            }
        }
        if let Ok(want) = std::env::var("LIVE_DUMP_UID") {
            for pass in 0..3 {
                if pass > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                for cal in &cals {
                    let rows = client
                        .list_all_events_untyped(
                            &cal.ID,
                            chrono::Utc::now().timestamp() - 365 * 24 * 3600,
                            chrono::Utc::now().timestamp() + 365 * 24 * 3600,
                        )
                        .unwrap_or_default();
                    for ev in &rows {
                        let v = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
                        let uid = v.get("UID").and_then(|u| u.as_str()).unwrap_or("");
                        if uid.contains(want.as_str()) {
                            println!(
                                "DUMP pass={pass} cal={} {v}",
                                &cal.ID[..8.min(cal.ID.len())]
                            );
                        }
                    }
                }
            }
        }
        for cal2 in &cals {
            let mut page = 0u32;
            let mut total_rows = 0usize;
            loop {
                let params = vec![("Page", page.to_string()), ("PageSize", "100".into())];
                match client.fetch_events_raw(&cal2.ID, &params) {
                    Ok((st, body)) => {
                        let v: serde_json::Value =
                            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                        let n = v
                            .get("Events")
                            .and_then(|e| e.as_array())
                            .map_or(0, Vec::len);
                        total_rows += n;
                        let more = v.get("More").and_then(|m| m.as_i64()).unwrap_or(0) != 0
                            || v.get("More").and_then(|m| m.as_bool()).unwrap_or(false);
                        eprintln!(
                            "diag untyped-all cal={} page={page} status={st} rows={n} more={more}",
                            cal2.ID
                        );
                        if page == 0 {
                            if let Some(first) = v
                                .get("Events")
                                .and_then(|e| e.as_array())
                                .and_then(|a| a.first())
                            {
                                eprintln!(
                                    "diag first row StartTime={} EndTime={} RRule={} UID={}",
                                    first.get("StartTime").map_or("?".into(), |m| m.to_string()),
                                    first.get("EndTime").map_or("?".into(), |m| m.to_string()),
                                    first.get("RRule").map_or("?".into(), |m| m.to_string()),
                                    first.get("UID").map_or("?".into(), |m| m.to_string()),
                                );
                            }
                            eprintln!(
                                "diag window start={} end={} now={}",
                                chrono::Utc::now().timestamp() - 365 * 24 * 3600,
                                chrono::Utc::now().timestamp() + 365 * 24 * 3600,
                                chrono::Utc::now().timestamp()
                            );
                        }
                        if !more || page > 20 {
                            break;
                        }
                        page += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "diag untyped-all cal={} TRANSPORT-ERROR: {e}",
                            &cal2.ID[..8.min(cal2.ID.len())]
                        );
                        break;
                    }
                }
            }
            eprintln!("diag untyped-all cal={} TOTAL={total_rows}", cal2.ID);
        }
        // Repeat-read experiment: 12 IDENTICAL untyped p0 reads spaced 5s apart
        // with epoch timestamps. Rows appearing late => session-age/count
        // healing (engine fix = delayed retry); rows immediately => cold works.
        if let Some(first) = cals.first() {
            for i in 0..12 {
                if i > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                let params = vec![("Page", "0".into()), ("PageSize", "100".into())];
                match client.fetch_events_raw(&first.ID, &params) {
                    Ok((st, body)) => {
                        let v: serde_json::Value =
                            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                        let n = v
                            .get("Events")
                            .and_then(|e| e.as_array())
                            .map_or(0, Vec::len);
                        eprintln!(
                            "diag repeat iter={i} t={} status={st} rows={n}",
                            chrono::Utc::now().timestamp()
                        );
                        if n > 0 {
                            break;
                        }
                    }
                    Err(e) => eprintln!("diag repeat iter={i} TRANSPORT-ERROR: {e}"),
                }
            }
        }
    }
    let json: Vec<serde_json::Value> =
        serde_json::from_str(&engine.get_events_json()).unwrap_or_default();
    eprintln!("decrypted events: {}", json.len());
    for ev in &json {
        let s = |k: &str| ev.get(k).and_then(|v| v.as_str()).unwrap_or("?");
        let attendees = ev
            .get("attendees")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        println!(
            "- {} | {} | {} -> {} | rrule={} exdates={} attendees={} cal={} rid={} tz={}/{}",
            s("uid"),
            s("summary"),
            s("dtstart"),
            s("dtend"),
            s("rrule"),
            ev.get("exdates")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len),
            attendees,
            s("calendar_name"),
            ev.get("recurrence_id")
                .map_or("?".into(), |m| m.to_string()),
            s("start_timezone"),
            s("end_timezone"),
        );
    }
}
