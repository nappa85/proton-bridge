// Live contacts-upsync wire gate (test account ONLY).
//
// Drives the PRODUCTION `SyncEngine` upload path headlessly:
// SRP login -> TOTP 2FA submit -> scratch contact CREATE -> UPDATE ->
// DELETE, each as its own sync cycle with a fresh engine (planner ->
// seal -> wire -> re-list). Prints only IDs/codes/UIDs, never tokens,
// passwords, or card plaintext.
//
// This validates the fixed request shapes before any phone deploy:
// `Contacts:[{Cards}]` (never bare arrays), `PUT …/delete` (never HTTP
// DELETE), `proton-web-` UIDs, non-empty FN, no PRODID. Any 4xx here is a
// wire-shape rejection to fix locally — NOT a cue to retry blindly.
//
// Usage:
//   PROTON_TEST_PASSWORD='...' cargo run -p proton-sync --example live_contacts_check -- <username> <otp>
use proton_api::{AuthClient, ContactsClient, LoginState};
use proton_sync::{contact_plan::ContactItem, SyncConfig, SyncEngine};
use std::collections::{HashMap, HashSet};

fn login(username: &str, password: &str, otp: &str) -> proton_api::AuthTokens {
    let auth = AuthClient::new();
    match auth.login(username, password) {
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
            auth.submit_2fa(otp, &access_token, &refresh_token, &uid)
                .unwrap_or_else(|e| {
                    eprintln!("submit_2fa failed: {e}");
                    std::process::exit(1);
                })
        }
        Err(e) => {
            eprintln!("login failed: {e}");
            std::process::exit(1);
        }
    }
}

fn base_config(username: &str, password: &str, tokens: &proton_api::AuthTokens) -> SyncConfig {
    SyncConfig {
        username: username.to_string(),
        // In-memory only: derives mailbox passphrases, never persisted.
        password: password.to_string(),
        access_token: Some(tokens.access_token.clone()),
        refresh_token: Some(tokens.refresh_token.clone()),
        uid: Some(tokens.uid.clone()),
        ..Default::default()
    }
}

/// Run one upload cycle; exit non-zero unless the engine completes.
fn run_cycle(tag: &str, config: SyncConfig) -> SyncEngine {
    let mut engine = SyncEngine::new(config.clone());
    engine.start_sync(config);
    let status = engine.status();
    eprintln!(
        "cycle[{tag}] status={} error={:?}",
        status.state, status.error
    );
    if status.state != "complete" {
        if let Some(dbg) = engine.get_keys_debug() {
            eprintln!("cycle[{tag}] keys_debug: {dbg}");
        }
        std::process::exit(1);
    }
    engine
}

fn find_by_fn(client: &ContactsClient, marker: &str) -> Vec<proton_api::Contact> {
    // The list rows carry server-side names; match our unique marker.
    client
        .list_all()
        .unwrap_or_else(|e| {
            eprintln!("list_all failed: {e}");
            std::process::exit(1);
        })
        .into_iter()
        .filter(|c| c.Name.contains(marker))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: live_contacts_check <username> <otp>");
        std::process::exit(2);
    }
    let username = args[1].clone();
    let otp = args[2].clone();
    let password = std::env::var("PROTON_TEST_PASSWORD").unwrap_or_else(|_| {
        eprintln!("PROTON_TEST_PASSWORD env var required");
        std::process::exit(2);
    });

    // Unique marker per run (nanos): the scratch contact is findable and
    // two runs can never mistake each other's rows.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let marker = format!("SailfishProbe{nanos}");
    eprintln!("marker: {marker} (scratch rows only — deleted at the end)");

    let tokens = login(&username, &password, &otp);
    eprintln!("auth OK (tokens withheld from output)");
    let client = ContactsClient::new(tokens.access_token.clone(), tokens.uid.clone());

    // ---- 1. CREATE: phone-only inventory row -> batch POST ----
    let fields = proton_api::ParsedContact {
        display_name: marker.clone(),
        first_name: "Probe".to_string(),
        last_name: marker.clone(),
        emails: vec![proton_api::vcard::ParsedEmail {
            email: format!("{marker}@example.invalid"),
            types: vec!["HOME".to_string()],
        }],
        phones: vec![proton_api::vcard::ParsedPhone {
            number: "+3902000000".to_string(),
            types: vec!["CELL".to_string()],
        }],
        ..Default::default()
    };
    let mut create_cfg = base_config(&username, &password, &tokens);
    create_cfg.contact_inventory = Some(vec![ContactItem {
        qcontact_id: "probe-q1".to_string(),
        proton_uid: None,
        modified: true,
        last_synced_mtime: None,
        fields: Some(fields),
    }]);
    create_cfg.contact_known_uids = Some(HashSet::new());
    create_cfg.contact_anchors = Some(HashMap::new());
    run_cycle("create", create_cfg);

    let rows = find_by_fn(&client, &marker);
    if rows.len() != 1 {
        eprintln!("CREATE GATE FAILED: expected 1 row, found {}", rows.len());
        std::process::exit(1);
    }
    let row = &rows[0];
    eprintln!(
        "created: id={} uid={} mtime={}",
        row.ID, row.UID, row.ModifyTime
    );
    let proton_uid = row.UID.clone();

    // ---- 2. UPDATE: same UID, edited phone snapshot -> PUT ----
    let fields2 = proton_api::ParsedContact {
        display_name: format!("{marker} edited"),
        first_name: "ProbeEdited".to_string(),
        last_name: marker.clone(),
        emails: vec![proton_api::vcard::ParsedEmail {
            email: format!("{marker}@example.invalid"),
            types: vec!["HOME".to_string()],
        }],
        ..Default::default()
    };
    let mut update_cfg = base_config(&username, &password, &tokens);
    update_cfg.contact_inventory = Some(vec![ContactItem {
        qcontact_id: "probe-q1".to_string(),
        proton_uid: Some(proton_uid.clone()),
        modified: true,
        last_synced_mtime: Some(row.ModifyTime),
        fields: Some(fields2),
    }]);
    update_cfg.contact_known_uids = Some([proton_uid.clone()].into_iter().collect());
    let mut anchors = HashMap::new();
    anchors.insert(proton_uid.clone(), row.ModifyTime);
    update_cfg.contact_anchors = Some(anchors);
    run_cycle("update", update_cfg);

    let rows = find_by_fn(&client, "edited");
    if rows.len() != 1 || rows[0].UID != proton_uid {
        eprintln!(
            "UPDATE GATE FAILED: edited row not found (n={})",
            rows.len()
        );
        std::process::exit(1);
    }
    eprintln!("updated: id={} mtime={}", rows[0].ID, rows[0].ModifyTime);

    // ---- 3. DELETE: known UID missing locally -> PUT …/delete ----
    let mut delete_cfg = base_config(&username, &password, &tokens);
    delete_cfg.contact_inventory = Some(Vec::new());
    delete_cfg.contact_known_uids = Some([proton_uid.clone()].into_iter().collect());
    delete_cfg.contact_anchors = Some(HashMap::new());
    run_cycle("delete", delete_cfg);

    let rows = find_by_fn(&client, &marker);
    if !rows.is_empty() {
        eprintln!("DELETE GATE FAILED: {} scratch row(s) survive", rows.len());
        std::process::exit(1);
    }
    eprintln!("deleted: no scratch rows remain — CONTACTS UPSYNC WIRE GATE GREEN");
}
