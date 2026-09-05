use crate::{config::SyncConfig, status::SyncStatus};

use base64::Engine;
use proton_api::{
    decrypt_contact_card, derive_mailbox_password, download_url_photos, parse_vcard, AuthTokens,
    ContactsClient, KeysClient, LoginState, TokenManager, UnlockedKey,
};
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct ProcessedContact {
    id: String,
    uid: String,
    name: String,
    first_name: String,
    last_name: String,
    display_name: String,
    emails: Vec<ProcessedEmail>,
    phones: Vec<ProcessedPhone>,
    addresses: Vec<ProcessedAddress>,
    organization: String,
    title: String,
    role: String,
    notes: Vec<String>,
    birthday: String,
    anniversary: String,
    nickname: String,
    url: String,
    gender: String,
    photos: Vec<String>,
    keys_debug: String,
}

#[derive(Serialize)]
struct ProcessedEmail {
    email: String,
    types: Vec<String>,
}

#[derive(Serialize)]
struct ProcessedPhone {
    number: String,
    types: Vec<String>,
}

#[derive(Serialize)]
struct ProcessedAddress {
    street: String,
    locality: String,
    region: String,
    postal_code: String,
    country: String,
    types: Vec<String>,
}

pub struct SyncEngine {
    config: Arc<Mutex<SyncConfig>>,
    status: Arc<Mutex<SyncStatus>>,
    token_manager: Arc<Mutex<TokenManager>>,
    contacts_client: Option<ContactsClient>,
    access_token: Option<String>,
    uid: Option<String>,
    abort_flag: Arc<Mutex<bool>>,
    contacts_json: Arc<Mutex<Option<String>>>,
    keys_debug: Option<String>,
    derived_passwords: Arc<Mutex<Option<std::collections::HashMap<String, String>>>>,
    decrypt_errors: Arc<Mutex<u32>>,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let mut token_manager = TokenManager::new();
        if let (Some(rt), Some(uid)) = (&config.refresh_token, &config.uid) {
            if !rt.is_empty() && !uid.is_empty() {
                let at = config.access_token.as_deref().unwrap_or("");
                token_manager.restore_tokens(AuthTokens {
                    access_token: at.to_string(),
                    refresh_token: rt.clone(),
                    uid: uid.clone(),
                });
                if !at.is_empty() {
                    token_manager.set_expiry(3600);
                }
            }
        }

        Self {
            config: Arc::new(Mutex::new(config)),
            status: Arc::new(Mutex::new(SyncStatus::default())),
            token_manager: Arc::new(Mutex::new(token_manager)),
            contacts_client: None,
            access_token: None,
            uid: None,
            abort_flag: Arc::new(Mutex::new(false)),
            contacts_json: Arc::new(Mutex::new(None)),
            keys_debug: None,
            derived_passwords: Arc::new(Mutex::new(None)),
            decrypt_errors: Arc::new(Mutex::new(0)),
        }
    }

    pub fn config(&self) -> SyncConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn start_sync(&mut self, config: SyncConfig) {
        *self.config.lock().unwrap() = config;
        *self.abort_flag.lock().unwrap() = false;

        self.run_sync();
    }

    fn run_sync(&mut self) {
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.0,
            total_contacts: 0,
            synced_contacts: 0,
            error: None,
            last_sync: None,
        });

        let config = self.config.lock().unwrap().clone();

        if config.username.is_empty() {
            self.set_status(SyncStatus {
                state: "error".into(),
                error: Some("Username is required".into()),
                ..Default::default()
            });
            return;
        }

        if let Err(e) = self.authenticate(&config) {
            self.set_status(SyncStatus {
                state: "error".into(),
                error: Some(format!("Auth failed: {e}")),
                ..Default::default()
            });
            return;
        }

        if self.should_abort() {
            self.set_status(SyncStatus {
                state: "idle".into(),
                ..Default::default()
            });
            return;
        }

        let unlocked_keys = match self.unlock_keys(&config) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Key unlock failed (will sync without decryption): {e}");
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!(
                        "Key unlock failed: {e} – re-enter credentials in Settings → Proton"
                    )),
                    ..Default::default()
                });
                *self.decrypt_errors.lock().unwrap() = 1;
                return;
            }
        };

        // Notify if no keys could be unlocked but keys were expected – likely password changed or derived map stale
        if unlocked_keys.is_empty() {
            let debug = self.keys_debug.clone().unwrap_or_default();
            // user_keys>0 but total_unlocked==0 indicates failure
            if debug.contains("user_keys=") && !debug.contains("user_keys=0") {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some("Failed to unlock any Proton keys – password changed or new key requires re-authentication. Update credentials in Settings → Proton.".into()),
                    ..Default::default()
                });
                *self.decrypt_errors.lock().unwrap() = 1;
                return;
            }
        }

        match self.fetch_contacts() {
            Ok(contacts) => {
                let total = contacts.len() as u32;

                let mut unlocked_keys_mut = unlocked_keys;
                let keys_debug = self.keys_debug.clone().unwrap_or_default();
                let mut decrypt_err_count: u32 = 0;

                let mut processed: Vec<ProcessedContact> = contacts
                    .iter()
                    .map(|c| {
                        let mut pc = ProcessedContact {
                            id: c.ID.clone(),
                            uid: c.UID.clone(),
                            name: c.Name.clone(),
                            first_name: String::new(),
                            last_name: String::new(),
                            display_name: c.Name.clone(),
                            emails: c
                                .ContactEmails
                                .iter()
                                .map(|e| ProcessedEmail {
                                    email: e.Email.clone(),
                                    types: e.Type.clone(),
                                })
                                .collect(),
                            phones: Vec::new(),
                            addresses: Vec::new(),
                            organization: String::new(),
                            title: String::new(),
                            role: String::new(),
                            notes: Vec::new(),
                            birthday: String::new(),
                            anniversary: String::new(),
                            nickname: String::new(),
                            url: String::new(),
                            gender: String::new(),
                            photos: Vec::new(),
                            keys_debug: keys_debug.clone(),
                        };

                        if let Some(cards) = &c.Cards {
                            for card in cards {
                                let vcard_data = if card.Type == 1 || card.Type == 3 {
                                    match decrypt_contact_card(&card.Data, &mut unlocked_keys_mut) {
                                        Ok(plain) => {
                                            pc.keys_debug = format!(
                                                "{};decrypted_type_{}=ok",
                                                pc.keys_debug, card.Type
                                            );
                                            plain
                                        }
                                        Err(e) => {
                                            pc.keys_debug = format!(
                                                "{};decrypted_type_{}=ERR:{}",
                                                pc.keys_debug, card.Type, e
                                            );
                                            decrypt_err_count += 1;
                                            continue;
                                        }
                                    }
                                } else if card.Type == 0 || card.Type == 2 {
                                    if card.Data.starts_with("BEGIN:VCARD") {
                                        card.Data.clone()
                                    } else if let Ok(decoded) =
                                        base64::engine::general_purpose::STANDARD.decode(&card.Data)
                                    {
                                        String::from_utf8_lossy(&decoded).to_string()
                                    } else {
                                        card.Data.clone()
                                    }
                                } else {
                                    continue;
                                };

                                match parse_vcard(&vcard_data) {
                                    Ok(vc) => {
                                        if !vc.first_name.is_empty() || !vc.last_name.is_empty() {
                                            pc.first_name = vc.first_name;
                                            pc.last_name = vc.last_name;
                                        }
                                        if !vc.display_name.is_empty() {
                                            pc.display_name = vc.display_name;
                                        }
                                        if !vc.emails.is_empty() && pc.emails.is_empty() {
                                            pc.emails = vc
                                                .emails
                                                .into_iter()
                                                .map(|e| ProcessedEmail {
                                                    email: e.email,
                                                    types: e.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.phones.is_empty() {
                                            pc.phones = vc
                                                .phones
                                                .into_iter()
                                                .map(|p| ProcessedPhone {
                                                    number: p.number,
                                                    types: p.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.addresses.is_empty() {
                                            pc.addresses = vc
                                                .addresses
                                                .into_iter()
                                                .map(|a| ProcessedAddress {
                                                    street: a.street,
                                                    locality: a.locality,
                                                    region: a.region,
                                                    postal_code: a.postal_code,
                                                    country: a.country,
                                                    types: a.types,
                                                })
                                                .collect();
                                        }
                                        if !vc.organization.is_empty() {
                                            pc.organization = vc.organization;
                                        }
                                        if !vc.title.is_empty() {
                                            pc.title = vc.title;
                                        }
                                        if !vc.role.is_empty() {
                                            pc.role = vc.role;
                                        }
                                        if !vc.notes.is_empty() {
                                            pc.notes = vc.notes;
                                        }
                                        if !vc.birthday.is_empty() {
                                            pc.birthday = vc.birthday;
                                        }
                                        if !vc.anniversary.is_empty() {
                                            pc.anniversary = vc.anniversary;
                                        }
                                        if !vc.nickname.is_empty() {
                                            pc.nickname = vc.nickname;
                                        }
                                        if !vc.url.is_empty() {
                                            pc.url = vc.url;
                                        }
                                        if !vc.gender.is_empty() {
                                            pc.gender = vc.gender;
                                        }
                                        if !vc.photos.is_empty() {
                                            pc.photos = vc.photos;
                                        }
                                    }
                                    Err(e) => {
                                        pc.keys_debug =
                                            format!("{};parse_vcard_err={}", pc.keys_debug, e);
                                    }
                                }
                            }
                        }

                        pc
                    })
                    .collect();

                for pc in &mut processed {
                    download_url_photos(&mut pc.photos);
                }

                let json = serde_json::to_string(&processed).unwrap_or_else(|_| "[]".into());
                *self.contacts_json.lock().unwrap() = Some(json);
                *self.decrypt_errors.lock().unwrap() = decrypt_err_count;

                if decrypt_err_count > 0 {
                    let debug = self.keys_debug.clone().unwrap_or_default();
                    self.set_status(SyncStatus {
                        state: "error".into(),
                        error: Some(format!(
                            "Decryption failed for {decrypt_err_count} contact(s) – mailbox password changed or new key requires re-authentication. Update credentials in Settings → Proton. Debug: {debug}"
                        )),
                        ..Default::default()
                    });
                    return;
                }

                self.set_status(SyncStatus {
                    state: "complete".into(),
                    progress: 1.0,
                    total_contacts: total,
                    synced_contacts: total,
                    error: None,
                    last_sync: Some(chrono::Utc::now().to_rfc3339()),
                });
            }
            Err(e) => {
                self.set_status(SyncStatus {
                    state: "error".into(),
                    error: Some(format!("Fetch failed: {e}")),
                    ..Default::default()
                });
            }
        }
    }

    fn unlock_keys(
        &mut self,
        config: &SyncConfig,
    ) -> Result<Vec<UnlockedKey>, proton_api::ProtonError> {
        let access_token = match &self.access_token {
            Some(t) => t.clone(),
            None => {
                self.keys_debug = Some("no_access_token".into());
                return Ok(Vec::new());
            }
        };
        let uid = match &self.uid {
            Some(u) => u.clone(),
            None => {
                self.keys_debug = Some("no_uid".into());
                return Ok(Vec::new());
            }
        };

        let keys_client = KeysClient::new(access_token, uid);

        let user = match keys_client.get_user() {
            Ok(u) => u,
            Err(e) => {
                self.keys_debug = Some(format!("get_user_err={e}"));
                return Err(e);
            }
        };
        let salts = match keys_client.get_key_salts() {
            Ok(s) => s,
            Err(e) => {
                self.keys_debug = Some(format!("get_salts_err={e}"));
                return Err(e);
            }
        };
        let addresses = match keys_client.get_addresses() {
            Ok(a) => a,
            Err(e) => {
                self.keys_debug = Some(format!("get_addresses_err={e}"));
                return Err(e);
            }
        };

        let mut unlocked_keys: Vec<UnlockedKey> = Vec::new();
        let mut derived_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut debug_parts: Vec<String> = Vec::new();
        debug_parts.push(format!("user_keys={}", user.Keys.len()));
        debug_parts.push(format!("salts={}", salts.len()));
        debug_parts.push(format!("addrs={}", addresses.len()));
        debug_parts.push(format!("pw_len={}", config.password.len()));
        debug_parts.push(format!(
            "derived_keys={}",
            config
                .derived_passwords
                .as_ref()
                .map(|m| m.len())
                .unwrap_or(0)
        ));

        for key in &user.Keys {
            if key.PrivateKey.is_empty() {
                debug_parts.push(format!("userkey_{}_skip_empty", &key.ID[..8]));
                continue;
            }

            let salt = salts.iter().find(|s| s.ID == key.ID);
            let has_salt = salt.is_some();
            let salt_val = salt
                .and_then(|s| s.KeySalt.as_ref())
                .cloned()
                .unwrap_or_default();
            let salt_len = salt_val.len();

            let passphrase = Self::get_passphrase_for_key(
                &key.ID,
                &config.password,
                config.derived_passwords.as_ref(),
                salt,
                &key.Token,
            );

            match passphrase {
                Some(pp) => {
                    // Remember derived passphrase for storage (only if derived from raw password, not from stored derived)
                    let pp_for_store = if config.password.is_empty() {
                        None
                    } else {
                        Some(pp.clone())
                    };
                    match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                        Ok(unlocked) => {
                            debug_parts.push(format!("userkey_{}_ok", &key.ID[..8]));
                            if let Some(store_pp) = pp_for_store {
                                derived_map.insert(
                                    key.ID.clone(),
                                    base64::engine::general_purpose::STANDARD.encode(&store_pp),
                                );
                            }
                            unlocked_keys.push(unlocked);
                        }
                        Err(e) => {
                            debug_parts.push(format!(
                                "userkey_{}_unlock_err={}_pp_len={}",
                                &key.ID[..8],
                                e,
                                pp.len()
                            ));
                        }
                    }
                }
                None => {
                    debug_parts.push(format!(
                        "userkey_{}_no_passphase_has_salt={}_salt_len={}",
                        &key.ID[..8],
                        has_salt,
                        salt_len
                    ));
                }
            }
        }

        for addr in &addresses {
            for key in &addr.Keys {
                if key.PrivateKey.is_empty() {
                    continue;
                }

                let salt = salts.iter().find(|s| s.ID == key.ID);
                let has_token = !key.Token.is_empty();

                let passphrase = Self::get_passphrase_for_key(
                    &key.ID,
                    &config.password,
                    config.derived_passwords.as_ref(),
                    salt,
                    &key.Token,
                );

                match passphrase {
                    Some(pp) => {
                        let pp_for_store = if config.password.is_empty() {
                            None
                        } else {
                            Some(pp.clone())
                        };
                        match UnlockedKey::from_armored(&key.PrivateKey, &pp) {
                            Ok(unlocked) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_ok_token={}",
                                    &key.ID[..8],
                                    has_token
                                ));
                                if let Some(store_pp) = pp_for_store {
                                    derived_map.insert(
                                        key.ID.clone(),
                                        base64::engine::general_purpose::STANDARD.encode(&store_pp),
                                    );
                                }
                                unlocked_keys.push(unlocked);
                            }
                            Err(e) => {
                                debug_parts.push(format!(
                                    "addrkey_{}_unlock_err={}_token={}",
                                    &key.ID[..8],
                                    e,
                                    has_token
                                ));
                            }
                        }
                    }
                    None => {
                        debug_parts.push(format!(
                            "addrkey_{}_no_pp_token={}",
                            &key.ID[..8],
                            has_token
                        ));
                    }
                }
            }
        }

        debug_parts.push(format!("total_unlocked={}", unlocked_keys.len()));
        self.keys_debug = Some(debug_parts.join(";"));
        if !derived_map.is_empty() {
            *self.derived_passwords.lock().unwrap() = Some(derived_map);
        }
        Ok(unlocked_keys)
    }

    fn get_passphrase_for_key(
        key_id: &str,
        password: &str,
        derived: Option<&std::collections::HashMap<String, String>>,
        salt: Option<&proton_api::KeySalt>,
        token: &str,
    ) -> Option<Vec<u8>> {
        if let Some(map) = derived {
            if let Some(b64) = map.get(key_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    return Some(bytes);
                }
            }
        }
        Self::derive_passphrase(password, salt, token)
    }

    fn derive_passphrase(
        password: &str,
        salt: Option<&proton_api::KeySalt>,
        _token: &str,
    ) -> Option<Vec<u8>> {
        if password.is_empty() {
            return None;
        }
        let salt = salt?;
        let key_salt_str = salt.KeySalt.as_ref()?;

        if key_salt_str.is_empty() {
            return Some(password.as_bytes().to_vec());
        }

        match derive_mailbox_password(password.as_bytes(), key_salt_str) {
            Ok(pp) => Some(pp),
            Err(e) => {
                eprintln!("Failed to derive mailbox password: {e}");
                None
            }
        }
    }

    fn authenticate(&mut self, config: &SyncConfig) -> Result<(), proton_api::ProtonError> {
        let mut tm = self.token_manager.lock().unwrap();

        let has_refresh = tm.refresh_token().is_some() && !tm.refresh_token().unwrap().is_empty();

        if has_refresh {
            match tm.access_token() {
                Ok(token) => {
                    let uid = tm.uid().unwrap_or(&config.username).to_string();
                    drop(tm);
                    self.access_token = Some(token.clone());
                    self.uid = Some(uid.clone());
                    self.contacts_client = Some(ContactsClient::new(token, uid));
                    return Ok(());
                }
                Err(_) => {
                    drop(tm);
                    tm = self.token_manager.lock().unwrap();
                }
            }
        }

        if config.password.is_empty() {
            return Err(proton_api::ProtonError::Auth(
                "No refresh token and no password available".into(),
            ));
        }

        match tm.login(&config.username, &config.password)? {
            LoginState::Authenticated { .. } => {}
            LoginState::Requires2FA {
                access_token,
                refresh_token,
                uid,
                ..
            } => {
                if let Some(code) = &config.totp_code {
                    tm.submit_2fa(code, &access_token, &refresh_token, &uid)?;
                } else {
                    drop(tm);
                    self.set_status(SyncStatus {
                        state: "needs_2fa".into(),
                        error: Some("2FA verification required".into()),
                        ..Default::default()
                    });
                    return Err(proton_api::ProtonError::Auth("2FA_REQUIRED".into()));
                }
            }
        }

        let access_token = tm.access_token()?;
        let uid = tm.uid().unwrap_or(&config.username).to_string();
        drop(tm);

        self.access_token = Some(access_token.clone());
        self.uid = Some(uid.clone());
        self.contacts_client = Some(ContactsClient::new(access_token, uid));
        Ok(())
    }

    fn fetch_contacts(&mut self) -> Result<Vec<proton_api::Contact>, proton_api::ProtonError> {
        let client = self
            .contacts_client
            .as_ref()
            .ok_or(proton_api::ProtonError::Auth("No client".into()))?;

        let contacts = client.list_all()?;

        let total = contacts.len() as u32;
        self.set_status(SyncStatus {
            state: "syncing".into(),
            progress: 0.5,
            total_contacts: total,
            synced_contacts: 0,
            error: None,
            last_sync: None,
        });

        Ok(contacts)
    }

    pub fn abort(&mut self) {
        *self.abort_flag.lock().unwrap() = true;
        self.set_status(SyncStatus {
            state: "idle".into(),
            progress: 0.0,
            ..Default::default()
        });
    }

    pub fn status(&self) -> SyncStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn get_contacts_json(&self) -> String {
        self.contacts_json
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "[]".into())
    }

    pub fn get_refresh_token(&self) -> Option<String> {
        self.token_manager
            .lock()
            .unwrap()
            .refresh_token()
            .map(|s| s.to_string())
    }

    pub fn get_uid(&self) -> Option<String> {
        self.token_manager
            .lock()
            .unwrap()
            .uid()
            .map(|s| s.to_string())
    }

    pub fn get_derived_passwords_json(&self) -> Option<String> {
        let map = self.derived_passwords.lock().unwrap().clone()?;
        serde_json::to_string(&map).ok()
    }

    pub fn get_decrypt_error_count(&self) -> u32 {
        *self.decrypt_errors.lock().unwrap()
    }

    pub fn get_keys_debug(&self) -> Option<String> {
        self.keys_debug.clone()
    }

    fn set_status(&self, status: SyncStatus) {
        *self.status.lock().unwrap() = status;
    }

    fn should_abort(&self) -> bool {
        *self.abort_flag.lock().unwrap()
    }
}
