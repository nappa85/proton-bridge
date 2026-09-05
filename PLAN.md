# SailfishOS Proton Contacts Sync Plugin

Native SailfishOS Buteo sync plugin for Proton Contacts, using a Rust sync engine + C++ Qt plugin shim with PGP decryption of encrypted contact cards.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Buteo/msyncd                               │
│  ┌─────────────────────────────────────────┐ │
│  │  proton_bridge_shim.cpp (C++ Qt plugin)  │ │
│  │  - SignOn credentials                   │ │
│  │  - QContactManager CRUD                 │ │
│  │  - Phone/address/email type mapping      │ │
│  │  - Per-account collections               │ │
│  └────────────┬────────────────────────────┘ │
│               │ JSON over FFI                │
│  ┌────────────▼────────────────────────────┐ │
│  │  libproton-client.so (Rust staticlib)    │ │
│  │  proton-api: SRP auth, contacts API,     │ │
│  │              PGP decrypt, vCard parse    │ │
│  │  proton-sync: SyncEngine orchestration   │ │
│  └─────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

## What Works

- SRP authentication with v4 endpoints (`/core/v4/auth/info`, `/core/v4/auth`, `/auth/v4/refresh`) + `is_totp_required` handling `Enabled=1/3` (go-proton-api `TwoFAStatus`)
- TOTP 2FA during account creation (`proton.qml` custom `AccountCreationAgent`) and credentials update (`proton-update.qml` `AccountCredentialsAgent`): OTP collected **in-page** (`TextField`), not via `signon-ui` `InProcessEntryView` (SIGSEGV on this SFOS). SignOn `proton` plugin does SRP → `TwoFARequired` + locked tokens, QML shows OTP, `updateSignInCredentials` with `TwoFactorPassword` + locked `AccessToken`/`RefreshToken`/`Uid` + transient `Password` → `POST /auth/v4/2fa` scope upgrade → `derive_all_passwords` → `store(tokens+DerivedPasswords)` + `QSettings` fallback
- Token + derived persistence: `RefreshToken`/`Uid`/`AccessToken` + `DerivedPasswords` (`keyID→base64`) stored in `signond` blob (`STORE` `identity_id=…` + `signond` `storeData`) and `QSettings("proton","sync-tokens")` `[<Uid>]`/`[<username>]` + `Healing CredentialsId` for `variant type double` QML bug; sync runs `NoUserInteractionPolicy` refresh → `pw_len=0` but `derived_len=139` → `total_unlocked=1`
- Contact fetching: list v4 → individual GET per contact → full Cards data
- PGP decryption of Type 3 (encrypted) contact cards using `sequoia-openpgp`
- vCard parsing with `ical_vcard` (handles `ITEM1.EMAIL` groups, `PREF` params, etc.)
- vCard escape sequence unescaping (`\,` → `,`, `\n` → newline, etc.)
- URL-based photo download → data URI conversion
- All contact fields: name, phones with types (Mobile/Home/Work), emails with contexts, addresses with contexts, birthday, anniversary, gender, org/title/role, notes, nickname, URL, photos
- Per-account QContactCollection (supports multiple Proton accounts)
- Full replacement sync (clear old → save new) prevents duplicate contacts on re-sync
- QtContacts type mapping: phone SubTypes (Mobile, Fax, etc.), phone/email/address Contexts (Home, Work)

## Build & Deploy

```bash
# Build (requires Docker: proton-build-env + coderus/sailfishos-platform-sdk-aarch64)
./make-pkg-bundle.sh

# Deploy to phone (scp fails; copy manually)
cp /tmp/libproton-client.so /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so
chmod 755 /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so

# Sync
rm -f /home/defaultuser/.config/proton/sync-tokens.conf
systemctl --user restart msyncd
sleep 2
dbus-send --session --type=method_call --dest=com.meego.msyncd /synchronizer com.meego.msyncd.startSync string:"proton.Contacts-<accountid>"
```

## 2FA / OTP Design (implemented — raw password never persisted)

```
Account creation (proton.qml, custom AccountCreationAgent, OTP in-page):
  Page collects username/password → _pendingUsername/_pendingPassword
    → AccountManager.createAccount("proton") → creationAccount.identifier = id
    → creationAccount.onStatusChanged(Initialized) → signInParameters("proton-carddav", user, "x")
         + sip.setParameter("Password", _pendingPassword)  // transient, not Secret
         → Account.createSignInCredentials("Jolla","Jolla", sip, "")  // Secret="x" dummy, symmetricKey=""
        signond → proton plugin process(hasPasswordParam=true, pw_len=20):
          2FA? → userActionRequired path is NOT used (SIGSEGV in InProcessEntryView on this SFOS)
                 instead plugin returns TwoFARequired + locked tokens (store NOT called)
                 QML shows OTP TextField, user enters 6-digit code → updateSignInCredentials("Jolla","Jolla", sip+TwoFactorPassword+lockedTokens)
                 signond → process(totp+lockedTokens, Password=20) → POST /auth/v4/2fa (scope upgrade, no new tokens)
                 handleAuthOk → derive_all_passwords(Password, AccessToken, Uid) → tokens+DerivedPasswords → store(tokens+DerivedPasswords) + QSettings("proton","sync-tokens") [Uid]/[username] → result(UserName+tokens+DerivedPasswords, no Secret)
    → onSignInCredentialsUpdated → _setCredentialsId(string) for ""+service "CredentialsId" (parseInt+string, not double) → sync() → accountCreated → goToEndDestination()

Credentials update (proton-update.qml, AccountCredentialsAgent):
  Same Password-transient + hasFreshPassword guard in proton_signon_plugin.cpp:process
  (skips blind refresh when Password present, forces SRP → TwoFARequired → OTP)

Sync (buteo OOPP, proton_bridge_shim.cpp, NoUserInteractionPolicy):
  requestCredentials → signond merges stored RefreshToken/Uid/DerivedPasswords blob
  (signond strips Secret; DerivedPasswords may be filtered, so shim falls back to QSettings by m_accountId → Uid → username)
  → plugin does POST /auth/v4/refresh → handleAuthOk (no Secret, Password via fallback) → SyncEngine with pw_len=0, derived_len=139 → unlock_keys via DerivedPasswords cache (QSettings) → contacts
```

* Raw 20-char login password is **only** the transient `Password` param for `derive_all_passwords` at `Verify`; `Secret` in `signond` stays dummy `"x"` (`signon-secrets.db` `CREDENTIALS` `password` column is `"x"`), `handleAuthOk` never `emit result(Secret)`.
* `QSettings("proton","sync-tokens")` holds `[<Uid>]` + `[<username>]` `derived_passwords` JSON (`keyID → base64(mailboxPassword)`) for `engine.rs` `get_passphrase_for_key` fallback.
* `delayDeletion` + `goToEndDestination()` (not `pop`) prevents double-pop to provider picker; `Qt.callLater` replaced by direct `forceActiveFocus()` (Qt 5.6 has no `callLater`).

## Known Issues / TODO

- **Token-based address keys**: Address keys with non-empty `Token` field can't be decrypted yet — contacts using those keys won't sync (shows `addrkey_…_no_pp_token=true` in `Keys debug`)
- **Two-way sync**: Currently download-only (Proton → phone). No upload of local changes
- **Incremental sync**: No sync token support; full fetch every time
- **Contact dedup**: No duplicate detection across Proton + local contacts
- **Multiple photos**: People app only supports one avatar; only first photo is used
- **Password never persisted** (intentional): raw 20-char login password is transient `Password` param only for `derive_all_passwords` at `Verify`; `signon-secrets.db` `CREDENTIALS.password` stays dummy `"x"`, `handleAuthOk` never returns `Secret`. New `KeySalt` after manual Proton key rotation will need one more **Update credentials → OTP** to re-derive and re-store `DerivedPasswords`.

## Key Technical Details

- Rust uses `aarch64-unknown-linux-gnu` target (NOT musl) — musl embeds its own libc, crashing the oopp-runner
- User-Agent MUST be `curl/8.0` on all reqwest clients — Proton rejects reqwest's default
- `APP_VERSION` must be `web-mail@6.3.2` — `other@1.0.0` triggers CAPTCHA/abuse detection
- Auth endpoint URLs MUST use v4 paths, including `/auth/v4/refresh` (legacy paths produce tokens lacking scopes)
- SDK sysroot glibc 2.35, phone has 2.41 — compatible (forward-compatible glibc)
- `devel-su` doesn't work from SSH — user must run root commands on phone terminal directly
- `journalctl` needs root on this phone (volatile journal); signond debug logging enabled via `LoggingLevel=2` in `/etc/signond.conf`

## Proton 2FA (TOTP) — Verified API Behavior

Empirically verified against the live API with a TOTP-enabled account
(reference implementation: ProtonMail/go-proton-api `auth.go`, `manager_auth.go`,
`manager_auth_types.go`):

1. **Login** (`POST /core/v4/auth`): if TOTP is enabled the response still
   contains full `AccessToken` + `RefreshToken`, but with a **locked session**
   scope list: `["self","parent","user","twofactor"]`. The locked token CANNOT
   access `/core/v4/keys/salts` (403, "MissingScopes: full, locked").
2. **2FA submit** (`POST /auth/v4/2fa`, body `{"TwoFactorCode": "123456"}`,
   headers `x-pm-uid` + `Bearer <locked-access-token>`): returns
   `{Code:1000, Scope, Scopes}` — **NO new tokens**. It *upgrades the scopes of
   the existing locked session in place*. Keep using the original
   access/refresh tokens.
   - `/core/v4/auth/2fa` is a WRONG/legacy path: returns 422 `TotpWrong` even
     for valid codes (use `/auth/v4/2fa`).
   - Same code twice → 422 `{"Details":{"LoginFailedReason":"TotpReuse"}}`.
     Wrong code → `TotpWrong`.
3. 2FA detection on the login response: top-level `"2FA": {"Enabled": N,
   "TOTP": 1}` where Enabled: 1=TOTP, 2=FIDO2, 3=both (go-proton-api
   `TwoFAStatus`). A legacy `TwoFactor` object may also appear.
4. `HEAD https://mail.proton.me/` with the Bearer access token returns **200** —
   this is what the stock account-creation credentials verification
   (`AccountAuthenticator.sendAuthenticatedRequest`) relies on.
5. `POST /auth/v4/refresh` works with the login-issued refresh token after 2FA.

## SailfishOS Accounts/SignOn Internals (researched from source + on-device)

Verified against SFOS 5.2 (jolla-settings-accounts 0.6.15,
libsignon-qt5 8.61, sailfish-components-accounts 0.4.9) — sources:
sailfishos/sailfish-components-accounts (account.cpp,
accountauthenticator.cpp), sailfishos-mirror/signond
(signonsessioncore.cpp, pluginproxy.cpp, remotepluginprocess.cpp),
on-device QML dumps of /usr/share/accounts/ui and
com/jolla/settings/accounts.

### Account creation flow (stock OnlineSyncAccountCreationAgent)

1. Dialog (OnlineSyncAccountCreationDialog) collects username/password
   (note: **`skipAuthentication` is NOT an alias on the agent** in 0.6.15,
   only a dialog-internal property — assigning it in a provider .qml crashes
   with "Cannot assign to non-existent property").
2. `AccountFactory.createAccount(provider, service, username, password, ...)`
   creates the account + identity and runs the SignOn session
   (via `Account::createSignInCredentials` → `handleCredentialsStored` →
   `session->process(sessionData, mechanism)`), **UiPolicy defaults to
   DefaultPolicy (UI allowed)** at this stage.
3. `OnlineSyncAccountCreator._completeAccountCreation()` then calls
   `AccountAuthenticator.signIn()` which **forces
   `UiPolicy=NoUserInteractionPolicy`** (accountauthenticator.cpp) and
   validates via `sendAuthenticatedRequest` (HEAD with Bearer token →
   200 OK on mail.proton.me).
4. Any plugin UI request under NoUserInteractionPolicy is rejected by signond
   with `QUERY_ERROR_FORBIDDEN`; a UI request with **no UI service available**
   is rejected with `QUERY_ERROR_NO_SIGNONUI` (code 2).

### The signon UI query path (why dialogs "do nothing")

- signond (`SignonSessionCore::processUiRequest`) calls
  `com.nokia.singlesignonui /SignonUi queryDialog(params)` — but on Sailfish
  the **D-Bus name is never owned by a daemon**. Instead each app that wants
  dialogs embeds `SignonUiService` (QML import
  `com.jolla.signonuiservice 1.0`, from libjollasignonuiservice-qt5) and
  passes in the sign-on session data:
  - `InProcessServiceName` = `signonUiService.inProcessServiceName`
  - `InProcessObjectPath` = `signonUiService.inProcessObjectPath`
  - plus `signonUiService.inProcessParent = <overlay Item>` (the dialog is
    embedded into that item in-process).
  Reference implementation: `OAuthAccountSetupPage.qml` in
  com/jolla/settings/accounts (the OAuth webview flow).
- Without those parameters, every `userActionRequired()` from a plugin fails
  instantly: signond feeds `QueryErrorCode=2 (NO_SIGNONUI)` back to the
  plugin's `userActionFinished()` → **plugins MUST detect the
  `QueryErrorCode` property in that callback and fail cleanly** (re-prompting
  there loops infinitely: plugin → signond → plugin at 100% CPU).
- The jolla-signon-ui "entry view" (extracted from qrc zlib blobs in
  libjollasignonuiservice-qt5.so) is a minimal dialog: Username field,
  Password field, Cancel/Accept buttons. On Accept it returns the entered
  values as `UserName` and `Secret` properties to
  `userActionFinished()`. It shows **both fields regardless of
  QueryUserName/QueryPassword** — for the OTP the user types the code into
  the password ("Secret") field. `Title` becomes the dialog title label.
- signond key constants (lib/plugins/SignOn/uisessiondata_priv.h): the keys
  sent to UI are `Caption`, `Title`, `QueryMessage`, `QueryUserName`,
  `QueryPassword`, `UserName`, `Secret`, `QueryErrorCode`, `UiPolicy`,
  `Identity`, `StoredIdentity`, `Method`, `Mechanism`, `ClientData`...
  (a `Query2fa`/`2fa`/`2faText` triple exists in the header but is NOT
  consumed by this signon-ui build — don't rely on it).
- SignOn `store()` semantics: signond persists every map property EXCEPT
  `UserName`, `Secret`, `AccessControlTokens` into a per-identity,
  per-method **blob store** (`credentialsdb loadData/storeData`). On the next
  session the stored map is merged into the plugin input. This is how
  tokens (AccessToken/RefreshToken/Uid) persist without the password.
  The password itself lives only in the identity secret (signond DB).
- `Account::signIn()` (used by the buteo plugin for verification) reads
  credentials via the identity; the buteo sync plugin must set
  `UiPolicy=NoUserInteractionPolicy` in its session data so sync never pops
  dialogs — with a valid RefreshToken blob the plugin refreshes headlessly.
- Plugin loading: signond runs each plugin in `signonpluginprocess`
  (remotepluginprocess.cpp), type from `libprotonplugin.so` JSON
  `{"Type": "proton"}` in /usr/lib64/signon/.
- QML ids are **not** properties of enclosing objects: `dialog.someId` is
  undefined; reference ids lexically (`someId`), or the assignment crashes
  with `Cannot assign [undefined] to QQuickItem*`.

### Where each piece lives on the phone

- `/usr/lib64/signon/libprotonplugin.so` — SignOn auth plugin (method "proton")
- `/usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so` — Buteo sync plugin
- `/usr/share/accounts/ui/proton.qml` — creation agent
- `/usr/share/accounts/ui/proton-update.qml` — credentials update agent
- `/usr/share/accounts/ui/proton-settings.qml` — settings agent
- `/usr/share/accounts/providers/proton.provider`, `/usr/share/accounts/services/proton-carddav.service`
- `/etc/buteo/profiles/client/proton.xml`, `/etc/buteo/profiles/sync/proton-carddav.xml`
- `signond` restarts on demand (D-Bus activation); after replacing the
  plugin `pkill -9 -x signond` (it auto-respawns).

## Source Layout

```
proton-api/       — Pure Rust Proton API client
  auth.rs           SRP auth + is_totp_required(1/3) + submit_2fa(/auth/v4/2fa) + TokenManager
  crypto.rs         derive_mailbox_password(), decrypt_contact_card(), UnlockedKey
  keys.rs           KeysClient + derive_all_passwords() → DerivedPasswords JSON
  contacts.rs       Contacts list/get API
  models.rs         Contact, ContactCard, UserKey, etc.
  vcard.rs          ical_vcard parser + download_url_photos()

proton-sync/      — Sync engine orchestration
  engine.rs         SyncEngine: auth (refresh) → unlock_keys via DerivedPasswords cache (QSettings) → fetch → parse → JSON

proton-bridge/    — Rust FFI + C++ plugins
  src/auth.rs       FFI proton_auth_login/submit_2fa/refresh/derive_passwords
  src/bridge.rs     FFI proton_bridge_* (SyncEngine JSON, status, tokens, derived)
  signon/proton_signon_plugin.{h,cpp}  SignOn "proton" plugin: process(Password transient) → handleAuthOk(derive → store DerivedPasswords)
  cxx/proton_bridge_shim.{h,cpp}      Buteo OOPP plugin: requestCredentials(NoUserInteraction) + QSettings fallback by Uid/username, pollStatus Keys debug

ui/               — QML
  proton.qml                 AccountCreationAgent (custom, _pendingUsername/_pendingPassword, TwoFARequired OTP TextField, _setCredentialsId string, goToEndDestination)
  proton-update.qml          AccountCredentialsAgent (same Password transient + hasFreshPassword guard)
  proton-settings.qml        OnlineSyncAccountSettingsAgent

buteo-profiles/   — Buteo sync profile XMLs (proton / proton-carddav-*.xml)
accounts/         — Accounts&SSO provider/service XML (proton.provider, proton-carddav.service)
rpm/              — RPM spec files
FINDINGS_OTP.md   — Full OTP failure post-mortem (delayDeletion, double CredentialsId, Secret stripping, pw_len=0 → derived)
```
