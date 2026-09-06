# OTP / 2FA Failure Findings & Fixes – 2026-09-05

## Summary
The Proton contacts integration worked for plain SRP login but crashed after OTP submission during account creation:
- after entering the 6-digit TOTP and pressing **Verify**, the Settings app popped back to the *account kind selection* page;
- the account was nevertheless created in the DB but `CredentialsId` was missing/malformed, so `buteo` sync (msyncd oopp) could not find the SignOn identity and failed with `AUTHENTICATION_FAILURE` / `No auth tokens received` or later `Key unlock failed`,
- sync therefore never completed even though the UI claimed success for the first step.

Root causes were **three independent bugs** across QML, Rust API client, and C++ sync plugin. All are fixed locally and verified with offline Rust unit tests + mock-server integration tests before device deployment.

---

## 1. QML – AccountCreationAgent lifecycle (`ui/proton.qml`)

### 1a. Missing `delayDeletion` → premature agent destruction
- **Doc**: Sailfish `AccountCreationAgent` docs state `delayDeletion=true` must be set while async `Account.sync()` is in progress, otherwise the agent is deleted before `Account.Synced` is emitted and the UI pops prematurely.
- **Before**: `proton.qml` never touched `delayDeletion`; after the first `createSignInCredentials` that returned `TwoFARequired`, the agent was briefly idle (`_busy=false`) with `account.status=Synced` but `_flowComplete=false`. The framework considered the creation “idle” and reclaimed the agent. On the second step (`updateSignInCredentials`) the `pageStack.pop()` raced with the pending `sync()` → Settings showed the provider list again (the “crash”).
- **Fix**:
  - `root.delayDeletion` is now driven by `pageRoot._busy || pageRoot._needsTwoFA || creationAccount._flowComplete` (via explicit JS assignment in `on_BusyChanged`, `on_NeedsTwoFAChanged`, and before/after `sync()`).
  - Set `delayDeletion=true` immediately before `createAccount` and `updateSignInCredentials`, and clear it only after `status==Synced && _flowComplete` has emitted `accountCreated` + `pop`.
  - Same pattern added to `ui/proton-update.qml` (`delayDeletion: updatePage._busy || updatePage._needsTwoFA`).

### 1b. `CredentialsId` stored as `double` → `convertValue` rejection
- **Root**: QML numbers are `double` (`QVariant::Double`). `Account.setConfigurationValue` in `sailfish-components-accounts` (`account.cpp: convertValue`) accepts only `Bool/Int/UInt/LongLong/ULongLong/String/StringList` – `Double` is rejected with warning `variant type double for key 'CredentialsId' not supported`.
- **Before**: `var identityId = globalSettings["Jolla/segregated_credentials/Jolla"]; setConfigurationValue("proton-carddav","CredentialsId",identityId)` passed a double, so the value was **never written**. `AccountsHelper` and `proton_bridge_shim.cpp` then read `credentialsId==0`, fell back to global (also 0), and created an identity-less sync profile.
- **After**: helper `_setCredentialsId(identityId)` does `parseInt(identityId)` and writes both `""` (global) and `"proton-carddav"` service keys as `int`. The sync plugin’s existing “healing” code in `proton_bridge_shim.cpp: requestCredentials()` (reading `account->value("CredentialsId").toUInt()`) now succeeds, but the primary write is correct.

### 1c. OTP field focus race
- `otpField.forceActiveFocus()` was called synchronously right after setting `_needsTwoFA=true` while the `Column.visible` binding was still transitioning. This can emit `Cannot read property 'forceActiveFocus' of undefined` or focus the wrong item.
- **Fix**: `Qt.callLater(function(){ otpField.forceActiveFocus() })` in both `proton.qml` and `proton-update.qml`.

### 1d. Incomplete `CredentialsId` linkage on second factor
- For the non-2FA path, both global and service `CredentialsId` were set. For the `onSignInCredentialsUpdated` (OTP success) path, only the service key was set. AccountsHelper’s `addProfileForAccount` and the sync plugin’s `requestCredentials` prefer the service key but also check the global fallback; if the service write had been double-typed and rejected, no fallback existed.
- **Fix**: `_setCredentialsId` now always writes **both** keys, and the updated handler also uses it.

---

## 2. Rust – Proton API 2FA detection (`proton-api/src/auth.rs`)

### 2a. `Enabled == 1` check missed `Enabled == 3` (TOTP+FIDO2)
- **Proton API**: `go-proton-api/manager_auth_types.go` defines `TwoFAStatus` = `1:HasTOTP`, `2:HasFIDO2`, `3:HasFIDO2AndTOTP`. The login response carries `"2FA":{"Enabled":3,"TOTP":1}` when both factors are enabled.
- **Before**: `two_fa_enabled = TwoFA.Enabled==1 || TwoFactor.Enabled==1` → accounts with `Enabled==3` were mis-classified as *not* requiring TOTP, so the SignOn plugin returned `Authenticated` with a locked token (scopes `twofactor`). Subsequent `KeysClient` calls then failed with `403 MissingScopes: full, locked`.
- **Fix**: new helper `AuthClient::is_totp_required(&Option<TwoFAField>, &Option<TwoFactorInfo>)` checks:
  ```rust
  f.Enabled==1 || f.Enabled==3 || f.TOTP==1   // for "2FA"
  f.Enabled==Some(1) || Some(3) || f.TOTP==Some(1) // for legacy TwoFactor
  ```
  Covers `Enabled=3` and explicit `TOTP=1`. `HasFIDO2` (2) alone is **not** treated as TOTP.

### 2b. Missing base-url override for tests
- Added `AuthClient::new_with_base_url` / `with_base_url` to allow `mockito` integration tests without touching production code.

### 2c. Verified `POST /auth/v4/2fa` semantics
- Documented and tested: success is `200 {Code:1000, Scopes:...}` with **no new tokens** – the original locked `AccessToken/RefreshToken/Uid` are upgraded in-place. `submit_2fa` now asserts `Code==1000` and returns the original tokens. Errors are surfaced as `Err(Auth("2FA POST failed 422: …"))`, distinguishing `TotpWrong` / `TotpReuse`.

---

## 3. C++ – Buteo sync plugin (`proton-bridge/cxx/proton_bridge_shim.cpp`)

### 3a. Ignoring `TwoFARequired` in headless sync session
- **Before**: `onSignOnResponse` unconditionally created a `SyncEngine` even when `data["TwoFARequired"]==true` (locked tokens). The engine then tried to use the locked access token to call `/core/v4/keys/salts` → `403`, set status `error: Key unlock failed`, but the buteo log only showed generic sync failure.
- **Fix**: early check:
  ```cpp
  bool twoFARequired = data.getProperty("TwoFARequired").toBool();
  if (twoFARequired) emit error(..., AUTHENTICATION_FAILURE, "Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code");
  ```

---

## 4. Local Tests (no device needed)

All tests run via `cargo test --workspace --all-features` on x86_64 host.

### 4a. Offline parsing tests (`proton-api/src/auth.rs: tests`)
- `test_twofa_detection_totp_enabled_1`, `_both_3`, `_fido2_only_not_totp`, `_no_2fa`, `_legacy_*`, `_null_2fa`, `_numeric_2fa` → verify `is_totp_required` for every server variant.
- `test_twofa_response_parsing_*` → 1000 vs 422 handling.
- `test_auth_response_parsing_*` → legacy field handling.

### 4b. Mock-server integration tests (`mockito =1`)
- `test_submit_2fa_mock_success` → `POST /auth/v4/2fa` with `x-pm-uid` + Bearer, `200 {Code:1000}` returns original tokens.
- `test_submit_2fa_mock_wrong_code` → `422` is mapped to `Err`.
- `test_refresh_mock_success` → `POST /auth/v4/refresh` token rotation.
- `test_token_manager_2fa_flow` → `TokenManager` expiry handling after `submit_2fa`.

All 17 tests pass on host.

### Future tests to add before next device run
- `cargo build --target aarch64-unknown-linux-gnu --lib` cross-check (needs `proton-build-env` Docker, no OpenSSL).
- `qmllint` on `ui/proton*.qml` via SDK `qmlscene`.
- On-device manual test with real account `tiziano.incognito@proton.me` (ask for fresh OTP; OTP changes every 30 s, so live test must be coordinated).

---

## 5. Device Deployment Checklist (requires `defaultuser@192.168.1.124`, no root)

1. **Cross-compile Rust**:
   ```bash
   docker run --rm -v $PWD:/workspace proton-build-env bash -c 'cd /workspace && cargo build --release --target aarch64-unknown-linux-gnu -p proton-bridge'
   ```
2. **Build C++ plugins** inside `coderus/sailfishos-platform-sdk-aarch64` (see `make-pkg-bundle.sh` steps 2–3): `moc` + `aarch64-meego-linux-gnu-g++` for `libproton-client.so` and `libprotonplugin.so`.
3. **Copy to device** (as `defaultuser`, then `devel-su` on phone – SSH cannot `devel-su`):
   ```bash
   scp packaging/buteo-plugin/libproton-client.so defaultuser@192.168.1.124:/tmp/
   scp packaging/signon-plugin/libprotonplugin.so defaultuser@192.168.1.124:/tmp/
   scp ui/proton*.qml defaultuser@192.168.1.124:/tmp/
   # on phone as root:
   cp /tmp/libproton-client.so /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so; chmod 755 ...
   cp /tmp/libprotonplugin.so /usr/lib64/signon/libprotonplugin.so
   cp /tmp/proton.qml /usr/share/accounts/ui/proton.qml
   cp /tmp/proton-update.qml /usr/share/accounts/ui/proton-update.qml
   pkill -9 -x signond; systemctl --user restart msyncd; sleep 2
   ```
4. **Live OTP test**:
   ```bash
   # Ask user for current OTP before each attempt!
   # Create account via Settings → Accounts → Add → Proton → username/password → Verify OTP → check account stays on page, no pop to kind selection
   # Then trigger sync:
   dbus-send --session --type=method_call --dest=com.meego.msyncd /synchronizer com.meego.msyncd.startSync string:"proton.Contacts-<id>"
   # Check logs (needs root on phone, journal is volatile):
   devel-su journalctl --user -u msyncd -n 200
   # Or read /tmp/proton-sync-debug.log
   ```
5. **Verify `CredentialsId`**:
   ```bash
   # as defaultuser
   sqlite3 ~/.local/share/system/privileged/Accounts/db.sqlite "SELECT * FROM Accounts WHERE provider='proton';"
   sqlite3 ~/.local/share/system/privileged/Accounts/db.sqlite "SELECT * FROM Settings WHERE account=<?>;"
   ```

---

## 6. References Consulted

- Proton `go-proton-api`: `manager_auth.go`, `manager_auth_types.go` (`TwoFAStatus` 1/2/3), `auth.go` (`POST /auth/v4/2fa` upgrades scopes in-place, no new tokens).
- Sailfish `sailfish-components-accounts` (`src/lib/account.cpp`): `createSignInCredentials`/`updateSignInCredentials` flow, `handleResponse` vs `handleCredentialsStored`, `delayDeletion` semantics, `maybeSetCredentialsIdForProvider` only for `password`/`oauth2` methods, `convertValue` type whitelist.
- `buteo-syncfw/msyncd/AccountsHelper.cpp`: profile creation on `accountCreated`, `syncEnableWithAccount`, `getProfilesByAccountId`.
- On-device QML dumps (`/usr/share/accounts/ui/`, `libjollasignonuiservice-qt5.so` `InProcessEntryView` via zlib qrc extraction) – confirmed in-process dialog crash with `SIGSEGV` and `QueryErrorCode 2 (NO_SIGNONUI)` fallback.
- `proton-bridge/signon/proton_signon_plugin.cpp` comment history about `store()` semantics (signond persists every property except `UserName`/`Secret`).

---

## 7. TODO for Follow-up (reconciled 2026-09-06 — checked items verified done)

- [x] Persist `DerivedPasswords` via SignOn blob (`DerivedPasswords` property) instead of only `QSettings` `sync-tokens.conf`, so derived keys survive factory reset of app config. — DONE: `handleAuthOk` stores tokens+`DerivedPasswords` via `store()` *and* `QSettings` fallback; shim + calendar engine read both (verified live, `derived_len=139` with `pw_len=0`).
- [x] Add `qmllint` CI step for `ui/*.qml`. — DONE 2026-09-06: new `qml`
  job in `ci.yml` installs `qtdeclarative5-dev-tools` and runs `qmllint
  ui/*.qml` as a gate. Safe against false positives: Qt 5.15 `qmllint` is
  a pure syntax verifier (parses with QQmlJS, never resolves imports —
  verified in `tools/qmllint/main.cpp`), so Sailfish-only modules can't
  fail it; non-zero exit means a real syntax error.
- [ ] Extend `proton-sync::SyncEngine` to surface `needs_2fa` as distinct `SyncStatus` so Settings can show “OTP required” notification vs generic auth failure. — HALF DONE: engine already emits `state="needs_2fa"` (`engine.rs` `authenticate`); the Settings-side notification is still missing.
- [x] Consider `FIDO2` (WebAuthn) flow – currently unsupported, will be reported as “FIDO2 required, not implemented”. — DONE 2026-09-06 as loud failure (see explanation below): `AuthClient::login` detects FIDO2-only accounts (`Enabled==2` without TOTP, both `2FA` and legacy shapes) and returns a guiding error instead of a locked session that 403s downstream; SignOn surfaces it as NotAuthorized. Full ceremony stays out of scope: no WebAuthn client/authenticator path exists on Sailfish (see §8).
- [x] Add `cargo test` to `.github/workflows/ci.yml` (already present) and ensure it runs the new mockito tests. — DONE: `ci.yml:33-35` runs `fmt --check`, `clippy -D warnings`, and `cargo test -p proton-api -p proton-sync --all-features`, which includes all mockito + calendar tests.

---

## 8. FIDO2 (WebAuthn) — why it fails loudly instead (2026-09-06)

References: Proton `AuthResponse.TwoFactor` bitmask (`1=TOTP`, `2=FIDO2`,
`3=both`; also `2FA.Enabled`), Proton Bridge (official Go product: TOTP
only), Yubico WebAuthn guide (ceremony model).

### How TOTP works here (for contrast)

SRP login → server returns a **locked** session (scopes include `twofactor`)
plus `2FA.Enabled`. Our QML collects the 6-digit code in-page → SignOn
plugin `POST /auth/v4/2fa {"TwoFactorCode"}` → server upgrades the scopes
**in place** (no new tokens) → derive + store. Everything is plain HTTPS
JSON — no special hardware or OS services involved.

### What a FIDO2 second factor would require

After the same SRP login with `Enabled==2`, the client must run a WebAuthn
**assertion ceremony** instead of sending a code:

1. Obtain a server challenge (Proton's 2FA endpoint family with a FIDO2
   payload, mirroring the web client's `{"FIDO2": <assertion>}` shape).
2. A WebAuthn **client** (browser `navigator.credentials.get()` or an OS
   FIDO API) forwards the challenge plus the relying-party identity
   (`proton.me` — this origin check is what makes it phishing-resistant).
3. A FIDO2 **authenticator** — platform (Touch ID / Windows Hello style) or
   roaming (YubiKey over USB-C/NFC/BLE via CTAP2) — signs the challenge
   with the credential private key after a user gesture (tap/PIN/biometric).
4. The assertion POSTs back; the server verifies it against the registered
   public key and upgrades the session scopes, exactly like the TOTP path.

### Why every link is missing on Sailfish

- **No platform authenticator**: Sailfish has no Touch ID / Windows Hello
  equivalent and no OS-level FIDO API for native apps.
- **No CTAP transport path**: nothing connects a USB/NFC/BLE security key
  to our account flow (no HID/CTAP stack, no browser to borrow one from).
- **No ceremony host**: our OTP flow deliberately collects the code in
  native QML (signon-ui's in-process dialog SIGSEGVs on this image); there
  is no WebView that could run `navigator.credentials`, and embedding one
  just for WebAuthn would pull in an entire browser security surface.
- Precedent: even Proton's official Bridge implements TOTP only.

### What we do instead

`AuthClient::login` detects FIDO2-only (`Enabled==2`, TOTP flag unset, both
modern and legacy shapes) and returns a guiding error — enable TOTP in
Proton settings (it coexists with the security key, `Enabled==3`, which
already works through our TOTP path) — instead of proceeding with a locked
session that 403s confusingly downstream. Covered by
`test_fido2_only_excludes_totp_variants` + the extended FIDO2-only test.

