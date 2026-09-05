# SailfishOS Proton Contacts & Calendar Integration

Native SailfishOS account provider + Buteo sync plugin for Proton Contacts and Calendar (single `libproton-client.so`, single RPM). Built with Rust core + `mKCal`/`QOrganizer` bridge.

## Architecture

```
proton-api/       → Pure Rust: Proton REST API client (SRP auth, 2FA, contacts CRUD, calendar CRUD, PGP, key salts)
proton-sync/      → Pure Rust: Sync engines (contacts: SyncEngine, calendar: CalendarSyncEngine) + QSettings derived cache
proton-bridge/    → Rust FFI + C++: SignOn auth plugin (libprotonplugin.so) + Buteo OOPP plugin (libproton-client.so, QContactManager + QOrganizerManager mkcal)
ui/               → QML AccountCreationAgent / AccountCredentialsAgent (OTP in-page, Password transient, Contacts+Calendar toggles)
buteo-profiles/   → Buteo client/sync profile templates (proton / proton-carddav-*.xml / proton-caldav-*.xml + proton.Calendar.xml)
packaging/        → RPM build artifacts (staged by make-pkg-bundle.sh)
accounts/         → Accounts&SSO provider/service XML (proton.provider, proton-carddav.service, proton-caldav.service)
rpm/              → RPM specs (single buteo-sync-plugin-proton + sailfish-account-proton RPMs)
```

**Security note (OTP):** The raw Proton login password is **never persisted** — it is passed only as transient `Password` param to the `proton` SignOn plugin for SRP + `POST /auth/v4/2fa` scope upgrade, then immediately `derive_all_passwords` (`KeysClient` → `derive_mailbox_password`) stores only the per-key `DerivedPasswords` map (`keyID → base64(mailboxPassword)`) in `signond` blob + `QSettings("proton","sync-tokens")` and in `~/.config/signond/signon-secrets.db` `STORE` (+ `QSettings` fallback by `Uid`/`username`). The Buteo sync later runs `NoUserInteractionPolicy` with only `RefreshToken`/`Uid`/`DerivedPasswords` (`pw_len=0` is expected).

## Build System

- **Host CI**: `cargo fmt/clippy/test` on x86_64
- **Release**: Cross-compile to `aarch64-unknown-linux-gnu` → stage into `packaging/` → build RPMs inside `coderus/sailfishos-platform-sdk-aarch64` container via `mb2`

## Quick Start

### Prerequisites
- Rust stable + `aarch64-unknown-linux-gnu` target
- Docker (for RPM builds)
- SailfishOS Platform SDK (for device testing)

### Development Build (host only)
```bash
# Format, lint, test
cargo fmt --check --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

# Cross-compile check (lib crates only)
cargo build --workspace --release --target aarch64-unknown-linux-gnu --lib
```

### Full RPM Build (requires Docker)
```bash
# Stage artifacts + build both RPMs
./make-pkg-bundle.sh
# Then run the container build steps from .github/workflows/release.yml
# Or use the GitHub Actions workflow by pushing a v* tag
```

### Install on Device
```bash
# Transfer RPMs to device
scp packaging/RPMS/*.rpm nemo@device:

# Install
ssh nemo@device "pkcon install-local *.rpm"

# Restart msyncd to load new plugin
ssh nemo@device "systemctl --user restart msyncd"
```

## Project Structure

| Path | Purpose |
|------|---------|
| `proton-api/src/auth.rs` | SRP + `is_totp_required` + `submit_2fa` (`/auth/v4/2fa` scope upgrade) + `derive_all_passwords` |
| `proton-api/src/keys.rs` | `KeysClient` (`/core/v4/users`, `/keys/salts`, `/addresses`) + `derive_all_passwords` |
| `proton-api/src/calendar.rs` | `CalendarClient` (`/calendar/v1`/`/keys`/`/passphrase`/`/events`) + `decrypt_calendar_event` + `parse_ical` (VCALENDAR/VEVENT) |
| `proton-sync/src/engine.rs` | `SyncEngine` `unlock_keys` via `DerivedPasswords` cache → `QContactManager` `Saved 1 contacts` |
| `proton-sync/src/calendar.rs` / `calendar_full.rs` | `CalendarSyncEngine` (stub → `QOrganizerManager mkcal` `Saved` test event, full VCALENDAR decrypt next) |
| `proton-bridge/src/auth.rs` | FFI `proton_auth_login/submit_2fa/refresh/derive_passwords` |
| `proton-bridge/signon/proton_signon_plugin.{h,cpp}` | SignOn `proton` plugin (`process` `Password` transient → `handleAuthOk` stores `DerivedPasswords` in `store`+`QSettings`) |
| `proton-bridge/cxx/proton_bridge_shim.{h,cpp}` | Buteo OOPP `ProtonContactsPlugin` (`QContactManager`) + `ProtonCalendarPlugin` (`QOrganizerManager mkcal`) single `libproton-client.so` |
| `ui/proton.qml` / `proton-update.qml` / `proton-settings.qml` | `AccountCreationAgent` / `AccountCredentialsAgent` / `OnlineSyncAccountSettingsAgent` (OTP in-page, `Password` transient, `CredentialsId` string, `goToEndDestination`, **Contacts+Calendar toggles**) |
| `buteo-profiles/` / `packaging/accounts/` / `rpm/` | `proton.provider` + `proton-carddav.service` + `proton-caldav.service` + `proton.Contacts.xml`/`proton.Calendar.xml` + single-RPM `make-pkg-bundle.sh` |
| `FINDINGS_OTP.md` | Full OTP post-mortem (`delayDeletion`, double `CredentialsId`, `Secret` stripping → `Password` fallback, `QSettings` `DerivedPasswords`) |

## References

- [SailfishOS Accounts&SSO](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Accounts_and_SSO/)
- [SailfishOS Buteo Sync](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Synchronization/)
- [CXX-Qt Book](https://kdab.github.io/cxx-qt/book/)
- [Proton Internal API (go-proton-api)](https://github.com/ProtonMail/go-proton-api)
- [buteo-sync-plugins-social (Google contacts)](https://github.com/sailfishos/buteo-sync-plugins-social/tree/master/src/google/google-contacts)

## License

GPL-3.0-or-later
