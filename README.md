# SailfishOS Proton Contacts Integration

Native SailfishOS account provider + Buteo sync plugin for Proton Contacts.
Built with Rust core + CXX-Qt bridge.

## Architecture

```
proton-api/       → Pure Rust: Proton REST API client (SRP auth, 2FA, contacts CRUD, PGP, key salts)
proton-sync/      → Pure Rust: Sync engine (auth, PGP decrypt, vCard mapping, QSettings derived cache)
proton-bridge/    → Rust FFI + C++: SignOn auth plugin (libprotonplugin.so) + Buteo OOPP plugin (libproton-client.so)
ui/               → QML AccountCreationAgent / AccountCredentialsAgent (OTP collected in-page, Password transient)
buteo-profiles/   → Buteo client/sync profile templates (proton / proton-carddav-*.xml)
packaging/        → RPM build artifacts (staged by make-pkg-bundle.sh)
accounts/         → Accounts&SSO provider/service XML (proton.provider, proton-carddav.service)
rpm/              → RPM spec files
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
| `proton-sync/src/engine.rs` | `SyncEngine` `unlock_keys` via `DerivedPasswords` cache → `QSettings` `sync-tokens.conf` |
| `proton-bridge/src/auth.rs` | FFI `proton_auth_login/submit_2fa/refresh/derive_passwords` |
| `proton-bridge/signon/proton_signon_plugin.{h,cpp}` | SignOn `proton` plugin (`process` + `handleAuthOk` stores `AccessToken`/`RefreshToken`/`Uid` + `DerivedPasswords`) |
| `proton-bridge/cxx/proton_bridge_shim.{h,cpp}` | Buteo OOPP plugin (`requestCredentials` `NoUserInteraction` + `QSettings` fallback by `Uid`/`username`) |
| `ui/proton.qml` / `proton-update.qml` | `AccountCreationAgent` / `AccountCredentialsAgent` (custom OTP in-page, `Password` transient, `CredentialsId` string fix, `goToEndDestination`) |
| `buteo-profiles/` / `packaging/accounts/` / `rpm/` | Profile & provider/service XML, RPM specs, `make-pkg-bundle.sh` staging |
| `FINDINGS_OTP.md` | Full OTP failure analysis + `delayDeletion`/`CredentialsId`/`Secret` stripping fixes |

## References

- [SailfishOS Accounts&SSO](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Accounts_and_SSO/)
- [SailfishOS Buteo Sync](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Synchronization/)
- [CXX-Qt Book](https://kdab.github.io/cxx-qt/book/)
- [Proton Internal API (go-proton-api)](https://github.com/ProtonMail/go-proton-api)
- [buteo-sync-plugins-social (Google contacts)](https://github.com/sailfishos/buteo-sync-plugins-social/tree/master/src/google/google-contacts)

## License

GPL-3.0-or-later
