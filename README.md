# SailfishOS Proton Contacts Integration

Native SailfishOS account provider + Buteo sync plugin for Proton Contacts.
Built with Rust core + CXX-Qt bridge.

## Architecture

```
proton-api/       → Pure Rust: Proton REST API client (auth, contacts CRUD, PGP)
proton-sync/      → Pure Rust: Sync engine (delta, conflict resolution, vCard mapping)
proton-bridge/    → CXX-Qt: Buteo plugin (cdylib) + QtPIM FFI
packaging/        → RPM build artifacts (staged by make-pkg-bundle.sh)
accounts/         → Accounts&SSO provider/service XML
ui/               → QML account creation/settings UI
buteo-profiles/   → Buteo client/sync profile templates
rpm/              → RPM spec files
```

## Build System (from ElectricEel)

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
| `proton-api/src/` | Proton API client |
| `proton-sync/src/` | Sync engine |
| `proton-bridge/src/` | CXX-Qt bridge (Rust) |
| `proton-bridge/cxx/` | Buteo plugin shim (C++) |
| `accounts/` | Provider/service XML |
| `ui/` | QML UI |
| `buteo-profiles/` | Sync profile templates |
| `rpm/` | RPM specs |
| `make-pkg-bundle.sh` | Staging script |
| `.github/workflows/` | CI + Release |

## References

- [SailfishOS Accounts&SSO](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Accounts_and_SSO/)
- [SailfishOS Buteo Sync](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Synchronization/)
- [CXX-Qt Book](https://kdab.github.io/cxx-qt/book/)
- [Proton Internal API (go-proton-api)](https://github.com/ProtonMail/go-proton-api)
- [buteo-sync-plugins-social (Google contacts)](https://github.com/sailfishos/buteo-sync-plugins-social/tree/master/src/google/google-contacts)

## License

GPL-3.0-or-later