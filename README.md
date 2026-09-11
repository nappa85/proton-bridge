# SailfishOS Proton Contacts & Calendar Integration

Native SailfishOS integration that syncs Proton Contacts and Calendar
directly with the built-in People and Calendar apps. Add your Proton
account once in Settings → Accounts, flip the Contacts and Calendar
toggles, and both stay in two-way sync — edits on the phone upload to
Proton, edits on Proton download to the phone.

- Two-way sync for contacts (create, edit, delete) including photos
- Two-way sync for calendar events (create, edit, delete) including
  reminders and recurring events
- Login with username, password, and TOTP two-factor code, entered
  in-page during account setup
- Multiple Proton accounts, each kept in its own collection/notebooks
- Translated account screens; per-account data purge from Settings
- Your Proton login password is never stored on the device — only
  derived per-key secrets are kept (see `docs/auth.md`)

## Documentation

Technical documentation lives in `docs/`:

- `architecture.md` — components, plugin mechanics, on-device paths,
  stored state, diagnostics
- `auth.md` — login, two-factor, key unlocking, account screens
- `contacts-sync.md` — how contact sync works end to end
- `calendar-sync.md` — how calendar sync works end to end
- `build-deploy.md` — checks, builds, RPMs, translations, manual sync

## Quick Start

### Prerequisites

- Rust stable + `aarch64-unknown-linux-gnu` target
- Docker (for RPM builds)
- SailfishOS Platform SDK (for device testing)

### Check (host only)

```bash
cargo fmt --check --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

### Build RPMs (requires Docker)

```bash
./make-pkg-bundle.sh
# Or push a v* tag to build via the GitHub Actions release workflow.
# See docs/build-deploy.md for details and the --no-deploy option.
```

### Install on Device

```bash
# Transfer RPMs to device
scp <rpm-files> defaultuser@phone:

# Install (on the phone)
pkcon install-local *.rpm

# Restart the sync service to load the new plugin
systemctl --user restart msyncd
```

## References

- [SailfishOS Accounts&SSO](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Accounts_and_SSO/)
- [SailfishOS Buteo Sync](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Synchronization/)
- [Proton Internal API (go-proton-api)](https://github.com/ProtonMail/go-proton-api)
- [buteo-sync-plugins-social (Google contacts)](https://github.com/sailfishos/buteo-sync-plugins-social/tree/master/src/google/google-contacts)

## License

GPL-3.0-or-later
