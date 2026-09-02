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

- SRP authentication with v4 endpoints (`/core/v4/auth/info`, `/core/v4/auth`, `/auth/v4/refresh`)
- Token persistence via QSettings (refresh token + UID)
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

## Known Issues / TODO

- **Token-based address keys**: Address keys with non-empty `Token` field can't be decrypted yet — contacts using those keys won't sync
- **2FA**: No TOTP input during account setup for 2FA-enabled accounts
- **Two-way sync**: Currently download-only (Proton → phone). No upload of local changes
- **Incremental sync**: No sync token support; full fetch every time
- **Contact dedup**: No duplicate detection across Proton + local contacts
- **Multiple photos**: People app only supports one avatar; only first photo is used

## Key Technical Details

- Rust uses `aarch64-unknown-linux-gnu` target (NOT musl) — musl embeds its own libc, crashing the oopp-runner
- User-Agent MUST be `curl/8.0` on all reqwest clients — Proton rejects reqwest's default
- `APP_VERSION` must be `web-mail@6.3.2` — `other@1.0.0` triggers CAPTCHA/abuse detection
- Auth endpoint URLs MUST use v4 paths, including `/auth/v4/refresh` (legacy paths produce tokens lacking scopes)
- SDK sysroot glibc 2.35, phone has 2.41 — compatible (forward-compatible glibc)
- `devel-su` doesn't work from SSH — user must run root commands on phone terminal directly

## Source Layout

```
proton-api/       — Pure Rust Proton API client
  auth.rs           SRP auth + 2FA + refresh
  crypto.rs         derive_mailbox_password(), decrypt_contact_card()
  keys.rs           User/address key management
  contacts.rs       Contacts list/get API
  models.rs         Contact, ContactCard, UserKey, etc.
  vcard.rs          ical_vcard parser + download_url_photos()

proton-sync/      — Sync engine orchestration
  engine.rs         SyncEngine: auth → unlock keys → fetch → parse → JSON

proton-bridge/    — C++ FFI layer
  cxx/proton_bridge_shim.cpp   Buteo plugin + QContactManager
  cxx/proton_bridge_shim.h     QtContacts includes
  src/lib.rs                    FFI bridge (proton_bridge_* C functions)

buteo-profiles/   — Buteo sync profile XMLs
accounts/         — Accounts/SSO provider + service XMLs
ui/               — QML account creation/settings UI
rpm/              — RPM spec files
```
