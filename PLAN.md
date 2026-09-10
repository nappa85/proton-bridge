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

- **Token-based address keys**: FIXED 2026-09-06 — `Token` is decrypted with
  the unlocked user keys (go-proton-api `Key::Unlock`), verified live on
  device (`addrkey_…_ok_via_token` with `pw_len=0`)
- [ ] **Contacts upsync** (filed 2026-09-08, after calendar upsync verified
  end-to-end — follow the same template: inventory/planner/batcher/
  fail-closed executor/selective handling, but contacts-specific):
  engine is download-only with full replacement (local creates wiped,
  edits overwritten, deletes resurrected; `ContactsClient`
  create/update/delete exist but are never called). Researched 2026-09-08
  (WebClients `contacts/encrypt.ts` + `ContactImporting.tsx`, authoritative):
  cards seal with the USER primary keypair (encrypt to user-public, sign
  with user-private — opposite of calendar's address-key rule); split is
  Type 2 signed (version/prodid/fn/uid/email/key-fields, uid+fn auto-added)
  + Type 3 armored (everything else) + Type 0 cleartext (only with
  categories);   batch create ≤10, rate limit 100 req/10s. Change tracking
  via Proton-ID↔QContactId map + lastModified snapshots in QSettings
  (QtContacts has no mKCal-style tombstones; shim already stores Guid +
  SyncTarget per contact).
  PROGRESS 2026-09-08: `build_vcard` serializer + WebClients split
  (signed uid/fn/emails, encrypted rest, no cleartext without categories;
  FN fallback, 75-octet folding, round-trip tests green); contact seal op
  DONE (`contact_seal.rs`: whole-message armored encrypt to USER-public +
  detached sign with USER-private, decrypt-back through the existing read
  path). Lesson: encryption and signing need DIFFERENT capabilities
  (ECDH subkey encrypts, EdDSA signs) — every (enc, sign) pair combo is
  tried, first working wins. PLANNER DONE (`contact_plan.rs`: ID-map
  diffing for deletes — QtContacts has no tombstones; ModifyTime anchors;
  server-wins conflicts; 10 offline tests). ENGINE WIRED (creates chunked
  ≤10 with per-op code checks, update rebuilds with server-photo carry,
  deletes single-batch + local filter, re-list only for creates/updates,
  fail-closed; mockito delete + create/update cycles with real generated
  keys). FFI in/out done. SHIM exports inventory (full field mirror,
  photos omitted v1) + persists ID map/snapshots/anchors (SDK `moc` +
  `g++ -c` OK — incl. fixes: `QContactGender::GenderType` has no Other,
  `QContactUrl::url()` is QString, cbindgen header needs forced rebuild).
   Found + fixed live: `CreateContactResult.Contact` is NESTED on the wire
   (WebClients reference), our `#[flatten]` never matched. NEXT 2026-09-09:
   research-first pass over WebClients `contacts/{encrypt,constants,surgery,
   vcard,decrypt}.ts` + `api/contacts.ts` and go-proton-api `contact{,s}.go`
   found 5 more never-live-tested wire bugs, all fixed locally with offline
   tests (see `FINDINGS_CONTACTS_UPSYNC.md`): create body is now
   `Contacts:[{Cards}]` (was bare arrays), delete is `PUT …/delete` (was
   HTTP DELETE — matched NEITHER reference), fresh UIDs are
   `proton-web-uuid` via `getrandom` (was nanos, collidable), empty FN falls
   back to `Unknown`, PRODID no longer emitted (VERSION only, like fresh web
   contacts); `get()` debug dump to `/tmp/proton-contact-raw.json` removed.
   Local green: fmt + clippy `-D warnings` clean, 153 tests pass
   (92+3+58), aarch64 cross OK, SDK `moc` + `g++ -c` OK. Staged
   `/tmp/libproton-client.so` sha256
   `af82339da7dec5d0d00ca75e9b17120bfb1ff57949a6fa7ee65d01cdc0953cc8`.
   New host gate `proton-sync/examples/live_contacts_check.rs` (scratch
   create → update → delete, compiles, BLOCKED twice by host 9001 CAPTCHA —
   see CAPTCHA TODO below; OTPs unconsumed). INCIDENT 2026-09-09 07:33 +
   08:32: a phone edit wiped the server contact twice. ROOT CAUSE (proven
   locally, `missing field photos`): the shim never sends the `photos` key
   but `ParsedContact` required it, so every edited row failed the whole
   inventory parse → inventory=None → known-diff DELETE. Fixed:
   `#[serde(default)]` on all vCard contract fields + half-fed defense
   (inventory-None + known-Some drops known, never plans deletes) +
   delete-hold rule + file-log trace (inputs/plan/ran/defer-reasons/hold
   markers in `keys_debug`). Details + live log evidence in
   `FINDINGS_CONTACTS_UPSYNC.md` §7. FOLLOW-UP 09:06: sealed PUT got server
   `400 Bad Request` (fail-closed, local intact). Two fixes: error bodies
   now captured (`check_response`, no more blind 4xx) + emails grouped
   (`itemN.EMAIL`, WebClients refuses ungrouped). Staged sha256
   `2e52fffa999bc801ce91594278b8aa682987967ea8311ff9ff09ad4efd851282`
   (on phone `/tmp`, verified), 161 tests green. VERIFIED LIVE 09:16:
   phone edit → `ran updated=1`, post-upload re-list carries the edited
   name (grouped-email theory confirmed). VERIFIED LIVE 09:21: revert
   re-gate green (`ran updated=1`, anchors advanced) — updates stable,
   repeatable. REVIEW 2026-09-09 (research-first, no device): re-read both
   references against the still-unverified create/delete paths; found 1
   real bug + 1 hardening gap, fixed locally with offline tests (see
   `FINDINGS_CONTACTS_UPSYNC.md` §9): email-only contacts no longer seal
   an empty Type-3 wrapper (`build_vcard` → `(String, Option)` mirroring
   the `encrypt.ts` `toEncryptAndSign.length > 0` gate — same 400-risk
   class as ungrouped EMAIL); `delete()` now fails on an explicit
   top-level error `Code` (lenient: codeless `{}` stays success).
   go-proton-api routes confirmed byte-identical to ours (WebClients
   `/contacts` suffix noted as a future-400 suspect only). Local green:
   fmt + clippy `-D warnings` clean, 167 tests pass (99+3+65),
   `make-pkg-bundle.sh --no-deploy` full gate green (container cross +
   SDK moc/g++/link). Staged `packaging/buteo-plugin/libproton-client.so`
   sha256 `384e9d9d415179b2b5d0f93c22977119b305277506c87891e77565448acc72fe`
   (supersedes ALL earlier builds — deploy only this). LIVE 2026-09-09:
   11:32 phone-created-UID edit → `updated=1` (UPDATE convergence, no
   dup); 11:36 two phone creates → `created=2` (single POST, re-list
   carries fresh UIDs, decrypt round-trip OK); 11:37 both deleted →
   Full create/update/delete cycle verified end-to-end. CLOSED 11:38:
   user confirmed scratch rows gone on web; steady-state re-sync with
   zero ops (`c=0 u=0 d=0`), ID map self-pruned 4→2.
- **Two-way sync**: Contacts upsync implements it (creates/updates/deletes
  upload; server-wins conflicts; contacts upsync gate in progress — see
  above); calendar create/update/delete already live-verified
- **Incremental sync**: No sync token support; full fetch every time
- **Contact dedup**: No duplicate detection across Proton + local contacts
- **Multiple photos**: People app only supports one avatar; only first photo is used
- [x] **Contacts photo upload** (filed 2026-09-09, DONE 2026-09-10
  local-only): device avatars now upload. Seal side: creates keep phone
  photos (no longer dropped), updates prefer phone photos over the
  server carry (empty phone still carries; avatar *deletion* does not
  propagate — v1 limitation). Shim side: dirty/never-synced rows export
  the avatar, compared against a new persisted download baseline
  (`contacts_photos`, read back post-save so the comparison is
  QUrl-like-for-like) — untouched avatars stay omitted (no re-upload
  churn, no echo-fidelity risk); `data:` URIs pass through, file paths
  load + downscale to 512px bounding JPEG q85 (WebClients imports cap at
  180 — JPEG codecs are QtGui built-in, no plugin dependency;
  `+lQt5Gui` in the buteo link, base-system lib). Conversion failures
  omit (server copy wins). Verified: fmt + clippy clean, 202 tests
  (120+5+77: create-seals-photo, phone-wins, server-carry, escaping),
  full bundle green. Staged `packaging/buteo-plugin/libproton-client.so`
  sha256   `1d2dc0ceaacfe46f1c703e7275473fadff559bad380e890a3adbfdf433c6384c`
  (supersedes `60c05ed7…` — deploy only this). VERIFIED LIVE 2026-09-10
  (deployed, sha-checked): avatar set on existing contact → `updated=1`,
  photo visible on Proton web. Phone gate remainder: avatar removal →
  photo stays (documented v1 gap, untested).
- **Password never persisted** (intentional): raw 20-char login password is transient `Password` param only for `derive_all_passwords` at `Verify`; `signon-secrets.db` `CREDENTIALS.password` stays dummy `"x"`, `handleAuthOk` never returns `Secret`. New `KeySalt` after manual Proton key rotation will need one more **Update credentials → OTP** to re-derive and re-store `DerivedPasswords`.
- [x] **CAPTCHA / human-verification handling** (filed 2026-09-09, hit live
  from the host: SRP login → `422 Code 9001`; IMPLEMENTED 2026-09-09
  local-only — a live 9001 cannot be triggered on demand, so the device
  half stays code-reviewed only): research corrected the direction
  (details in `FINDINGS_CONTACTS_UPSYNC.md` §8 + new §11): an external
  browser does NOT unblock API logins (the proof returns via postMessage
  to the embedding page; WebClients #473 open) — so the UI promises
  nothing except explanation + retry guidance. Implemented:
  `ProtonError::Captcha(CaptchaChallenge)` parsed from the 9001 body
  (`HumanVerificationMethods`/`Token`/`WebUrl`, URL constructed
  Captcha.tsx-style when absent; Display redacts token+URL per hydroxide
  precedent; strict shape or generic-error fallback) in login + 2FA
  submit paths; FFI status 3 + `captcha_url`/`captcha_methods` (cbindgen
  header regenerated); SignOn plugin maps it to a `CaptchaRequired`
  result (same shape as `TwoFARequired`, login + both 2FA-submit paths,
  nothing stored); both QML agents show message + methods + tappable
  verify link + Try-again with retry-safe state (incl. the
  captcha-answers-OTP-verify edge that would have completed the flow
  falsely). Full-review notes: QML hand-reviewed only (no qmllint on
  host or SDK — CI gate covers it), token never logged (both full-data
  QML logs removed). Verified: fmt + clippy clean, 184 tests
  (108+5+71: parse/Fixture/WebUrl/reject/Display-redaction/2FA-submit
  mapping/FFI status), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `0fd5770e4db4fd6cfbd7222e7a46e71ee76b3d7bbcc82293de442c90c8132086`
  + refreshed account tarball (new QML) — deploy both. Phone gate when
  a 9001 next occurs naturally (nothing to trigger it): captcha page
  shows instead of JSON soup. Still open (future): embedded-WebView
  proof capture (proton-filter-cli shape) or Proton device-flow support
  (#473); retry-with-proof headers (`x-pm-human-verification-token`,
  12087 handling).
- [x] **Debug-log cleanup / opt-in flag** (filed 2026-09-07, DONE
  2026-09-09 local-only): single mechanism both layers — `PROTON_VERBOSE`
  env (non-empty, not `"0"`). Rust: `diag::verbose()` + `vlog!` macro
  (`proton-api/src/diag.rs`); all 11 routine contacts-upsync journal
  lines gated, genuine error lines (`Key unlock failed`, derive/photo/
  fetch failures) always show, calendar `LIVE_TRACE`/`LIVE_DIAG` sites
  untouched, `examples/` host tools untouched. Shim: `proton_verbose()`
  + `proton_log_verbose()`; full `Contact JSON:` rows (PII + photo
  data-URIs — the biggest entry) verbose-only, everything else
  (errors, counts, IDs-only upsync inputs, `keys_debug` summary) always
  logs. Size cap: `diag::rotate_log_if_needed` (tested: missing/small/
  exact-cap/line-boundary-tail) via FFI `proton_bridge_rotate_log`
  (cbindgen header regenerated), called at both plugin inits — 1 MiB
  cap, 256 KiB tail + marker. Device toggle needs no root:
  `systemctl --user set-environment PROTON_VERBOSE=1` (+ msyncd
  restart; `unset-environment` to revert). Verified: fmt + clippy
  `-D warnings` clean, 171 tests (103+3+65), stderr proven silent by
  default / traced with the flag, `make-pkg-bundle.sh --no-deploy`
  green. Staged `packaging/buteo-plugin/libproton-client.so` sha256
  `147ae55fce8da30109ae29baa2e8c960c102d1b4ffa573a907865c304292fe1a`
  (supersedes `384e9d9d…` — deploy only this; note it also carries the
  §9 single-card + delete-Code work already live-verified). VERIFIED
  LIVE 2026-09-09 (deployed, sha-checked): default-mode syncs log zero
  `Contact JSON:` with trace/counts intact; verbose run restores them.
  Env cleaned + msyncd restarted after. Lesson: the oopp-runner
  inherits msyncd's env at msyncd start — `set-environment` requires a
  msyncd restart to take effect. Rotation not triggerable live (~130
  KiB log) — offline-tested only.)
- [ ] **UI i18n** (DEFERRED 2026-09-07 by user decision — do after settings
  UI strings stabilize; they changed twice in two days and each change
  invalidates translations): audit 2026-09-07 found all static strings in
  `ui/proton.qml` / `ui/proton-update.qml` already use `qsTr` + `//%` (plus
  3 stock `qsTrId`s from Jolla's catalog), and `ui/proton-settings.qml`
  purge strings were converted to `qsTr` + `//%`. But there is NO
  translation pipeline (no `.ts`, no `lupdate`/`lrelease` in CI/specs), so
  custom strings render English everywhere. Reference
  `sailfish-account-nextcloud` ships zero custom strings — no Jolla
  precedent to copy. Design (researched 2026-09-07): our QML runs in the
  Settings app process, so per-app auto-loading does NOT apply — load via
  our `Proton 1.0` C++ extension (`QQmlExtensionPlugin::initializeEngine`
  → `installTranslator`, `.qm` from `/usr/share/proton/translations/`;
  needs a real non-English-locale device test, host-process assumptions
  have bitten before). Steps: (1) seed `translations/proton-<lang>.ts` via
  `lupdate`; (2) `lrelease` → `.qm` at bundle time + account spec `%files`;
  (3) `initializeEngine` translator install with graceful fallback;
  (4) CI gate keeping `.ts` in sync; (5) keep `qsTr` (free English
  fallback — custom `qsTrId` without shipped `.qm` renders empty). Also in
  scope: `proton.provider` name/description (XML, not QML). Out of scope:
  dynamic server/plugin error messages (`_errorMessage`, English by
  nature). Cheap first step when revived: commit English-source `.ts`
  template only.
- [ ] **Docs rewrite: findings → objective documentation** (filed 2026-09-09
  by user decision — final TODO, do after all sync work stabilizes):
  convert `PLAN.md` / `ARCHITECTURE.md` / `FINDINGS_OTP.md` /
  `FINDINGS_CALENDAR.md` / `FINDINGS_CONTACTS_UPSYNC.md` from running
  research/dev journals into objective documentation. Target shape:
  only schemas of how things work (architecture, component contracts,
  API wire shapes, sync-cycle state machines, file paths) — strip all
  commentary, live-log excerpts, incident narratives, per-session
  progress notes, TODOs, and superseded analysis. Keep the references
  (URLs) that pin each schema to its source. Suggested order: freeze
  one `docs/` layout (e.g. `architecture.md`, `auth.md`,
  `contacts-sync.md`, `calendar-sync.md`, `build-deploy.md`), rewrite
  each from the current files, then delete the `FINDINGS_*.md` journals
  (history stays in git).
- [x] **Calendar personal-part route** (filed 2026-09-09, DONE 2026-09-10
  local-only): reminder-only phone edits now take `PUT
  .../events/{id}/personal` (`CreateSinglePersonalEventData`, exact
  WebClients shape) instead of a full reseal — no crypto ops, no
  SEQUENCE churn, no 2001/2011 surface. Strict whitelist gating
  (`content_matches_except_notifications`: all compared fields present
  and exactly equal, non-recurring, no attendees/exdates/personal rows;
  any doubt falls through to the existing replace), sharing one
  Notifications/Color marshal with the sync body so the routes can't
  diverge. Verified: fmt + clippy clean, 210 tests (127+5+78: marshal
  tri-state, comparator accept/12-rejections/undecryptable, transport
  success + both rejection shapes with bodies, engine cycle proving
  personal-PUT-fires + zero reseal-PUTs), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `e46b3605d0b625fced6af81dbe3291a9eac0d4540bcf9abd7ef0093a50bf1a47`
  (supersedes `1d2dc0ce…` — deploy only this). VERIFIED LIVE 2026-09-10
  (deployed, sha-checked): reminder change on a plain event →
  `upsync_personal`, web shows the 1-hour display reminder with the
  inherited email gone — byte-identical outcome to the 09-08 full-reseal
  verification of the same edit (custom list replaces inheritance in
  Proton's model, on web too; the phone edits a single display alarm).
  Parity proven, no semantic change. Phone gate remainder: a text/time
  edit must still take the reseal path.
- [ ] **RSVP sync-back + invitation sending** (filed 2026-09-09,
  CONTRACT READY 2026-09-10, see `FINDINGS_CALENDAR.md` §16 — no code
  yet, deliberately): RSVP = `PUT .../events/{id}/attendees/{attendeeID}
  {Status, UpdateTime, Comment?}` (Status enum verified identical to
  ours); acceptance = `PUT .../events/{uid}/accept {Signature}`
  (signature recipe open); authoring via sync `Attendees` rows (web
  composer flow open). Blockers, all real: our rows lack attendee ID
  (ID≠Token, relation unknown), UpdateTime/Comment/self-resolution
  missing; NO phone trigger (attendee events read-only); NO live invite
  data (T16 must survive). Implementation starts only with all three.
- [ ] **Contacts photo upload** (filed 2026-09-09): photos are dropped on
  create and only carried over on update (server copy wins). The
  "Multiple photos" entry above covers the People-app single-avatar
  limit, not upload. Direction: seal `PHOTO` data-URI lines into the
  encrypted card on create/update; verify size limits against the API
  first (contact cards have no documented per-card cap — probe with the
  mock shape, then one live photo contact).
- [x] **Contacts key-field edits** (filed 2026-09-09, DONE 2026-09-09
  local-only): server cards with per-email crypto settings (`KEY` /
  `X-PM-*` grouped with their address in the signed card — WebClients
  `VCARD_KEY_FIELDS`, go-proton-api `GetGroup` model) no longer defer
  updates forever. The rebuild carries those groups verbatim, regrouped
  onto the rebuilt emails (address→new `itemN`, bodies byte-identical;
  deleted addresses drop their groups); the guard exempts them
  per-card-side (signed only — encrypted-side keys still defer rather
  than relocate protection domains). Verified: fmt + clippy clean, 199
  tests (117+5+77: extract/orphan-bare/guard-exemption/regroup+drop/
  case-fold/append-folding, seal carry+regroup/drop/defer-encrypted/
  diagnose, engine PUT-fires), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `60c05ed7d6cc71f4200436f8d267f993220d7555510fe56553e1bb1ad5b181c6`
  (supersedes `609dc594…` — deploy only this). VERIFIED LIVE 2026-09-10
  (deployed `60c05ed7…`, confirmed `adopted=0` trace): phone rename on
  the trusted-key contact → `updated=1`, no deferral; web shows the new
  name AND the key still trusted — groups carried byte-identical,
  server accepted. (Side incidents same day, both recorded: msyncd was
  found dead 21h from a restart loop — reset+restarted, now monitored;
  an unsaved/overwritten phone edit confirmed the download-wins path
  behaves.)
- [x] **Contacts categories/Type-0 preservation** (found + done 2026-09-10
  local-only, shrinks the deferred class): labeled (imported) contacts
  deferred every phone edit (`cleartext-card`) because the rebuild would
  drop their labels. A real user export then corrected the design
  mid-session: live `CATEGORIES` are GROUPED (`ITEM1.CATEGORIES`, tied
  to the email's group — an ungrouped-only cut would have emitted the
  wrong shape), and `PRODID` carries params (`;VALUE=TEXT`). So the
  rebuild extracts cleartext lines with group→address resolution and
  re-emits them byte-identical except for the regrouped prefix
  (unknown-address lines go ungrouped — never dropped, never
  misattached; per-card-side exemption, encrypted-side keys still
  defer). Wire fix included: Type-0 `Signature: null` tolerated on read
  and omitted on write (was `""`). Verified: fmt + clippy clean, 222
  tests (134+5+83), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `36d44fcc72c628769258b566cedda87a653d8b9fafb8492742b87837bd809b00`
  (supersedes `9179ed5d…` — deploy only this). LIVE GATE BLOCKED
  2026-09-10: import→export round trip with zero phone involvement loses
  CATEGORIES, and web has no label UI — so no Type-0 fixture can reach
  the account through supported paths (import drops them on the way in
  and/or export drops them on the way out; indistinguishable
  black-box-side). The code stays implemented + offline-proven (220
  tests); it activates if a Type-0 card is ever encountered. Please
  delete the re-imported probe contact.
- [x] **Calendar out-of-window deletes** (filed 2026-09-09, CORRECTED +
  DONE 2026-09-09 local-only): audit found the filed claim ("can't
  upload") stale — the UID augment already covered (pid, uid)
  tombstones. The true residual hole was pid-less tombstones (id-map
  entry lost) silently orphaning while their rows survived server-side.
  Fixed: engine augment also UID-lists uid-only tombstones (ID-deduped
  merges) + planner resolves them (master → series delete via existing
  batch expansion, `#rid` standalone → surviving occurrence only,
  rid-miss/no-rows → orphan path unchanged). Details + tests in
  `FINDINGS_CALENDAR.md` §13. Verified: fmt + clippy clean, 177 tests
  (103+3+71), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `364ef3d0d45ce2a2920039374c1919ec208544dc3092b6f67b181fccfb2db41a`
  (supersedes `147ae55f…` — deploy only this). Live delta: none on
  happy path; phone gate is deploy + steady sync.
- [ ] **Typed windowed listing anomaly** (filed 2026-09-09, runs 1–10 in
  `FINDINGS_CALENDAR.md` §7): identical typed queries intermittently
  return 200-empty while untyped succeeds; cause unexplained, typed code
  retained mock-tested beside the untyped primary. Direction: either a
  focused live session to isolate it (same token/session, overlapping
  windows, per-query logging already exists) or delete the typed path
  outright so it stops looking like a supported alternative.
- [ ] **Deferred-update visibility** (filed 2026-09-09): conflict
  notifications are wired (`proton_bridge_shim.cpp:496`), but deferred
  counts/reasons are file-log-only, and the download still overwrites a
  deferred local edit so the next snapshot looks clean. Direction:
  include deferred counts + first reason in the conflict notification
  and/or keep the local row dirty until its content actually uploads.
- [x] **Rate-limit pacing + create-retry duplication** (filed 2026-09-09,
  DONE 2026-09-09 local-only, contacts engine): retries are now
  idempotent instead of merely documented. Each create seals under a
  STABLE UID (`pending_uid` from the shim's `contacts_pending` map, else
  fresh): a retry either succeeds (first POST never landed) or hits the
  UID-conflict per-op error (Overwrite=0 throws — `OVERWRITE` enum) and
  is ADOPTED from a fresh listing; unresolvable conflicts fail closed;
  missing per-op Index fails closed (strict wire shape). Posted-but-
  unconfirmed (qid→uid) jobs expose via new FFI
  `proton_bridge_get_contact_pending_json`, persisted wholesale by the
  shim on EVERY outcome (complete clears, error keeps — the error path
  is exactly when entries exist) and fed back as `pending_uid` for
  guid-less rows (contract `#[serde(default)]`, both-directions
  compatible). Pacing: 100 ms between update PUTs / create chunks
  (`CONTACT_UPLOAD_PACING_MS`, WebClients `API_SAFE_INTERVAL`).
  Verified: fmt + clippy clean, 189 tests (108+5+76: retry-reuse with
  same-UID POST proof, conflict-adopt, unresolvable-fails-closed,
  getter default, contract compat), full bundle green. Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `609dc594a35bc1b03c7624bfe29ff7f15090a8eac6322572af4195f263a6a721`
  (supersedes `0fd5770e…` — deploy only this). Live delta: none on
  happy path (same UIDs/PUTs); phone gate is deploy + steady sync.
- [x] **Calendar create idempotency** (filed 2026-09-09 as the calendar
  half of the above, DONE 2026-09-10 local-only): same template —
  stable event UIDs (`pending_uid` from the shim `calendar_pending`
  map, else fresh `proton-sync-{account}-{nanos}`), per-op Index
  partition instead of all-or-nothing, UID-conflict adopt via
  `list_by_uid`, unresolvable-conflict fail-closed, re-list-confirmed
  drain (out-of-window creates stay pending — convergent on dedupe,
  never worse than fresh). Conflict semantics undocumented in proton-cal
  (Overwrite: 0 sent, behavior on clash unknown) — the design is ≥
  status quo in every branch (upsert→converges, error+row→adopt,
  error+no-row→same stuckness as today). Shim persists wholesale on
  complete AND error + exports for never-synced rows; FFI
  `proton_calendar_get_pending_json`. Verified: fmt + clippy clean, 214
  tests (127+5+82: retry-reuse with same-UID POST proof, adopt,
  unresolvable-fails-closed, contract compat), full bundle green.
  Staged `packaging/buteo-plugin/libproton-client.so` sha256
  `6dcb165aa9309a3753448d748873f41399889f81ded19d8075f9bc1a9a327b6a`
  (supersedes `e46b3605…` — deploy only this). Live delta: none on
  happy path; phone gate is deploy + steady sync.
- [ ] **FIDO2 feasibility re-research** (filed 2026-09-09 by user
  challenge — RESEARCHED 2026-09-09, verdict in `FINDINGS_OTP.md` §9):
  the fingerprint reader canNOT become an authenticator (live fpd
  introspection: enroll/match-only API, no keys/signing — fingerprint is
  UV *inside* an authenticator, not one; software-authenticator path not
  recommended). But the server needs no browser (challenge arrives in
  auth-info, assertion POSTs to `core/v4/auth/2fa`), so **roaming USB-HID
  keys via native CTAP2** (`webauthn-authenticator-rs` et al.) are
  feasible in principle — sketch + build risks + key-matrix caveat in
  §9c. Do not start without a real USB-C key in hand (host CLI probe
  first, then port). Default stays: loud failure + TOTP-coexistence
  guidance.

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
