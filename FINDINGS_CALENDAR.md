# Calendar + Token-Key Findings – 2026-09-05 (research before implementation)

Per user instruction: no try-and-error on device; research docs + reference
implementations first, local tests before any device run. Phone
(defaultuser@192.168.1.124, no root – ask for root commands), SDK container
`coderus/sailfishos-platform-sdk-aarch64:latest`, Proton test account
`tiziano.incognito@proton.me` (ask for OTP) – all reserved for later.

## 1. Stub inventory (verified 2026-09-05)

- `proton-api/src/calendar.rs` – BROKEN (uncommitted): calls `verify_signature`
  which does not exist → `cargo test` fails. `decrypt_calendar_keys` body was
  already replaced in working tree (decrypt MemberPassphrase with address keys
  → unlock calendar keys) – direction correct, needs tests.
  Remaining stubs: `list_events` sends only Start/End, no `Type`, no
  pagination, no 93-day chunking; no `get_members`/`get_bootstrap`; `parse_ical`
  only 6 fields, no unfolding/folding, no params, no RRULE/EXDATE/SEQUENCE/etc.
- `proton-sync/src/calendar.rs` – `run_sync` lists calendars/events but
  decrypts with `&mut [], &mut []` (always fails), only counts events.
- `proton-sync/src/calendar_full.rs` – `process_event` fabricates
  `summary="Proton Event <UID>"`, no decrypt, no JSON plumbing to C++.
- `proton-sync/src/engine.rs` – `derive_passphrase`/`get_passphrase_for_key`
  ignores `Token` (`_token` unused) → PLAN known issue
  `addrkey_…_no_pp_token=true`. Address keys with Token never unlock.
- `proton-bridge/src/bridge.rs` – `proton_calendar_*` FFI broken:
  `start_sync` discards stored config (`SyncConfig::default()`), no derived
  passwords, no events JSON/keys_debug/refresh/uid getters.
- `proton-bridge/cxx/proton_bridge_shim.cpp` – `ProtonCalendarPlugin::startSync`
  writes 1 hard-coded test event to `defaultCollectionId`, no credentials,
  no Rust engine, no per-account collection, no GUID dedupe.

## 2. Reference implementations consulted (no device needed)

- `ProtonMail/go-proton-api` `keyring.go`: `Key::Unlock(passphrase, userKR)`:
  if `Token=="" || Signature==""` → secret=passphrase; else decrypt armored
  `Token` with user keyring, verify detached `Signature` with user keyring,
  binary content = secret → unlock `PrivateKey`. `Unlock()` in `unlock.go`:
  user keys via salted passphrase, address keys via `TryUnlock(pass, userKR)`.
  → Our fix: keep unlocked user keys, for each addr key with Token try
  `decrypt_contact_card(Token, user_keys)` (lenient: skip signature verify
  on Token path, log).
- `go-proton-api` `calendar_types.go`: `CalendarPassphrase::Decrypt(memberID,
  addrKR)` finds member entry, `decrypt` = PGP-decrypt armored Passphrase +
  `VerifyDetached` (optional in practice). `CalendarKeys::Unlock(passphrase)`
  tries every key, keeps those that unlock (old generations needed).
  → Our `decrypt_calendar_keys` matches; keep lenient (skip sig verify).
- `go-proton-api` `calendar_event_types.go` `CalendarEventPart::Decode`:
  `Type` enum Clear=0/Encrypted=1/Signed=2 (3=both, bit flags – our `&1`/`&2`
  correct). If Encrypted + `kp!=nil` → `Data` is base64 raw, combine via
  `NewPGPSplitMessage(kp, raw)` then decrypt with calKR; else armored PGP
  decrypt with calKR. If Signed → `VerifyDetached(Data, Signature)` with addrKR.
  → Our `decrypt_calendar_event` must accept optional key packets
  (`SharedKeyPacket`/`CalendarKeyPacket`): base64(kp)+base64(Data) concat as
  binary OpenPGP message → sequoia decrypt. Signatures: lenient skip (see below).
- `cheeseandcereal/proton-cal` `docs/crypto.md` + `docs/api.md` + `docs/overview.md`
  (verified live June 2026, best reference):
  - Hierarchy: password → SRP → salts → salted passphrase (bcrypt, strip
    29-char prefix) → user key → address key (Token) → calendar passphrase
    (per-member armored, try ALL address keys, sig verify optional) →
    calendar keys (keep all that unlock) → 2 session keys per event.
  - Event split: Shared signed (Type2: UID/DTSTAMP/DTSTART/DTEND/RRULE/EXDATE/
    SEQUENCE/ORGANIZER…) + Shared encrypted (Type3: SUMMARY/DESCRIPTION/
    LOCATION + every “rest” property) + Calendar signed (STATUS/TRANSP) +
    Calendar encrypted (COMMENT) + Attendees encrypted. Fragments are full
    `BEGIN:VCALENDAR/VEVENT` wrappers, CRLF, no VERSION/PRODID, no trailing
    CRLF – strict parsers reject; must merge.
  - Merge rule (`ical.MergeFragments`): shared-signed wins structural
    (UID/DTSTAMP/DTSTART/DTEND/RRULE/RECURRENCE-ID/SEQUENCE), first-seen wins
    otherwise, multi-valued (EXDATE/ATTENDEE) unioned. `X-PM-SESSION-KEY`
    stripped. Row fields outside cards: `Color`, `Notifications` tri-state
    (null=inherit, []=none, array=custom), `Attendees/AttendeesInfo`,
    `IsOrganizer`, etc. – must re-send verbatim on update.
  - Listing: `GET /calendar/v1/{id}/events` ONLY window-filters when `Type`
    supplied. Must query all 4 Types (0=PartDayInside,1=PartDayBefore,
    2=FullDayInside,3=FullDayBefore) in parallel, `PageSize<=100`,
    paginate via `More` (not Total), window ≤93d (8035200s), pad ±1d,
    dedupe by ID. Unscoped query returns everything (trap). `?UID=` filters
    server-side. `MetaDataOnly` has no effect. Single event = `{"Event":{}}`.
  - Bootstrap: `GET /calendar/v2/{id}/bootstrap` = Keys+Passphrase+Members+
    Settings in one call (only v2 route; list stays v1). List response drift:
    Name/Description/Color now only on `Members[0]`, top-level legacy fallback.
    Type 0=normal/1=subscribed/2=holidays. Default calendar =
    `GET /settings/calendar → DefaultCalendarID`.
  - Write path (future): `PUT /calendar/v1/{id}/events/sync` batch only,
    whole-object replace – updates must re-send Notifications/Color/Attendees
    verbatim + patch cards in place. Out of scope for read-only v1.
  - Lenient decrypt (`event.Decrypt`): skips sig verify + unparseable parts,
    sets `DecryptFailed`, errors only on nil. → We adopt same: signature
    failures never fail decrypt.
  - Scopes: restored sessions lack salts scope (403/9101); salts must be
    fetched at login or via `PUT /core/v4/users/unlock`. Our sync uses stored
    DerivedPasswords so no salts call needed – document.
- `proton.me/blog/protoncalendar-security-model`: member passphrase
  encrypted+signed with address key; event Data encrypted with calendar key +
  signed with author address key. Confirms key-packets model.
- `Nojuza/proton-calendar-cli` `RESEARCH.md`: same 4-part model, CALENDAR_CARD_TYPE
  0/1/2/3, sync endpoint primary write, `Start/End` ignored without Type (paginate
  client-side). Confirms api.md.
- `ProtonMail/gopenpgp` docs: split message = `BinaryKeyPacket()` +
  `BinaryDataPacket()` (both base64 in our JSON). Concatenating binary packets
  yields decryptable message (attachment issue #14 confirms concat works when
  done on raw bytes, not armored text).
- Sailfish Calendar stack (`docs.sailfishos.org/.../Calendar`):
  Platform API = KCalendarCore + mKCal (SQLite, Sailfish is upstream),
  QML = `nemo-qml-plugin-calendar`, sync via `buteo-sync-plugin-caldav`
  (`NotebookSyncAgent`, `icalconverter`). Our QOrganizer `mkcal` approach
  writes to same DB and is acceptable for read-only v1; full CalDAV-style
  would use `mKCal::ExtendedCalendar` directly – noted as future.
  `buteo-sync-plugin-caldav/src/notebooksyncagent.cpp` (1466 lines) confirms
  per-account notebooks/collections + GUID/UID mapping + full-replacement vs
  incremental – we mirror contacts pattern (clear collection → save new).

## 3. Implementation plan (local-first)

1. `calendar.rs`: add `verify_signature` lenient no-op (fixes build); extend
   `decrypt_calendar_event(part, cal_keys, addr_keys, shared_kp, cal_kp)` with
   split-packet path (base64 concat → sequoia) + armored fallback; add
   `get_members`, `get_bootstrap`, `list_events(Type,Page,PageSize)` +
   `list_all_events_windowed` (4 Types, 93d chunks, More-pagination, dedupe);
   rewrite `parse_ical` with unfolding + param-stripping + full field set.
   Offline tests: unfolding, params, rest-rule, split-decrypt via generated
   keys, window-chunking logic, bootstrap/member parsing.
2. `engine.rs`: implement Token path – after unlocking user keys, try
   `decrypt_contact_card(Token, user_keys)` → secret → `UnlockedKey::from_armored`.
   Keep derived-map fast path. Tests: synthetic user+address keys with Token.
3. `calendar` engines: single real engine (auth refresh → unlock addr →
   bootstrap per calendar → unlock cal keys → windowed list → decrypt+merge →
   JSON with row metadata). Keep `calendar.rs` + `calendar_full.rs` API compat
   initially, then unify.
4. `bridge.rs` FFI: mirror contacts engine (derived in, JSON out, keys_debug,
   refresh/uid). Tests: FFI round-trip with mock server.
5. `proton_bridge_shim.cpp`: credentials (copy contacts pattern) → Rust engine
   → poll → QOrganizer mapping (label/desc/location/start/end/allDay/recurrence/
   reminders/collection per account/GUID). No device run until SDK
   `aarch64` compile passes in container.

## 6. Implementation log – 2026-09-05 (local only, no device run)

All verified with `cargo fmt`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings` (clean), `cargo test --workspace --all-features`
(31 passed: 27 proton-api + 4 proton-sync-calendar), cross
`cargo build --release --target aarch64-unknown-linux-gnu -p proton-bridge`
in `proton-build-env` (OK after fixing a corrupted `.cargo-home` cc-1.4.4
extraction – root-owned files, removed via container `--user root`; pre-existing
infra issue, unrelated to code), and SDK-container `moc` + `g++ -c` of
`proton_bridge_shim.{h,cpp}` (OK after two Qt 5.6 fixes below).

- `proton-api/src/calendar.rs`: fixed build break (`verify_signature` now a
  lenient no-op, never fails – matches proton-cal lenient read path).
  Added `decrypt_calendar_part` (split-packet `base64(kp)+base64(Data)` concat
  → `decrypt_bytes_with_key`, armored fallback, calendar keys first then
  address keys); kept `decrypt_calendar_event` wrapper. Added `get_members`,
  `get_bootstrap` (v2 with v1 fallback), `list_events_page` (Type+Page+PageSize,
  `More` cursor), `list_all_events_windowed` (4 Types, 93d chunks, ±1d pad,
  dedupe). Rewrote `parse_ical` (unfold, param-strip, TEXT unescape, UID/
  SUMMARY/DESCRIPTION/LOCATION/DTSTART/DTEND/DTSTAMP/CREATED/RRULE/EXDATE/
  SEQUENCE/STATUS/TRANSP/ORGANIZER/ATTENDEE) + `merge_ical_fragments`
  (shared-signed first wins structural, multi-valued unioned). 10 new offline
  tests (mockito for paging/bootstrap, unfolding/params, merge priority,
  lenient sig, signed-only no-keys, encrypted-no-keys).
- `proton-api/src/crypto.rs`: added `decrypt_bytes_with_key`,
  `decrypt_raw_with_key`, `decrypt_raw_bytes_with_key` (binary Token path
  needs non-UTF8 plaintext; existing `decrypt_with_key` is UTF-8 only).
- `proton-api/src/models.rs`: added `CalendarMember`, `CalendarBootstrap`,
  `CalendarEventsListResponse`, row columns (`RRule/Exdates/RecurrenceID/Color/
  Notifications/IsOrganizer/Permissions`); `Default` derives for calendar types.
- `proton-sync/src/engine.rs`: Token-aware address unlock
  (`decrypt_token_secret` via `decrypt_raw_with_key` on unlocked user keys,
  then `UnlockedKey::from_armored`; salt fallback preserved; Token-derived
  secrets cached into derived map). Fixes PLAN `addrkey_…_no_pp_token` issue.
- `proton-sync/src/calendar.rs`: real engine (refresh → unlock user+address →
  per-calendar bootstrap → member pick (first, list returns own) + any-member
  fallback → `decrypt_calendar_keys` → `list_all_events` windowed →
  per-part decrypt with correct key packet → merge → `CalEventJson` with row
  metadata). 4 offline tests (signed-only decrypt, encrypted-no-keys skip,
  member pick, token restore).
- `proton-sync/src/calendar_full.rs`: stub removed; thin delegating wrapper
  around `calendar::CalendarSyncEngine` (API compat only).
- `proton-bridge/src/bridge.rs` + `lib.rs`: calendar FFI mirrors contacts
  (`create_with_derived`, correct stored-config `start_sync` (was
  `SyncConfig::default()` bug), `get_events_json` snapshot+live fallback,
  `get_keys_debug`/`get_refresh_token`/`get_uid`). Header regenerates via
  cbindgen (gitignored).
- `proton-bridge/cxx/proton_bridge_shim.{h,cpp}`: `ProtonCalendarPlugin`
  rewritten (was 1 hard-coded test event): SignOn NoUserInteraction via
  `proton-caldav` (fallback `proton-carddav` shared identity) + CredentialsId
  healing + QSettings derived fallback → Rust engine → 500ms poll → QSettings
  token persist → `writeEventsToMkCal` (per-account collection
  `Proton Calendar (<id>)`, full-replacement delete, GUID
  `proton-cal-<acct>-<eventId>`, start/end with unix fallback, allDay,
  FREQ-only recurrence, mailto: attendees). Qt 5.6 fixes found by container
  compile: `QDateTime::fromSecsSinceEpoch` → `fromTime_t` (Qt 5.8+ only),
  `removeItems(ids, errMap)` → `removeItems(ids)` (no 2-arg overload).
  New QtOrganizer includes verified present in SDK sysroot.

Remaining for future (not started, need live data + device):
- Recurrence: only FREQ mapped; no COUNT/UNTIL/BYDAY expansion, no EXDATE/
  RECURRENCE-ID exception rows, no `Notifications`→VALARM mapping, no Color→
  collection mapping, no attendees RSVP rows, no upload/sync-write path
  (`PUT .../events/sync` whole-object replace – see api.md pitfalls).
- Token `Signature` verify still skipped (lenient, documented); consider
  sequoia detached-verify once author public keys are available.
- `parseCalTime` TZID handling is floating (no QTimeZone conversion); all-day
  exclusive-end semantics assumed; member pick is first-member (refine by
  AddressID/email for shared calendars once live bootstrap seen).
- Live verification still required: fresh OTP (30s window, ask user), root
  commands on phone terminal (`devel-su` fails over SSH; `journalctl` needs
  root), then `make-pkg-bundle.sh` full link + `scp` + on-phone `cp/chmod` +
  `pkill signond` + `restart msyncd` + `dbus-send startSync proton-caldav-<id>`.

## 7. Live runs – 2026-09-06 (test account, read-only host tool)

Tool: `proton-sync/examples/live_calendar_check.rs` (SRP → 2FA → real
`CalendarSyncEngine`; prints summaries + `keys_debug` only, never tokens).

- Run 1: login + OTP accepted; Token unlock VERIFIED (`a_KBB-LONd_tok_ok`),
  calendar keys unlock on both calendars — but 0 events, silent `complete`.
- Run 2 (`LIVE_DIAG=1`): all Type-scoped queries → **400 Bad Request**.
  Root cause: 93d server cap (code 2000). The diag used a 730d window, and
  the engine chunked ≤93d but then applied ±1d padding → up to 95d → 400,
  swallowed by `unwrap_or_default` into a false empty success.
- Fixes: content chunks ≤91d (`MAX_WINDOW_SECS - 2*86400`) so padded spans
  stay ≤93d (+ regression test); tolerant `More` parsing (int/bool/Total
  fallback); per-calendar query errors tracked and returned instead of
  silent empty success; calendar display name from `Members[0]`
  (top-level `Name` is empty — confirms api.md response drift).
- Run 3: exact-93d spans (8035200s) STILL 400 on both calendars. Window
  size is not the (only) cause — need the response body Code. Added
  `fetch_events_raw` (no `error_for_status`) + 4-combo probe in the live
  tool (typed 30d / typed 30d+Timezone / untyped / untyped+window).
- Run 4 (probe): **root cause found**: `400 {"Code":2000,"Error":"The
  Timezone is required"}`. The `Timezone` query param is MANDATORY (docs
  list it as optional). With `Timezone=UTC`, typed queries return 200 with
  rows; untyped also works. Bonus finding: real signed fragments DO carry
  `VERSION:2.0` + `PRODID:-//Proton AG//web-calendar…` (our parser already
  skips both). Fix: `Timezone` threaded through `list_events_page` /
  `fetch_events_page_raw` / `list_all_events_windowed` ("UTC" default).
- Run 5 (Timezone fix): `complete`, 0 events, no errors — queries 200-empty,
  contradicting run 4's probe which returned rows for [now+335d, now+365d].
  Added `LIVE_TRACE` per-query logging (cal/type/window/page → rows/more) to
  the windowed listing to see what each chunk returns.
- Run 6 (same session): probe rows again (SunhQ4…, aG1c-…); envelope loop
  400s are just its 730d windows. **Untyped sweep: 19 + 1 = all 20 events
  exist server-side.** Typed+UTC at 93d spans returns 200-empty while 30d
  returns rows → suspected real cap < 93d (disproved in run 8).
- Run 9 (head-to-head): `fetch_events_page_raw` on the probe's 7d window →
  Type=0: 2 rows, Type=1: 2 rows. URLs well-formed (`Timezone=UTC` present).
  Engine path exonerated; run 6 empties were server-side typed-query lag.
  Typed envelopes carry `[Code, Events, More]` (no `Total`; `More` numeric).
- Run 10: same-session probe rows + engine zero again. Decision: engine now
  uses untyped paged listing + client-side overlap filtering (recurring
  masters always included), the approach Nojuza/proton-calendar-cli documents
  as reliable. Typed windowed code retained (mock-tested) for future perf
  work; the intermittent typed 200-empty anomaly is unexplained — all
  evidence (identical URLs, same token/session, overlapping windows) is
  logged above for a future live session.
- Run 11 (untyped engine): `complete` total=0 again — binary verified fresh
  (new-code strings present, rlib newer than source). Rows arrive (sweep
  counts them) but never reach output: suspect is now the client-side
  overlap filter (`StartTime < end && EndTime > start`) or zero/unset row
  times. Sweep now prints first-row StartTime/EndTime/RRule + window.
- Run 12: sweep shows real rows (`StartTime=1788723000`, in-window) yet
  engine outputs 0. Hardened parsing (lenient calendar models, element-wise
  rows) + regression test — still 0 on the next run.
- Run 13: added raw-vs-kept per-page tracing inside `list_all_events_untyped`
  to locate the drop (fetch / filter / process) definitively.
- Run 23: body HAS all 19 rows — `raw=0` is purely our parse dropping every
  row. `#[serde(default)]` doesn't accept explicit `null`s or type mismatches,
  and one bad field killed the row. Fix: null-tolerant scalars
  (`deserialize_string_default` / `deserialize_i64_default` /
  `deserialize_opt_i64`) on all row/part fields, element-wise rows AND
  parts, skip-error logging with row ID, live-shaped regression test
  (nulls in every scalar). Previous typed/untyped/ordering mysteries were
  all this one bug (null bodies were never on the wire).
- Run 24: **20/20 events decrypted** (`complete total=20`). Verified live:
  T01 UTC, T02 zoned-floating, T03/T04 all-day (exclusive end), T05 escapes,
  T06 folding, T07 location-only, T08 empty-summary (UID fallback),
  T09–T11 FREQ+COUNT, T12 yearly since 2016 (BeforeWindow), T13 UNTIL,
  T14 EXDATE=1, T15 master+exception (same UID, exception has no RRULE),
  T16 attendees=2, T18 past event, T19 midnight span, T20 second calendar
  (member name "porcodio" — member-based names work). **T17
  (STATUS:CANCELLED) not returned by the server at all** — cancelled events
  are omitted from listing (nothing to map; no code change).
  Note: T03 single-day all-day has no DTEND in fragments (row unix times
  cover it via shim fallback).

## 8. Calendar test-event matrix – 2026-09-06 (for live mapping verification)

Note: calendar maps to QOrganizer/mkcal (not QContact). Tag every summary with
`[Tnn]` to correlate phone items with Proton events. Shim v1 maps: summary→
displayLabel, description, location, allDay, dtstart/dtend (unix fallback),
guid `proton-cal-<acct>-<id>`, rrule FREQ→recurrence, attendees mailto:.
NOT mapped in v1 (record phone behavior as future work): organizer, STATUS,
TRANSP, SEQUENCE, EXDATE list, reminders/Notifications, Color, DTSTAMP/CREATED.

- T01 simple UTC timed (SUMMARY/DESCRIPTION/LOCATION, DTSTART/DTEND …Z, 1h).
- T02 zoned timed (TZID=Europe/Rome wall-clock; checks floating-time fallback).
- T03 all-day single (VALUE=DATE, DTEND exclusive next day).
- T04 all-day multi-day (3 days; end=start+3d exclusive).
- T05 description with `\n`, `\,`, `\;`, `\\` escapes + unicode/emoji.
- T06 long description (>75 octets, folded lines; checks unfold).
- T07 location only + summary (no description).
- T08 empty summary (must fall back to UID as displayLabel, must still sync).
- T09 daily recurring (RRULE:FREQ=DAILY;COUNT=5).
- T10 weekly recurring (FREQ=WEEKLY;COUNT=4).
- T11 monthly recurring (FREQ=MONTHLY;COUNT=3).
- T12 yearly recurring all-day (FREQ=YEARLY; birthday-style, old start year –
  exercises FullDayBeforeWindow Type 3).
- T13 recurring with UNTIL (timed, UNTIL in UTC end-of-day form).
- T14 recurring + EXDATE (single-occurrence delete; EXDATE union path).
- T15 recurring + edited occurrence (exception row, same UID + RECURRENCE-ID,
  SEQUENCE>=master; same-UID dedupe uses row ID so both rows must appear).
- T16 organizer + 2 attendees (ORGANIZER/ATTENDEE mailto: mapping).
- T17 STATUS:CANCELLED + TRANSP:TRANSPARENT (documents unmapped STATUS/TRANSP).
- T18 past event (started last month; exercises PartDayBeforeWindow Type 1).
- T19 multi-day timed spanning midnight (22:00→02:00).
- T20 second calendar event (per-account collection + calendar_id/name check).

## 4. Device checklist (DO NOT RUN YET – needs user)

- Ask user for: root commands on phone terminal (`devel-su` fails over SSH),
  fresh OTP (30s window, coordinate live), `journalctl` (needs root, volatile).
- Build: `cargo test` → `cargo build --target aarch64-unknown-linux-gnu` →
  SDK container `moc`+`g++` for both `.so` → `scp` to `/tmp` → user runs
  `cp`+`chmod`+`pkill signond`+`restart msyncd` on phone → trigger
  `dbus-send startSync proton-caldav-<id>` → read `/tmp/proton-sync-debug.log`.

## 5. References (URLs verified 2026-09-05)

- https://github.com/cheeseandcereal/proton-cal (docs/overview.md, crypto.md, api.md)
- https://github.com/Nojuza/proton-calendar-cli/blob/main/RESEARCH.md
- https://proton.me/blog/protoncalendar-security-model
- https://github.com/ProtonMail/go-proton-api/blob/master/calendar_types.go,
  calendar.go, calendar_event_types.go, keyring.go, unlock.go
- https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/Apps_and_MW/Calendar
- https://github.com/sailfishos/buteo-sync-plugin-caldav

## 9. Device runs – 2026-09-05/06 (account 104 = tiziano)

- `libQt5Organizer.so.5` is NOT in the 5.2 image (nothing `*rganizer*`
  under /usr/lib*) — new `.so` failed to load (`PLUGIN_ERROR`, zero log
  lines; contacts broke too). Fix path: user installed
  `qt5-qtpim-organizer` from Jolla repo (1 command, no rebuild). Moot now:
  the mKCal rewrite dropped the organizer linkage entirely (spec instead
  gained `Requires: mkcal-qt5` + `kf5-calendarcore`). Worse: the `mkcal`
  QOrganizer *backend* is absent too (`QOrganizerManager mkcal error=1`),
  so QOrganizer can never reach the calendar DB here — backend must move
  to mKCal/KCalendarCore (present: libmkcal-qt5 0.7.22, KF5CalendarCore
  5.117; SDK sysroot lacks their headers — vendor or fetch -devel).
- First calendar run (after lib install): SignOn refresh OK, then
  `get_key_salts` → **403/9101 locked-scope** on the restored session —
  exactly the proton-cal documented case. Our engines treated salts as
  fatal; fixed to best-effort in both `unlock_address_keys` and contacts
  `unlock_keys` (derived + Token paths don't need salts). Rebuilt,
  relinked, staged `/tmp/libproton-client.so` (awaits user `cp`).
- UI toggle doesn't propagate: Settings Calendar toggle stayed off in
  msyncd's copy (`enabled=false` reverts on restart); `updateProfile` via
  gdbus + immediate `startSync` works around it for tests. Toggle wiring
  needs a look (service XML vs AccountsHelper mapping).
- mKCal rewrite (2026-09-06): backend moved QOrganizer → mKCal 0.7.33 +
  KF5CalendarCore 5.116 (exact device -devel RPMs pulled via
  `pkcon download`, headers vendored in `proton-bridge/device-headers/`,
  include layout from the shipped `.pc` files). Mapping now covers
  summary/desc/location/allDay/start/end + FREQ/COUNT/UNTIL + EXDATEs +
  recurrence-id linkage + attendees/organizer + status/transparency/color
  + per-account notebook `proton-calendar-<id>` with full replacement.
- User verification 2026-09-06 (20/20 in mkcal): T20 no per-calendar
  distinction; all-day +1 day (T03×2, T04×4); T05 "ed emoji"→"edemoji"
  (unfold stripped ALL leading spaces, RFC removes exactly one — fixed +
  regression test); T15 exception not visible (needs recurrence_id data);
  T17 N/A by design (deleted events never listed; cancelled-status needs a
  declined invite, not a deletion). Fixes: per-Proton-calendar notebooks
  (legacy single notebook retired on next sync), all-day exclusive-end −1d,
  recurrence_id plumbed to JSON. Staged `/tmp/libproton-client.so`.
- T15 root cause (data 2026-09-06): event tz is Africa/Abidjan (UTC+0);
  exception rid=1789502400 (Sep 15 20:00Z) == occurrence 20:00 Abidjan, but
  the deployed shim stored floating times as phone-local CEST (18:00Z) → 2h
  mismatch → orphaned exception. Same 2h shift affected ALL Abidjan-timed
  events' display. Fix: attach event QTimeZone to floating times (already
  implemented + SDK-verified, awaiting deploy).
- T15 dissociate path 2026-09-06 10:47: with unambiguous UTC construction,
  `recursAt=1`, rid=20:00Z, dissociate succeeded, 20/20 saved — yet the
  phone still shows all occurrences at the edited time. Display/storage
  investigation continues (DB path unknown on this port).
- Dump attempt 1 (2026-09-06): forgot `LIVE_DIAG=1`, dump block skipped;
  incidentally re-confirmed host rid=1789502400 stable + T02 tz=Europe/Rome
  (mixed account timezones: Rome/Abidjan/UTC).
- Also fixed per user report: `make-pkg-bundle.sh` now takes `--no-deploy`
  (or `SKIP_DEPLOY=1`) to skip all ssh/scp contact instead of the
  localhost hack that popped SSH dialogs.
- T15 CLOSED 2026-09-06 11:11: `recursAt=1`, rid=20:00Z, dissociate
  succeeded, 20/20 saved. Post-mortem of the confusion: the device
  `22:00Z` readings were NEVER server data — Qt 5.6 `fromTime_t` returns
  local wall time (CEST 22:00) and `setTimeSpec(UTC)` kept the wall clock,
  so the LOGGED rid was corrupted while host (new Qt) read 20:00Z from the
  identical row. The per-session-rendering theory is withdrawn; the
  `utcFromUnix` fix addresses the true cause. Lesson: verify conversion
  primitives on-device, not just logic.
- T15 journal (root, 2026-09-06): `not loading <uid> (local changes)` for
  all 20 rows — mkcal skips reloading rows with pending local inserts, i.e.
  our adds ARE queued correctly; harmless by-product of a redundant load.
- mKCal DB path (from `databaseName()` log): standard
  `~/.local/share/system/privileged/Calendar/mkcal/db` (earlier
  "missing folder" was a permission artifact of listing as non-root).
- Account cleanup (user question 2026-09-06): on account deletion Buteo
  removes sync *profiles* but synced *data* is the plugin's job — we have
  no removal handler, so collections/notebooks would orphan. TODO:
  account-removed handler deleting the per-account QContactCollection +
  mkcal notebook (both already account-keyed).
- T15 decomposed (2026-09-06): dissociated exceptions never persist
  (in-memory success, absent in DB, save 0/0 — framework exception
  machinery unreliable here), while plain events + EXDATEs use proven
  paths. Exceptions now: EXDATE original on master + standalone edited
  event (`<uid>#<rid>`). Staged `/tmp/libproton-client.so` (9978784).
- Decomposed exception persists (row 60, live, correct Sep 15 22:30 times,
  no rid). Delete pass still removes 18 of 19: one live ghost survives per
  cycle — census pending to identify it.
- Census 2026-09-06: exactly the right 20 live rows (T08 shows UID as
  summary ✓, T15 master + T15 exception both live ✓, T20 in own notebook),
  no ghosts/dupes — the 18-vs-19 count gap is log noise, end state proven
  correct. Awaiting user visual confirmation of T15 (Sep 14/15/16).
- T15 CLOSED (user-confirmed 2026-09-06): exception at Sep 16 00:30 CEST
  (= Sep 15 22:30 Abidjan), master series with EXDATE suppressing Sep 15.
  All matrix items pass. Remaining TODOs: Settings-toggle→profile wiring,
  account-deletion data cleanup, reminder (Notifications)→VALARM mapping,
  upsync (read-only v1). (Spec already gained mkcal-qt5/kf5-calendarcore
  Requires; organizer dep eliminated with the mKCal rewrite.)

## 10. TODO for Follow-up (consolidated 2026-09-06)

Calendar sync:
- [x] Settings-toggle→profile wiring (FIXED 2026-09-06, verified end-to-end): labels come from
  `AccountsUtil.serviceDisplayNameForService` (hardcoded name list, then
  type map). Our caldav service was typed `carddav` → two "Contacts"
  toggles, so the user flipped Contacts and the calendar profile stayed
  disabled. DB row 44 confirmed cached as `carddav`. Deeper: the stock
  toggle hardcodes a CalDAV discovery page for `serviceType === "caldav"`
  which reverts on failure — impossible for Proton. Fix applied: custom
  service type `proton-calendar` (plain switch + own display name per the
  default branch; msyncd/shim match by NAME). Staged
  `/tmp/proton-caldav.service`; DB row updated, user flipped ON, profile
  self-enabled, `startSync` true with no workaround, sync 0/0 (20 saved).
  Cosmetic remainder: toggle has no description line (default branch).
- [x] Account-deletion data cleanup: per user feedback, explicit pulley-menu
  action instead of magic auto-cleanup. Forked `proton-settings.qml`
  (stock agent has no menu hook) + new `Proton 1.0` QML extension
  (`proton-bridge/settings/`, `ProtonDataPurger.purgeData`) with remorse.
  VERIFIED 2026-09-06 end to end: purge deleted collection + both notebooks
  (`purgeData done ok=1`, UI empty), re-sync restored 1 contact + 20 events.
- [x] Reminders (2026-09-06): `Notifications` tri-state row field now flows
  to JSON (`parse_notification_trigger` + offline tests for -PT15M/-PT1H/
  -P1D/-P1W/-PT0S/unsigned/garbage/months-rejected) and is stored as
  KCalendarCore VALARMs (display/email, start-offset). Null (inherit
  calendar defaults) stays untouched for the app to resolve. Staged
  `/tmp/libproton-client.so` — needs a reminder-bearing event to verify
  (none of T01–T20 has custom reminders).
- [x] Calendar-default reminders (2026-09-06): events with `Notifications:
  null` inherit the calendar's `DefaultPartDayNotifications` /
  `DefaultFullDayNotifications` (fetched via bootstrap `CalendarSettings`
  + v1 `/settings` fallback) so the phone fires the same reminders Proton
  shows (e.g. 15 min before). Explicit `[]` stays reminder-free. Covered by
  offline resolve tests (timed/all-day/explicit/garbage-skipped). Restaged
  `/tmp/libproton-client.so` (18:25) with both halves.
- [x] Reminder live-fire (2026-09-06): user created an event 20 min out
  with a 15-min reminder; sync stored 21 events.
- [x] Verify VALARM rows (CLOSED 2026-09-06 21:22 — root cause was the
  `MakesUserBusy` SILENT PARSE KILLER below, not the v2/v1 gap; `Alarm
  COUNT(*) = 21` verified live, re-verified 21 on 2026-09-07): bootstrap
  v2 carries NO `CalendarSettings` and all rows are `Notifications: null`
  — defaults live only on the v1 `/settings` route (verified: 15-min timed
  / 15-hour full-day). `get_bootstrap` now fills the gap (+ mock tests).
  Staged `/tmp/libproton-client.so` (18:44).
- [x] UID clash across re-created accounts (ROOT-CAUSED + FIXED
  2026-09-06, user spotted it): stored mKCal UIDs were the RAW Proton/ical
  UIDs while mKCal enforces storage-wide uniqueness → orphan 104 rows made
  every 105 batch INSERT fail the whole `save()`. Fix `namespacedUid()`
  (`proton-cal-<id>-<raw>`) at all three UID sites. VERIFIED 21:03:
  `Saved 21`, and full-replacement correctly `Removed 20+1` then re-saved.
- [x] Reminder defaults (CLOSED — the "server-null" theory below was WRONG;
  superseded by the SILENT PARSE KILLER entry: live envelope DID carry real
  defaults, `MakesUserBusy: 1` killed the parse. First recorded as RESOLVED
  as server-null 2026-09-06 21:03): the
  verbose shape line shows `http200 keys=[CalendarSettings,Code]
  inner=[...DefaultFullDayNotifications,DefaultPartDayNotifications...]`
  yet parsed empty — struct field names match, so the server sends the
  keys with NULL values: this account has NO default reminders
  configured. Our parser is innocent; the earlier "15-min/15-hour"
  reading was Proton clients' client-side fallback, not stored data.
  Consequence: `Notifications:null` events correctly get no VALARM;
  only the explicit 21st-event reminder stores (expect Alarm=1). Open
  product call: mirror Proton clients with a hardcoded client-side
  default (e.g. 15 min before) for null-Notification events.
  REJECTED by user (horrible idea) — and unnecessary, see next entry.
- [x] SILENT PARSE KILLER (found 2026-09-06 21:15 via full-body logging,
  user-requested): the live envelope DOES carry real defaults
  (`-PT15M` display+email part-day, `-PT15H` display+email full-day) but
  `"MakesUserBusy": 1` (Go int-bool) failed the strict
  `Option<bool>` field → whole-struct `from_value` failed →
  `unwrap_or_default()` → fake "empty". The codebase already had
  `deserialize_opt_bool` for this hazard (`Display`, `FullDay`) —
  `MakesUserBusy` just missed the attribute.   Fixed + regression test
  with the exact live envelope. Shipped 21:19; expect `settings=1` and
  Alarm ≈ 21 (display Type 1 inherited, email Type 0 skipped as
  server-sent).   VERIFIED 21:22: `settings=1` both cals, `Saved 21`, and
  `Persisted calendar defaults for account 105` (cache seeded — later
  restored sessions inherit even if live settings ever go empty).
  VERIFIED 21:2x: `Alarm COUNT(*) = 21` on device. Reminders saga closed. Lesson applied per user feedback: settings responses now
  log full scrubbed bodies (`diag.rs`: secret redaction + 8k cap), and
  the account-level `/settings/calendar` route is logged per sync too
  (view prefs only — defaults live per-calendar, confirmed).
- Correction (2026-09-06): the "every sync refreshes first" theory was
  WRONG for the calendar engine — `CalendarSyncEngine::new` calls
  `set_expiry(3600)` when an access token is present, so the phone uses
  SignOn's token directly (hence no `refresh_scopes=` line: no refresh
  ran). Salts 403 + `locked` remains unexplained but non-blocking
  (derived path unlocks everything).
  Note: fresh login ALSO returns `settings_empty` (20:08, minutes-old
  session), so the defaults cache cannot self-seed from the phone —
  seeding via host live tool + direct QSettings write is the fallback
  plan (needs fresh OTP).
- [x] Scope probe results (CLOSED — conclusion was "emptiness is NOT
  scope-related at all", and the true root cause was found later as the
  `MakesUserBusy` parse killer; no action left. Host, OTP 20:4x): refresh
  does NOT narrow
  scopes — `Scope=full self payments keys parent user loggedin
  nondelinquent mail calendar drive pass verified settings wallet meet`
  (note: NO `locked` in the list, yet salts work) — and salts_ok both
  fresh and refreshed. BUT `/settings` parses empty on the FRESH
  full-scope session too: the emptiness is NOT scope-related at all.
  Open: server truly has no defaults vs our parser dropping the shape
  (`get_settings` falls back to the whole envelope when the
  `CalendarSettings` key is absent, then `unwrap_or_default()` hides
  the difference). Next: instrumented build logs `refresh_scopes=`
  (what the phone session really holds) and `settings_empty http..
  keys=[..] inner=[..]` per cal. (Probe artifact noted: the probe's own
  refresh rotates the server token, 401ing the subsequent engine run —
  probe now exits early.)
- [x] Cache calendar defaults for restored sessions (CLOSED — fully
  implemented engine `last_defaults` → `proton_calendar_get_defaults_json`
  → shim QSettings persist/feedback; live "Persisted calendar defaults for
  account 105" 2026-09-06, re-persisted 2026-09-07. Was in progress
  2026-09-06): on restored logins the v1 `/settings` ALSO returns `{}`
  (`settings_empty` on all three cals, verified 19:05) — so there is
  nothing to inherit and `Alarm COUNT(*)` stays 1 (custom-only event).
  Design: engine records last-seen non-empty defaults per cal
  (`last_defaults`, parsed via the same Type-0-skipping parser) and
  exposes them via `proton_calendar_get_defaults_json` (null when this
  run saw none — never clobbers a good cache); the shim persists them to
  QSettings `proton/sync-tokens/<accountId>/calendar_defaults` on
  `complete` and feeds them back through
  `..._with_derived_and_defaults` as `SyncConfig.calendar_defaults`.
  Precedence: explicit array > live defaults > cached defaults > none.
  Unit-tested (`test_resolve_notifications_cached_fallback`); workspace
  green (35+2+11), clippy/fmt clean. NOT yet staged — needs a FRESH login
  first (only fresh sessions return real settings to seed the cache),
  then a restored-session sync to verify `Alarm COUNT(*)` ≈ 21.
- Empty-`{}` normalization (2026-09-06): v2 can also send an empty
  `CalendarSettings` object (present-but-useless → old code skipped the v1
  fill-in). `is_empty()` treats it as absent on both paths. Email
  reminders (Type 0) are server-sent — no longer stored (display only).
  Process note: verify deploys by sha256, not timestamps (phone/host
  clocks disagree by minutes).
- [x] Verify VALARM rows (CLOSED — duplicate of the entry above; same
  `MakesUserBusy` root cause, `Alarm COUNT(*) = 21` verified 2026-09-06 and
  2026-09-07): either bootstrap carries no defaults (parse gap?) or rows
  are all null and defaults resolution isn't triggering. Added
  `LIVE_CALSET` diag (bootstrap Settings dump + per-row raw
  Notifications).
- [ ] Upsync (currently read-only): local creates/edits/deletes never reach
  Proton (`PUT .../events/sync` whole-object replace — see api.md pitfalls:
  re-send Notifications/Color/Attendees verbatim, patch cards in place,
  reuse session keys, SEQUENCE rules for exceptions).
- [x] Recurrence fidelity (2026-09-07, local only — needs live T09–T15
  re-sync to verify on device): INTERVAL/BYDAY/BYMONTHDAY/BYMONTH/BYYEARDAY/
  BYWEEKNO/BYSETPOS/WKST now parsed (Rust `parse_rrule` + 4 offline tests)
  and mapped to `KCalendarCore::RecurrenceRule` (`setFrequency/setByDays/
  setByMonthDays/setByMonths/setByYearDays/setByWeekNumbers/setBySetPos/
  setWeekStart`; HOURLY/MINUTELY/SECONDLY added; COUNT wins over UNTIL;
  BYHOUR/BYMINUTE/BYSECOND ignored by design — time comes from DTSTART).
  EXDATEs now interpret floating values in the event timezone (was hardcoded
  UTC → 2h shift for zoned events). RECURRENCE-ID (+RANGE) parsed into
  `recurrence_id_ical` for completeness; row `RecurrenceID` unix stays
  authoritative for the decomposed-exception path. Moved-across-days
  exceptions still show standalone (correct times) instead of linked — the
  mkcal exception machinery never persisted dissociated rows (see §9 T15).
  Workspace green (47+2+12), clippy/fmt clean, SDK `moc` + `g++ -c` OK.
  See §11 for details. Remaining: visual re-check of T09–T15 after deploy.
- [x] Attendees/invites identities (2026-09-07, local only): ORGANIZER CN
  and ATTENDEE CN/RSVP/PARTSTAT/ROLE/CUTYPE now parsed (quoted-CN and
  colon-in-CN safe) into `CalAttendee` + `organizer_name`, plumbed through
  `CalEventJson.attendees_full` (backward compatible: legacy `attendees`
  email list + `organizer` bare email kept), and stored as
  `KCalendarCore::Attendee(name,email,rsvp,status,role)` + `Person(name,
  email)` organizer with legacy fallback. Covered by 5 Rust offline tests
  + 1 engine passthrough test. Remaining (still open): RSVP status sync
  back to server, invitation sending, CUTYPE display — all need the upsync
  write path (`PUT .../events/sync`).
- [x] Tombstone accumulation: purge soft-deleted rows scoped to our
  notebooks after each successful save (`deletedIncidences` +
  `purgeDeletedIncidences`; upsync caveat noted in code). Staged
  `/tmp/libproton-client.so` — verify via sqlite tombstone count.
- [ ] Typed windowed listing anomaly (runs 1–10 notes above): identical
  typed queries intermittently 200-empty while untyped succeeds; untyped +
  client filter is primary, typed code retained mock-tested for future work.
- [ ] Token `Signature` verify skipped (lenient, proton-cal behavior) —
  consider sequoia detached-verify once author public keys are available.
- Derived-map shadowing (2026-09-06): different logins stored single-key
  maps per group (`[104]`={addr}, `[Uid]`={user}); first-hit-wins broke
  contacts (user key needed, shadowed). Fix: merge all sources
  (accountId < username < Uid < blob) in both handlers, with source
  logging.
- Merge VERIFIED 2026-09-06 17:45: `derived_keys=2`, `userkey_…_ok`,
  `addrkey_…_ok_via_token`, contact decrypted + saved. The complete
  go-proton-api chain (derived user unlock → Token decrypt → address
  unlock → card decrypt) works live on restored sessions.

Contacts sync (from PLAN.md, still open):
- [ ] Two-way sync (download-only today), incremental sync (full fetch),
  cross-source dedup, multiple photos (first avatar only).

Packaging/release:
- [x] Repo URLs (`nappa85/proton-bridge` to match remote, in workspace
  `Cargo.toml` + both specs).
- [x] Release integrity (2026-09-06): staged tarballs were stale (missing
  caldav service, update UI, settings plugin; `.o` junk; deleted
  `proton-creation.qml`). `make-pkg-bundle.sh` now assembles both tarballs
  deterministically from the repo (version from Cargo.toml). `release.yml`
  fixed three ways: `--no-deploy` (was stalling/failing on phone scp),
  stamp-before-bundle (tarballs + spec copies cohere), and in-place `mb2`
  invocation (short-circuit skips `%prep`, so the old `-w packaging/rpm`
  could never unpack). Both RPMs verified built locally with correct
  contents + deps. Also added the missing `proton-update.qml` to the
  account spec (was absent from the RPM).
- [x] Mutual `Requires` (2026-09-06): neither RPM worked alone (engine
  without provider = dead code; provider without engine = dead toggles).
  Verified in built RPM metadata both directions. Unversioned (parsers are
  forward/backward tolerant by design).

## 11. Recurrence + attendee fidelity – 2026-09-07 (local only, no device)

Per user instruction: research docs + reference implementations first, local
tests before any device run. No OTP / root / ssh used in this session.
Phone (defaultuser@192.168.1.124) and SDK container reserved for the deploy
step below. Baseline before changes: `cargo test` 38+2+11 green,
`cargo fmt --check` clean, `clippy -D warnings` clean.

### References consulted (no device needed)

- RFC5545 §3.3.10 (recur rule parts: FREQ/UNTIL/COUNT/INTERVAL/BYDAY/
  BYMONTHDAY/BYYEARDAY/BYWEEKNO/BYMONTH/BYSETPOS/WKST + BYDAY numeric-prefix
  rules + Limit/Expand table) via icalendar.org (FREQ required, INTERVAL
  default 1, BYDAY `+1MO`/`-1SU` only valid MONTHLY/YEARLY, COUNT/UNTIL
  mutually exclusive, missing BYxxx falls back to DTSTART).
- `KCalendarCore::RecurrenceRule` (device -devel headers vendored in
  `proton-bridge/device-headers/`): `setFrequency/setByDays(WDayPos)/
  setByMonthDays/setByYearDays/setByWeekNumbers/setByMonths/setBySetPos/
  setWeekStart`, `WDayPos(pos, day)` day 1=MO..7=SU pos 0=all, `setRRule`
  is store-only (not evaluated), `setDuration(COUNT)` vs `setEndDt(UNTIL)`.
- `KCalendarCore::Attendee` (`Attendee(name,email,rsvp,status,role)`,
  `PartStat` NEEDS-ACTION/ACCEPTED/DECLINED/TENTATIVE/DELEGATED/COMPLETED/
  IN-PROCESS, `Role` CHAIR/REQ-/OPT-/NON-PARTICIPANT, `setCuType(QString)`)
  + `KCalendarCore::Person(name,email)` + `setOrganizer(Person)` (device
  headers; `setOrganizer(QString)` email-only path kept as fallback).
- Prior art in repo: `buteo-sync-plugin-caldav` `NotebookSyncAgent`
  (per-account notebooks + GUID mapping pattern we already mirror);
  proton-cal `ical.MergeFragments` (shared-signed wins structural,
  multi-valued union — extended here to attendee_details by email).

### What changed (all offline-testable, backward compatible)

- `proton-api/src/calendar.rs`:
  - `split_ical_line_full` (colon outside quoted params) + `parse_ical_params`
    (quote-aware `;` split, DQUOTE strip) + `parse_mailto_email` + structured
    `parse_attendee_identity` / `parse_organizer_identity`.
  - `ParsedCalendarEvent` gains `organizer_name`, `attendee_details:
    Vec<CalAttendee>`, `recurrence_id`, `recurrence_id_range` (all
    `#[serde(default)]`); `organizer` is now the BARE email (was the raw
    `mailto:` URI — the shim's `stripMailto` makes this compatible both ways);
    `attendees` legacy email list kept alongside `attendee_details`.
  - `parse_rrule` → `RecurrenceSpec` (lenient: bad parts skipped, INTERVAL
    defaults 1, numeric BYDAY prefix validated via plain `parse::<i32>`,
    lists deduped + range-clamped, WKST validated, BYHOUR/MINUTE/SECOND
    ignored by design).
  - `merge_ical_fragments` merges the new fields (first-wins structural +
    attendee union by email).
  - 10 new offline tests: weekly BYDAY+INTERVAL, monthly numeric BYDAY +
    BYMONTHDAY, yearly BYMONTH+UNTIL+BYSETPOS, lenient-garbage, attendee
    RSVP/PARTSTAT/ROLE/CUTYPE, quoted-CN comma, RECURRENCE-ID+RANGE,
    EXDATE-TZID merge union, quoted-colon split. Existing
    `test_parse_ical_unfolds_and_strips_params` updated for bare-email
    organizer + new detail assertions.
- `proton-api/src/lib.rs`: re-export `CalAttendee/RecurrenceSpec/RruleByDay/
  parse_rrule` for the sync engine.
- `proton-sync/src/calendar.rs`: `CalEventJson` gains `organizer_name`,
  `attendees_full`, `recurrence_id_ical`, `recurrence_id_range` (all
  `#[serde(default)]` — old phone builds ignore them, new builds accept old
  JSON); `process_event` populates them; new passthrough test incl. old-JSON
  compat check.
- `proton-bridge/cxx/proton_bridge_shim.{h,cpp}`: `Person` include;
  `fillEventFromJson` now maps INTERVAL/BYDAY (numeric-prefix aware)/
  BYMONTHDAY/BYMONTH/BYYEARDAY/BYWEEKNO/BYSETPOS/WKST (+HOURLY/MINUTELY/
  SECONDLY FREQ; COUNT-wins-over-UNTIL; raw RRULE also stored via
  `setRRule` for reference), interprets EXDATEs in the event timezone
  (was hardcoded UTC), prefers `attendees_full` objects (CN/RSVP/PARTSTAT/
  ROLE/CUTYPE → `Attendee`/`setCuType`) with legacy string-list fallback,
  and sets organizer as `Person(name,email)` with email-only fallback.

### Verification (local only)

- `cargo fmt --all` + `cargo fmt --check --all` clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
  (fixed 6 pedantic lints: dead_code wrapper, collapsible-match/if, simpler
  BYDAY numeric parse).
- `cargo test --workspace --all-features`: 47 + 2 + 12 = 61 passed, 0 failed
  (was 38+2+11 = 51; +10 new).
- SDK container `moc` + `aarch64-meego-linux-gnu-g++ -c` of
  `proton_bridge_shim.{h,cpp}`: both OK (only pre-existing
  `incidences(notebook)` deprecation warning).

### Deploy checklist (DO NOT RUN YET — needs user)

- Staging + full link + device deploy still pending for these changes:
  `./make-pkg-bundle.sh` (needs Docker `proton-build-env` + SDK container),
  then `scp /tmp/libproton-client.so` + on-phone (root, `devel-su` fails over
  SSH — user runs on phone terminal): `cp/chmod`, `pkill signond`,
  `systemctl --user restart msyncd`, `dbus-send startSync proton-caldav-<id>`.
- Live re-check matrix: T09 (DAILY COUNT), T10 (WEEKLY COUNT — now with real
  BYDAY if Proton emits it), T11 (MONTHLY), T12 (YEARLY birthday), T13
  (UNTIL), T14 (EXDATE delete), T15 (master+exception), T16 (organizer + 2
  attendees with CN/RSVP), plus a new BYDAY INTERVAL event if the test
  account has none (e.g. `FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,TH`).
- Still open (future): upsync write path (`PUT .../events/sync`), RSVP sync
  back + invitation sending, CUTYPE display, complex-rule visual diffs for
  moved-across-days exceptions (standalone by design — see §9 T15).

### Live verification 2026-09-07 (device, account 105)

Deployed `libproton-client.so` sha256
`3279c70051d800cbd06c41271bcd22a6e02e244c1e30d2e46368b92943b331a2`
(Rust recurrence + attendee work + shim mapping). Sync result:
`Saved 1 contacts`, `Saved 21 calendar events to mkcal`, `Alarm COUNT(*) =
21` (one Display row per event — confirms the single-relative-offset model,
not per-occurrence expansion). Keys: `derived_keys=2`,
`u_…_derived` + `a_…_tok_ok`, `calkeys=1 addrkeys=2 settings=1` on both
calendars; `salts_unavailable` 403 as expected on restored sessions
(non-blocking, derived+Token path). Account-level `/settings/calendar`
returns view prefs only (`PrimaryTimezone: Africa/Abidjan` — matches the
mixed Rome/Abidjan/UTC account timezones seen in §9); per-calendar defaults
came from the v1 settings route and were re-persisted
(`Persisted calendar defaults for account 105`). Notebooks for both Proton
calendars were (re)created per-calendar as designed. Remaining: user visual
check in the Calendar app (T09–T15 recurrence series, T14 EXDATE skip, T15
master+standalone exception, T16 organizer/attendees, T20 notebook).

## 12. Upsync write-path design – 2026-09-07 (local only, no live calls)

Per user instruction: research docs + reference implementations first,
offline tests before any device/live run. No OTP / root / ssh used. The
Upsync checkbox in §10 stays `[ ]` — this session built the offline-tested
design layer only; nothing uploads yet.

### Contract (sources)

- proton-cal `docs/api.md` "The sync endpoint (write path)" + "Recurring
  events" (verified live June 2026, best reference) and `pkg/event/
  {wire,write}.go` + `pkg/ical/patch.go` + `pkg/ical/text.go` +
  `pkg/calcolor` (all fetched 2026-09-07).
- ProtonMail/WebClients `packages/shared/lib/api/calendars.ts`
  (`syncMultipleEvents`, personal-part route).

### Rules that drive the design

- ONE write route: `PUT /calendar/v1/{calID}/events/sync`, batch
  `{MemberID, IsImport?, Events[]}`. No standalone POST. Response top-level
  `1001` = batch accepted (`1000` single-op cases); per-op `{Index,
  Response: {Code: 1000, Error, Event?}}`; deletes return top-level only.
- Shapes: create `{Overwrite: 0, Event}` WITH fresh key packets (+
  `IsImport: 0`); update `{ID, Event}` with NO key packets (server keeps
  originals — caller must reuse stored session keys); delete `{ID}`.
- Update = whole-object REPLACE: omitted `Notifications`/`Color`/
  `Attendees` reset server-side. Re-send existing values verbatim unless
  explicitly changing them. `Notifications` tri-state (`null` inherit /
  `[]` none / array custom — mirrors our read-side `resolve_notifications`
  exactly); `Color: null` on update is IGNORED (revert = set the calendar's
  own color explicitly); content arrays `[]` never `null`.
- Cards patched IN PLACE (never rebuilt from fields — rebuild drops
  `X-PM-CONFERENCE-*`, ORGANIZER, attendees card, third-party `X-` props):
  signed card owns structural props (DTSTART/DTEND/RRULE/EXDATE/SEQUENCE),
  encrypted card owns text (SUMMARY/DESCRIPTION/LOCATION), attendees card
  verbatim. Update re-encrypts with the SAME session keys (decrypted from
  stored packets with the calendar key); events without an encrypted
  calendar card (web-app creates) have no `CalendarKeyPacket` — skip it.
- SEQUENCE (server-enforced, code 2001): bump ONLY on significant
  (date/time/recurrence) changes per RFC 5546 — field edits keep it, or a
  master edit leapfrogs its exceptions; exceptions need `SEQUENCE >=
  master`. Master time/rule change invalidates exceptions (clean up
  explicitly). Series delete = master + all same-UID rows in ONE batch (no
  server cascade — orphans otherwise).
- RRULE server limits (mirror web `getIsRruleSupported`): FREQ in
  {DAILY,WEEKLY,MONTHLY,YEARLY}, `COUNT <= 49`, `UNTIL <= 2037-12-31`,
  COUNT/UNTIL exclusive.
- Palette: 20 fixed accent hexes (code 2011 otherwise); vendored in
  `calendar_write.rs` from `pkg/calcolor`.

### Implemented this session (`proton-api/src/calendar_write.rs`, new)

- Wire types with exact PascalCase + presence semantics
  (`SyncEventBody`/`SyncEventOp`/`SyncBatchRequest` with
  `skip_serializing_if`; minimal `SyncContentPart` so `MemberID`/`Author`
  never leak onto the wire) + `SyncBatchResponse::first_error` /
  `first_event` (1000/1001).
- `marshal_notifications` tri-state, `marshal_color`, `marshal_attendees`
  clear rows (`Token`/`Status`/`Comment`), 20-color palette +
  `resolve_color`/`valid_color`/`color_name`.
- `CardPatch` + `patch_card` mirroring `PatchCard` (unfold → Delete, Set
  replaces in place incl. multi-occurrence collapse, missing Sets appended
  name-sorted, Append dedupes, VALARM blocks + wrapper verbatim, 75/74-octet
  folding, no trailing CRLF). One deliberate divergence: server-sent
  `VERSION`/`PRODID` lines are kept verbatim (proton-cal strips; keeping
  bytes the server produced is safer for a whole-object replace).
- `escape_ical_text` mirroring `escapeText` (bare CR dropped).
- `next_sequence` / `exception_sequence_ok`, `delete_batch` builder,
  `CalendarClient::put_sync` transport.
- 15 offline tests (tri-state, palette, wire shapes incl. key-packet
  absence on update, response interpretation incl. 2001 SEQUENCE error,
  patch set/delete/append/nested/fold/round-trip-via-`parse_ical`,
  sequence rules, 2 mockito PUT tests). Workspace: 62+2+12 = 76 passed,
  fmt + `clippy -D warnings` clean. Zero live calls (mockito only).

### Next steps

1. [~] Engine wiring (delete path LIVE-VERIFIED 2026-09-07, creates/updates
   deferred): build `47b3dc6c` deployed, two live syncs confirm the design:
   run 1 (no baseline: rows saved by the old build lack IDs) →
   `upsync_deferred creates=21 updates=0`, NOTHING uploaded (fail-safe);
   `proton_id_map/anchors/last_modified` persisted; run 2 → no deferred
   line at all (all 21 resolve), zero `upsync_deleted`, zero conflicts —
   safe steady state.    `Calendar inventory: 21 live/tombstone rows` both
   runs; `Saved 21` each time.
   FIRST REAL UPLOAD 2026-09-07 11:50 (user deleted one phone event):
   `upsync_deleted cal=RfXFIcmY n=1` → `Saved 20`; follow-up sync stable
   at inventory 20 / Saved 20 — no resurrection, no further deletes,
   tombstone purged via the selective path. USER-CONFIRMED: event gone
   from Proton web. Calendar delete path verified end-to-end.
   UPDATES/CREATES 2026-09-07 (local only, live gate pending):
   `build_update_body` (GET-fresh → patch text/times/RRULE in place →
   reseal same keys; defers attendee/personal rows, undecryptable rows) +
   `build_create_body` (4-part shape, fresh keys, UID passed in, DTSTAMP
   now, all-day exclusive-end + month-rollover tested) with decrypt-back
   tests on generated keys; engine executes creates → updates → deletes
   per cal with re-list reconciliation (deletes filter locally); per-op
   defer (log + skip), transport errors fail closed; unserializable phone
   rules keep the server rule on update / defer creates (never flatten a
   series); fresh-UID collisions on re-list-failure retry documented.
   Shim exports `fields` (dirty/never-synced rows only) + `calendar_id`
   + common-subset RRULE serializer. Engine mockito test with REAL
   generated keys (unencrypted + empty salts + password unlock path).
   UPDATE VERIFIED LIVE 2026-09-08 (user-edited T20, 2nd calendar):
   `upsync_updated cal=jL51FptW n=1`, sync complete, USER-CONFIRMED new
   title on Proton web; phone agrees via post-upload re-list. Path to
   green: address-key signing fix (2001) + attendee-guard/VERSION-strip/
   DATE-param fixes (2011) — exact culprit among the three unisolated,
   all three were genuine divergences from proton-cal.
   CREATE VERIFIED LIVE 2026-09-08 (user-created phone event, main
   calendar): `upsync_created cal=RfXFIcmY n=1` → `Saved 21`;
   USER-CONFIRMED on Proton web with correct time; re-sync stable at 21
   (no duplicates). Notebook scoping confirmed: only our
   `proton-calendar-105-*` notebooks feed the planner — other calendars'
   events are invisible to uploads and untouched by downloads.
   REMINDER UPLOAD VERIFIED LIVE 2026-09-08 (T05 → 1 hour before):
   `upsync_updated n=1`; web shows ONLY the 1-hour display reminder —
   inherited 15-min display AND email both correctly gone (custom list
   replaces inheritance in Proton's model, not merged with it). Phone UI
   limitation noted: the Calendar app edits a single display alarm; email
   reminders can never originate from the phone (explicit server-side
   email entries WOULD be preserved via the Type-0 merge — code-covered,
   no live case on this account).
   PHONE UI WALL 2026-09-08: T16 (organizer + 2 attendees, the only
   attendee event on the account) is fully read-only on the phone
   (no edit, no reminder change — only whole-event delete). Deleting it
   as a test was REJECTED: delete ops are ID-only (no cards involved),
   so an attendee-event delete exercises zero new code paths beyond the
   already-verified plain delete, while destroying irreplaceable
   invite-shaped test data. Attendee-safe updates stay offline-verified
   (decrypt-back + token-preservation tests), which is the right place
   given the UI wall.
   COMPLETE-CALENDAR ROUND 2026-09-08 (local only): attendee-safe updates
   (`Attendees` token rows modeled + re-sent verbatim — RSVP can no longer
   be wiped; only `PersonalEvents`/undecryptable rows defer), reminder
   upload (phone alarms merged with row Type-0 entries, defaults-equal →
   inherit-null, unknown-defaults → verbatim; `""` color reverts to member
   color), out-of-window deletes (`list_by_uid` + engine augment merging
   hits pre-plan), author-matched signing (address-email map, lenient
   match, first-key fallback). Shim exports `notifications`/`color`/`uid`
   + common-subset RRULE; SDK `moc` + `g++ -c` OK. Workspace 79+3+46 =
   128 green. Calendar create/update/delete fully live-verified; checkbox
   stays open pending contacts parity. Remaining known v1 gaps: phone
   attendee-identity edits (download-wins), exotic-rule phone edits
   (server keeps rule), multi-address signer is best-match only.
   LIVE 2001 LESSON 2026-09-08 (first update attempt): server rejected
   with `Invalid event data (Provide data signed using the address key)`
   — root cause OUR bug, not crypto format: `unlock_address_keys`
   returns user keys FIRST, and sealing signed with the first pair (a
   user key). proton-cal seals with the address keyring. Fix:
   `UnlockedAddressKeys{keys, address_start}` split (decrypt tries the
   whole set, SEALING uses `address_only()` exclusively) + structural
   regression test locking the order. Multi-address refinement (match
   signer to the event Author) recorded as future work. If the server
   still rejects after this fix, next suspect is signature hash/type
   (sequoia    `Signer` defaults), not key identity.
   LIVE 2011 ROUND 2026-09-08 (first update retry): address-key signatures
   ACCEPTED, but `code 2011: These properties are not supported`. Type
   constants verified identical to proton-cal (`0/1/2/3`); top-level body
   keys identical too — so it's an iCal property in our fragments. Three
   divergences from the verified reference, all fixed locally (tests
   green, live retry pending): (1) attendee guard scanned only SHARED
   signed cards — invites may carry ORGANIZER/ATTENDEE in CALENDAR signed
   cards (now scans both); (2) our reseal echoed server-sent
   VERSION/PRODID (read-tolerated, never emitted by proton-cal — now
   stripped on update in every group); (3) all-day DATE values lacked the
   `;VALUE=DATE` parameter our parser strips on read (now emitted;
   round-trips through `parse_ical`). Plus failure-only scrubbed batch
   logging (`upsync_{create,update}_rejected`: op IDs + part types +
   notif/color presence, never Data/Signatures/plaintext) so the next
   rejection arrives with structure attached. If 2011 persists, the
   scrubbed line + WHICH event (recurring? all-day? invite?) narrows it
   without another blind round.
   Workspace 75+3+37 = 115 green. Known v1 gaps (documented in code):
   attendee/RSVP/reminder/color phone edits stay download-wins; out-of-
   window deletes can't upload; re-list failure after a create may retry
   into a duplicate (same-content updates/deletes are retry-safe).
   `SyncConfig.local_inventory/anchor_map/api_base_url` (all `#[serde(default)]`,
   `None` = byte-identical download-only); `run_upload_phase` (plan → per-cal
   delete batches → fail-closed abort → filter uploaded from `fetched` →
   purgeable/conflicts/anchors getters); FFI
   `..._create_engine_with_inventory` + `..._get_{purgeable,conflicts,anchors}_json`
   (malformed JSON degrades to `None`, never half-fed); shim feeds
   `exportLocalInventory` + anchors, persists anchors wholesale, selective
   purge = planner set ∪ replacement removals (legacy notebook stays
   unconditional), conflict notification, tombstone-vs-live filter in export.
   `KeysClient`/`CalendarClient` base-url overrides (ungated) for mockito.
   Cycle tests (mock server, zero live calls): tombstone → exact PUT wire
   shape → filtered download + getters; no-inventory run asserts `expect(0)`
   PUTs. `CalEventJson.mtime` feeds anchors. Workspace 68+3+36 = 107 green.
   Creates/updates are PLANNED but not executed (no sealed bodies without
   inventory field data — needs shim field export + engine seal step next).
2. [x] Crypto seal/reseal (DONE 2026-09-07, `proton-api/src/calendar_seal.rs`,
   all offline with generated keys — pure-Rust backend, no fixtures):
   `extract_session_key` (bare PKESK via `PacketPile`, any pair),
   `encrypt_with_session_key` (`Encryptor2::with_session_key`, no recipients
   → SEIP-only bytes, exactly the split model), `fresh_key_packet`
   (`PKESK3::for_recipient`, tries every pair — the primary is usually
   sign-only EdDSA), `detached_sign` (armored, `Signer::detached`), plus
   `seal_card` (create: fresh SK) / `reseal_card` (update: same SK, no new
   packet). 6 tests incl. the killer checks: sealed output decrypts through
   the EXISTING `decrypt_calendar_part` split branch; original-kp + new-data
   decrypts (update invariant); detached sig verifies via
   `DetachedVerifierBuilder` (stronger than our lenient read path);
   wrong-key extraction fails; fresh seals differ. Two API traps recorded:
   `Cert::armored()` is public-only (secrets need `as_tsk()`), and
   `finalize()` cascades (call once on the outermost filter). Workspace:
   68+2+12 = 82 passed, fmt + `clippy -D warnings` clean.
2. [~] Change detection (planning + persist DONE 2026-09-07, wiring pending):
   `proton-sync/src/upsync.rs` — `LocalItem` inventory (mkcal UID,
   optional Proton ID, tombstone/dirty flags, per-row `LastEditTime`
   anchor; serde JSON = exact shim↔engine contract, tested), `plan_sync`
   (creates → updates → deletes order, both-edited → server-wins
   `conflicts`, server-deleted → `apply_server_deletes`, tombstones-with-ID
   → delete ops + `purgeable_tombstones`, orphans counted),
   `AnchorMap::merge_anchors` (upsert, prune only gone-everywhere — never
   merely-unlisted, window != delete), `assemble_delete_batch` (series
   expansion via `ids_for_uid`, unknown IDs pass through),
   `assemble_update_batch`, closure-driven `execute_uploads` (fail-closed,
   no network in tests), fixed `SyncCycle::ORDER`. 21 offline tests.
   Shim: `X-PROTON-EVENT-ID` stamping (previous session) + now
   `persistUpsyncMaps` (id map + anchors + lastModified snapshots, written
   live after every save — harmless until consumed), `exportLocalInventory`
   (live rows + tombstones, custom-prop with id-map fallback, missing
   snapshot = clean so pre-feature rows never mass-upload),
   `purgeListedTombstones` (selective; UNCALLED — unconditional purge stays
   until wiring). `CalEventJson` gained `mtime` (anchor feed). SDK `moc` +
   `g++ -c` OK. Workspace 68+2+33 = 103 green. Still wiring-phase: FFI
   inventory/anchors in-out, engine cycle execution, call-site switch of
   the purge, tombstone custom-prop survival check live.
3. [ ] Personal-part route (`PUT .../events/{id}/personal`) for
   reminder-only edits (cheaper than full reseal) + invite/RSVP flows.
4. [ ] Live gate: fresh OTP session + a scratch test event (create → edit →
   exception → series-delete) before wiring into the sync engine.

## 13. Pid-less tombstone deletes – 2026-09-09 (local only, no device/live)

Audit of the "out-of-window deletes can't upload" TODO found it stale:
the UID augment (`run_upload_phase` + `list_by_uid`, mock-tested) already
covers tombstones carrying (proton_id, uid). The TRUE residual hole was
narrower: a tombstone with a raw UID but NO Proton ID (id-map entry lost
— custom prop shed + `proton_id_map` miss) planned as a silent orphan
(`orphan_local_deletes`) even when its rows existed server-side, so the
server event survived a phone delete forever. Fixed, mirroring the
existing series-delete semantics: the engine augment now also UID-lists
pid-less tombstones (hits deduped by row ID — a UID query can return
rows the window already listed), and `plan_sync` resolves them from the
merged rows — master tombstone → one Delete (the batch assembler expands
the UID series as usual), `<uid>#<rid>` standalone → the surviving
occurrence row only (`exception_rid` helper; numeric-UID guard included),
rid-miss or no rows → orphan path unchanged. One Delete op suffices in
all cases (`assemble_delete_batch` expands via `ids_for_uid`, same as
stamped tombstones). Verified: fmt + clippy `-D warnings` clean,
177 workspace tests green (+6: 5 planner incl. rid parsing/series/
miss/empty cases, 1 mockito engine cycle asserting the exact
`{"MemberID":"m1","Events":[{"ID":"e9"}]}` PUT for a pid-less
tombstone), `make-pkg-bundle.sh --no-deploy` green. Staged
`packaging/buteo-plugin/libproton-client.so` sha256
`364ef3d0d45ce2a2920039374c1919ec208544dc3092b6f67b181fccfb2db41a`
(supersedes `147ae55f…`; also carries no other changes). Live
behavioral delta after deploy: none on the happy path (same plans for
all previously-covered shapes); only id-map-loss tombstones change
(delete instead of silent orphan). Phone gate: deploy + steady sync
(zero ops expected), no OTP needed.

## 14. Personal-part route – 2026-09-10 (local only, no device/live)

Reminder-only phone edits took a full reseal + whole-object replace
(SEQUENCE churn, 2001/2011 surface for changing nothing structural).
Researched first: WebClients `updatePersonalEventPart`
(`PUT calendar/v1/{calID}/events/{eventID}/personal`,
`CreateSinglePersonalEventData{Notifications, Color}` — just two
fields, no cards/keys) + `Api.ts` response shape. Implemented:
`PersonalEventBody` + one shared Notifications/Color marshal used by
BOTH routes (extracted from the update path — existing override tests
prove no behavior change); `CalendarClient::put_personal` (HTTP +
envelope-code failures keep the body, contacts-4xx lesson);
`content_matches_except_notifications` strict whitelist (every compared
field present and exactly equal — times vs authoritative row columns
with the all-day adjustment, texts vs decrypted merged view;
non-recurring, no attendees/exdates/recurrence/personal rows; any
decrypt failure or doubt → existing replace); engine routes
notification-change-only updates to it (distinct `upsync_personal`
trace, same re-list discipline). 210 workspace tests green, bundle
green, staged `e46b3605…`. Phone gate: reminder change on a plain
event → `upsync_personal` + web shows it; text/time edits must still
reseal.

### Live 2026-09-10 — PERSONAL ROUTE VERIFIED (+ parity note)

Deployed `e46b3605…` (sha-checked). Reminder change on a plain event →
`upsync_personal cal=RfXFIcmY id=wFxf…`, 21 saved, web shows the 1-hour
display reminder with the inherited email gone. That email loss is
Proton-model-correct, NOT a regression: byte-identical to the 09-08
full-reseal verification of the same edit (custom list replaces
inheritance, including on Proton web itself; the phone edits a single
display alarm and can never originate email). Explicit server-side
email entries remain preserved via the Type-0 merge on later edits
(unchanged code path). Personal route proven semantically identical to
the reseal for reminder edits, minus crypto/SEQUENCE/rejection costs.
Remainder: one text/time edit to prove the router still reseals those.

## 15. Calendar create idempotency – 2026-09-10 (local only, no device/live)

Contacts-side retry work exposed the same hole here (fresh
`proton-sync-{account}-{nanos}` UID per attempt → POST-ok + re-list-fail
duplicates). proton-cal documents `Overwrite: 0` sends but NOT clash
semantics, so the design assumes nothing: stable UIDs + per-op Index
partition + adopt-via-`list_by_uid` on any non-1000 code +
fail-closed otherwise + re-list-confirmed drain (out-of-window creates
stay pending — convergent on dedupe, never worse than fresh). Branch
analysis: upsert→converges, error+row→adopt, error+no-row→today's
stuckness. Shim `calendar_pending` wholesale-persisted on both outcomes
+ exported for never-synced rows; FFI getter added. Tests found two
mock-harness truths worth keeping: mockito 1.7 serves never-hit mocks
first (catch-alls shadow query mocks until hit — `.expect(0)` marks
satisfied), and the windowed re-list filters 1970 fixtures (use live
timestamps). 214 workspace tests green, bundle green, staged
`6dcb165a…`. Phone gate: deploy + steady sync (no behavior change
without a failure).

## 16. RSVP/invite write contracts – 2026-09-10 (research only, no code)

The TODO asked for the contract before any code; here it is (all
fetched 2026-09-10, no device needed). Deliberately no implementation:
there is no phone-side trigger (attendee events are fully read-only in
the Calendar app — T16 wall, reconfirmed) and no live invite data, so
code would be unverifiable dead weight.

### Routes (WebClients `api/calendars.ts`, all live client shapes)

- RSVP change: `PUT calendar/v1/{calID}/events/{eventID}/attendees/
  {attendeeID}` body `{Status, UpdateTime, Comment?}` (`updateAttendee-
  Partstat`). `Status` = `ATTENDEE_STATUS_API` (verified against
  `calendar/constants.ts`: 0 NEEDS_ACTION / 1 TENTATIVE / 2 DECLINED /
  3 ACCEPTED — byte-identical to our `AttendeeToken.Status` comment).
  `Comment` = `{Message, Type}` (0 cleartext / 1 encrypted+signed).
- Invite acceptance (no local event yet): `PUT calendar/v1/events/{uid}/
  accept` body `{Signature}` (`acceptInvite` — UID-addressed, not event
  ID). Signature construction (what is signed) NOT recovered — needs
  the web accept-flow source or a live trace; do not guess.
- Sending/adding attendees: via the sync update's `Attendees` clear
  rows + `AttendeesEventContent` cards (api.md `formatData`); proton-cal
  `api.md` documents reads + sync shape but no attendee-authoring flow.
  Needs the web composer/invite source before any code.
- Calendar-membership invitations (`…/invitations[/{id}]/{accept,reject}`,
  `getCalendarInvitations`) are a DIFFERENT feature (shared calendars),
  not event RSVP — do not conflate.

### Gaps in our stack for each (all verified against code)

1. RSVP needs the attendee **ID**: the route takes `{attendeeID}` but
   our `AttendeeToken` keeps `{Token, Status}` only, and the `Attendee`
   interface carries ID and Token as SEPARATE fields (relation
   unknown — do NOT assume equal). Also missing: `UpdateTime`
   tracking, `Comment` model, and self-attendee resolution (web uses
   `selfAddress`/`selfAttendeeIndex` matched against account
   addresses). Plus the trigger question above.
2. Acceptance needs the signature recipe (open) + live invite data.
3. Authoring needs the web composer flow (open) + the same live data.

Recommendation (unchanged): keep download-wins + verbatim attendee
re-send (already live-safe); revisit when a live Proton-to-Proton
invite exists on the test account AND a phone trigger is identified.

### Live 2026-09-11 — PERSONAL ROUTE, SECOND PROOF

Deployed `e45896a4…` (sha-checked; steady contacts sync green first).
T02 (zoned Rome event) → 2-hour reminder → `upsync_personal
cal=RfXFIcmY`, 21 saved, no reseal, web confirmed. Reminder-only path
verified twice live (1-hour + 2-hour, UTC + zoned). Remainder: text/time
edit proving the router still reseals those.

### Live 2026-09-11 — ROUTER DISCRIMINATION PROOF (personal TODO closed)

T02 description edit → `upsync_updated cal=RfXFIcmY n=1` (full reseal,
no personal path), 21 saved, web confirmed. With the two reminder-only
proofs, the router is verified live in both directions: reminders take
the cheap personal PUT, content edits take the whole-object replace.
