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
