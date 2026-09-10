# Contacts Upsync Findings – 2026-09-09 (research before implementation)

Per user instruction: no try-and-error on device; research docs + reference
implementations first, local tests before any device run. Phone
(defaultuser@192.168.1.124, no root – ask for root commands), Proton test
account `tiziano.incognito@proton.me` (ask for OTP) – both reserved for the
live gate below. Nothing in this session ran on the phone or against the
live API.

## 1. References consulted (all fetched 2026-09-09, no device needed)

Authoritative (WebClients = what the Proton web app actually sends):

- `ProtonMail/WebClients` `packages/shared/lib/contacts/encrypt.ts`
  (`prepareCardsFromVCard`, `splitVCardProperties`): Type 3 =
  `encryptMessage{encryptionKeys:[userPublic], signingKeys:[userPrivate],
  detached:true}` → `(Data, Signature)`; Type 2 =
  `signMessage{stripTrailingSpaces:true, detached:true}`; FN auto-added
  (from `n` given/family, else first email, else `Unknown`), UID auto-added
  (`generateProtonWebUID`); Type 0 only when categories exist.
- `.../contacts/constants.ts`: `SIGNED_FIELDS = version, prodid, fn, uid,
  email + key fields`; `CLEAR_FIELDS = version, prodid, categories`;
  `VCARD_KEY_FIELDS = key, x-pm-mimetype, x-pm-encrypt(-untrusted), x-pm-sign,
  x-pm-scheme, x-pm-tls`; `ADD_CONTACTS_MAX_SIZE = 10` (batch ≤10);
  `API_SAFE_INTERVAL = 100` (100 req/10s); `CONTACTS_REQUESTS_PER_SECOND = 10`.
- `.../contacts/surgery.ts` (`prepareForSaving`): drops empty props, adds
  `pref` ordering to fn/email/tel/adr/key/photo, adds `itemN` groups to
  emails missing them.
- `.../contacts/vcard.ts` (`vCardPropertiesToICAL`): VERSION:4.0 forced;
  PRODID emitted ONLY if present as a property (fresh phone-built contacts
  have none — imports preserve the source's).
- `.../contacts/decrypt.ts`: Type 3 decrypts with user keys (whole armored
  message, no split packets — unlike calendar); UID lines are stripped from
  ENCRYPTED cards after decrypt (`sanitizedCards`).
- `packages/shared/lib/api/contacts.ts`: `POST contacts/v4/contacts`
  `{Contacts:{Cards}[], Overwrite, Labels, Import?}`; `PUT
  contacts/v4/contacts/{id}` `{Cards}`; **`PUT contacts/v4/contacts/delete`
  `{IDs}`** (never HTTP DELETE); `DELETE contacts/v4/contacts` = wipe all.
- `packages/shared/lib/helpers/uid.ts`: `proton-web-<8hex>-<4hex>-…`
  (8-4-4-4-12) UID shape.
- `packages/shared/lib/constants.ts`: `CONTACT_CARD_TYPE`
  `ENCRYPTED_AND_SIGNED=3, SIGNED=2, ENCRYPTED=1, CLEAR_TEXT=0`.

Corroborating (go-proton-api = proven live client, same `/contacts/v4`
base our reads use):

- `contact.go`: `POST /contacts/v4`, `PUT /contacts/v4/{id}`,
  **`PUT /contacts/v4/delete`** `{IDs}`; `GET /contacts/v4` (+`/{id}`).
- `contact_types.go`: `CreateContactsReq{Contacts []ContactCards, Overwrite,
  Labels}` (objects-with-Cards), `UpdateContactReq{Cards}`,
  `DeleteContactsReq{IDs}`.

## 2. Bugs found by research (all would have failed live; all fixed locally)

1. **Create request shape** (`proton-api/src/models.rs`): we sent
   `Contacts: Vec<Vec<ContactCard>>` → `{"Contacts":[[{…}]]}` (bare
   arrays). Both references send objects-with-Cards
   (`{"Contacts":[{"Cards":[{…}]}]}`). Fixed: new `CreateContactCards{Cards}`
   struct; engine wraps each sealed entry; mockito POST now asserts the
   `"Contacts":[{"Cards":[` prefix; new `test_create_request_wire_shape`.
2. **Delete method + path** (`proton-api/src/contacts.rs:delete`): we sent
   `DELETE /contacts/v4` + `{IDs}`. BOTH references use
   `PUT …/delete` + `{IDs}`. Fixed to `PUT /contacts/v4/delete`
   (go-proton-api base, same as our working reads); delete-cycle mock
   updated to PUT + body assert.
3. **Fresh UID format + collision** (`engine.rs` nanos
   `proton-sync-contact-{nanos}`): non-WebClients shape, and two creates in
   one fast loop could share a UID. Fixed: `generate_contact_uid()`
   (`contacts.rs`, `getrandom`, zero new deps, time+pid fallback) emitting
   `proton-web-8-4-4-4-12`; engine uses it per job; shape+uniqueness test.
4. **Empty FN** (`vcard.rs:build_vcard`): nameless+emailless contacts emitted
   `FN:` (empty). WebClients falls back to `Unknown`
   (`getFallbackFNValue`). Fixed + test.
5. **PRODID always emitted** (`vcard.rs`): fresh web contacts carry VERSION
   only; PRODID comes from imports. Always-emitting risked a calendar-style
   2011 property rejection. Dropped (VERSION still forced by the wrapper) +
   `test_build_vcard_emits_no_prodid`. Read-side `is_known_vcard_prop`
   unchanged (PRODID stays read-tolerated).

Hygiene: removed the `get()` debug dump to `/tmp/proton-contact-raw.json`
(world-readable raw contact JSON on every fetch; cf. PLAN debug-log TODO).

## 3. Design notes (deliberate, do not "unify")

- Cards seal to the USER keypair (encrypt to user-public, detached-sign
  with user-private) — the OPPOSITE of calendar (calendar keys + address
  signatures). `contact_seal.rs` header already records this.
- Our seal (sequoia encrypt + separate detached sign over plaintext) is
  wire-equivalent to openpgpjs `encryptMessage{signingKeys, detached:true}`
  (encrypted Data + detached plaintext Signature). Decrypt-back through the
  existing read path is test-covered.
- `detached_sign` does not `stripTrailingSpaces`; harmless — we generate
  lines without trailing spaces, and calendar signatures with the same
  primitive are already live-accepted.
- EMAIL `itemN` groups + `pref` params (WebClients `prepareForSaving`) are
  NOT emitted v1: acceptable for key-less contacts (grouping only matters
  for per-email key settings, which defer via the unknown-props guard).
  Recorded as a gap, not a bug.
- Split contract verified match: signed = uid/fn/emails (+VERSION),
  encrypted = N/TEL/ADR/ORG/TITLE/ROLE/NOTE/URL/BDAY/ANNIVERSARY/NICKNAME/
  GENDER/PHOTO, no Type 0 without categories.

## 4. Remaining v1 gaps (documented, need live data or product calls)

- Deferred-update visibility: FIXED 2026-09-09 (file-log trace, §7) —
  deferral reasons with IDs now land in the log every run. Still open:
  surfacing deferred counts in the conflict notification (currently the
  download still overwrites a deferred local edit; the next snapshot then
  looks clean).
- Create retry duplication: POST success + re-list failure → Err →
  next cycle retries the create with a NEW UID (fresh UID is not persisted
  against `qcontact_id`). Same as calendar's documented caveat.
- Rate limit: updates are one PUT per row with no `API_SAFE_INTERVAL`
  pacing (fine for a handful of edits; bulk edits could 429).
- No photo upload (server photos preserved on update, dropped on create);
  no categories/Type 0 emission; key fields (`KEY`, `X-PM-*`) defer updates.
- `apply_server_deletes` / `stale_map_entries` need no consumer: full
  replacement already drops server-deleted rows, and `persistContactsMaps`
  overwrites the map wholesale (self-pruning). Noted so nobody "wires"
  them redundantly.

## 5. Verification log (local only, 2026-09-09)

- `cargo fmt --check --all` clean; `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` clean.
- `cargo test --workspace --all-features`: 95 + 3 + 63 = 161 passed,
  0 failed (was 88+3+56 before this session; +13 new).
- Cross `cargo build --release --target aarch64-unknown-linux-gnu
  -p proton-bridge` in `proton-build-env`: OK (also after the 400 fixes).
- SDK-container `moc` (407 lines) + full `make-pkg-bundle.sh --no-deploy`
  link of `proton_bridge_shim.{h,cpp}`: OK (only pre-existing `incidences`
  deprecation warnings).
- Staged `/home/marco/Progetti/sailfish-proton/packaging/buteo-plugin/
  libproton-client.so` sha256
  `2e52fffa999bc801ce91594278b8aa682987967ea8311ff9ff09ad4efd851282`
  (GROUPED-EMAIL + error-body build; supersedes all earlier builds —
  deploy none of those) (via `make-pkg-bundle.sh --no-deploy`, transferred
  to phone `/tmp`, sha verified).
- New host live-gate tool `proton-sync/examples/live_contacts_check.rs`
  (compiles; NOT RUN — needs fresh OTP): scratch create → update → delete
  through the production engine, asserts 1 row → edited row → zero rows,
  prints IDs/codes only.

## 6. Live gate (DO NOT RUN YET — needs user)

Attempt 2026-09-09 (~07:20 UTC): host wire gate BLOCKED before any upload —
SRP `POST /core/v4/auth` returned **422 Code 9001 HumanVerification**
(CAPTCHA, `verify.proton.me` token) on the first attempt. Our client sends
the correct `web-mail@6.3.2` + `curl/8.0` (verified in `auth.rs`), so this
is IP/reputation-based (host network, and/or the test account's recent
login count — calendar live tools last succeeded 2026-09-07). The OTP was
never consumed (`submit_2fa` never ran). Do NOT rapid-retry logins (worsens
the flag). Paths: (a) retry host gate later with a fresh OTP; (b) user
completes the CAPTCHA in a browser; (c) skip to the phone gate — the phone
syncs via stored `RefreshToken` (no SRP login, no CAPTCHA) and covers the
same wire shapes end-to-end (paths (a)/(b) stay open for later).

Attempt 2026-09-09 (~07:35 UTC, fresh OTP): STILL blocked — new
HumanVerification token issued. The flag is persistent for this host
network, not a transient window; host SRP logins are unusable until the
flag clears or the CAPTCHA is completed in a browser. OTP again unconsumed
(login fails before 2FA). Decision: phone gate (steps 2–3 below).

1. Host wire gate (proves §2 fixes against the real API, no phone):
   `PROTON_TEST_PASSWORD='…' cargo run -p proton-sync --example
   live_contacts_check -- tiziano.incognito@proton.me <OTP>` (fresh code,
   30s window — coordinate). Uses uniquely-marked `SailfishProbe<nanos>`
   rows, deleted in step 3; abort leaves at most one scratch row, which a
   re-run does NOT clean (marker differs) — delete via Proton web if needed.
2. Phone deploy (root on phone terminal, `devel-su` fails over SSH):
   `scp packaging/buteo-plugin/libproton-client.so
   defaultuser@192.168.1.124:/tmp/` then on phone:
   `cp /tmp/libproton-client.so
   /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so && chmod 755 … &&
   pkill -9 -x signond; systemctl --user restart msyncd`.
   Verify sha256 on phone matches §5 before restart.
3. Phone sync gate: scratch contact create → edit → delete in the People
   app, one `dbus-send startSync proton.Contacts-<id>` per step, watch
   `/tmp/proton-sync-debug.log` (`upsync_created/updated/deleted`,
   `upsync_deferred`) + Proton web as ground truth.

## 7. 07:33 incident — server contact wiped by an edit (2026-09-09, live)

Symptom: user edited the single synced contact on the phone ("nappa85")
and synced; the contact vanished from BOTH the phone collection and Proton
web. Baseline 07:31 sync was clean (1 row, no uploads, steady state).

CORRECTED root cause (the "create+delete pairing" theory below was WRONG —
the 08:32 re-wipe with the new file-log trace disproved it: `plan c=0 u=0
d=1` for a present, known, modified row is impossible with a parsed
inventory): **`ParsedContact.photos` lacked `#[serde(default)]` while the
shim never sends the `photos` key** (no photo upload v1). So EVERY
inventory row carrying `fields` — i.e. exactly the edited/dirty rows —
failed the WHOLE `Vec<ContactItem>` parse (`missing field photos`,
reproduced locally), the FFI `ok()` degraded it to inventory=None, and the
known-diff planner fired a DELETE for the just-edited contact. Clean rows
carry no `fields`, parsed fine, planned nothing — which is why the baseline
looked steady and every edit wiped. Both wipes (07:33, 08:32) are this one
bug; no create was ever involved.

Fix (implemented 2026-09-09, offline-tested, staged — see §5 for build):
1. **Contract hardening** (`vcard.rs`): `#[serde(default)]` on EVERY
   `ParsedContact`/`ParsedEmail`/`ParsedPhone`/`ParsedAddress` field — one
   omitted key can never fail the inventory parse again. Regression test
   feeds the literal shim JSON (no `photos`) and asserts parse + UPDATE
   plan.
2. **Half-fed defense** (`engine.rs`): the shim always feeds inventory AND
   known together, so inventory=None + known=Some(non-empty) now drops
   known (never plan deletes half-fed) with a `half_fed` trace marker.
   Genuine "deleted every local contact" arrives as Some([]) and still
   fires (pure-delete cycle test). Regression test included.
3. **Hold rule** (`engine.rs`, kept as defense-in-depth for the
   still-possible Guid-mangling class): deletes HELD while guid-less or
   server-unknown rows are present; transient by construction (next
   download + map refresh resolves it). 2 regression tests.
4. **Observability** (the user's explicit ask — "keep the logs in our
   logfile"): the phase builds a `contact_upsync …` trace (inputs
   inv/known counts, planned c/u/d, ran created/updated/deleted/deferred,
   deferral reasons with IDs, `deletes_held`/`half_fed` markers) folded
   into `keys_debug`, which the shim logs to the file on EVERY run. The
   shim also logs upsync inputs (per-row identity flags — never contents —
   plus known UIDs and anchors) and anchor persistence. The 08:32 trace is
   what convicted the parse bug; upload decisions no longer depend on the
   journal.

Known accepted tradeoff: an edit that loses its Guid now duplicates
(original + recreated copy) instead of deleting — duplicates merge on web,
data loss does not recur. Legitimate deletes co-occurring with stray rows
wait one cycle.

### 08:48 follow-up — edit planned but deferred (same day, live)

With the parse fix deployed, the re-created contact's phone edit planned
correctly (`plan c=0 u=1 d=0`, inventory parsed, no delete) but the upload
deferred: `ran … deferred=1`, reason `update:<uid>:unsealable`. Safe
direction (server untouched, phone reverted to server version on download),
but the edit did not upload. Cause: Proton web groups emails
(`prepareForSaving` adds `itemN` groups, so every real-world signed card
carries `item1.EMAIL`), and the unknown-props guard compared the raw
`ITEM1.EMAIL` name against the allowlist — every web-created contact with
an email deferred. Fix: `card_prop_names` strips group prefixes (`.` is
not a valid property-name character, so anything before the last dot is a
group); genuinely exotic bases still defer, and new `diagnose_update_block`
names them in the trace (`unknown-props:X-CUSTOM` — schema only, safe to
log). Our own rebuilds stay ungrouped (self-consistent; grouped key
settings still defer via the guard, so per-email crypto linkage is never
destroyed). Tests: guard unit test, seal+diagnose test, full engine cycle
with grouped-email server cards asserting the PUT fires
(`ran created=0 updated=1 deleted=0 deferred=0`, REAL keys). Live re-gate
pending (deploy `bc6309ef…`, re-apply the phone edit, expect `updated=1` +
web shows it).

### 09:06 follow-up — server 400s the update (same day, live)

With `bc6309ef…` the edit sealed and the PUT fired — then Proton answered
**400 Bad Request** on `PUT /contacts/v4/{id}` (fail-closed: error status,
local untouched, no wipe — the safety design held). Blind spot found along
the way: `error_for_status` discarded the `{Code, Error}` body, so the
*reason* was invisible. Fix: `check_response` keeps the truncated body in
the error for create/update/delete (+ mockito 400 test). Content suspect
for the 400: our rebuilt cards emit **ungrouped** `EMAIL` while WebClients
`prepareForSaving` ALWAYS groups (`item1.EMAIL`, and its reader throws on
group-less emails) — the server most likely enforces the same. Fix:
`build_vcard` now numbers email groups sequentially (`item1.`…), other
props stay ungrouped like the web shape; round-trip test proves our parser
recovers them. Our rebuilds also drop the source groups (fine: grouped key
settings still defer via the guard). If the 400 persists, its body will
now arrive in the log naming the cause. Staged `2e52fffa…` (see §5).

### 09:16 follow-up — UPDATE VERIFIED LIVE

With `2e52fffa…` the pending phone edit uploaded: `plan c=0 u=1 d=0` →
`ran created=0 updated=1 deleted=0 deferred=0`, anchors re-persisted with
the new server mtime, post-upload re-list returned the edited name
(`Marco NapettiT01`). The grouped-email theory is confirmed: ungrouped
`EMAIL` was the 400. Contacts update path is live-verified end-to-end.
Revert re-gate 09:21 also green (`ran updated=1`, re-list back to plain
`Marco Napetti`, anchors advanced again) — updates are stable, repeatable.
Remaining gate: create → delete.

## 8. CAPTCHA (9001) handling gap – 2026-09-09 (user question, code-read only)

No layer handles human-verification today — no browser is ever opened:

- Rust `auth.rs:login` embeds the whole 9001 JSON (token/methods/WebUrl)
  in a flat `Auth POST failed 422…` error string; nothing parses Code 9001.
- FFI `proton_auth_login` maps it to `status=2` + that string.
- SignOn `process()` step 3 emits generic `NotAuthorized(errMsg)` — the
  plugin never calls `userActionRequired` (signon-ui SIGSEGVs) and signond
  has no plugin→browser mechanism at all.
- QML shows the raw message as plain text (WebUrl not clickable, no
  guidance); sync refresh failures surface as "Session expired, please
  sign in again", which loops back into the same CAPTCHA.
- 9001 only gates SRP *password* logins (creation/credential-update),
  never the refresh-token sync path — normal phone use rarely hits it;
  our host datacenter IP + repeated test logins did.

Future (not started): parse 9001 into a structured error
(token/methods/WebUrl) → distinct plugin `CaptchaRequired` result → QML
message with the verify URL as a link / "Open in browser" button
(`Qt.openUrlExternally`, user-initiated — auto-open from a plugin is not
possible). Completing the challenge in the phone browser then retrying
login normally clears the flag.

## 9. Research-first review – 2026-09-09 (local only, no device/live)

Per user instruction (no try-and-error on device): full re-read of both
references against the still-unverified create/delete paths (update is
live-green since §7 09:16/09:21). Fetched fresh 2026-09-09:

- WebClients `packages/shared/lib/api/contacts.ts` (authoritative wire):
  `POST contacts/v4/contacts {Contacts, Overwrite, Labels, Import}`,
  `PUT contacts/v4/contacts/{id} {Cards}`,
  `PUT contacts/v4/contacts/delete {IDs}`, `DELETE contacts/v4/contacts` =
  wipe-all. NOTE the `/contacts` suffix: WebClients moved to
  `contacts/v4/contacts/*` while go-proton-api + our client use
  `contacts/v4/*`. Both are live-accepted (our `PUT /contacts/v4/{id}`
  verified 09:16) — if a future create 400s with an otherwise-correct
  body, the path suffix is the first suspect (no code change: our reads
  depend on the short path).
- WebClients `.../contacts/encrypt.ts` (`prepareCardsFromVCard`): Type 3
  pushed ONLY `if (toEncryptAndSign.length > 0)`, Type 2 ONLY
  `if (toSign.length > 0)` (always true — uid+fn auto-added). OUR BUG:
  `build_vcard` + both seal fns ALWAYS emitted `[Type2, Type3]`, so an
  email-only contact (very common phone shape: name + email, no
  phone/address/org/notes) uploaded an EMPTY `BEGIN:VCARD/VERSION/END`
  wrapper as Type 3 — a shape the web never sends, never live-tested,
  same class as the ungrouped-EMAIL 400. Fixed: `build_vcard` returns
  `(String, Option<String>)` (`None` when the encrypt side is empty);
  both seal fns emit `[Type2]` or `[Type2, Type2+Type3]` (order kept —
  live-accepted). `OVERWRITE` enum confirms our `Overwrite: 0`
  (throw-on-UID-conflict, correct for fresh random UIDs).
- go-proton-api `contact.go` (raw master, fetched): `GET /contacts/v4`,
  `GET /contacts/v4/{id}`, `POST /contacts/v4`, `PUT /contacts/v4/{id}`,
  `PUT /contacts/v4/delete` — byte-identical to our 5 routes.
  `contact_types.go`: `CreateContactsReq{Contacts []ContactCards,
  Overwrite, Labels}` (our §2 fix confirmed),
  `CreateContactsRes{Index, Response{APIError, Contact}}` (nested Contact
  confirmed — our `CreateContactResult` shape),
  `UpdateContactReq{Cards}`, `DeleteContactsReq{IDs}`. Delete returns
  transport-error only upstream — but our calendar discipline is
  fail-closed per-op codes, so `delete()` now ALSO fails on an explicit
  top-level `Code` outside 1000/1001 (lenient: codeless `{}` stays
  success — zero regression risk either way).
- Shim re-read (`exportContactsInventory` + `persistContactsMaps` +
  bridge FFI): create/delete inventory shapes verified correct
  (guid-less rows always carry `fields`; dirty known rows always carry
  `fields`; clean rows carry none and never plan uploads; malformed JSON
  degrades to `None` → half-fed defense). One cosmetic note: the engine
  `created` counter sums per-chunk `Responses.len()`, not jobs — the
  trace may undercount a multi-chunk batch (no functional effect).
  Minor accepted loss: web contacts with gender Other export as `""`
  (shim only round-trips Male/Female) — dropped on next edit, v1 gap.

### Verification log (local only, 2026-09-09)

- `cargo fmt --all` + `--check` clean; `cargo clippy --workspace
  --all-targets --all-features -- -D warnings` clean.
- `cargo test --workspace --all-features`: 99 + 3 + 65 = 167 passed,
  0 failed (+6 new: email-only vcard omission, 2 seal single-card
  tests, delete-Code leniency, engine single-card POST with a
  `"Type":3`-detector mock at expect-zero, 11-row 2-POST chunking
  proof for `ADD_CONTACTS_MAX_SIZE = 10`).
- `make-pkg-bundle.sh --no-deploy` full gate green (container Rust
  cross + SDK `moc` + `g++ -c` + link of all three `.so`). Staged
  `packaging/buteo-plugin/libproton-client.so` sha256
  `384e9d9d415179b2b5d0f93c22977119b305277506c87891e77565448acc72fe`
  (supersedes `2e52fffa…` — deploy ONLY this build).
- Infra note (pre-existing, recurs): container-as-root builds leave
  root-owned files under `target/aarch64-unknown-linux-gnu` (this time
  the two `.cargo-*-lock` files); removed locally with `rm` (dir is
  user-owned). If a full fingerprint dir goes root-owned, the
  documented fix is container `--user root` cleanup (cf. calendar §6).

### Live gate (DO NOT RUN YET — needs user)

Unchanged from §6 step 2–3, new binary hash: `scp
packaging/buteo-plugin/libproton-client.so
defaultuser@192.168.1.124:/tmp/` then on phone (root on phone
terminal, `devel-su` fails over SSH):
`cp /tmp/libproton-client.so
/usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so && chmod 755 … &&
pkill -9 -x signond; systemctl --user restart msyncd`. Verify sha256
`384e9d9d…` on phone before restart. Then one sync per step, watching
`/tmp/proton-sync-debug.log` (`contact_upsync plan …` /
`ran created=/updated=/deleted=` / hold markers): (1) revert the
`T01` name edit → expect `updated=1`, web shows it; (2) create a
name+phone contact AND a name+email-only contact (exercises the §9
single-card fix) → expect `created=2`; (3) delete both → expect
`deleted=2`, web empty of them; (4) re-sync → steady state, no ops.
Host `live_contacts_check` stays BLOCKED (9001 CAPTCHA, §6/§8).

### Live 2026-09-09 11:32 UTC — phone-created contact edit uploads via UPDATE

User deployed `384e9d9d…` (sha verified on phone), edited the
phone-created `Tiziano Incognito` contact
(`proton-web-d4f0a6fc-f86a-0733-bf99-e19ef2d6ee36`, previously synced
from the phone) and synced. Trace: `inputs inv=2 known=2` → `plan c=0
u=1 d=0 server_deletes_locally=0` → `ran created=0 updated=1 deleted=0
deferred=0`, anchors re-persisted with the new server mtime
(1788946354), download saved 2 contacts, calendar steady at 21. New
case vs §7: the edited row is a PHONE-created UID (fresh `proton-web-`
from our generator), proving phone-created → synced → edited converges
through UPDATE (identity preserved, no duplicate create, hold rule not
falsely triggered). Remaining gate: fresh create (`created=1`) →
delete (`deleted=1`) → steady re-sync.

### Live 2026-09-09 11:36 UTC — CREATE VERIFIED (`created=2`)

User created two phone contacts (`A B`: name+email only; `B A`:
name+phone only); sync triggered remotely. Trace: `inputs inv=4
known=2` → `plan c=2 u=0 d=0 server_deletes_locally=0` → `ran
created=2 updated=0 deleted=0 deferred=0` — single POST (≤10 batch),
per-op codes 1000, re-list returned both fresh `proton-web-` UIDs with
correct names, anchors persisted for both, download saved 4 contacts
(`decrypted_type_3=ok` on both new rows = sealed ciphertext round-trips
through the real read path). Note: both rows carried `N` (first+last
name), so both sealed `[Type2, Type3]` — the §9 single-Type-2 shape
(nameless/emailless-only… precisely: no encrypt-side props at all) had
no live case yet; it stays offline-proof-only. Remaining gate: delete
both scratch rows → expect `deleted=2`, web empty of them → steady
re-sync with zero ops.

### Live 2026-09-09 11:37 UTC — DELETE VERIFIED (`deleted=2`)

User deleted both scratch rows on the phone; sync triggered remotely.
Trace: `inputs inv=2 known=4` → `plan c=0 u=0 d=2
server_deletes_locally=0` → `ran created=0 updated=0 deleted=2
deferred=0` — single `PUT …/delete` batch, no hold (no guid-less or
server-unknown rows present, so identity was unambiguous), anchors
pruned to the 2 survivors, download saved 2 contacts. Full contacts
upsync cycle now live-verified end-to-end on `384e9d9d…`: update
(server-created UID 09:16/09:21 + phone-created UID 11:32), create ×2
(11:36), delete ×2 (11:37). Remaining: user confirms the scratch rows
are gone on Proton web + one steady-state re-sync with zero ops.

### Live 2026-09-09 11:38 UTC — STEADY STATE, GATE CLOSED

User confirmed the scratch rows are gone on Proton web. Triggered
re-sync: `inputs inv=2 known=2` → `plan c=0 u=0 d=0
server_deletes_locally=0` → `ran created=0 updated=0 deleted=0
deferred=0`, 2 contacts saved. Zero ops, and `known` converged 4→2 —
the ID map self-pruned the deleted UIDs on the previous cycle, exactly
as designed (no `stale_map_entries` residue). Contacts upsync is fully
live-verified: update / create / delete / steady-state.

## 10. Debug-log cleanup – 2026-09-09 (local only, no device/live)

PLAN TODO, my pick as next item. One mechanism both layers
(`PROTON_VERBOSE`, non-empty ≠ `"0"`; device toggle without root:
`systemctl --user set-environment PROTON_VERBOSE=1` + msyncd restart —
the oopp-runner inherits the environment). Rust `diag::verbose()` +
`vlog!` (`proton-api/src/diag.rs`): 11 routine contacts-upsync journal
lines gated, error lines always on, calendar `LIVE_TRACE`/`LIVE_DIAG`
precedent kept as-is. Shim `proton_verbose()` +
`proton_log_verbose()`: full `Contact JSON:` rows (PII + photo
data-URIs) verbose-only; IDs-only traces, counts, errors, `keys_debug`
always. Size cap: `rotate_log_if_needed` (1 MiB → 256 KiB tail +
marker, line-boundary cut, UTF-8-safe) via FFI
`proton_bridge_rotate_log`, called at both plugin inits. Verified:
fmt + clippy clean, 171 tests (+4 diag), stderr silent-by-default /
traced-with-flag proven on the mock cycle test, full
`make-pkg-bundle.sh --no-deploy` green. Staged sha256
`147ae55fce8da30109ae29baa2e8c960c102d1b4ffa573a907865c304292fe1a`
(supersedes `384e9d9d…`). Live behavior change to expect after deploy:
`Contact JSON:` lines vanish from the file log by default (re-enable
with the flag); everything the gate relied on (`plan`/`ran` trace,
anchors, counts) still logs. Phone gate pending (deploy + one sync,
default + verbose).

### Live 2026-09-09 12:16–12:19 UTC — VERIFIED BOTH MODES, TODO CLOSED

User deployed `147ae55f…` (sha verified on phone). Default-mode syncs
(12:16 UI-triggered, 12:17 remote-triggered): steady `c=0 u=0 d=0`,
`Saved 2`, trace/counts intact, zero `Contact JSON:` lines. Verbose
run (12:19): `Contact JSON:` lines return. Lesson recorded: the
oopp-runner inherits msyncd's environment at msyncd start, so
`set-environment` alone does nothing — the documented sequence is
`set-environment` + `systemctl --user restart msyncd` (still no root).
Environment cleaned afterwards (`unset-environment` + restart,
verified zero `PROTON` entries) with a final steady sync. Rotation
(1 MiB cap) not triggerable live (log is ~130 KiB) — offline-tested
only. Debug-log TODO closed.

## 11. CAPTCHA handling – 2026-09-09 (local only, no live 9001 available)

Research corrected the filed direction before any code: an external
browser does NOT unblock API logins (proof returns via postMessage to
the embedding page — major0/proton-utils doc, hydroxide fixtures,
WebClients #473 OPEN requesting a device flow; even official Bridge
only prints the URL + waits ENTER, retrying with the original token
into 12087). So the UI promises explanation + retry guidance, never
"continue". Authoritative wire (all fetched 2026-09-09): 9001 body =
`Details{HumanVerificationMethods[], HumanVerificationToken, WebUrl?}`
(go-proton-api `hv.go`, hydroxide real-shape fixture); verify URL =
`Details.WebUrl` or Captcha.tsx-built
`verify.proton.me/?methods=a,b&token=…`; retry headers
`x-pm-human-verification-token/-type`; 12087 = bad/stale proof; current
WebClients 2FA route is `core/v4/auth/2fa` for BOTH TOTP and FIDO2
(our `/auth/v4/2fa` TOTP path stays — verified live, do not touch).
Implemented: `ProtonError::Captcha(CaptchaChallenge)` (Display redacts
token+URL — hydroxide String()-must-not-leak precedent) parsed in
login + 2FA-submit paths (strict shape, generic fallback); FFI status 3
+ `captcha_url`/`captcha_methods` (cbindgen header regenerated);
SignOn maps it to `CaptchaRequired` (TwoFA-shaped result, nothing
stored; login + both submit paths); both QML agents show message +
methods + tappable link + Try-again (incl. the captcha-answers-OTP
edge; token never logged — both full-data QML logs removed).
Verified: fmt + clippy `-D warnings` clean, 184 tests (108+5+71),
full `make-pkg-bundle.sh --no-deploy` green (all three `.so`).
Staged `0fd5770e…` + refreshed account tarball. Open device half:
QML hand-reviewed only (no qmllint on host/SDK — CI gate on push);
phone gate whenever a 9001 occurs naturally (untriggerable on
demand). Future: embedded-WebView proof capture or Proton device flow;
retry-with-proof headers.

## 12. Create idempotency – 2026-09-09 (local only, no device/live)

Retries no longer duplicate: creates seal under a STABLE UID
(`pending_uid` from the shim `contacts_pending` map, else fresh
`proton-web-`); a retry succeeds cleanly or UID-conflicts (Overwrite=0
throws per `OVERWRITE`) into list-and-adopt; unresolvable conflicts and
missing per-op Indexes fail closed. Posted-but-unconfirmed jobs expose
via FFI `proton_bridge_get_contact_pending_json`, persisted wholesale
on every outcome (error keeps, complete clears) and fed back for
guid-less rows; contract `#[serde(default)]` both-directions safe. Plus
100 ms pacing between update PUTs / create chunks (`API_SAFE_INTERVAL`).
Same-UID proof: the signed Type-2 card carries the UID in plaintext, so
the retry test asserts both POSTs contain it. 189 workspace tests
green, bundle green, staged `609dc594…`.

### Incident: disk-full file destruction + recovery (same day, local)

`/home` hit 100% mid-session (Steam 254G + podman storage 50G — user
data, untouched; `docker builder prune` freed 76G of reclaimable build
cache). A large file write failed halfway and left
`proton-sync/src/engine.rs` at 0 bytes. Recovery, no data loss:
full-file `read` outputs were extracted from opencode's session DB
(`~/.local/share/opencode/opencode.db`, `part` table) and reassembled
(all 1817 lines, verified), then the day's engine edits were replayed
with per-write verification. Lessons: keep `/home` clear of 100%
(builds link large static binaries — sequoia); treat every tool write
as unverified until read back or compiled (a buffered write can report
success then fail at flush); the session DB is a usable last-resort
backup for read outputs. Also fixed while here: two tests sharing one
temp dir (parallel race), mockito `$`-anchored GET mocks (matches
path+query — never match), and an unrealistic single-entry chunk mock
(real wire returns one response per contact).
