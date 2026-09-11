# Build & deploy

## Host gates (CI, x86_64)

`.github/workflows/ci.yml`:

- `cargo fmt --check --all`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `qmllint ui/*.qml` (syntax-only; Sailfish-only imports cannot fail it)
- `bash tools/build-qm.sh --check` (fails on any translation drift)
- Cross check: `cargo build -p proton-api -p proton-sync --release --target
  aarch64-unknown-linux-gnu --lib` + `cargo check -p proton-bridge --target
  …`

Cross target is `aarch64-unknown-linux-gnu` (not musl — musl embeds its own
libc and crashes the oopp-runner). Linker `aarch64-linux-gnu-gcc`
(`.cargo/config.toml`, `Dockerfile.build` `proton-build-env` image).
Rust TLS is rustls-only (`reqwest` `rustls-tls`, sequoia `crypto-rust`).
SDK sysroot glibc 2.35 vs phone 2.41 is forward-compatible.

## make-pkg-bundle.sh

`--no-deploy` (or `SKIP_DEPLOY=1`) skips all ssh/scp contact.
`SKIP_RUST_DOCKER=1` skips the Step-1 `proton-build-env` container rebuild
and reuses a prebuilt `target/<triple>/release/libproton_bridge.a` (the CI
release workflow sets it — the image is local-only, never published — after
cross-compiling the workspace on the runner itself). Stages:

1. Rust cross: `cargo build --release --target aarch64-unknown-linux-gnu
   -p proton-bridge` → `target/<triple>/release/libproton_bridge.a`
   (`build.rs` regenerates `proton_bridge.h` via cbindgen).
2. C++ in `coderus/sailfishos-platform-sdk-aarch64` (`SailfishOS-5.2.0.15-aarch64`,
   `TOOLING moc`, `aarch64-meego-linux-gnu-g++ -std=c++14 -fPIC --sysroot`):
   `moc` + compile + `-shared` link for all three `.so` (buteo plugin with
   `BUTEO_INC`, signon plugin with `SIGNON_INC`, settings with
   `SETTINGS_INC`; mKCal/KF5 headers vendored in
   `proton-bridge/device-headers/` per shipped `.pc` layout; buteo link adds
   `-lQt5Gui` for the JPEG photo path).
3. Version from `Cargo.toml`; deterministic tarballs
   `buteo-sync-plugin-proton-<ver>.tar.bz2` +
   `sailfish-account-proton-<ver>.tar.bz2`; in-place `mb2` build per tree
   (release workflow stamps the version into `Cargo.toml` + both specs
   first).
4. Deploy (skipped with `--no-deploy`): `scp` to `/tmp`, on-phone
   `cp`/`chmod 755`, `pkill -9 -x signond` (auto-respawns),
   `systemctl --user restart msyncd`. `devel-su` does not work over SSH —
   root steps run on the phone terminal. `journalctl` needs root (volatile
   journal); signond debug via `LoggingLevel=2` in `/etc/signond.conf`.
   Verify deploys by sha256 (phone/host clocks disagree).

Device UI toggles map by service **name** (`proton-caldav` matched in
msyncd/shim); the `proton-calendar` service type renders a plain switch.

## RPMs

- `buteo-sync-plugin-proton.spec`: ships `libproton-client.so` (+ client +
  sync profiles), `libprotonsettingsplugin.so` + `qmldir`;
  `Requires: buteo-syncfw-qt5, sailfish-account-proton, qtpim-contacts,
  mkcal-qt5, kf5-calendarcore, accounts/signon-qt5`; `%post/%postun`
  reload msyncd.
- `sailfish-account-proton.spec`: ships `proton.qml`, `proton-update.qml`,
  `proton-settings.qml`, provider + both services, `proton_*.qm`;
  `Requires: libaccounts/signon-glib, buteo-sync-plugin-proton,
  jolla-settings-accounts`. Mutual `Requires` both directions (unversioned).
- Release workflow (tag `v*`): stamp → cross → bundle → `mb2` each tree →
  `rpm -qp` arch/version check → publish.

## i18n pipeline

- `tools/build-qm.sh`: `lupdate ui/proton.qml ui/proton-update.qml
  ui/proton-settings.qml -ts translations/proton.ts` → `tools/apply-translations.py`
  (rebuilds each `proton_<lang>.ts` from the template keyed by source text:
  keeps finished strings, marks new `unfinished`, drops vanished) →
  `lrelease`. Linguist tools bootstrap from the PySide6-Essentials wheel
  into `$XDG_CACHE_HOME/qt-tools` (no system Qt needed). Template holds the
  custom strings (all `qsTr` + `//%`); stock `qsTrId`s stay Jolla's and never
  ship. Committed per-language `.qm` are byte-reproducible.
- Loading: the `Proton 1.0` extension's `initializeEngine` installs
  `proton_<full-locale>` then `proton_<language>`; English needs no file.
  Server/plugin error strings stay English by nature; provider XML
  name/description has no framework translation mechanism.

## Manual sync trigger (user-level, no root)

```bash
systemctl --user restart msyncd
sleep 2
dbus-send --session --type=method_call --dest=com.meego.msyncd \
  /synchronizer com.meego.msyncd.startSync string:"proton.Contacts-<accountId>"
dbus-send --session --type=method_call --dest=com.meego.msyncd \
  /synchronizer com.meego.msyncd.startSync string:"proton-caldav-<accountId>"
```

Manual `startSync` never checks connectivity. If msyncd hits
`start-limit-hit` after restart loops: `systemctl --user reset-failed
msyncd` + restart.

## References

- https://kdab.github.io/cxx-qt/book/ (not currently used by the bridge)
