#!/usr/bin/env bash
# Build Qt message catalogs for the account QML agents.
#
# Toolchain: Qt Linguist binaries (lupdate/lrelease) extracted from the
# PySide6-Essentials wheel (pip download only — no system Qt needed) and
# cached under $XDG_CACHE_HOME/qt-tools (default ~/.cache/qt-tools).
# Rationale: neither the host, the proton-build-env image, nor the
# SailfishOS SDK ship linguist tools. The wheel's bundled Qt libs
# (PySide6/Qt/lib) are cached alongside the binaries because the tools
# resolve them via RUNPATH $ORIGIN/Qt/lib — copying the binaries out alone
# breaks on machines without system Qt6 (loader failure, exit 127).
# NOTE: Qt6-built .qm files were verified loadable by the on-device
# Qt 5.6 QTranslator (probe binary, see git history + docs/build-deploy.md)
# — re-verify if the Qt major changes.
#
# Usage:
#   tools/build-qm.sh            # refresh translations/*.ts + rebuild *.qm
#   tools/build-qm.sh --check    # CI gate: fail if committed files differ
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-..}")/.." && pwd)"
tools_dir="${XDG_CACHE_HOME:-$HOME/.cache}/qt-tools"
lupdate="$tools_dir/PySide6/lupdate"
lrelease="$tools_dir/PySide6/lrelease"
check_only=0
if [ "${1:-}" = "--check" ]; then
    check_only=1
fi

if [ ! -x "$lupdate" ] || [ ! -x "$lrelease" ]; then
    echo "Fetching Qt linguist tools (PySide6-Essentials wheel)..."
    mkdir -p "$tools_dir" /tmp/qttools-wheel
    pip download --no-deps --dest /tmp/qttools-wheel PySide6-Essentials
    rm -rf "$tools_dir/PySide6" "$tools_dir/lupdate" "$tools_dir/lrelease" "$tools_dir/qmllint"
    python3 -c "
import zipfile, glob
z = zipfile.ZipFile(glob.glob('/tmp/qttools-wheel/*.whl')[0])
names = [n for n in z.namelist()
         if n in ('PySide6/lupdate', 'PySide6/lrelease')
         or n.startswith('PySide6/Qt/lib/')]
z.extractall('$tools_dir', members=names)
"
    chmod +x "$lupdate" "$lrelease"
    rm -rf /tmp/qttools-wheel
fi

# Smoke test with stderr visible: a broken toolchain (e.g. unresolvable
# bundled libs) must fail here with its loader error, not later as a bare
# exit 127 with output suppressed.
"$lupdate" -version

cd "$repo_root"
"$lupdate" ui/proton.qml ui/proton-update.qml ui/proton-settings.qml \
    -ts translations/proton.ts
python3 tools/apply-translations.py
"$lrelease" translations/proton_it.ts 2>&1 | tail -n 2

if [ "$check_only" = "1" ]; then
    # Any change under translations/ (modified OR untracked — a fresh
    # language must be committed too) fails the gate.
    if [ -n "$(git status --porcelain -- translations/)" ]; then
        echo "ERROR: translations/ out of sync — run tools/build-qm.sh and commit"
        git status --short -- translations/
        exit 1
    fi
fi
echo "Catalogs ready: $(ls translations/*.qm)"
