#!/usr/bin/env bash
# Build Qt message catalogs for the account QML agents.
#
# Toolchain: Qt Linguist binaries (lupdate/lrelease) extracted from the
# PySide6-Essentials wheel (pip download only — no system Qt needed) and
# cached under $XDG_CACHE_HOME/qt-tools (default ~/.cache/qt-tools).
# Rationale: neither the host, the proton-build-env image, nor the
# SailfishOS SDK ship linguist tools. NOTE: Qt6-built .qm files were
# verified loadable by the on-device Qt 5.6 QTranslator (probe binary,
# see FINDINGS i18n entry) — re-verify if the Qt major changes.
#
# Usage:
#   tools/build-qm.sh            # refresh translations/*.ts + rebuild *.qm
#   tools/build-qm.sh --check    # CI gate: fail if committed files differ
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-..}")/.." && pwd)"
tools_dir="${XDG_CACHE_HOME:-$HOME/.cache}/qt-tools"
check_only=0
if [ "${1:-}" = "--check" ]; then
    check_only=1
fi

if [ ! -x "$tools_dir/lupdate" ] || [ ! -x "$tools_dir/lrelease" ]; then
    echo "Fetching Qt linguist tools (PySide6-Essentials wheel)..."
    mkdir -p "$tools_dir" /tmp/qttools-wheel
    pip download --no-deps --dest /tmp/qttools-wheel PySide6-Essentials
    python3 -c "import zipfile,glob; z=zipfile.ZipFile(glob.glob('/tmp/qttools-wheel/*.whl')[0]); [z.extract(n,'/tmp/qttools-wheel/x') for n in z.namelist() if n.endswith(('/lupdate','/lrelease'))]"
    cp /tmp/qttools-wheel/x/PySide6/lupdate /tmp/qttools-wheel/x/PySide6/lrelease "$tools_dir/"
    chmod +x "$tools_dir/lupdate" "$tools_dir/lrelease"
    rm -rf /tmp/qttools-wheel
fi

cd "$repo_root"
"$tools_dir/lupdate" ui/proton.qml ui/proton-update.qml ui/proton-settings.qml \
    -ts translations/proton.ts 2>/dev/null
python3 tools/apply-translations.py
"$tools_dir/lrelease" translations/proton_it.ts 2>&1 | tail -n 2

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
