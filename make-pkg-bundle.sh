#!/usr/bin/env bash
# Build Proton Contacts Buteo sync plugin
# 1. Cross-compile Rust staticlib (aarch64-unknown-linux-gnu)
# 2. Compile C++ plugin + link (SDK container)
# 3. Deploy to phone
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
packaging_dir="$repo_root/packaging"
target_triple="aarch64-unknown-linux-gnu"

mkdir -p "$packaging_dir/buteo-plugin" \
         "$packaging_dir/accounts" \
         "$packaging_dir/ui" \
         "$packaging_dir/rpm" \
         "$packaging_dir/buteo-profiles/client" \
         "$packaging_dir/buteo-profiles/sync"

echo "========================================="
echo " Step 1: Cross-compile Rust for aarch64 "
echo "========================================="

docker run --rm -v "$repo_root":/workspace proton-build-env bash -c '
set -e
cd /workspace
export CARGO_HOME=/workspace/.cargo-home
cargo build --release --target aarch64-unknown-linux-gnu -p proton-bridge 2>&1 | tail -5
'

if [ ! -f "$repo_root/target/$target_triple/release/libproton_bridge.a" ]; then
    echo "ERROR: libproton_bridge.a not found"
    exit 1
fi

echo "========================================="
echo " Step 2: Compile C++ Buteo plugin        "
echo "========================================="

cp "$repo_root/proton-bridge/cxx/proton_bridge_shim.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/cxx/proton_bridge_shim.cpp" "$packaging_dir/buteo-plugin/"
cp "$repo_root/proton-bridge/proton_bridge.h" "$packaging_dir/buteo-plugin/"
cp "$repo_root/target/$target_triple/release/libproton_bridge.a" "$packaging_dir/buteo-plugin/"

mkdir -p "$packaging_dir/buteo-headers/Buteo"
if [ -d "$repo_root/buteo-syncfw/libbuteosyncfw" ]; then
    for header in $(find "$repo_root/buteo-syncfw/libbuteosyncfw" -name "*.h" -type f); do
        cp "$header" "$packaging_dir/buteo-headers/Buteo/" 2>/dev/null || true
    done
fi

docker run --rm --user root \
    -v "$packaging_dir":/home/mersdk/packaging \
    coderus/sailfishos-platform-sdk-aarch64 bash -c '
set -e
export PATH="/opt/cross/bin:$PATH"
export TARGET_ROOT="/srv/mer/targets/SailfishOS-5.2.0.15-aarch64"
export TOOLING_ROOT="/srv/mer/toolings/SailfishOS-5.2.0.15"
export MOC="$TOOLING_ROOT/usr/lib/qt5/bin/moc"

chown -R 1000:1000 /home/mersdk/packaging/

# Fix assembler symlink
ln -sf /opt/cross/bin/aarch64-meego-linux-gnu-as /opt/cross/bin/as 2>/dev/null || true

# Setup dev symlinks
ln -sf libbuteosyncfw5.so.0 $TARGET_ROOT/usr/lib64/libbuteosyncfw5.so 2>/dev/null || true
ln -sf libQt5Core.so.5 $TARGET_ROOT/usr/lib64/libQt5Core.so 2>/dev/null || true
ln -sf libQt5Contacts.so.5 $TARGET_ROOT/usr/lib64/libQt5Contacts.so 2>/dev/null || true
ln -sf libaccounts-qt5.so.1 $TARGET_ROOT/usr/lib64/libaccounts-qt5.so 2>/dev/null || true
ln -sf libsignon-qt5.so.1 $TARGET_ROOT/usr/lib64/libsignon-qt5.so 2>/dev/null || true
ln -sf libQt5DBus.so.5 $TARGET_ROOT/usr/lib64/libQt5DBus.so 2>/dev/null || true
ln -sf libQt5Xml.so.5 $TARGET_ROOT/usr/lib64/libQt5Xml.so 2>/dev/null || true
ln -sf libQt5Network.so.5 $TARGET_ROOT/usr/lib64/libQt5Network.so 2>/dev/null || true

COMMON_INC="-I/home/mersdk/packaging/buteo-headers \
    -I/home/mersdk/packaging/buteo-headers/Buteo \
    -I$TARGET_ROOT/usr/include/qt5 \
    -I$TARGET_ROOT/usr/include/qt5/QtCore \
    -I$TARGET_ROOT/usr/include/qt5/QtContacts \
    -I$TARGET_ROOT/usr/include/qt5/QtDBus \
    -I$TARGET_ROOT/usr/include/qt5/QtXml \
    -I$TARGET_ROOT/usr/include/accounts-qt5 \
    -I$TARGET_ROOT/usr/include/signon-qt5 \
    -I$TARGET_ROOT/usr/include \
    -DQT_CORE_LIB"

# Moc
$MOC $COMMON_INC \
    /home/mersdk/packaging/buteo-plugin/proton_bridge_shim.h \
    -o /home/mersdk/packaging/buteo-plugin/moc_proton_bridge_shim.cpp

# Compile
aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $COMMON_INC \
    -o /home/mersdk/packaging/buteo-plugin/shim.o \
    /home/mersdk/packaging/buteo-plugin/proton_bridge_shim.cpp

aarch64-meego-linux-gnu-g++ \
    -std=c++14 -c -fPIC --sysroot=$TARGET_ROOT \
    $COMMON_INC \
    -o /home/mersdk/packaging/buteo-plugin/moc_shim.o \
    /home/mersdk/packaging/buteo-plugin/moc_proton_bridge_shim.cpp

# Link
rm -f /home/mersdk/packaging/buteo-plugin/libproton-client.so
aarch64-meego-linux-gnu-g++ \
    -shared -fPIC --sysroot=$TARGET_ROOT \
    -o /home/mersdk/packaging/buteo-plugin/libproton-client.so \
    /home/mersdk/packaging/buteo-plugin/shim.o \
    /home/mersdk/packaging/buteo-plugin/moc_shim.o \
    -L$TARGET_ROOT/usr/lib64 \
    /home/mersdk/packaging/buteo-plugin/libproton_bridge.a \
    -lbuteosyncfw5 \
    -lQt5Core \
    -lQt5Contacts \
    -lQt5DBus \
    -lQt5Xml \
    -lQt5Network \
    -laccounts-qt5 \
    -lsignon-qt5 \
    -lpthread -ldl -lm

chown 1000:1000 /home/mersdk/packaging/buteo-plugin/libproton-client.so
echo "Plugin built successfully"
ls -lh /home/mersdk/packaging/buteo-plugin/libproton-client.so

echo "=== GLIBC requirements ==="
objdump -T /home/mersdk/packaging/buteo-plugin/libproton-client.so | grep GLIBC | awk "{print \$5}" | sort -V -u
'

echo "========================================="
echo " Step 3: Deploy to phone                 "
echo "========================================="

PHONE_IP="${1:-192.168.1.124}"
PLUGIN="$packaging_dir/buteo-plugin/libproton-client.so"

echo "Deploying to $PHONE_IP..."
scp "$PLUGIN" defaultuser@$PHONE_IP:/tmp/libproton-client.so

# Copy profiles
scp "$repo_root/buteo-profiles/client/proton-contacts.xml" defaultuser@$PHONE_IP:/tmp/
scp "$repo_root/buteo-profiles/sync/proton.Contacts.xml" defaultuser@$PHONE_IP:/tmp/

ssh defaultuser@$PHONE_IP "
set -e
# Install plugin (need root for /usr/lib64)
devel-su bash -c '
cp /tmp/libproton-client.so /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so
chmod 755 /usr/lib64/buteo-plugins-qt5/oopp/libproton-client.so
rm -f /usr/lib64/buteo-plugins-qt5/oopp/libproton-contacts-client.so
rm -f /usr/lib64/buteo-plugins-qt5/oopp/proton-contacts-client.so
cp /tmp/proton-contacts.xml /etc/buteo/profiles/client/proton.xml
cp /tmp/proton.Contacts.xml /etc/buteo/profiles/sync/proton.Contacts.xml
'

# Restart msyncd
systemctl --user restart msyncd
sleep 2
echo 'Deployed!'
" 2>&1

echo "Done. Test with: ssh defaultuser@$PHONE_IP 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/100000/dbus/user_bus_socket dbus-send --session --print-reply --dest=com.meego.msyncd /synchronizer com.meego.msyncd.startSync string:proton.Contacts-2'"
