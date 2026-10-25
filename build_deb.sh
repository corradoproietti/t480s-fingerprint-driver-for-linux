#!/usr/bin/env bash
set -euo pipefail

PKG_NAME="libfprint-2-tod1-synaptics009a"
PKG_VERSION="0.1.0-1"
ARCH="amd64"
DEB_FILE="${PKG_NAME}_${PKG_VERSION}_${ARCH}.deb"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "[1/4] Building release shared library (cargo build --release)..."
RUSTFLAGS="--remap-path-prefix=${SCRIPT_DIR}=/src --remap-path-prefix=${HOME}=/build" cargo build --release

SO_SRC="target/release/libt480s_fingerprint_v2.so"
if [[ ! -f "${SO_SRC}" ]]; then
    echo "Error: ${SO_SRC} not found!" >&2
    exit 1
fi

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

echo "[2/4] Staging Debian package tree..."
install -d -m 0755 "${STAGE_DIR}/DEBIAN"
install -d -m 0755 "${STAGE_DIR}/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1"
install -d -m 0755 "${STAGE_DIR}/lib/systemd/system/fprintd.service.d"
install -d -m 0755 "${STAGE_DIR}/usr/share/doc/${PKG_NAME}"

# Install and strip the TOD shared library
install -m 0644 "${SO_SRC}" \
    "${STAGE_DIR}/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so"
strip --strip-unneeded \
    "${STAGE_DIR}/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/libfprint-2-tod1-synaptics009a.so"

# Install systemd drop-in to keep fprintd alive (-t / --no-timeout) so the TLS 1.2 session
# stays warm in RAM (instant ~5ms LED turn-on and no 30-second USB port resets).
cat > "${STAGE_DIR}/lib/systemd/system/fprintd.service.d/synaptics009a-no-timeout.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/libexec/fprintd -t
EOF
chmod 0644 "${STAGE_DIR}/lib/systemd/system/fprintd.service.d/synaptics009a-no-timeout.conf"

# Install copyright metadata
cat > "${STAGE_DIR}/usr/share/doc/${PKG_NAME}/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: t480s-fingerprint-driver-for-linux
Source: https://github.com/corradoproietti/t480s-fingerprint-driver-for-linux

Files: *
Copyright: 2026 Corrado Proietti
License: MIT or LGPL-2.1+
EOF
chmod 0644 "${STAGE_DIR}/usr/share/doc/${PKG_NAME}/copyright"

# Compute installed size in KiB
INSTALLED_SIZE="$(du -sk "${STAGE_DIR}/usr" "${STAGE_DIR}/lib" | awk '{s+=$1} END {print s}')"

cat > "${STAGE_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: libs
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6 (>= 2.34), libglib2.0-0t64 | libglib2.0-0, libusb-1.0-0, libfprint-2-tod1, fprintd
Conflicts: python3-validity, open-fprintd
Maintainer: Corrado Proietti
Homepage: https://github.com/corradoproietti/t480s-fingerprint-driver-for-linux
Description: T480s Fingerprint Driver for Linux (Synaptics 06cb:009a libfprint-2-tod1)
 Native Rust Match-on-Chip (MoC) Touch OEM Driver (TOD) plugin for
 libfprint-2 and fprintd supporting the Synaptics Metallica MIS Touch
 Fingerprint Reader (USB 06cb:009a) found in Lenovo ThinkPad T480s,
 T480, X280, and P52s laptops.
 .
 Features full TLS 1.2 ECDH/ECDSA P-256 encrypted sensor communication,
 on-chip QMatcher 1:N/1:1 verification, 12-stage DB2 flash enrollment,
 background session pre-warming, and suspend/resume lifecycle support.
EOF
chmod 0644 "${STAGE_DIR}/DEBIAN/control"

cat > "${STAGE_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    ldconfig || true
    if [ -f /etc/systemd/system/fprintd.service.d/no-timeout.conf ]; then
        rm -f /etc/systemd/system/fprintd.service.d/no-timeout.conf
        rmdir --ignore-fail-on-non-empty /etc/systemd/system/fprintd.service.d 2>/dev/null || true
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl restart fprintd.service || true
    fi
fi
exit 0
EOF
chmod 0755 "${STAGE_DIR}/DEBIAN/postinst"

cat > "${STAGE_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop fprintd.service || true
    fi
fi
exit 0
EOF
chmod 0755 "${STAGE_DIR}/DEBIAN/prerm"

cat > "${STAGE_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    ldconfig || true
    if [ "$1" = "purge" ]; then
        rm -f /var/lib/fprint/.synaptics_06cb_009a_pairing.json
        rm -f /var/lib/fprint/.synaptics_06cb_009a_calib.bin
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
    fi
fi
exit 0
EOF
chmod 0755 "${STAGE_DIR}/DEBIAN/postrm"

echo "[3/4] Building ${DEB_FILE}..."
dpkg-deb --root-owner-group --build "${STAGE_DIR}" "${DEB_FILE}"

echo "[4/4] Package built successfully:"
ls -lh "${DEB_FILE}"
dpkg-deb --info "${DEB_FILE}"
dpkg-deb --contents "${DEB_FILE}"
