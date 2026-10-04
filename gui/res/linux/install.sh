#!/usr/bin/env bash
# Installs the prebuilt penumbra-gui binary, .desktop entry, icons and
# udev rules under /usr/local. Intended for distros without a native
# package manager entry. Arch users should use the PKGBUILD instead.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo --preserve-env=PATH "$0" "$@"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"

echo "Installing into ${PREFIX} ..."

install -Dm755 "${HERE}/penumbra-gui"                      "${PREFIX}/bin/penumbra-gui"
install -Dm644 "${HERE}/penumbra-gui.desktop"              "${PREFIX}/share/applications/penumbra-gui.desktop"

for size in 16 32 48 128 256; do
    install -Dm644 "${HERE}/icons/${size}x${size}.png" \
        "${PREFIX}/share/icons/hicolor/${size}x${size}/apps/penumbra-gui.png"
done

# udev rules always live under /etc to take effect.
install -Dm644 "${HERE}/51-mtk-penumbra.rules" /etc/udev/rules.d/51-mtk-penumbra.rules

echo "Reloading udev ..."
udevadm control --reload-rules
udevadm trigger

cat <<EOF

Done.

If your user can't yet access MediaTek USB endpoints, add yourself to the
group used by the rules. On most distros that is one of:

    sudo usermod -aG plugdev "\$USER"   # Debian / Ubuntu
    sudo usermod -aG uucp    "\$USER"   # Arch
    sudo usermod -aG dialout "\$USER"   # Fedora-style

The shipped rules use GROUP="uucp"; edit /etc/udev/rules.d/51-mtk-penumbra.rules
if you want a different group, then re-run \`udevadm control --reload-rules\`.

Log out and back in for the new group to take effect.
EOF
