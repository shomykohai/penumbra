# Penumbra GUI on Linux

`penumbra-gui` is a Rust/egui desktop app and runs natively on Linux (X11
and Wayland). On Linux there is no separate driver to install — `libusb`
already ships with the kernel — but you do need a udev rule so non-root
users can open the MediaTek BROM / Preloader / DA endpoints.

## Quick install (any distro, no compilation)

The prebuilt tarball is attached to every GitHub release. It contains
the binary, the `.desktop` entry, the icon hierarchy, the udev rules,
the license, and an `install.sh` that copies everything into the right
places.

```
wget https://github.com/Swaggyxren/penumbraGUI/releases/download/v1.1.0-gui/penumbra-gui-linux-x86_64.tar.gz
tar xzf penumbra-gui-linux-x86_64.tar.gz
cd penumbra-gui-linux-x86_64
sudo ./install.sh
```

`install.sh` drops:

- the binary into `/usr/local/bin/penumbra-gui`,
- the `.desktop` entry into `/usr/local/share/applications/`,
- icons under `/usr/local/share/icons/hicolor/`,
- udev rules into `/etc/udev/rules.d/51-mtk-penumbra.rules`,

then reloads udev so the rules take effect immediately. After install
the app shows up in your launcher as **Penumbra Flash Tool**.

The Linux binary statically links libusb, so the only runtime
dependencies beyond glibc are `libudev` (already on every systemd
distro) and the standard wayland / xcb / fontconfig / freetype libs
that any Linux desktop already has.

## Per-distro group setup

The shipped udev rule uses `GROUP="uucp"` (Arch's group for serial /
USB devices). On other distros you may need a different group:

```
sudo usermod -aG uucp    "$USER"   # Arch
sudo usermod -aG plugdev "$USER"   # Debian / Ubuntu
sudo usermod -aG dialout "$USER"   # Fedora-style
```

If your distro uses `plugdev` or `dialout` instead of `uucp`, edit
`/etc/udev/rules.d/51-mtk-penumbra.rules` and replace `GROUP="uucp"`
with the right group, then:

```
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Log out + log back in after `usermod` so the new group membership takes
effect.

## Building from source (optional)

If you want to hack on the GUI rather than just install it:

```
git clone https://github.com/Swaggyxren/penumbraGUI.git
cd penumbraGUI
cargo build --release -p penumbra-gui
./target/release/penumbra-gui
```

Requires `rustc >= 1.83`, `cargo`, and the standard Linux desktop libs
(`fontconfig`, `freetype2`, `libxcb`, `libxkbcommon`, `wayland`,
optionally `libusb`). The `gui` crate already enables the libusb
backend in its `Cargo.toml`, so no extra `--features` flag is needed.

## Putting the device into BROM / Preloader mode

Same procedure as Windows:

1. Power the phone off.
2. Hold **Vol Up + Vol Down** (or just Vol Up on some models).
3. Plug in USB while holding.

When the rules are loaded correctly, `lsusb` should list the device with
the `0e8d:` (or the vendor's) IDs from
`core/src/connection/port.rs::KNOWN_PORTS`, and `penumbra-gui` should
connect immediately without `sudo`.
