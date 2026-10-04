<img src="./docs/content/assets/banner.svg" alt="Penumbra banner">

---

Penumbra is a Rust crate and tool for interacting with Mediatek devices.<br>
It provides flashing and readback capabilities, as well as bootloader unlocking and relocking on vulnerable devices.<br>


## Features

* Flashing, readback and erase of partitions
* Support for both V5 (XFlash) and V6 (XML) devices
* CLI and a TUI
* Scatter file flashing

Furthermore, on vulnerable devices, the following features are also supported:

* Bootloader unlocking and relocking on vulnerable devices
* RPMB operations (read/write/erase, EMMC only for now)
* Arbitrary memory read/write
* ..and more!

## Requirements

* On Windows, you'll need to install MediaTek VCOM drivers. For using `linecode` exploit (also known as Kamakiri2), you'll need to install either `libusb` or `WinUSB` drivers with [Zadig](https://zadig.akeo.ie/).
* On Linux you'll need to install `libudev` and add your user to the `dialout` group. In case Penumbra doesn't recognize the device, run with sudo or allow access to the device with udev rules.

For more details, check the [installation guide](https://penumbra.itssho.my/Penumbra/Antumbra/Install).

## Usage

Penumbra can be used as a crate for interacting directly with a device, and includes a CLI, [TUI](tui), and native [GUI](gui).

For learning how to use the TUI, [read the documentation here](https://penumbra.itssho.my/Penumbra/Antumbra/TUI).
For using the CLI, [read the documentation with all commands here](https://penumbra.itssho.my/Penumbra/Antumbra/CLI).

### Native desktop GUI

The `penumbra-gui` application provides a graphical workflow for selecting DA, preloader, and auth files; connecting to a device; inspecting and backing up partitions; flashing individual images or scatter layouts; viewing live logs and progress; diagnosing host drivers; and rebooting or powering off the device.

Critical bootloader partitions are protected from accidental erase operations. Device-identifier alteration is intentionally not provided.

```sh
cargo run --release -p penumbra-gui
```

For using the crate, a brief introduction is provided in the [crate documentation](https://penumbra.itssho.my/Penumbra/Crate/index).

### Debug logs

Some issues may be hard to reproduce, and may require more insight of what is happening on the device.
If so, you can open an issue attaching debug logs.<br>
To get debug logs, run `antumbra` with the `-v` and `-l debug` flags. A file called `antumbra.log` will be created in the current directory.
This will also enable UART debug logging. If possible, attach UART logs too.
If you don't have UART, you can use the `--usb-log` flag in `antumbra` to enable DA logging over USB.
A file called `da.log` will be created in the current directory with the logs.

> [!NOTE]
> Penumbra currently supports both V5 (XFlash) and V6 (XML) devices. Issues reporting incompatibility with older (V3/Legacy) chipsets will be ignored until broader support is added.
> If your device falls in one of the supported protocols and you get the "unknown hardware code" warning, please open an issue attaching your device info, and relevant firmware
> files (preloader, DA, lk).

## Contributing

For contributing, you'll first need to setup a development environment.

Read on how to setup a dev environment and how to get started [here](CONTRIBUTING.md)

For contributing to the payloads, head to the [payloads repository](https://github.com/shomykohai/mtk-payloads).

### Current Roadmap

Core:
* [ ] Add V3 support
* [ ] Add amonet exploit

TUI:
* [x] Refactor the TUI code to be more maintainable
* [x] Add reusable components
* [x] Make better key bindings

CLI:
* [x] Add plstage
* [x] Add Read Offset, Write Offset and Erase Offset commands
* [x] Add register read/write commands

Documentation:
* [x] Add documentation for the crate
* [ ] Add linecode exploit documentation

## Learning Resources

Penumbra has [its own documentation](https://penumbra.itssho.my/), where you can learn more about Mediatek devices and how the Download protocol works.

Other learning resources I suggest are the following
* [mtkclient](https://github.com/bkerler/mtkclient)
* [moto-experiments](https://github.com/R0rt1z2/moto-experiments)
* [kaeru](https://github.com/R0rt1z2/kaeru)
* [Carbonara exploit](https://penumbra.itssho.my/Mediatek/Exploits/Carbonara)
* [mtk-payloads](https://github.com/shomykohai/mtk-payloads)
* [da-boot](https://github.com/mt6572-mainline/da-boot)
* [fenrir](https://github.com/R0rt1z2/fenrir)
* [sprig](https://github.com/R0rt1z2/sprig)
* [HeapB8 exploit technical writeup](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
* [hacc](https://github.com/shomykohai/hacc)

## Credits

* [ChimeraTool team](https://chimeratool.com/) - heapb8 was originally reverse-engineered from ChimeraTool.
* [Swaggyxren/penumbraGUI contributors](https://github.com/Swaggyxren/penumbraGUI) - native GUI design, driver diagnostics, packaging assets, and safety UX.

## License

Penumbra is licensed under the GNU Affero General Public License v3 or later (AGPL-3.0-or-later), see [LICENSE](LICENSE) for details.

Logo by [@archaeopteryz](https://github.com/archaeopteryz), all rights reserved. Use is allowed only for referencing "Penumbra" or "Antumbra", unless explicit permission has been granted.
