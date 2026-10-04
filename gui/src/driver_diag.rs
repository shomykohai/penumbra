/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Driver and system diagnostics for MediaTek flashing on Linux and Windows.

#[allow(unused_imports)]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagLevel {
    Ok,
    Warning,
    ActionRequired,
}

#[derive(Debug, Clone)]
pub struct DiagCheckItem {
    pub title: String,
    pub detail: String,
    pub level: DiagLevel,
}

#[derive(Debug, Clone)]
pub struct DriverDiagStatus {
    pub os_name: String,
    pub is_linux: bool,
    pub is_windows: bool,
    pub overall_level: DiagLevel,
    pub items: Vec<DiagCheckItem>,
    pub bash_commands: Option<String>,
    pub instructions: Option<String>,
}

impl Default for DriverDiagStatus {
    fn default() -> Self {
        Self::run()
    }
}

impl DriverDiagStatus {
    /// Runs a non-blocking diagnostic scan of system drivers and permissions.
    pub fn run() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::diagnose_linux()
        }

        #[cfg(target_os = "windows")]
        {
            Self::diagnose_windows()
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Self::diagnose_generic()
        }
    }

    /// Generates the standard Linux udev rules and group configuration bash commands.
    pub fn linux_setup_commands() -> String {
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "$USER".to_string());

        format!(
            "sudo tee /etc/udev/rules.d/51-mtk-penumbra.rules << 'EOF'\n\
# MediaTek BROM / Preloader / DA USB endpoints (Penumbra)\n\
SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0e8d\", MODE=\"0660\", TAG+=\"uaccess\", GROUP=\"uucp\"\n\
SUBSYSTEM==\"tty\", ATTRS{{idVendor}}==\"0e8d\", MODE=\"0660\", TAG+=\"uaccess\", ENV{{ID_MM_DEVICE_IGNORE}}=\"1\"\n\
EOF\n\
sudo udevadm control --reload-rules && sudo udevadm trigger\n\
sudo usermod -aG dialout,uucp,plugdev {username}\n"
        )
    }

    /// Provides step-by-step driver setup instructions for Windows.
    pub fn windows_instructions() -> &'static str {
        "1. MediaTek Preloader USB VCOM Driver is required for Windows to communicate with BROM & Preloader without disconnecting.\n\
2. Download and run the MediaTek USB VCOM Driver (or MTK All-In-One Driver installer).\n\
3. If using the LibUSB backend, use Zadig (https://zadig.akeo.ie) to install WinUSB on \"MediaTek USB Port\" (VID: 0E8D, PID: 0003).\n\
4. If driver installation is blocked on Windows 10/11, temporarily disable Driver Signature Enforcement in Windows Advanced Startup.\n\
5. Connect your device via USB while holding Volume Down or Volume Up."
    }

    #[cfg(target_os = "linux")]
    fn diagnose_linux() -> Self {
        let mut items = Vec::new();
        let mut overall_level = DiagLevel::Ok;

        // 1. Check udev rules
        let (udev_found, udev_path) = check_linux_udev_rules();
        if udev_found {
            items.push(DiagCheckItem {
                title: "MediaTek udev Rules".into(),
                detail: format!(
                    "Installed ({})",
                    udev_path.as_deref().unwrap_or("MediaTek rule active")
                ),
                level: DiagLevel::Ok,
            });
        } else {
            overall_level = DiagLevel::ActionRequired;
            items.push(DiagCheckItem {
                title: "MediaTek udev Rules".into(),
                detail: "Missing /etc/udev/rules.d/51-mtk-penumbra.rules (normal users cannot access USB endpoints)".into(),
                level: DiagLevel::ActionRequired,
            });
        }

        // 2. Check user group membership
        let (in_group, current_user, groups) = check_linux_user_groups();
        if in_group {
            let matching: Vec<_> = groups
                .iter()
                .filter(|g| ["uucp", "dialout", "plugdev"].contains(&g.as_str()))
                .cloned()
                .collect();
            items.push(DiagCheckItem {
                title: "User Permissions".into(),
                detail: format!("User '{current_user}' belongs to: {}", matching.join(", ")),
                level: DiagLevel::Ok,
            });
        } else {
            if overall_level == DiagLevel::Ok {
                overall_level = DiagLevel::ActionRequired;
            }
            items.push(DiagCheckItem {
                title: "User Permissions".into(),
                detail: format!(
                    "User '{current_user}' is not in 'uucp', 'dialout', or 'plugdev' group"
                ),
                level: DiagLevel::ActionRequired,
            });
        }

        // 3. Check ModemManager
        let modemmanager_active = check_modemmanager_active();
        if modemmanager_active {
            if udev_found {
                items.push(DiagCheckItem {
                    title: "ModemManager Filter".into(),
                    detail: "ModemManager running; udev rules configured to ignore MTK ports".into(),
                    level: DiagLevel::Ok,
                });
            } else {
                if overall_level != DiagLevel::ActionRequired {
                    overall_level = DiagLevel::Warning;
                }
                items.push(DiagCheckItem {
                    title: "ModemManager Interference".into(),
                    detail: "ModemManager is active and may interrupt Preloader handshake without udev filter".into(),
                    level: DiagLevel::Warning,
                });
            }
        } else {
            items.push(DiagCheckItem {
                title: "ModemManager".into(),
                detail: "Not active or not interfering".into(),
                level: DiagLevel::Ok,
            });
        }

        Self {
            os_name: "Linux".into(),
            is_linux: true,
            is_windows: false,
            overall_level,
            items,
            bash_commands: Some(Self::linux_setup_commands()),
            instructions: Some(Self::windows_instructions().to_string()),
        }
    }

    #[cfg(target_os = "windows")]
    fn diagnose_windows() -> Self {
        let mut items = Vec::new();
        let mut overall_level = DiagLevel::Ok;

        let (driver_found, driver_desc, is_functional) = check_windows_drivers();
        let winusb_status = check_windows_winusb_or_usbdk();

        // 1. Check MediaTek VCOM / CDC Driver
        if driver_found && is_functional {
            items.push(DiagCheckItem {
                title: "MediaTek VCOM Driver".into(),
                detail: format!("Detected: {driver_desc}"),
                level: DiagLevel::Ok,
            });
        } else if driver_found && !is_functional {
            overall_level = DiagLevel::ActionRequired;
            items.push(DiagCheckItem {
                title: "MediaTek Device Detected".into(),
                detail: format!("{driver_desc} — driver status error in Device Manager"),
                level: DiagLevel::ActionRequired,
            });
        } else {
            overall_level = DiagLevel::ActionRequired;
            items.push(DiagCheckItem {
                title: "MediaTek VCOM Driver".into(),
                detail: "Not installed in Windows Driver Store (required for Serial/COM port)".into(),
                level: DiagLevel::ActionRequired,
            });
        }

        // 2. Check LibUSB / WinUSB / UsbDk Support
        match winusb_status {
            WinUsbStatus::UsbDkInstalled => {
                items.push(DiagCheckItem {
                    title: "LibUSB Backend (UsbDk)".into(),
                    detail: "UsbDk filter installed (direct LibUSB communication ready)".into(),
                    level: DiagLevel::Ok,
                });
            }
            WinUsbStatus::WinUsbAssigned(name) => {
                items.push(DiagCheckItem {
                    title: "LibUSB Backend (WinUSB)".into(),
                    detail: format!("WinUSB assigned to '{name}' (LibUSB ready)"),
                    level: DiagLevel::Ok,
                });
            }
            WinUsbStatus::NotConfigured => {
                let level = if driver_found && is_functional {
                    DiagLevel::Warning
                } else {
                    DiagLevel::ActionRequired
                };
                items.push(DiagCheckItem {
                    title: "LibUSB Backend (WinUSB / UsbDk)".into(),
                    detail: "Not configured for VID 0E8D (required for LibUSB; install WinUSB via Zadig)".into(),
                    level,
                });
            }
        }

        Self {
            os_name: "Windows".into(),
            is_linux: false,
            is_windows: true,
            overall_level,
            items,
            bash_commands: Some(Self::linux_setup_commands()),
            instructions: Some(Self::windows_instructions().to_string()),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn diagnose_generic() -> Self {
        Self {
            os_name: std::env::consts::OS.to_string(),
            is_linux: false,
            is_windows: false,
            overall_level: DiagLevel::Ok,
            items: vec![DiagCheckItem {
                title: "USB Subsystem".into(),
                detail: "Standard OS USB stack active".into(),
                level: DiagLevel::Ok,
            }],
            bash_commands: Some(Self::linux_setup_commands()),
            instructions: Some(Self::windows_instructions().to_string()),
        }
    }

    /// Launches Windows Device Manager if on Windows.
    pub fn open_device_manager() -> bool {
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("devmgmt.msc").spawn().is_ok()
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Linux Internal Diagnostics
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn check_linux_udev_rules() -> (bool, Option<String>) {
    let candidate_files = [
        "/etc/udev/rules.d/51-mtk-penumbra.rules",
        "/etc/udev/rules.d/51-edl.rules",
        "/etc/udev/rules.d/99-mediatek.rules",
        "/usr/lib/udev/rules.d/51-mtk-penumbra.rules",
        "/lib/udev/rules.d/51-mtk-penumbra.rules",
    ];

    for path_str in candidate_files {
        let path = Path::new(path_str);
        if path.exists() {
            return (true, Some(path_str.to_string()));
        }
    }

    // Check directory contents for any rule matching MediaTek VID 0e8d
    let search_dirs = ["/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/lib/udev/rules.d"];
    for dir in search_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map_or(false, |ext| ext == "rules") {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        if content.contains("0e8d") || content.contains("0E8D") {
                            return (true, Some(p.display().to_string()));
                        }
                    }
                }
            }
        }
    }

    (false, None)
}

#[cfg(target_os = "linux")]
fn check_linux_user_groups() -> (bool, String, Vec<String>) {
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string());

    let mut groups = Vec::new();

    // Try `id -Gn` command
    if let Ok(out) = std::process::Command::new("id").arg("-Gn").output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            groups = text.split_whitespace().map(|s| s.to_string()).collect();
        }
    }

    // Fallback: parse /etc/group
    if groups.is_empty() {
        if let Ok(content) = std::fs::read_to_string("/etc/group") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 4 {
                    let group_name = parts[0];
                    let members: Vec<&str> = parts[3].split(',').collect();
                    if members.contains(&username.as_str()) {
                        groups.push(group_name.to_string());
                    }
                }
            }
        }
    }

    let in_group = groups.iter().any(|g| g == "uucp" || g == "dialout" || g == "plugdev");
    (in_group, username, groups)
}

#[cfg(target_os = "linux")]
fn check_modemmanager_active() -> bool {
    if let Ok(out) = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "ModemManager"])
        .output()
    {
        if out.status.success() {
            return true;
        }
    }

    // Fallback: inspect /proc for ModemManager process
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let comm_path = p.join("comm");
                if let Ok(comm) = std::fs::read_to_string(comm_path) {
                    if comm.trim() == "ModemManager" {
                        return true;
                    }
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Windows Internal Diagnostics
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq, Eq)]
enum WinUsbStatus {
    UsbDkInstalled,
    WinUsbAssigned(String),
    NotConfigured,
}

#[cfg(target_os = "windows")]
fn check_windows_drivers() -> (bool, String, bool) {
    // 1. Query PNP devices (both present and historical) matching MediaTek or VID 0E8D
    let ps_cmd = "Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_0E8D' -or $_.FriendlyName -match 'MediaTek|Preloader' } | Select-Object -First 1 | Select-Object -Property FriendlyName, Status | ConvertTo-Json -Compress";
    if let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !text.is_empty() && text.contains("FriendlyName") {
                let is_ok = text.contains("\"Status\":\"OK\"");
                let name = text
                    .split("\"FriendlyName\":")
                    .nth(1)
                    .and_then(|s| s.split('"').nth(1))
                    .unwrap_or("MediaTek USB Device");
                return (true, name.to_string(), is_ok);
            }
        }
    }

    // 2. Query pnputil for third-party driver store INF matching MediaTek
    if let Ok(out) = std::process::Command::new("pnputil")
        .args(["/enum-drivers"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.to_lowercase().contains("mediatek") || text.to_lowercase().contains("mtk") {
                return (true, "MediaTek OEM Driver package in Driver Store".into(), true);
            }
        }
    }

    // 3. Query registry for any VID_0E8D device instance registered under USB
    let reg_cmd = "Get-ChildItem -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'VID_0E8D' } | Select-Object -First 1 -ExpandProperty PSChildName";
    if let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", reg_cmd])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !text.is_empty() {
                return (true, format!("Hardware registered ({text})"), true);
            }
        }
    }

    (false, "No MediaTek VCOM driver found".into(), false)
}

#[cfg(target_os = "windows")]
fn check_windows_winusb_or_usbdk() -> WinUsbStatus {
    // 1. Check UsbDk filter service
    if check_windows_service("UsbDk") {
        return WinUsbStatus::UsbDkInstalled;
    }

    // 2. Check if any VID_0E8D device has Service == "WinUSB" or Class == "USBDevice"
    let ps_cmd = "Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_0E8D' -and ($_.Service -eq 'WinUSB' -or $_.Class -eq 'USBDevice') } | Select-Object -First 1 -ExpandProperty FriendlyName";
    if let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_cmd])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !text.is_empty() {
                return WinUsbStatus::WinUsbAssigned(text);
            }
        }
    }

    WinUsbStatus::NotConfigured
}

#[cfg(target_os = "windows")]
fn check_windows_service(service_name: &str) -> bool {
    let cmd = format!("Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Status");
    if let Ok(out) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return !text.is_empty();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_diag_run() {
        let diag = DriverDiagStatus::run();
        assert!(!diag.os_name.is_empty());
        assert!(!diag.items.is_empty());
        assert!(diag.bash_commands.is_some());
        assert!(diag.instructions.is_some());
    }

    #[test]
    fn test_linux_setup_commands() {
        let cmds = DriverDiagStatus::linux_setup_commands();
        assert!(cmds.contains("0e8d"));
        assert!(cmds.contains("51-mtk-penumbra.rules"));
        assert!(cmds.contains("udevadm control --reload-rules"));
        assert!(cmds.contains("usermod -aG"));
    }

    #[test]
    fn test_windows_instructions() {
        let instructions = DriverDiagStatus::windows_instructions();
        assert!(instructions.contains("MediaTek Preloader USB VCOM Driver"));
        assert!(instructions.contains("Zadig"));
        assert!(instructions.contains("0E8D"));
    }
}
