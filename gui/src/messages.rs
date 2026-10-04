/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Command and Event message types exchanged between the UI and worker thread.

use std::path::PathBuf;

use penumbra::da::BootMode;
use penumbra::port::PortBackend;
use penumbra::storage::Partition;

/// Which action to perform on seccfg lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAction {
    Unlock,
    Lock,
}

/// Detailed device summary retrieved upon successful handshake and init.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct DeviceSummary {
    pub chip_name: String,
    pub hw_code: u16,
    pub hw_subcode: u16,
    pub soc_id: Vec<u8>,
    pub meid: Vec<u8>,
    pub target_config: u32,
    pub sbc: bool,
    pub sla: bool,
    pub daa: bool,
    pub storage_type: String,
}

/// High-level connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnStatus {
    Disconnected,
    Connecting,
    Connected(String),
}

/// A request sent from the GUI to the background worker.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Command {
    Connect {
        da_path: Option<PathBuf>,
        preloader_path: Option<PathBuf>,
        auth_path: Option<PathBuf>,
        backend: PortBackend,
    },
    Disconnect,
    LoadPartitions,
    ReadPartition {
        name: String,
        output_path: PathBuf,
    },
    WritePartition {
        name: String,
        input_path: PathBuf,
    },
    ErasePartition {
        name: String,
    },
    BatchBackup {
        names: Vec<String>,
        output_dir: PathBuf,
    },
    FlashScatter {
        files: Vec<(String, PathBuf)>,
    },
    Seccfg(LockAction),
    ReadRpmb {
        output_path: PathBuf,
    },
    WriteRpmb {
        input_path: PathBuf,
    },
    EraseRpmb,
    Reboot(BootMode),
    Shutdown,
}

/// An event sent from the background worker to the GUI.
#[derive(Debug, Clone)]
pub enum Event {
    StatusChanged(ConnStatus),
    DeviceInfo(DeviceSummary),
    PartitionsLoaded(Vec<Partition>),
    ProgressStart {
        total_bytes: u64,
        message: String,
    },
    ProgressUpdate {
        written: u64,
        total_bytes: Option<u64>,
        message: Option<String>,
    },
    ProgressFinish {
        message: String,
    },
    Error(String),
    Info(String),
    InputEnabled(bool),
}

/// A single line for the log console.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: log::Level,
    #[allow(dead_code)]
    pub target: String,
    pub message: String,
}

/// Returns true if the partition is a critical bootloader partition (Preloader, LK, LK2, Bootloader)
/// that must never be erased to prevent permanently bricking the device.
pub fn is_critical_partition(name: &str) -> bool {
    let lower = name.trim().to_lowercase();
    // Preloader variants (preloader, preloader_a, preloader_b, preloader1, preloader2, preloader_emmc, etc.)
    if lower == "preloader"
        || lower.starts_with("preloader_")
        || lower.starts_with("preloader1")
        || lower.starts_with("preloader2")
    {
        return true;
    }
    // LK (Little Kernel bootloader) variants (lk, lk_a, lk_b, lk2, lk2_a, lk2_b, lk1_a, etc.)
    if lower == "lk"
        || lower == "lk2"
        || lower.starts_with("lk_")
        || lower.starts_with("lk2_")
        || lower.starts_with("lk1_")
    {
        return true;
    }
    if lower == "bootloader" {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_critical_partition() {
        assert!(is_critical_partition("preloader"));
        assert!(is_critical_partition("PRELOADER"));
        assert!(is_critical_partition("preloader_a"));
        assert!(is_critical_partition("preloader_b"));
        assert!(is_critical_partition("preloader1"));
        assert!(is_critical_partition("preloader_emmc"));
        assert!(is_critical_partition("lk"));
        assert!(is_critical_partition("LK"));
        assert!(is_critical_partition("lk_a"));
        assert!(is_critical_partition("lk_b"));
        assert!(is_critical_partition("lk2"));
        assert!(is_critical_partition("lk2_a"));
        assert!(is_critical_partition("bootloader"));

        assert!(!is_critical_partition("boot"));
        assert!(!is_critical_partition("boot_a"));
        assert!(!is_critical_partition("recovery"));
        assert!(!is_critical_partition("system"));
        assert!(!is_critical_partition("vendor"));
        assert!(!is_critical_partition("userdata"));
        assert!(!is_critical_partition("misc"));
    }
}
