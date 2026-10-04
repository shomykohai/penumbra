/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Penumbra Contributors
*/

/// Returns whether erasing `name` can make a device unable to enter its normal boot chain.
///
/// This is deliberately narrower than a list of partitions whose loss may erase user or
/// calibration data. The guard protects bootloader partitions that are especially easy to erase
/// accidentally; callers should still warn before every destructive operation.
pub fn is_critical_boot_partition(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();

    name == "bootloader"
        || name == "lk"
        || name == "lk2"
        || name.starts_with("lk_")
        || name.starts_with("lk1_")
        || name.starts_with("lk2_")
        || name == "preloader"
        || name.starts_with("preloader_")
        || name.starts_with("preloader1")
        || name.starts_with("preloader2")
}

pub fn critical_erase_message(name: &str) -> String {
    format!(
        "Refusing to erase critical boot partition '{name}'. Re-run with --force-critical to acknowledge the permanent-brick risk."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_critical_boot_partitions_case_insensitively() {
        for name in [
            "preloader",
            "PRELOADER",
            "preloader_a",
            "preloader_backup",
            "preloader1",
            "preloader2_emmc",
            "lk",
            "LK_A",
            "lk1_a",
            "lk2",
            "lk2_b",
            "bootloader",
        ] {
            assert!(is_critical_boot_partition(name), "{name}");
        }
    }

    #[test]
    fn does_not_overmatch_normal_partitions() {
        for name in ["boot", "boot_a", "recovery", "system", "vendor", "userdata", "misc"] {
            assert!(!is_critical_boot_partition(name), "{name}");
        }
    }
}
