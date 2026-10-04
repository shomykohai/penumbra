/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::{Device, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;
use crate::safety::{critical_erase_message, is_critical_boot_partition};

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// The partition to format
    pub partition: String,
    /// Allow formatting critical boot partitions such as preloader and LK.
    #[arg(long)]
    pub force_critical: bool,
}

impl CommandMetadata for FormatArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["ft"]
    }

    fn about() -> &'static str {
        "Format a partition on the device."
    }

    fn long_about() -> &'static str {
        "Format (erase) the specified partition on the device."
    }
}

impl DeviceCommand for FormatArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let Some(part) = dev.get_partition_active(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        if is_critical_boot_partition(&part.name) && !self.force_critical {
            return Err(anyhow::anyhow!(critical_erase_message(&part.name)));
        }

        let pb = AntumbraProgress::new(part.size);

        let mut progress_callback = pb.get_callback("Formatting...", "Format complete!");

        info!("Formatting partition '{}'", part.name);

        if let Err(e) = dev.erase_partition(&part.name, &mut progress_callback) {
            pb.abandon("Format failed!");
            Err(e)?;
        }

        info!("Partition '{}' formatted.", part.name);

        Ok(())
    }
}
