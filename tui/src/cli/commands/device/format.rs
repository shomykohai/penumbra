/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::Device;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct FormatArgs {
    /// The partition to format
    pub partition: String,
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
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let Some(part) = dev.dev_info.get_partition(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        let pb = AntumbraProgress::new(part.size as u64);

        let mut progress_callback = pb.get_callback("Formatting...", "Format complete!");

        info!("Formatting partition '{}'", part.name);

        if let Err(e) = dev.format(&part.name, &mut progress_callback) {
            pb.abandon("Format failed!");
            Err(e)?;
        }

        info!("Partition '{}' formatted.", part.name);

        Ok(())
    }
}
