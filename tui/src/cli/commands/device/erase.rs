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
pub struct EraseArgs {
    /// The partition to erase
    pub partition: String,
}

impl CommandMetadata for EraseArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["e"]
    }

    fn about() -> &'static str {
        "Erase a partition on the device."
    }

    fn long_about() -> &'static str {
        "Erase the specified partition on the device."
    }
}

impl DeviceCommand for EraseArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let Some(part) = dev.dev_info.get_partition(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        let pb = AntumbraProgress::new(part.size as u64);

        let mut progress_callback = pb.get_callback("Erasing...", "Erase complete!");

        info!("Erasing flash at address {:#X} with size {:#X}", part.address, part.size);

        match dev.erase_partition(&self.partition, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Erase failed!");
                Err(e)?;
            }
        };

        info!("Partition '{}' erase completed.", part.name);

        Ok(())
    }
}
