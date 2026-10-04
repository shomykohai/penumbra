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
pub struct EraseArgs {
    /// The partition to erase
    pub partition: String,
    /// Allow erasing critical boot partitions such as preloader and LK.
    #[arg(long)]
    pub force_critical: bool,
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

        let mut progress_callback = pb.get_callback("Erasing...", "Erase complete!");

        info!("Erasing flash at address {:#X} with size {:#X}", part.address, part.size);

        match dev.erase_flash(&self.partition, &mut progress_callback) {
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
