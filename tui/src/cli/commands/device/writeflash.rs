/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::{File, metadata};
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::Device;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct WriteArgs {
    /// The partition to flash
    pub partition: String,
    /// The file to download
    pub file: PathBuf,
}

impl CommandMetadata for WriteArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["wf"]
    }

    fn about() -> &'static str {
        "Write a file to a specified partition on the device."
    }

    fn long_about() -> &'static str {
        "Write (flash) a file to a specificed partition on the device.
        If this command fails, use `download` instead."
    }
}

impl DeviceCommand for WriteArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let file = File::open(&self.file)?;
        let mut reader = BufReader::new(file);

        let file_size = metadata(&self.file)?.len();

        let Some(part) = dev.dev_info.get_partition(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        let part_size = part.size as u64;

        let total_size = file_size.min(part_size);
        let pb = AntumbraProgress::new(total_size);

        let mut progress_callback = pb.get_callback("Writing flash...", "Write complete!");

        info!("Writing flash at address {:#X} with size {:#X}...", part.address, total_size);

        if let Err(e) = dev.write_partition(&part.name, &mut reader, &mut progress_callback) {
            pb.abandon("Write failed!");
            Err(e)?;
        }

        info!("Flash write completed, {:#X} bytes written.", total_size);

        Ok(())
    }
}
