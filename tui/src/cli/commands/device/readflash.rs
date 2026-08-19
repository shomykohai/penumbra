/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::File;
use std::io::{BufWriter, Write};
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
pub struct ReadArgs {
    /// The partition to read
    pub partition: String,
    /// The destination file
    pub output_file: PathBuf,
}

impl CommandMetadata for ReadArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["rf"]
    }

    fn about() -> &'static str {
        "Read a partition from the device and save it to a file."
    }

    fn long_about() -> &'static str {
        "Read a specified partition from the device and save it to a file with the given output filename."
    }
}

impl DeviceCommand for ReadArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let Some(part) = dev.dev_info.get_partition(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        let total_size = part.size as u64;
        let pb = AntumbraProgress::new(total_size);

        let mut progress_callback = pb.get_callback("Reading flash...", "Read complete!");

        let file = File::create(&self.output_file)?;
        let mut writer = BufWriter::new(file);

        info!("Reading flash at address {:#X} with size 0x{:X}", part.address, total_size);

        match dev.read_partition(&part.name, &mut writer, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Read failed!");
                Err(e)?;
            }
        };

        writer.flush()?;

        info!(
            "Flash read completed, {:#X} bytes written to '{}'.",
            total_size,
            self.output_file.display()
        );

        Ok(())
    }
}
