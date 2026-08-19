/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::File;
use std::io::BufWriter;
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
pub struct UploadArgs {
    /// The partition to read
    pub partition: String,
    /// The destination file
    pub output_file: PathBuf,
}

impl CommandMetadata for UploadArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["up", "read", "r"]
    }

    fn about() -> &'static str {
        "Upload a partition from the device to the host."
    }

    fn long_about() -> &'static str {
        "Upload (readback) a specificed partition on the device to a file on the host.
        Use this command for reading back if the `read` command fails."
    }
}

impl DeviceCommand for UploadArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let Some(part) = dev.dev_info.get_partition(&self.partition) else {
            return Err(anyhow::anyhow!("Partition '{}' not found on device.", self.partition));
        };

        let total_size = part.size as u64;
        let pb = AntumbraProgress::new(total_size);

        let mut progress_callback = pb.get_callback("Reading partition...", "Read complete!");

        let file = File::create(&self.output_file)?;
        let mut writer = BufWriter::new(file);

        info!("Reading partition '{}' with size {:#X}", part.name, part.size);

        match dev.upload(&part.name, &mut writer, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Upload failed!");
                Err(e)?;
            }
        };

        info!(
            "Readback complete, {:#X} bytes written to '{}'",
            total_size,
            self.output_file.display()
        );

        Ok(())
    }
}
