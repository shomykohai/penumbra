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
pub struct DownloadArgs {
    /// The partition to flash
    pub partition: String,
    /// The file to download
    pub file: PathBuf,
}

impl CommandMetadata for DownloadArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["dl", "write", "w"]
    }

    fn about() -> &'static str {
        "Download a file to a specified partition on the device."
    }

    fn long_about() -> &'static str {
        "Download (flash) a file to a specificed partition on the device.
        Use this command for flashing stock firmware on locked bootloader, or the device
        will return write data not allowed error."
    }
}

impl DeviceCommand for DownloadArgs {
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

        if file_size > part.size as u64 {
            return Err(anyhow::anyhow!(
                "File size ({}) exceeds partition size ({}).",
                file_size,
                part.size
            ));
        }

        let pb = AntumbraProgress::new(file_size);

        let mut progress_callback = pb.get_callback("Downloading...", "Download complete!");

        info!("Downloading to partition '{}'...", part.name);

        if let Err(e) =
            dev.download(&part.name, file_size as usize, &mut reader, &mut progress_callback)
        {
            pb.abandon("Download failed!");
            Err(e)?;
        }

        info!("Download to partition '{}' completed.", part.name);

        Ok(())
    }
}
