/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use clap_num::maybe_hex;
use log::info;
use penumbra::{Device, Storage};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct ReadOffArgs {
    /// The address to read from.
    #[clap(value_parser=maybe_hex::<u64>)]
    pub address: u64,
    /// The number of bytes to read.
    #[clap(value_parser=maybe_hex::<usize>)]
    pub length: usize,
    /// The destination file
    pub output_file: PathBuf,
}

impl CommandMetadata for ReadOffArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["ro"]
    }

    fn about() -> &'static str {
        "Read the device flash from the specific offset and save it to a file."
    }

    fn long_about() -> &'static str {
        "Read the device flash from the specified offset and length, and save it
        to a file with the given output filename."
    }
}

impl DeviceCommand for ReadOffArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let file = File::create(&self.output_file)?;
        let mut writer = BufWriter::new(file);

        let user_section = dev.dev_info.storage().unwrap().get_user_part();

        let pb = AntumbraProgress::new(self.length as u64);

        let mut progress_callback = pb.get_callback("Reading...", "Read complete!");

        info!("Reading flash at address {:#X} with size 0x{:X}", self.address, self.length);

        if let Err(e) = dev.read_offset(
            self.address,
            self.length,
            user_section,
            &mut writer,
            &mut progress_callback,
        ) {
            pb.abandon("Read failed!");
            Err(e)?;
        };

        writer.flush()?;

        info!(
            "Flash read completed, {:#X} bytes written to '{}'.",
            self.length,
            self.output_file.display()
        );

        Ok(())
    }
}
