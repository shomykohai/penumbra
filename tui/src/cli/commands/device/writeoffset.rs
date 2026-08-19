/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::fs::File;
use std::io::BufReader;
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
pub struct WriteOffArgs {
    /// The address to write to.
    #[clap(value_parser=maybe_hex::<u64>)]
    pub address: u64,
    /// The number of bytes to write.
    #[clap(value_parser=maybe_hex::<usize>)]
    pub length: usize,
    /// The input file
    pub input_file: PathBuf,
}

impl CommandMetadata for WriteOffArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["wo"]
    }

    fn about() -> &'static str {
        "Write the device flash to the specific offset from a file."
    }

    fn long_about() -> &'static str {
        "Write the device flash to the specified offset and length, from the given file.
        The file should be at least as large as the specified length.
        If the file is larger than the specified length, only the first 'length' bytes will be written to the device."
    }
}

impl DeviceCommand for WriteOffArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let file = File::open(&self.input_file)?;
        let mut reader = BufReader::new(file);

        let user_section = dev.dev_info.storage().unwrap().get_user_part();

        let pb = AntumbraProgress::new(self.length as u64);

        let mut progress_callback = pb.get_callback("Writing...", "Write complete!");

        info!("Writing flash at address {:#X} with size 0x{:X}", self.address, self.length);

        if let Err(e) = dev.write_offset(
            self.address,
            self.length,
            user_section,
            &mut reader,
            &mut progress_callback,
        ) {
            pb.abandon("Write failed!");
            Err(e)?;
        };

        info!("Flash write completed, {:#X} bytes written.", self.length);

        Ok(())
    }
}
