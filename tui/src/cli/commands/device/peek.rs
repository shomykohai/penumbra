/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use clap_num::maybe_hex;
use log::info;
use penumbra::Device;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct PeekArgs {
    /// The address to read from.
    #[clap(value_parser=maybe_hex::<u32>)]
    pub address: u32,
    /// The number of bytes to read.
    #[clap(value_parser=maybe_hex::<usize>)]
    pub length: usize,
    /// The output file to save the read data to.
    pub output_file: PathBuf,
}

impl CommandMetadata for PeekArgs {
    fn about() -> &'static str {
        "Peek memory."
    }

    fn long_about() -> &'static str {
        "Read memory from the specified address and length. DA Extensions must be loaded for this command to work."
    }
}

impl DeviceCommand for PeekArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let file = File::create(&self.output_file)?;
        let mut writer = BufWriter::new(file);

        let pb = AntumbraProgress::new(self.length as u64);

        let mut progress_callback = pb.get_callback("Peeking...", "Peek complete!");

        info!(
            "Reading memory from address 0x{:08X}, length 0x{:X} bytes...",
            self.address, self.length
        );

        match dev.peek(self.address, self.length, &mut writer, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Read failed!");
                Err(e)?;
            }
        }

        info!("Memory readback completed, saved to {:?}", self.output_file);

        Ok(())
    }
}
