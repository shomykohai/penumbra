/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::File;
use std::io::{BufReader, Cursor, Read, stdin};
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::Args;
use clap_num::maybe_hex;
use log::info;
use penumbra::Device;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct PokeArgs {
    /// The address to write to.
    #[clap(value_parser=maybe_hex::<u32>)]
    pub address: u32,
    /// The input file to read data from. If "-", reads from stdin.
    pub input_file: PathBuf,
}

impl CommandMetadata for PokeArgs {
    fn about() -> &'static str {
        "Poke memory."
    }

    fn long_about() -> &'static str {
        "Write data to the specified address. Data is read from a file or stdin. DA Extensions must be loaded for this command to work."
    }
}

impl DeviceCommand for PokeArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let (mut reader, length): (Box<dyn Read + Send>, u64) =
            if self.input_file.to_str() == Some("-") {
                let mut stdin_data = Vec::new();
                stdin().read_to_end(&mut stdin_data)?;
                let len = stdin_data.len() as u64;
                (Box::new(Cursor::new(stdin_data)), len)
            } else {
                let file = File::open(&self.input_file)?;
                let metadata = file.metadata()?;
                (Box::new(BufReader::new(file)), metadata.len())
            };

        if length == 0 {
            return Err(anyhow!("Input data is empty, nothing to write."));
        }

        let pb = AntumbraProgress::new(length);

        let mut progress_callback = pb.get_callback("Poking...", "Poke complete!");

        info!("Writing 0x{:X} bytes to address 0x{:08X}...", length, self.address);

        match dev.poke(self.address, length as usize, &mut reader, &mut progress_callback) {
            Ok(_) => {}
            Err(e) => {
                pb.abandon("Write failed!");
                Err(e)?;
            }
        }

        info!("Memory write completed.");

        Ok(())
    }
}
