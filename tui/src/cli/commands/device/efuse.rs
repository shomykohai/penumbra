/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use log::{error, info};
use penumbra::{Device, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::state::PersistedDeviceState;

#[derive(Subcommand, Debug, Clone)]
pub enum EfuseAction {
    /// Read eFuse data to a file
    Read {
        /// Path to the output file
        file: PathBuf,
    },
    /// Write eFuse data from a file
    Write {
        /// Path to the input file containing eFuse data
        file: PathBuf,
        /// Confirmation flag required to write eFuses
        #[arg(long)]
        confirm: bool,
        /// You really know what you're doing, right?
        #[arg(long, hide = true)]
        iamawareoftherisks: bool,
    },
}

#[derive(Args, Debug)]
pub struct EfuseArgs {
    #[command(subcommand)]
    pub action: EfuseAction,
}

impl CommandMetadata for EfuseArgs {
    fn about() -> &'static str {
        "Read or write eFuses on the device."
    }

    fn long_about() -> &'static str {
        "Read or write eFuses on the device using a specified binary file."
    }
}

impl DeviceCommand for EfuseArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        match &self.action {
            EfuseAction::Read { file } => {
                info!("Reading eFuses to file: {}", file.display());

                let writer = BufWriter::new(File::create(file)?);
                dev.read_efuses(writer)?;

                info!("eFuse read completed successfully.");
            }
            EfuseAction::Write { file, confirm, iamawareoftherisks } => {
                if !confirm {
                    error!(
                        "Writing eFuses is a destructive operation. Use the --confirm flag to proceed."
                    );
                    error!(
                        "By proceeding, you acknowledge that you understand the risks and consequences of writing eFuses."
                    );
                    bail!("eFuse write aborted: missing --confirm flag");
                }

                if !iamawareoftherisks {
                    error!(
                        "No support will be provided for any issues arising from writing eFuses. Proceed at your own risk."
                    );
                    error!(
                        "Authors are not responsible for any damage caused during the process, nor will liability be accepted for issues arising from writing eFuses."
                    );
                    error!(
                        "If you REALLY know what you're doing, add the --iamawareoftherisks flag to confirm your understanding of the risks."
                    );
                    bail!("eFuse write aborted: missing --iamawareoftherisks flag");
                }

                let reader = File::open(file)?;
                let size = reader.metadata()?.len();

                info!("Writing eFuses from file: {}", file.display());

                dev.write_efuses(reader, size)?;

                info!("eFuse write completed successfully.");
            }
        }

        Ok(())
    }
}
