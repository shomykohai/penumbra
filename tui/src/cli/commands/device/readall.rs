/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::fs::{File, create_dir_all, read_dir};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::Args;
use log::info;
use penumbra::Device;
use penumbra::da::DownloadProtocol;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct ReadAllArgs {
    /// The directory where the read partitions will be saved
    pub output_dir: PathBuf,
    /// What to skip
    #[arg(long, short = 's', value_delimiter = ',')]
    pub skip: Vec<String>,
}

impl CommandMetadata for ReadAllArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["rl"]
    }

    fn about() -> &'static str {
        "Read all partitions from the device and save them to the specified output directory."
    }

    fn long_about() -> &'static str {
        "Read all partitions from the device and save them to the specified output directory,
        skipping any partitions listed in the skip option."
    }
}

impl DeviceCommand for ReadAllArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        let output_dir: &Path = &self.output_dir;

        if let Err(e) = create_dir_all(output_dir) {
            return Err(anyhow!(
                "Failed to create output directory '{}': {}",
                output_dir.display(),
                e
            ));
        }

        let mut dir_entries = read_dir(output_dir)?;
        if dir_entries.next().is_some() {
            return Err(anyhow!("Output directory '{}' is not empty", output_dir.display()));
        }

        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let partitions = dev.get_partitions();
        if partitions.is_empty() {
            info!("No partitions found on device.");
            return Ok(());
        }

        let proto = dev.get_protocol().ok_or(anyhow!("Failed to get device protocol"))?;

        for p in partitions {
            if self.skip.contains(&p.name) {
                info!("Skipping partition '{}'", p.name);
                continue;
            }

            let output_path = self.output_dir.join(format!("{}.bin", p.name));
            let mut output_file = BufWriter::new(File::create(&output_path)?);

            let part_size = p.size as u64;
            let pb = AntumbraProgress::new(part_size);

            let mut progress_callback = pb.get_callback("Reading partition...", "Read complete!");

            info!("Reading partition '{}'...", p.name);

            match proto.read_flash(
                p.address,
                p.size,
                p.kind,
                &mut output_file,
                &mut progress_callback,
            ) {
                Ok(_) => {}
                Err(_) => {
                    pb.abandon("Read failed! Skipping partition.");
                }
            }

            output_file.flush()?;
            info!("Saved partition '{}' to '{}'", p.name, output_path.display());
        }

        info!("All partitions read successfully.");

        Ok(())
    }
}
