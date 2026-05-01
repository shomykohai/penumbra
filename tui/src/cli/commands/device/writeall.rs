/*
    SPDX-License-Identifier: AGPL-3.0-or-later

    SPDX-FileCopyrightText: 2025-2026 Shomy
    SPDX-FileCopyrightText: 2026 Igor Belwon <igor.belwon@mentallysanemainliners.org>
*/
use std::fs::{File, exists, metadata, read_dir};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::Args;
use log::info;
use penumbra::Device;

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct WriteAllArgs {
    /// The directory with the partitions (from rl)
    pub input_dir: PathBuf,
    /// What to skip
    #[arg(long, short = 's', value_delimiter = ',')]
    pub skip: Vec<String>,
    /// Ignore missing partitions
    #[arg(long, short = 'i')]
    pub ignore_missing: bool,
}

impl CommandMetadata for WriteAllArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["wl"]
    }

    fn about() -> &'static str {
        "Writes all partitions from the specified directory and flashes them to the device."
    }

    fn long_about() -> &'static str {
        "Writes all partitions from the specified directory and flashes them to the device,
        skipping any partitions listed in the skip option or that do not exist in the directory."
    }
}

impl DeviceCommand for WriteAllArgs {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()> {
        let input_dir: &Path = &self.input_dir;

        if exists(input_dir).is_err() {
            return Err(anyhow!("The specified directory does not exist!",));
        }

        let mut dir_entries = read_dir(input_dir)?;
        if dir_entries.next().is_none() {
            return Err(anyhow!("The input directory '{}' is empty!", input_dir.display()));
        }

        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        for (name, filename) in dir_entries.filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();

            // So that we get ("part_name", "filename").
            if path.extension()? == "bin" {
                let part_name = path.file_stem()?.to_string_lossy().into_owned();
                let full_path = path.to_string_lossy().into_owned();

                Some((part_name, full_path))
            } else {
                None
            }
        }) {
            if self.skip.contains(&name) {
                info!("Skipping partition '{}'.", name);
                continue;
            }

            let file = File::open(&filename)?;
            let mut reader = BufReader::new(file);

            let file_size = metadata(filename)?.len();

            let Some(part) = dev.dev_info.get_partition(&name) else {
                if !self.ignore_missing {
                    return Err(anyhow::anyhow!(
                        "Partition '{name}' doesn't exist. This behaviour can be ignored with -i."
                    ));
                }
                info!("Skipping partition '{}' due to it not existing on the device.", name);
                continue;
            };

            if file_size > part.size as u64 {
                return Err(anyhow::anyhow!(
                    "File size ({file_size}) exceeds partition size ({}).",
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
                return Err(e)?;
            }

            info!("Download to partition '{}' completed.", part.name);
        }

        info!("Write completed successfully.");

        Ok(())
    }
}
