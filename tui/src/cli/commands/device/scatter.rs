/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::{Device, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;
use crate::helpers::ScatterFiles;

#[derive(Args, Debug)]
pub struct ScatterArgs {
    /// The scatter file to use
    pub scatter: PathBuf,
}

impl CommandMetadata for ScatterArgs {
    fn about() -> &'static str {
        "Flash the device firmware using a scatter file."
    }

    fn long_about() -> &'static str {
        "Flash the device firmware using the provided scatter file.
        The firmware files are relative to the scatter file. If not found,
        an error will be thrown.
        If necessary, some partition will be backed up in a proper directory
        relative to the scatter file"
    }
}

impl DeviceCommand for ScatterArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        let scatter_content = std::fs::read_to_string(&self.scatter)?;

        let scatter_dir = self.scatter.parent().unwrap_or_else(|| Path::new("")).to_path_buf();

        let files = ScatterFiles::new(scatter_dir);
        let readers = files.clone();

        let reader_source = move |file_path: &str| readers.reader(file_path);
        let writer_sink = move |file_path: &str| files.writer(file_path);

        let progress_bar = AntumbraProgress::new(0);

        let progress_callback = move |curr: u64, total: u64| {
            progress_bar.set_total(total);
            progress_bar.update(curr, "Flashing device...");

            if curr >= total && total > 0 {
                progress_bar.finish("");
            }
        };

        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        info!("Flashing from scatter file {}", self.scatter.to_string_lossy());

        dev.flash_scatter(&scatter_content, reader_source, writer_sink, progress_callback)?;

        info!("Successfully flashed from scatter file!");

        Ok(())
    }
}
