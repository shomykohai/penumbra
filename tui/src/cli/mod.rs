/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
mod commands;
mod common;
mod helpers;
mod macros;
mod state;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use clap::{CommandFactory, Parser};
use log::info;
use penumbra::connection::port::ConnectionType;
use penumbra::core::devinfo::DevInfoData;
use penumbra::{Device, DeviceBuilder, find_mtk_port};
use tokio::fs::read;

use crate::cli::commands::*;
use crate::cli::macros::mtk_commands;
use crate::cli::state::PersistedDeviceState;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct CliArgs {
    /// Run in CLI mode without TUI
    #[arg(short, long)]
    pub cli: bool,
    /// Enable verbose logging, including debug information
    #[arg(short, long)]
    pub verbose: bool,
    /// The DA file to use
    #[arg(short, long = "da", value_name = "DA_FILE")]
    pub da_file: Option<PathBuf>,
    /// The preloader file to use
    #[arg(short, long = "pl", value_name = "PRELOADER_FILE")]
    pub preloader_file: Option<PathBuf>,
    /// Subcommands for CLI mode. If provided, TUI mode will be disabled.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

mtk_commands! {
    Download(DownloadArgs),
    Upload(UploadArgs),
    Format(FormatArgs),
    WriteFlash(WriteArgs),
    ReadFlash(ReadArgs),
    Erase(EraseArgs),
    ReadAll(ReadAllArgs),
    Seccfg(SeccfgArgs),
    Pgpt(PgptArgs),
    Peek(PeekArgs),
    Shutdown(ShutdownArgs),
    Reboot(RebootArgs),
    XFlash(XFlashArgs),
}

#[async_trait]
pub trait MtkCommand {
    fn da(&self) -> Option<&PathBuf> {
        None
    }
    fn pl(&self) -> Option<&PathBuf> {
        None
    }
    async fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()>;
}

pub async fn run_cli(args: &CliArgs) -> Result<()> {
    if args.command.is_none() {
        CliArgs::command().print_help()?;
        return Ok(());
    }

    let mut state = PersistedDeviceState::load().await;

    let da_data = if let Some(cmd) = &args.command {
        if let Some(da_path) = cmd.da() {
            let data = read(da_path).await?;
            state.da_file_path = Some(da_path.to_string_lossy().to_string());
            Some(data)
        } else {
            None
        }
    } else {
        None
    };

    let pl_data = if let Some(cmd) = &args.command {
        if let Some(pl_path) = cmd.pl() {
            let data = read(pl_path).await?;
            Some(data)
        } else {
            None
        }
    } else {
        None
    };

    let mut last_seen = Instant::now();
    let timeout = Duration::from_millis(500);

    info!("Waiting for MTK device...");
    let mtk_port = loop {
        if let Some(port) = find_mtk_port().await {
            info!("Found MTK port: {}", port.get_port_name());
            break port;
        } else if last_seen.elapsed() > timeout {
            state.reset().await?;
            last_seen = Instant::now();
        }
    };

    let mut builder = DeviceBuilder::default()
        .with_mtk_port(mtk_port)
        .with_verbose(args.verbose);

    builder = if let Some(da) = da_data {
        builder.with_da_data(da)
    } else if let Some(da_path_str) = &state.da_file_path {
        let da_path = Path::new(da_path_str);
        let data = read(da_path).await?;
        builder.with_da_data(data)
    } else {
        builder
    };

    builder = if let Some(pl) = pl_data { builder.with_preloader(pl) } else { builder };

    let mut dev = builder.build()?;

    if state.hw_code != 0 {
        let dev_info = DevInfoData {
            soc_id: state.soc_id.clone(),
            meid: state.meid.clone(),
            hw_code: state.hw_code,
            chipset: String::from("Unknown"),
            storage: None,
            partitions: vec![],
            target_config: state.target_config,
        };

        if state.flash_mode != 0 {
            dev.set_connection_type(ConnectionType::Da)?;
        }

        dev.reinit(dev_info).await?;
    } else {
        info!("Initializing device...");
        dev.init().await?;

        state.soc_id = dev.dev_info.soc_id().await;
        state.meid = dev.dev_info.meid().await;
        state.hw_code = dev.dev_info.hw_code().await;
        state.target_config = dev.dev_info.target_config().await;

        state.save().await?;
    }

    info!("=====================================");
    info!("SBC: {}", (state.target_config & 0x1) != 0);
    info!("SLA: {}", (state.target_config & 0x2) != 0);
    info!("DAA: {}", (state.target_config & 0x4) != 0);
    info!("=====================================");

    if let Some(cmd) = &args.command {
        cmd.run(&mut dev, &mut state).await?;
        state.target_config = dev.dev_info.target_config().await; // Update just in case after Kamakiri
        state.save().await?;
    }

    Ok(())
}
