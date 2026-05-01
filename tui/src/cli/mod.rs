/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
pub mod commands;
pub mod common;
pub mod helpers;
pub mod macros;
pub mod state;

use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use penumbra::Device;

use crate::cli::commands::*;
use crate::cli::macros::cli_commands;
use crate::cli::state::PersistedDeviceState;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct CliArgs {
    /// Run in CLI mode without TUI
    #[arg(short, long, global = true)]
    pub cli: bool,
    /// Enable verbose logging, including debug information
    #[arg(short, long, global = true)]
    pub verbose: bool,
    /// The DA file to use
    #[arg(short, long = "da", value_name = "DA_FILE", global = true)]
    pub da_file: Option<PathBuf>,
    /// The preloader file to use
    #[arg(short, long = "pl", value_name = "PRELOADER_FILE", global = true)]
    pub preloader_file: Option<PathBuf>,
    /// The auth file for DAA enabled devices
    #[arg(short, long = "auth", value_name = "AUTH_FILE", global = true)]
    pub auth_file: Option<PathBuf>,
    /// Enable USB DA logging
    #[arg(long = "usb-log", global = true)]
    pub usb_log: bool,
    /// Subcommands for CLI mode. If provided, TUI mode will be disabled.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

pub trait DeviceCommand {
    fn run(&self, dev: &mut Device, state: &mut PersistedDeviceState) -> Result<()>;
}

pub trait CliCommand {
    fn run(&self, state: &mut PersistedDeviceState) -> Result<()>;
}

cli_commands! {
    device {
        Download(DownloadArgs),
        Upload(UploadArgs),
        Format(FormatArgs),
        WriteFlash(WriteArgs),
        ReadFlash(ReadArgs),
        WriteOffset(WriteOffArgs),
        ReadOffset(ReadOffArgs),
        Erase(EraseArgs),
        WriteAll(WriteAllArgs),
        ReadAll(ReadAllArgs),
        Seccfg(SeccfgArgs),
        Pgpt(PgptArgs),
        Peek(PeekArgs),
        Poke(PokeArgs),
        Rpmb(RpmbArgs),
        Shutdown(ShutdownArgs),
        Reboot(RebootArgs),
        XFlash(XFlashArgs),
        SetActiveSlot(SetActiveSlotArgs),
        Crash(CrashArgs)
    }
    cli {}
}

pub async fn run_cli(args: &CliArgs) -> Result<()> {
    if let Some(cmd) = &args.command {
        let mut state = PersistedDeviceState::load().await;

        cmd.execute(args, &mut state).await?;

        state.save().await?;
    } else {
        CliArgs::command().print_help()?;
    }

    Ok(())
}
