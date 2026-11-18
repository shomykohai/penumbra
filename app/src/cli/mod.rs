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
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{CommandFactory, Parser};
use clap_num::maybe_hex;
use penumbra::da::DaLogLevel;
use penumbra::{Device, MtkPort, PortBackend};

use crate::cli::commands::*;
use crate::cli::macros::cli_commands;
use crate::cli::state::PersistedDeviceState;
use crate::config::AntumbraConfig;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct CliArgs {
    /// Run in TUI mode. Defaults to CLI mode if not specified.
    #[arg(short, long, global = true)]
    pub tui: bool,
    /// Enable verbose logging, including debug information.
    /// This does not influence the DA UART log level.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(
            short = 'b',
            long = "backend",
            global = true,
            default_value = "auto",
            help_heading = "Device & Connection Options",
            value_parser = PossibleValuesParser::new(["auto", "usb", "libusb", "serial"])
                .map(|s| match s.to_lowercase().as_str() {

                    "auto" => PortBackend::Auto,
                    #[cfg(not(target_os = "android"))]
                    "usb" => PortBackend::Usb,
                    "libusb" => PortBackend::Libusb,
                    #[cfg(not(target_os = "android"))]
                    "serial" => PortBackend::Serial,
                    _ => PortBackend::Auto,
                })
        )]
    pub backend: PortBackend,

    /// Optional USB VID. If not specified, the first available device will be used.
    #[arg(long = "vid", help_heading = "Device & Connection Options", global = true)]
    #[clap(value_parser=maybe_hex::<u16>)]
    pub vid: Option<u16>,
    /// Optional USB PID. If not specified, the first available device will be used.
    #[arg(long = "pid", help_heading = "Device & Connection Options", global = true)]
    #[clap(value_parser=maybe_hex::<u16>)]
    pub pid: Option<u16>,

    /// Sets the DA internal log level.
    #[arg(
            short = 'l',
            long = "log-level",
            global = true,
            default_value = "info",
            help_heading = "Device & Connection Options",
            value_parser = PossibleValuesParser::new(["trace", "debug", "info", "warning", "warn", "error", "fatal"])
                .map(|s| match s.to_lowercase().as_str() {
                    "trace" => DaLogLevel::Trace,
                    "debug" => DaLogLevel::Debug,
                    "info" => DaLogLevel::Info,
                    "warning" | "warn" => DaLogLevel::Warning,
                    "error" => DaLogLevel::Error,
                    "fatal" => DaLogLevel::Fatal,
                    _ => unreachable!(),
                })
        )]
    pub da_log_level: DaLogLevel,
    /// The DA file to use for entering DA mode.
    #[arg(
        short,
        long = "da",
        value_name = "DA_FILE",
        global = true,
        help_heading = "Device & Connection Options"
    )]
    pub da_file: Option<PathBuf>,
    /// The preloader file to use for the device. This is required when connecting XFlash devices
    /// in bootrom mode.
    #[arg(
        short,
        long = "pl",
        value_name = "PRELOADER_FILE",
        global = true,
        help_heading = "Device & Connection Options"
    )]
    pub preloader_file: Option<PathBuf>,
    /// The auth file required for DAA and SLA when connecting in bootrom mode.
    #[arg(
        short,
        long = "auth",
        value_name = "AUTH_FILE",
        global = true,
        help_heading = "Device & Connection Options"
    )]
    pub auth_file: Option<PathBuf>,
    /// Enable USB DA logging
    #[arg(long = "usb-log", global = true, help_heading = "Device & Connection Options")]
    pub usb_log: bool,
    /// Subcommands for CLI mode. If provided, TUI mode will be disabled.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

pub trait DeviceCommand {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()>;
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
        Scatter(ScatterArgs),
        Seccfg(SeccfgArgs),
        Pgpt(PgptArgs),
        Peek(PeekArgs),
        Poke(PokeArgs),
        Peek32(Peek32Args),
        Poke32(Poke32Args),
        Rpmb(RpmbArgs),
        Shutdown(ShutdownArgs),
        Reboot(RebootArgs),
        XFlash(XFlashArgs),
        StorageInfo(StorageInfoArgs),
        SetActiveSlot(SetActiveSlotArgs),
        GetActiveSlot(GetActiveSlotArgs),
        Keys(KeysArgs),
        Efuse(EfuseArgs),
        Crash(CrashArgs),
        BootPl(BootPlArgs),
    }
    cli {
        PatchDa(PatchDaArgs),
    }
}

pub fn run_cli(args: &CliArgs, _config: &AntumbraConfig) -> Result<()> {
    if let Some(cmd) = &args.command {
        let mut state = PersistedDeviceState::load();

        let result = cmd.execute(args, &mut state);

        state.save()?;

        result?
    } else {
        CliArgs::command().print_help()?;
    }

    Ok(())
}
