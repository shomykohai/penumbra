/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
#[macro_use]
mod macros;

#[cfg(feature = "tui")]
mod app;
#[cfg(feature = "tui")]
mod components;
#[cfg(feature = "tui")]
mod pages;
#[cfg(feature = "tui")]
mod themes;

mod auth;
mod cli;
mod config;
mod helpers;
mod logger;
mod safety;

use anyhow::Result;
use clap::Parser;
use cli::{CliArgs, run_cli};
use logger::init_logger;

use crate::auth::init_auth;
use crate::config::AntumbraConfig;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    #[cfg(all(windows, feature = "tui"))]
    let tui = args.tui || !cli_or_gui::is_launched_from_terminal();

    #[cfg(not(all(windows, feature = "tui")))]
    let tui = args.tui;

    init_logger(tui, args.verbose);

    let config = AntumbraConfig::load()?;

    init_auth(config.clone())?;

    if !tui || !cfg!(feature = "tui") {
        return run_cli(&args, &config);
    }

    #[cfg(feature = "tui")]
    {
        use app::App;

        let mut terminal = ratatui::init();
        let mut app = App::new(&args, config);

        let app_result = app.run(&mut terminal);

        ratatui::restore();
        app_result
    }

    #[cfg(not(feature = "tui"))]
    unreachable!()
}
