/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
mod app;
mod pages;
mod components;
use app::App;
use env_logger::Builder;
use std::fs::File;
use std::io::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let log_file = File::create("app.log").expect("Failed to create log file");

    Builder::new()
        .parse_default_env()
        .write_style(env_logger::WriteStyle::Always)
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .init();

    let mut terminal = ratatui::init();
    let mut app = App::new();

    let app_result = app.run(&mut terminal).await;

    ratatui::restore();
    app_result
}
