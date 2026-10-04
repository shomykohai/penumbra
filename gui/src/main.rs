/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Entry point for the Penumbra GUI.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

mod app;
mod driver_diag;
mod log_bridge;
mod messages;
mod theme;
mod worker;

use std::sync::mpsc;

use anyhow::Result;
use eframe::NativeOptions;
use eframe::egui::ViewportBuilder;

use crate::messages::{Event, LogLine};

fn main() -> Result<()> {
    let (log_tx, log_rx) = mpsc::channel::<LogLine>();
    let verbose = std::env::var("PENUMBRA_VERBOSE").is_ok();
    let _ = log_bridge::init(log_tx, verbose);

    eprintln!("[penumbra-gui] session log: {}", log_bridge::log_file_path().display());

    let (evt_tx, evt_rx) = mpsc::channel::<Event>();
    let handle = worker::spawn(evt_tx);

    let viewport = ViewportBuilder::default()
        .with_inner_size([1120.0, 740.0])
        .with_min_inner_size([920.0, 600.0])
        .with_title("Penumbra Flasher");

    let native_options = NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Penumbra Flasher",
        native_options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, handle, evt_rx, log_rx)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}
