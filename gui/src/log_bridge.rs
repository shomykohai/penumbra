/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

//! A `log::Log` adapter that forwards every log record to an `mpsc::Sender`
//! so the GUI can render it in the execution log pane, and simultaneously
//! writes every record to a rotating log file on disk for post-mortem debugging.
//!
//! A minimal "target=level[,...]" parser is used to honour the `RUST_LOG`
//! environment variable without pulling in the private `env_logger::filter`
//! module (which was made pub(crate) in env_logger 0.11).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::Sender;

use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};

use crate::messages::LogLine;

/// Returns the path where the session log file will be written.
///
/// Preference order:
/// 1. `$PENUMBRA_LOG_DIR` env var
/// 2. `$XDG_STATE_HOME/penumbra-gui/` (Linux standard)
/// 3. `$HOME/.local/state/penumbra-gui/`
/// 4. Current working directory as a last resort
pub fn log_file_path() -> PathBuf {
    let dir = std::env::var_os("PENUMBRA_LOG_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(|d| PathBuf::from(d).join("penumbra-gui"))
        })
        .or_else(|| {
            dirs_next::home_dir().map(|h| h.join(".local/state/penumbra-gui"))
        })
        .unwrap_or_else(|| PathBuf::from("."));

    std::fs::create_dir_all(&dir).ok();
    dir.join("penumbra-gui.log")
}

/// Sink that delivers log records into the GUI's event channel and a log file.
pub struct ChannelLogger {
    sender: Mutex<Sender<LogLine>>,
    /// Buffered file sink. `None` if the log file could not be opened.
    file: Option<Mutex<File>>,
    default: LevelFilter,
    per_target: HashMap<String, LevelFilter>,
}

/// Crates whose Info/Debug records the user does not want to see in the
/// execution log under normal operation. zbus / ashpd are particularly
/// chatty on Linux because egui's native file picker goes through
/// xdg-desktop-portal. winit / wgpu / eframe surface routine framework
/// chatter that has nothing to do with the device.
///
/// Errors and warnings still pass through. The user can override any of
/// these by setting RUST_LOG (e.g. `RUST_LOG=zbus=debug`); RUST_LOG
/// rules are parsed first, and the defaults below are only filled in
/// for targets the user did not already set explicitly.
const QUIET_TARGETS: &[&str] = &[
    "zbus",
    "zvariant",
    "ashpd",
    "polling",
    "async_io",
    "tracing",
    "winit",
    "calloop",
    "sctk",
    "smithay_client_toolkit",
    "mio",
    "naga",
    "wgpu_core",
    "wgpu_hal",
    "eframe",
    "egui_winit",
    "egui_glow",
];

impl ChannelLogger {
    fn new(sender: Sender<LogLine>, verbose: bool) -> Self {
        let (default, mut per_target) =
            parse_filter(&std::env::var("RUST_LOG").ok(), verbose);

        // Quiet noisy framework crates by default, but only if the user
        // hasn't already opted them in via RUST_LOG.
        for tgt in QUIET_TARGETS {
            per_target.entry((*tgt).to_string()).or_insert(LevelFilter::Warn);
        }

        // Default core penumbra and gui loggers to Debug so hardware and handshake details are preserved
        per_target.entry("penumbra".to_string()).or_insert(LevelFilter::Debug);
        per_target.entry("penumbra_mtk".to_string()).or_insert(LevelFilter::Debug);
        per_target.entry("penumbra_gui".to_string()).or_insert(LevelFilter::Debug);

        // Open (or create) the session log file in append mode.
        let path = log_file_path();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&path)
            .ok()
            .map(Mutex::new);

        // Write a header so it's easy to tell sessions apart.
        if let Some(f) = &file {
            if let Ok(mut guard) = f.lock() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = writeln!(
                    guard,
                    "\n=== penumbra-gui {} — session started (unix={}) ===",
                    env!("CARGO_PKG_VERSION"),
                    now,
                );
                let _ = writeln!(guard, "=== log file: {} ===", path.display());
                let _ = guard.flush();
            }
        }

        Self { sender: Mutex::new(sender), file, default, per_target }
    }

    fn level_for(&self, target: &str) -> LevelFilter {
        // Pick the longest matching prefix, matching env_logger's default behaviour.
        let mut best: Option<(usize, LevelFilter)> = None;
        for (key, lvl) in &self.per_target {
            if target == key || target.starts_with(&format!("{key}::")) {
                let len = key.len();
                if best.map(|(l, _)| len > l).unwrap_or(true) {
                    best = Some((len, *lvl));
                }
            }
        }
        best.map(|(_, l)| l).unwrap_or(self.default)
    }
}

impl Log for ChannelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level_for(metadata.target())
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let message = format!("{}", record.args());

        // Write to the file sink first (always, regardless of GUI state).
        if let Some(f) = &self.file {
            if let Ok(mut guard) = f.lock() {
                // Simple timestamp: seconds since epoch (no extra deps).
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = writeln!(
                    guard,
                    "[{secs}] [{level:<5}] [{target}] {message}",
                    level  = record.level(),
                    target = record.target(),
                );
                let _ = guard.flush();
            }
        }

        // Forward to the GUI channel.
        let line = LogLine {
            level: record.level(),
            target: record.target().to_string(),
            message,
        };
        if let Ok(tx) = self.sender.lock() {
            let _ = tx.send(line);
        }
    }

    fn flush(&self) {
        // fsync the file so nothing is lost on a hard crash.
        if let Some(f) = &self.file {
            if let Ok(guard) = f.lock() {
                let _ = guard.sync_all();
            }
        }
    }
}

/// Install a global channel logger that emits into `sender`.
///
/// This can only be called once per process.
pub fn init(sender: Sender<LogLine>, verbose: bool) -> Result<(), SetLoggerError> {
    let logger = ChannelLogger::new(sender, verbose);

    // Compute the maximum filter across all known rules so the log macros do
    // not short-circuit records that a per-target rule would have accepted.
    let max_level = logger
        .per_target
        .values()
        .copied()
        .chain(std::iter::once(logger.default))
        .max()
        .unwrap_or(LevelFilter::Info);

    log::set_max_level(max_level);
    log::set_boxed_logger(Box::new(logger))
}

fn parse_filter(
    raw: &Option<String>,
    verbose: bool,
) -> (LevelFilter, HashMap<String, LevelFilter>) {
    let default_level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };

    let Some(raw) = raw else {
        return (default_level, HashMap::new());
    };

    let mut default = default_level;
    let mut per_target: HashMap<String, LevelFilter> = HashMap::new();

    for spec in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match spec.split_once('=') {
            Some((target, level)) => {
                if let Some(lvl) = parse_level(level) {
                    per_target.insert(target.to_string(), lvl);
                }
            }
            None => {
                if let Some(lvl) = parse_level(spec) {
                    default = lvl;
                }
            }
        }
    }

    (default, per_target)
}

fn parse_level(s: &str) -> Option<LevelFilter> {
    match s.to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}
