/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use crate::logger::{INFO_SYMBOL, LOGGER_PREIX};

/// A wrapper around indicatif ProgressBar
/// With custom styling from the logger
pub struct AntumbraProgress {
    pb: ProgressBar,
    #[allow(dead_code)]
    prefix: String,
}

impl AntumbraProgress {
    pub fn new(total_size: u64) -> Self {
        let prefix = format!("{} {}", LOGGER_PREIX.bold().purple(), INFO_SYMBOL.purple());

        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::with_template(
                &format!(
                     "{}  [{{bar:40.magenta/red}}] {{bytes}}/{{total_bytes}} ({{elapsed}} / ETA: {{eta}}, {{bytes_per_sec}}) {{msg}}",
                     prefix
                 )
            )
            .unwrap()
            .progress_chars("##-"),
        );

        Self { pb, prefix }
    }

    pub fn update(&self, written: u64, msg: &str) {
        self.pb.set_position(written);
        self.pb.set_message(msg.to_string());
    }

    pub fn finish(&self, msg: &str) {
        self.pb.finish_with_message(msg.to_string());
    }

    pub fn abandon(&self, msg: &str) {
        self.pb.abandon_with_message(msg.to_string());
    }

    pub fn set_total(&self, total: u64) {
        if self.pb.length() != Some(total) {
            self.pb.set_length(total);
        }
    }

    pub fn get_callback<'a>(
        &'a self,
        running_msg: &'a str,
        finished_msg: &'a str,
    ) -> impl FnMut(u64, u64) + 'a {
        move |written: u64, total: u64| {
            self.update(written, running_msg);

            if written >= total {
                self.finish(finished_msg);
            }
        }
    }
}
