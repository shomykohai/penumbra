/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use log::debug;
use penumbra::SoC;

#[derive(Clone)]
pub struct ScatterFiles {
    dir: PathBuf,
}

impl ScatterFiles {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn resolve(&self, file_path: &str) -> PathBuf {
        let mut clean = file_path.trim_start_matches("./");

        if let Some(stripped) = clean.strip_prefix("backup/") {
            clean = stripped.trim_start_matches("./");
        }

        if let Some(stripped) = clean.strip_prefix("out/") {
            clean = stripped.trim_start_matches("./");
        }

        self.dir.join(clean)
    }

    pub fn reader(&self, file_path: &str) -> penumbra::Result<(BufReader<File>, u64)> {
        let full_path = if Path::new(file_path).is_absolute() {
            PathBuf::from(file_path)
        } else {
            self.resolve(file_path)
        };

        debug!("Reading from input file: {:?}", full_path);

        let file = File::open(&full_path)?;
        let size = file.metadata()?.len();

        Ok((BufReader::new(file), size))
    }

    pub fn writer(&self, file_path: &str) -> penumbra::Result<BufWriter<File>> {
        let full_path = self.resolve(file_path);

        debug!("Writing to output file: {:?}", full_path);

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(BufWriter::new(File::create(&full_path)?))
    }
}

pub trait SoCExt {
    fn segment_short(&self) -> &str;
    fn marketing_short(&self) -> Option<&str>;
    fn marketing_seg_name(&self) -> String;
}

impl SoCExt for SoC {
    fn segment_short(&self) -> &'static str {
        let name = self.segment_name();

        match name.match_indices('/').nth(2) {
            Some((index, _)) => &name[..index],
            None => name,
        }
    }

    fn marketing_short(&self) -> Option<&str> {
        let name = self.marketing_name()?;

        match name.match_indices('/').nth(2) {
            Some((index, _)) => Some(&name[..index]),
            None => Some(name),
        }
    }

    fn marketing_seg_name(&self) -> String {
        self.marketing_short().map_or_else(
            || self.segment_short().to_owned(),
            |marketing| format!("{} ({})", self.segment_short(), marketing),
        )
    }
}
