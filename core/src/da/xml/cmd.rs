/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::collections::BTreeMap;
use std::fmt::Display;

use penumbra_macros::XmlCommand;

pub const CMD_START: &[u8] = b"<command>CMD:START</command>";
pub const CMD_END: &[u8] = b"<command>CMD:END</command>";
pub const CMD_DOWNLOAD_FILE: &str = "CMD:DOWNLOAD-FILE";
pub const CMD_UPLOAD_FILE: &str = "CMD:UPLOAD-FILE";
pub const CMD_PROGRESS_REPORT: &str = "CMD:PROGRESS-REPORT";
pub const CMD_FILE_SYSTEM_OP: &str = "CMD:FILE-SYS-OPERATION";

/// Perform a (fake) file system operation
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum FileSystemOp {
    MkDir,
    Exists,
    FileSize(u64),
    RemoveAll,
    Remove,
}

impl FileSystemOp {
    pub fn default(&self) -> String {
        match self {
            Self::MkDir => "MKDIR\u{0}".to_string(),
            Self::Exists => "NOT-EXISTS\u{0}".to_string(), // To avoid more reads
            Self::FileSize(size) => format!("0x{:X}\u{0}", size),
            Self::RemoveAll => "REMOVE-ALL\u{0}".to_string(),
            Self::Remove => "REMOVE\u{0}".to_string(),
        }
    }
}

impl From<FileSystemOp> for String {
    fn from(op: FileSystemOp) -> Self {
        op.default()
    }
}

impl From<String> for FileSystemOp {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl From<&str> for FileSystemOp {
    fn from(s: &str) -> Self {
        match s {
            "MKDIR" => Self::MkDir,
            "NOT-EXISTS" => Self::Exists,
            "REMOVE-ALL" => Self::RemoveAll,
            "REMOVE" => Self::Remove,
            _ => u64::from_str_radix(s, 16).map_or(Self::Exists, Self::FileSize),
        }
    }
}

/// Lifetime of an XML command
#[derive(Debug, Clone, Copy)]
pub enum XmlCmdLifetime {
    CmdStart,
    CmdEnd,
}

/// Each XML command should implement this trait, by
/// using the `XmlCommand` derive macro.
pub trait XmlCommand: Display {
    fn cmd_name(&self) -> &'static str;
    fn args(&self) -> Vec<(Option<&'static str>, &'static str, String)>;
    fn version(&self) -> &'static str;
}

#[derive(XmlCommand)]
pub struct BootTo {
    #[xml(tag = "at_address", fmt = "0x{at_addr:x}")]
    at_addr: u64,
    #[xml(tag = "jmp_address", fmt = "0x{jmp_addr:x}")]
    jmp_addr: u64,
    #[xml(tag = "source_file", value = "MEM://0x0:0x0")]
    host_offset: &'static str,
}

#[derive(XmlCommand)]
#[xmlcmd(version = "1.1")]
pub struct SetRuntimeParameter {
    #[xml(tag = "checksum_level", value = "NONE")]
    checksum_level: &'static str,
    #[xml(tag = "battery_exist", value = "AUTO-DETECT")]
    battery_exist: &'static str,
    #[xml(tag = "da_log_level")]
    da_log_level: String,
    #[xml(tag = "log_channel")]
    log_channel: String,
    #[xml(tag = "system_os")]
    system_os: String,
    #[xml(custom_arg = "adv", tag = "initialize_dram", value = "YES")]
    init_dram: &'static str,
}

#[derive(XmlCommand)]
pub struct HostSupportedCommands {
    #[xml(
        tag = "host_capability",
        value = "CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@"
    )]
    host_capability: &'static str,
}

#[derive(XmlCommand)]
pub struct NotifyInitHw;

#[derive(XmlCommand)]
pub struct SetHostInfo {
    #[xml(tag = "info")]
    info: String,
}

#[derive(XmlCommand)]
pub struct GetSysProperty {
    #[xml(tag = "key")]
    key: String,
    #[allow(dead_code)]
    #[xml(tag = "target_file", value = "MEM://0x0:0x200000")]
    target_file: &'static str,
}

#[derive(XmlCommand)]
pub struct SecurityGetDevFwInfo {
    #[allow(dead_code)]
    #[xml(tag = "target_file", value = "MEM://0x0:0x200000")]
    target_file: &'static str,
}

#[derive(XmlCommand)]
pub struct SecuritySetFlashPolicy {
    #[xml(tag = "source_file")]
    source_file: String,
}

#[derive(XmlCommand)]
pub struct SecuritySetAllinoneSignature {
    #[xml(tag = "source_file")]
    source_file: String,
}

#[derive(XmlCommand)]
pub struct GetHwInfo {
    #[xml(tag = "target_file", value = "MEM://0x0:0x200000")]
    target_file: &'static str,
}

#[derive(XmlCommand)]
pub struct ReadPartition {
    #[xml(tag = "partition")]
    partition: String,
    #[allow(dead_code)]
    #[xml(tag = "target_file", fmt = "{partition}.bin")]
    target_file: String,
}

#[derive(XmlCommand)]
pub struct ReadFlash {
    #[xml(tag = "partition")]
    partition: String,
    #[allow(dead_code)]
    #[xml(tag = "target_file", fmt = "{partition}")]
    target_file: String,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u64,
    #[xml(tag = "offset", fmt = "0x{offset:X}")]
    offset: u64,
}

#[derive(XmlCommand)]
pub struct WritePartition {
    #[xml(tag = "partition")]
    partition: String,
    #[allow(dead_code)]
    #[xml(tag = "source_file", fmt = "{partition}.bin")]
    source_file: String,
}

#[derive(XmlCommand)]
pub struct WriteFlash {
    #[xml(tag = "partition")]
    partition: String,
    #[xml(tag = "source_file", fmt = "MEM:\\0x0:0x{length:X}")]
    length: u64,
    #[xml(tag = "offset", fmt = "0x{offset:X}")]
    offset: u64,
}

#[derive(XmlCommand)]
pub struct ErasePartition {
    #[xml(tag = "partition")]
    partition: String,
}

#[derive(XmlCommand)]
pub struct EraseFlash {
    #[xml(tag = "partition")]
    section: String,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u64,
    #[xml(tag = "offset", fmt = "0x{offset:X}")]
    offset: u64,
}

#[derive(XmlCommand)]
pub struct Reboot {
    #[xml(tag = "action")]
    action: String,
}

#[derive(XmlCommand)]
pub struct SetBootMode {
    #[xml(tag = "mode")]
    mode: String,
    #[xml(tag = "connect_type")]
    connect_type: String,
    #[xml(tag = "mobile_log")]
    mobile_log: String,
    #[xml(tag = "adb")]
    adb: String,
}

#[derive(XmlCommand)]
pub struct ReadEfuse {
    #[allow(dead_code)]
    #[xml(tag = "target_file", value = "MEM://0x0:0x200000")]
    target_file: &'static str,
}

#[derive(XmlCommand)]
pub struct WriteEfuse {
    #[allow(dead_code)]
    #[xml(tag = "source_file", value = "MEM://0x0:0x200000")]
    source_file: &'static str,
}

#[derive(XmlCommand)]
pub struct FlashUpdate {
    #[xml(tag = "source_file", value = "./scatter.xml")]
    source_file: &'static str,
    #[cfg(windows)]
    #[xml(tag = "path_separator", value = "\\")]
    path_separator: &'static str,
    #[cfg(unix)]
    #[xml(tag = "path_separator", value = "/")]
    path_separator: &'static str,
    #[xml(tag = "backup_folder", value = ".")]
    backup_folder: &'static str,
}

pub fn create_cmd<C: XmlCommand>(cmd: &C) -> String {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><da><version>{}</version><command>CMD:{}</command>"#,
        cmd.version(),
        cmd.cmd_name()
    );

    let mut sections: BTreeMap<Option<&str>, Vec<(&str, String)>> = BTreeMap::new();

    for (section, tag, content) in cmd.args() {
        sections.entry(section).or_default().push((tag, content));
    }

    for (section, entries) in sections {
        let tag = section.unwrap_or("arg");
        xml.push_str(&format!("<{}>", tag));
        for (tag_path, content) in entries {
            let parts: Vec<&str> = tag_path.split('/').collect();

            for p in &parts {
                xml.push_str(&format!("<{}>", p));
            }

            xml.push_str(&content);

            for p in parts.iter().rev() {
                xml.push_str(&format!("</{}>", p));
            }
        }
        xml.push_str(&format!("</{}>", tag));
    }

    xml.push_str("</da>\u{0}");
    xml
}
