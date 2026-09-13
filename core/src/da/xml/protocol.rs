/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::io::{BufReader, BufWriter};
use std::time::Duration;

use hacc::DaEntry;
#[cfg(feature = "exploits")]
use hacc::TryRead;
#[cfg(feature = "exploits")]
use hacc::TryWrite;
use log::{debug, error, info, trace};
use memchr::memmem;

use crate::activity::{Activity, DeviceActivity};
#[cfg(feature = "exploits")]
use crate::da::DownloadProtocolExt;
#[cfg(feature = "exploits")]
use crate::da::extensions;
use crate::da::protocol::{DataType, NOOP_PROGRESS, PacketHeader};
use crate::da::storage::{get_aux_gpt_parts, get_gpt_parts};
use crate::da::xml::cmd::{
    BootTo,
    CMD_DOWNLOAD_FILE,
    CMD_END,
    CMD_START,
    HostSupportedCommands,
    NotifyInitHw,
    SetHostInfo,
    SetRuntimeParameter,
    XmlCmdLifetime,
    XmlCommand,
    create_cmd,
};
#[cfg(feature = "exploits")]
use crate::da::xml::exts;
#[cfg(feature = "exploits")]
use crate::da::xml::patch;
use crate::da::xml::storage::detect_storage;
use crate::da::xml::{
    CMD_FILE_SYSTEM_OP,
    CMD_PROGRESS_REPORT,
    CMD_UPLOAD_FILE,
    FileSystemOp,
    GetSysProperty,
    ReadEfuse,
    Reboot,
    SecurityGetDevFwInfo,
    SecuritySetFlashPolicy,
    SetBootMode,
    WriteEfuse,
    flash,
};
use crate::da::{DaLogLevel, DaProtocolParams};
#[cfg(feature = "exploits")]
use crate::error::PenumbraError;
use crate::error::{AuthError, ProtocolError, XmlError, XmlErrorKind};
#[cfg(feature = "exploits")]
use crate::exploit::{Carbonara, HeapBait, Unfused};
use crate::port::{MAX_TIMEOUT, MIN_TIMEOUT, MtkPort};
use crate::storage::Partitions;
use crate::traits::{
    FromBytes,
    ProgressCallback,
    ReadExt,
    Reader,
    ReaderSource,
    ToBytes,
    Writer,
    WriterSink,
};
#[cfg(feature = "exploits")]
use crate::utils::hash::HashType;
#[cfg(feature = "exploits")]
use crate::utils::hash::hash;
use crate::utils::xml::{get_tag, get_tag_usize};
use crate::{
    AuthManager,
    BootMode,
    DevInfo,
    DeviceLog,
    DownloadProtocol,
    Error,
    PlProtocol,
    Result,
    SignData,
    SignPurpose,
    SignRequest,
    Storage,
    StorageKind,
    StorageType,
    VERSION,
    exploit,
};

pub struct Xml {
    pub(super) write_packed_length: Option<usize>,
    #[cfg(feature = "exploits")]
    pub(super) patched: bool,
    devinfo: DevInfo,
    storage: Option<StorageKind>,
    pub(super) log_level: DaLogLevel,
    pub(super) usb_log_channel: bool,
    pub(super) device_log: DeviceLog,
    pub(super) activity: DeviceActivity,
}

impl Xml {
    pub fn new(params: DaProtocolParams<'_>) -> Self {
        Self {
            write_packed_length: None,
            #[cfg(feature = "exploits")]
            patched: false,
            devinfo: params.devinfo,
            storage: None,
            log_level: params.log_level,
            usb_log_channel: params.usb_log_channel,
            device_log: params.device_log,
            activity: params.activity,
        }
    }

    fn flush_usb_logs<P: MtkPort>(&self, port: &mut P) -> Option<PacketHeader> {
        if !self.usb_log_channel {
            return None;
        }

        let prev_timeout = port.get_timeout();
        port.set_timeout(Duration::from_millis(10)).ok()?;

        let header = loop {
            let mut buf = [0u8; PacketHeader::SIZE];
            if port.read_exact(&mut buf).is_err() {
                break None;
            }

            let Some(hdr) = PacketHeader::from_bytes(&buf) else {
                break None;
            };

            if hdr.data_type == DataType::Message {
                let _ = self.drain_message(port, hdr.length);
            } else {
                break Some(hdr);
            }
        };

        let _ = port.set_timeout(prev_timeout);
        header
    }

    fn read_next_flow_header<P: MtkPort>(&self, port: &mut P) -> Result<PacketHeader> {
        loop {
            let mut buf = [0u8; PacketHeader::SIZE];
            port.read_exact(&mut buf)?;

            let hdr = PacketHeader::from_bytes(&buf).ok_or_else(|| {
                debug!("[RX] Invalid packet header bytes: {:02X?}", buf);
                ProtocolError::InvalidPacketHeader
            })?;

            match hdr.data_type {
                DataType::Flow => return Ok(hdr),
                DataType::Message => self.drain_message(port, hdr.length)?,
            }
        }
    }

    fn drain_message<P: MtkPort>(&self, port: &mut P, length: u32) -> Result<()> {
        if length < 4 {
            return Err(ProtocolError::InvalidResponseLength.into());
        }
        let len = usize::try_from(length).map_err(|_| PenumbraError::BufferTooSmall)?;
        let mut payload = Vec::new();
        payload.try_reserve(len).map_err(|_| PenumbraError::BufferTooSmall)?;
        payload.resize(len, 0);
        port.read_exact(&mut payload)?;

        let body = String::from_utf8_lossy(&payload[4..]).into_owned();

        trace!("[DA Message] {}", body);

        if self.usb_log_channel {
            self.device_log.push(body);
        }

        Ok(())
    }

    /// Checks for the lifetime acknowledgment (CMD:START or CMD:END).
    fn check_lifetime<P: MtkPort>(&mut self, port: &mut P, lifetime: XmlCmdLifetime) -> Result<()> {
        let data = match self.read_data(port) {
            Ok(d) => d,
            // We assume we're just resuming a session and the device has already sent the CMD:END
            Err(Error::Timeout) => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let pattern: &[u8] = match lifetime {
            XmlCmdLifetime::CmdStart => CMD_START,
            XmlCmdLifetime::CmdEnd => CMD_END,
        };

        if memmem::find(&data, b"<result>ERR</result>").is_some() {
            let msg: String = get_tag(core::str::from_utf8(&data).unwrap_or(""), "arg/message")?;

            let err = XmlError::from_message(msg.as_bytes());

            return Err(err.into());
        }

        if memmem::find(&data, pattern).is_none() {
            return Err(ProtocolError::InvalidAck.into());
        };

        Ok(())
    }

    /// Sends an acknowledgment to the device.
    /// By default, it sends "OK\0".
    /// If a value is provided, it sends "OK@{value}\0".
    pub fn ack<P: MtkPort>(&mut self, port: &mut P, value: Option<u64>) -> Result<()> {
        if let Some(v) = value {
            self.send(port, format!("OK@{v}\0").as_bytes())
        } else {
            self.send(port, b"OK\0")
        }
    }

    /// Reads an acknowledgment from the device.
    pub fn read_ack<P: MtkPort>(&mut self, port: &mut P) -> Result<()> {
        let resp = self.read_data(port)?;
        let s = String::from_utf8_lossy(&resp);

        if s == "OK\u{0}" || s == "OK@0x0\u{0}" {
            return Ok(());
        }

        if s.contains("ERR!UNSUPPORTED") {
            return Err(Error::Xml(XmlError::from_message(&resp)));
        }

        Err(ProtocolError::InvalidAck.into())
    }

    /// Acknowledges the lifetime of an XML command (CMD:START or CMD:END).
    pub fn lifetime_ack<P: MtkPort>(
        &mut self,
        port: &mut P,
        lifetime: XmlCmdLifetime,
    ) -> Result<()> {
        let resp = self.check_lifetime(port, lifetime);
        self.ack(port, None)?;

        resp
    }

    /// Sends an XML command to the device.
    pub fn send_cmd<P: MtkPort, C: XmlCommand>(&mut self, port: &mut P, cmd: &C) -> Result<bool> {
        let xml_str = create_cmd(cmd);
        let xml_bytes = xml_str.as_bytes();

        self.lifetime_ack(port, XmlCmdLifetime::CmdStart)?;
        self.send(port, xml_bytes)?;

        debug!("Sent XML Command: {}", cmd);

        // Read the ack back.
        // We don't wait for CMD:END here, because each CMD might
        // perform different actions in between.
        match self.read_ack(port) {
            Ok(_) => Ok(true),
            Err(Error::Xml(err)) if err.kind == XmlErrorKind::UnsupportedCmd => {
                debug!("Device does not support command: {}", cmd);
                self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;
                Err(Error::Xml(err))
            }
            Err(e) => Err(e),
        }
    }

    pub(super) fn upload_stage1<P: MtkPort>(&mut self, port: &mut P, da: &DaEntry) -> Result<bool> {
        let da1 = da.da1();
        let da1_data = da.da1_data();

        let da1_addr = da1.addr();
        let da1_length = da1.length();
        let da1_sig_len = da1.sig_len();

        info!("Uploading XML DA1 to address 0x{:08X} with length 0x{:X}", da1_addr, da1_length);

        let mut pl = PlProtocol::new(port);

        pl.send_da(da1_data, da1_length as u32, da1_addr, da1_sig_len as u32)?;
        info!("Sent DA1, jumping to address 0x{:08X}...", da1_addr);
        pl.jump_da(da1_addr)?;

        let log_level: &str = self.log_level.into();
        let channel = if self.usb_log_channel { "USB" } else { "UART" };
        let system_os = cfg_select! {
            target_os = "windows" => "WINDOWS",
            target_os = "linux" => "LINUX",
            _ => "LINUX",
        };

        xmlcmd_e!(self, port, SetRuntimeParameter, log_level, channel, system_os)?;
        xmlcmd_e!(self, port, HostSupportedCommands).ok();
        xmlcmd_e!(self, port, SetHostInfo, format!("Penumbra v{}", VERSION))?;

        // Wait for the device to initialize DRAM
        xmlcmd_p!(self, port, NotifyInitHw)?;

        // New DAs can have SLA in DA1 as well.
        match self.handle_sla(port, da) {
            Err(Error::Xml(err)) if err.kind == XmlErrorKind::UnsupportedCmd => {}
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        Ok(true)
    }

    pub fn get_upload_file_resp<P: MtkPort>(&mut self, port: &mut P) -> Result<String> {
        let mut buffer = Vec::new();
        let mut writer = BufWriter::new(&mut buffer);

        self.upload_data(port, 0, &mut writer, NOOP_PROGRESS)?;
        writer.flush()?;
        drop(writer);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Perform a (fake) file system operation
    /// This is used in SPFT for asking the tool to do stuff like creating directories,
    /// checking file existence, etc.
    /// We don't need it.
    pub fn file_system_op<P: MtkPort>(&mut self, port: &mut P, op: FileSystemOp) -> Result<()> {
        let resp = self.read_data(port)?;
        let resp = String::from_utf8_lossy(&resp);

        self.process_file_sys_op(port, &resp, op)
    }

    pub(super) fn process_file_sys_op<P: MtkPort>(
        &mut self,
        port: &mut P,
        resp: &str,
        op: FileSystemOp,
    ) -> Result<()> {
        let cmd: String = get_tag(resp, "command")?;
        if cmd != CMD_FILE_SYSTEM_OP {
            debug!("Invalid xml response for CMD:FILE-SYSTEM-OP: {}", resp);
            let message: String = get_tag(resp, "arg/message").unwrap_or_default();
            if message.is_empty() {
                return Err(XmlErrorKind::ExpectedFileSysOp.into());
            } else {
                return Err(XmlErrorKind::Other(message).into());
            }
        }

        debug!("Received file system operation command: {cmd}");

        self.ack(port, None)?;
        self.send(port, format!("OK@{}\0", op.default()).as_bytes())
    }

    pub(super) fn process_download_data<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        resp: &str,
        size: u64,
        timeout: Duration,
        mut reader: R,
        mut progress: F,
    ) -> Result<u64> {
        let cmd: String = get_tag(resp, "command")?;
        if cmd != CMD_DOWNLOAD_FILE {
            debug!("Invalid xml response for CMD:DOWNLOAD-FILE: {}", resp);
            let message: String = get_tag(resp, "arg/message").unwrap_or_default();
            if message.is_empty() {
                return Err(XmlErrorKind::ExpectedCmdDownloadFile.into());
            } else {
                return Err(XmlErrorKind::Other(message).into());
            }
        }

        let info: String = get_tag(resp, "arg/info").unwrap_or_default();
        debug!("Received CMD:DOWNLOAD-FILE command.");
        debug!("  Info: {info}");

        // Acknowledge we received the command
        self.ack(port, None)?;

        // Tell the device the size we want to send
        self.ack(port, Some(size))?;

        // Read the response
        self.read_ack(port)?;

        let packet_length: usize = get_tag_usize(resp, "arg/packet_length")?;
        // Store the packet length so that send won't split the data into smaller chunks
        self.write_packed_length = Some(packet_length);

        let mut chunk = vec![0u8; packet_length];
        let mut bytes_sent = 0u64;

        port.set_timeout(timeout)?;

        let result = 'download: {
            while bytes_sent < size {
                let to_read = (size - bytes_sent).min(packet_length as u64) as usize;
                if let Err(e) = reader.read_exact_fill(&mut chunk[..to_read]) {
                    break 'download Err(e.into());
                }

                // Status
                if let Err(e) = self.ack(port, Some(0)) {
                    break 'download Err(e);
                }
                if let Err(e) = self.read_ack(port) {
                    break 'download Err(e);
                }

                if let Err(e) = self.send(port, &chunk[..to_read]) {
                    break 'download Err(e);
                }
                if let Err(e) = self.read_ack(port) {
                    break 'download Err(e);
                }

                bytes_sent += to_read as u64;
                progress(bytes_sent, size);
            }

            Ok(())
        };

        port.set_timeout(MIN_TIMEOUT)?;
        result?;

        debug!("File download completed, 0x{:X} bytes sent.", size);

        Ok(bytes_sent)
    }

    pub(super) fn process_upload_data<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        resp: &str,
        mut writer: W,
        mut progress: F,
    ) -> Result<u64> {
        let cmd: String = get_tag(resp, "command")?;
        if cmd != CMD_UPLOAD_FILE {
            debug!("Invalid xml response for CMD:UPLOAD-FILE: {}", resp);
            let message: String = get_tag(resp, "arg/message").unwrap_or_default();
            if message.is_empty() {
                return Err(XmlErrorKind::ExpectedCmdUploadFile.into());
            } else {
                return Err(XmlErrorKind::Other(message).into());
            }
        }

        let packet_length = get_tag_usize(resp, "arg/packet_length")?;
        let info: String = get_tag(resp, "arg/info").unwrap_or_default();
        debug!("Received CMD:UPLOAD-FILE command.");
        debug!("  Info: {info}");

        self.ack(port, None)?;

        let resp = self.read_data(port)?;
        let resp = String::from_utf8_lossy(&resp);

        let size = {
            let trimmed = resp.trim_end_matches('\0').trim();
            let hex = trimmed.strip_prefix("OK@0x").ok_or(ProtocolError::InvalidResponseFormat)?;

            u64::from_str_radix(hex, 16).map_err(|_| ProtocolError::InvalidResponseFormat)?
        };

        self.ack(port, None)?;

        let mut bytes_received = 0u64;

        port.set_timeout(MAX_TIMEOUT)?;

        let result = 'upload: {
            while bytes_received < size {
                let to_read = (size - bytes_received).min(packet_length as u64) as usize;
                if let Err(e) = self.read_ack(port) {
                    break 'upload Err(e);
                }
                if let Err(e) = self.ack(port, None) {
                    break 'upload Err(e);
                }

                let data = match self.read_data(port) {
                    Ok(data) => data,
                    Err(e) => break 'upload Err(e),
                };

                if let Err(e) = writer.write_all(&data) {
                    break 'upload Err(e.into());
                }
                if let Err(e) = self.ack(port, None) {
                    break 'upload Err(e);
                }

                bytes_received += to_read as u64;
                progress(bytes_received, size);
            }

            Ok(())
        };

        port.set_timeout(MIN_TIMEOUT)?;
        result?;

        debug!("File upload completed, 0x{:X} bytes received.", size);

        Ok(bytes_received)
    }

    pub(super) fn process_progress_report<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        resp: &str,
        mut progress: F,
    ) -> Result<()> {
        let cmd: String = get_tag(resp, "command")?;
        if cmd != CMD_PROGRESS_REPORT {
            debug!("Invalid xml response for CMD:PROGRESS-REPORT: {}", resp);
            let message: String = get_tag(resp, "arg/message").unwrap_or_default();
            if message.is_empty() {
                return Err(XmlErrorKind::ExpectedCmdProgressReport.into());
            } else {
                return Err(XmlErrorKind::Other(message).into());
            }
        }

        let msg: String = get_tag(resp, "arg/message")?;
        debug!("Received progress report command. Message: {msg}");

        self.ack(port, None)?;

        // Progress report might make the device delay a bit during USB
        // transfers. As a solution, we increase the port timeout
        // while we're waiting for the progress report, and restore it afterwards.
        port.set_timeout(MAX_TIMEOUT)?;

        let mut resp: Vec<u8> = Vec::new();

        let result = 'progress: {
            while resp != b"OK!EOT\0" {
                resp = match self.read_data(port) {
                    Ok(resp) => resp,
                    Err(e) => break 'progress Err(e),
                };

                if let Err(e) = self.ack(port, None) {
                    break 'progress Err(e);
                }

                let resp_string = String::from_utf8_lossy(&resp);

                if !resp_string.starts_with("OK!PROGRESS@") {
                    continue;
                }

                let Some(prog) = resp_string.trim_end_matches('\0').split('@').nth(1) else {
                    break 'progress Err(ProtocolError::InvalidResponseFormat.into());
                };

                let Ok(progress_value) = prog.parse::<u64>() else {
                    break 'progress Err(ProtocolError::InvalidResponseFormat.into());
                };

                progress(progress_value, 100);
            }

            Ok(())
        };

        port.set_timeout(MIN_TIMEOUT)?;
        result?;

        progress(100, 100);

        Ok(())
    }

    #[cfg(feature = "exploits")]
    fn boot_extensions(&mut self, port: &mut impl MtkPort, da: &DaEntry<'_>) -> Result<bool> {
        if !self.patched {
            return Ok(false);
        }

        info!("Trying to boot DA extensions...");
        let succeeded = exts::boot_extensions(self, port, da)?;
        if succeeded {
            info!("DA extensions uploaded");
        }

        Ok(succeeded)
    }
}

impl DownloadProtocol for Xml {
    fn upload_da<P: MtkPort>(&mut self, port: &mut P, da: &mut DaEntry<'_>) -> Result<()> {
        exploit!(Unfused, self, port, da);

        self.upload_stage1(port, da)?;

        exploit!(Carbonara, self, port, da);

        let da2_addr = da.da2().addr();
        let da2_code = da.da2_code();

        info!("Uploading XML DA2 to address 0x{:08X} with length 0x{:X}", da2_addr, da2_code.len());

        if let Err(e) = self.boot_to(port, da2_addr, da2_code) {
            self.reboot(port, BootMode::Normal).ok();
            return Err(e);
        }

        info!("Successfully uploaded and booted to XML DA2");

        port.set_timeout(MAX_TIMEOUT)?;

        // This may fail on some devices
        xmlcmd_e!(self, port, HostSupportedCommands).ok();

        let result = xmlcmd_p!(self, port, NotifyInitHw);

        port.set_timeout(MIN_TIMEOUT)?;
        result?;

        exploit!(HeapBait, self, port, da);

        self.handle_sla(port, da)?;

        #[cfg(feature = "exploits")]
        self.boot_extensions(port, da).ok();

        Ok(())
    }

    fn boot_to<P: MtkPort>(&mut self, port: &mut P, addr: u32, data: &[u8]) -> Result<()> {
        xmlcmd!(self, port, BootTo, addr, addr)?;

        let reader = BufReader::new(data);
        self.download_data(port, data.len() as u64, reader, NOOP_PROGRESS)?;

        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
    }

    fn read_data<P: MtkPort>(&mut self, port: &mut P) -> Result<Vec<u8>> {
        let hdr = self.read_next_flow_header(port)?;

        debug!("[RX] Packet header received: 0x{:X} bytes", hdr.length);

        if hdr.length == 0 {
            return Ok(Vec::new());
        }
        let len = usize::try_from(hdr.length).map_err(|_| PenumbraError::BufferTooSmall)?;
        let mut data = Vec::new();
        data.try_reserve(len).map_err(|_| PenumbraError::BufferTooSmall)?;
        data.resize(len, 0);
        port.read_exact(&mut data)?;
        Ok(data)
    }

    fn send<P: MtkPort>(&mut self, port: &mut P, data: &[u8]) -> Result<()> {
        self.send_data(port, &[data])
    }

    fn send_data<P: MtkPort>(&mut self, port: &mut P, data: &[&[u8]]) -> Result<()> {
        let max_chunk_size = self.write_packed_length.unwrap_or(0x8000);

        self.flush_usb_logs(port);

        for param in data {
            let hdr = PacketHeader::new(DataType::Flow, param.len() as u32).to_bytes();
            port.write_all(&hdr)?;

            let mut pos = 0;
            while pos < param.len() {
                let end = (pos + max_chunk_size).min(param.len());
                let chunk = &param[pos..end];
                debug!("[TX] Sending chunk (0x{:X} bytes)", chunk.len());
                port.write_all(chunk)?;
                pos = end;
            }

            debug!("[TX] Completed sending 0x{:X} bytes", param.len());
        }

        Ok(())
    }

    fn shutdown<P: MtkPort>(&mut self, port: &mut P) -> Result<()> {
        info!("Shutting down device...");

        xmlcmd_e!(self, port, Reboot, "IMMEDIATE")
    }

    fn reboot<P: MtkPort>(&mut self, port: &mut P, mode: BootMode) -> Result<()> {
        info!("Rebooting device into {:?} mode...", mode);
        match mode {
            BootMode::Normal | BootMode::HomeScreen => self.shutdown(port),
            mode => {
                let xml_mode: &str = mode.into();
                xmlcmd_e!(self, port, SetBootMode, xml_mode, "USB", "ON", "ON")
            }
        }
    }

    fn download_data<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: u64,
        reader: R,
        progress: F,
    ) -> Result<u64> {
        let resp = self.read_data(port)?;
        let resp = String::from_utf8_lossy(&resp);

        self.process_download_data(port, &resp, size, MAX_TIMEOUT, reader, progress)
    }

    fn upload_data<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        _size: u64,
        writer: W,
        progress: F,
    ) -> Result<u64> {
        let resp = self.read_data(port)?;
        let resp = String::from_utf8_lossy(&resp);

        self.process_upload_data(port, &resp, writer, progress)
    }

    fn progress_report<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        _size: u64,
        progress: F,
    ) -> Result<()> {
        let resp = self.read_data(port)?;
        let resp = String::from_utf8_lossy(&resp);

        self.process_progress_report(port, &resp, progress)
    }

    fn read_flash<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: crate::PartitionKind,
        writer: W,
        progress: F,
    ) -> Result<()> {
        flash::read_flash(self, port, addr, size, section, writer, progress)
    }

    fn write_flash<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: crate::PartitionKind,
        reader: R,
        progress: F,
    ) -> Result<()> {
        flash::write_flash(self, port, addr, size, section, reader, progress)
    }

    fn erase_flash<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: crate::PartitionKind,
        progress: F,
    ) -> Result<()> {
        flash::erase_flash(self, port, addr, size, section, progress)
    }

    fn read_partition<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        writer: W,
        progress: F,
    ) -> Result<()> {
        self.activity.set(Activity::Reading { partition: name.into() });
        let result = flash::read_partition(self, port, name, writer, progress);
        self.activity.set(Activity::Idle);

        result
    }

    fn write_partition<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        size: u64,
        reader: R,
        progress: F,
    ) -> Result<()> {
        self.activity.set(Activity::Flashing { partition: name.into() });
        let result = flash::write_partition(self, port, name, size, reader, progress);
        self.activity.set(Activity::Idle);

        result
    }

    fn format_partition<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        progress: F,
    ) -> Result<()> {
        self.activity.set(Activity::Erasing { partition: name.into() });
        let result = flash::format_partition(self, port, name, progress);
        self.activity.set(Activity::Idle);

        result
    }

    fn flash_scatter<P, F, R, W, S, K>(
        &mut self,
        port: &mut P,
        scatter: &str,
        reader_source: S,
        writer_sink: K,
        progress: F,
    ) -> Result<()>
    where
        P: MtkPort,
        R: Reader,
        W: Writer,
        S: ReaderSource<R>,
        K: WriterSink<W>,
        F: ProgressCallback,
    {
        let result =
            flash::flash_scatter(self, port, scatter, reader_source, writer_sink, progress);
        self.activity.set(Activity::Idle);

        result
    }

    fn get_storage<P: MtkPort>(&mut self, port: &mut P) -> Option<&StorageKind> {
        if self.storage.is_none() {
            self.storage = detect_storage(self, port);
        }

        self.storage.as_ref()
    }

    fn get_storage_type<P: MtkPort>(&mut self, port: &mut P) -> crate::StorageType {
        self.get_storage(port).as_ref().map(|s| s.kind()).unwrap_or(StorageType::Unknown)
    }

    fn partitions<P: MtkPort>(&mut self, port: &mut P) -> Partitions {
        let Some(storage) = self.get_storage(port).cloned() else {
            return vec![].into_iter();
        };

        let parts = if !storage.kind().is_nand() {
            let aux = get_aux_gpt_parts(&storage);
            let mut parts = aux.to_vec();
            let mut gpt_parts = get_gpt_parts(self, port, &storage);

            parts.append(&mut gpt_parts);
            parts
        } else {
            vec![]
        };

        parts.into_iter()
    }

    fn read_efuses<W: Writer, P: MtkPort>(&mut self, port: &mut P, writer: W) -> Result<()> {
        const EFUSE_XML_BUF_LEN: u64 = 0x5000;

        xmlcmd!(self, port, ReadEfuse)?;
        self.upload_data(port, EFUSE_XML_BUF_LEN, writer, NOOP_PROGRESS)?;
        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
    }

    fn write_efuses<R: Reader, P: MtkPort>(
        &mut self,
        port: &mut P,
        reader: R,
        size: u64,
    ) -> Result<()> {
        xmlcmd!(self, port, WriteEfuse)?;
        self.download_data(port, size, reader, NOOP_PROGRESS)?;
        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
    }

    fn handle_sla<P: MtkPort>(&mut self, port: &mut P, da: &DaEntry) -> Result<()> {
        match xmlcmd!(self, port, GetSysProperty, "DA.SLA") {
            Err(Error::Xml(err)) if err.kind == XmlErrorKind::UnsupportedCmd => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {}
        }

        let response = self.get_upload_file_resp(port)?;
        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

        let sla_enabled = response.contains("ENABLED");
        if !sla_enabled {
            return Ok(());
        }

        info!("DA SLA is enabled");

        let da2 = da.da2_code();

        let auth = AuthManager::get();
        if !auth.can_sign(da2) {
            #[cfg(feature = "exploits")]
            {
                info!("No available signers for DA SLA, trying dummy signature...");
                let dummy_sig = [0u8; 256];
                xmlcmd!(self, port, SecuritySetFlashPolicy, "Penumbra Dummy SLA challenge")?;
                self.download_data(
                    port,
                    dummy_sig.len() as u64,
                    dummy_sig.as_slice(),
                    NOOP_PROGRESS,
                )?;
                if self.lifetime_ack(port, XmlCmdLifetime::CmdEnd).is_ok() {
                    info!("DA SLA signature accepted (dummy)!");
                    return Ok(());
                } else {
                    error!("DA SLA signature rejected (dummy).");
                }
            }

            error!("No signer available for DA SLA! Can't proceed any further.");
            return Err(AuthError::NoSignerAvailable.into());
        };

        xmlcmd!(self, port, SecurityGetDevFwInfo)?;
        let fw_info = self.get_upload_file_resp(port)?;
        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

        debug!("Firmware info: {}", fw_info);

        let mut data = SignData { raw: fw_info.as_bytes().to_vec(), ..Default::default() };

        if let Ok(rnd_str) = get_tag::<String>(&fw_info, "rnd")
            && let Ok(rnd) = hex::decode(rnd_str)
        {
            data.rnd = rnd;
        }

        if let Ok(hrid_str) = get_tag::<String>(&fw_info, "hrid")
            && let Ok(hrid) = hex::decode(hrid_str)
        {
            data.hrid = hrid;
        }

        if let Ok(socid_str) = get_tag::<String>(&fw_info, "socid")
            && let Ok(soc_id) = hex::decode(socid_str)
        {
            data.soc_id = soc_id;
        }

        let sign_req = SignRequest { data, purpose: SignPurpose::DaSla, pubk_mod: da2.to_vec() };

        info!("Found signer for DA SLA!");
        let signed = auth.sign(&sign_req)?;
        info!("Signed DA SLA challenge. Uploading to device...");

        xmlcmd!(self, port, SecuritySetFlashPolicy, "Penumbra SLA challenge")?;
        self.download_data(port, signed.len() as u64, signed.as_slice(), NOOP_PROGRESS)?;
        self.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;
        info!("DA SLA signature accepted!");

        Ok(())
    }

    fn get_devinfo(&mut self) -> &DevInfo {
        &self.devinfo
    }
}

#[cfg(feature = "exploits")]
impl DownloadProtocolExt for Xml {
    fn set_seccfg_lock_state<P: MtkPort>(
        &mut self,
        port: &mut P,
        state: hacc::LockState,
    ) -> Result<()> {
        use extensions::SecCfgAlgo;

        let section = self
            .get_storage(port)
            .as_ref()
            .map(|s| s.get_user_part())
            .ok_or(ProtocolError::CannotGetStorageInfo)?;

        let mut seccfg_data = [0u8; 0x200];

        let seccfg_part = self
            .get_partition("seccfg")
            .ok_or_else(|| PenumbraError::PartitionNotFound("seccfg".into()))?;

        self.read_flash(
            port,
            seccfg_part.address,
            seccfg_data.len() as u64,
            section,
            seccfg_data.as_mut_slice(),
            NOOP_PROGRESS,
        )?;

        let mut seccfg = hacc::SecCfgV4::try_read(&seccfg_data)?;

        if seccfg.lock_state() == state {
            return Ok(());
        }

        let hdr_size = seccfg.size() - size_of_val(seccfg.hash());
        let get_hdr_hash = |data: &[u8]| hash(HashType::Sha256, &data[..hdr_size]);

        let calculated_hash = get_hdr_hash(&seccfg_data);
        let stored_cipher = seccfg.hash();

        let mut sej_params = extensions::SejParams {
            length: 32,
            encrypt: false,
            legacy: false,
            ..Default::default()
        };

        let mut dec_hash = [0u8; 32];
        let mut verified_algo = None;

        for algo in [SecCfgAlgo::Sha, SecCfgAlgo::HWv4] {
            let anticlone = match algo {
                SecCfgAlgo::Sha => false,
                SecCfgAlgo::HWv4 => true,
                _ => continue,
            };

            if anticlone {
                sej_params.anti_clone = anticlone;
                exts::sej_aes(
                    self,
                    port,
                    &sej_params,
                    stored_cipher.as_slice(),
                    dec_hash.as_mut_slice(),
                )?;
            } else {
                dec_hash.copy_from_slice(stored_cipher);
            }

            if dec_hash == calculated_hash[..32] {
                verified_algo = Some(algo);
                break;
            }
        }

        let algo = verified_algo.ok_or(PenumbraError::SecCfgAlgoNotFound)?;

        seccfg.set_lock_state(state);
        seccfg.try_write(seccfg_data.as_mut_slice())?;

        let new_hash = get_hdr_hash(&seccfg_data);
        let mut final_enc_hash = [0u8; 32];

        if algo == SecCfgAlgo::Sha {
            final_enc_hash.copy_from_slice(&new_hash[..32]);
        } else {
            sej_params.encrypt = true;
            exts::sej_aes(self, port, &sej_params, &new_hash[..32], final_enc_hash.as_mut_slice())?;
        }

        seccfg.set_hash(&final_enc_hash);
        seccfg.try_write(seccfg_data.as_mut_slice())?;

        debug!("New seccfg:");
        debug!("{:?}", seccfg.lock_state());
        debug!("Hash: {:02X?}", seccfg.hash());

        self.write_partition(
            port,
            "seccfg",
            seccfg_data.len() as u64,
            seccfg_data.as_slice(),
            NOOP_PROGRESS,
        )
    }

    fn set_rpmb_lock_state<P: MtkPort>(
        &mut self,
        port: &mut P,
        state: hacc::LockState,
    ) -> Result<()> {
        use hacc::SecRpmbInfo;

        if self.get_storage_type(port) != StorageType::Ufs {
            return Err(PenumbraError::RpmbLockStateNotSupported.into());
        }

        let mut buf = [0u8; size_of::<SecRpmbInfo>()];

        self.read_rpmb(port, crate::RpmbRegion::R1, 0, 1, buf.as_mut_slice(), NOOP_PROGRESS)?;

        let mut info =
            SecRpmbInfo::try_read(&buf).map_err(|_| PenumbraError::RpmbLockStateNotSupported)?;

        info.set_lock_state(state);

        info.try_write(&mut buf)?;

        self.write_rpmb(port, crate::RpmbRegion::R1, 0, 1, buf.as_slice(), NOOP_PROGRESS)
    }

    fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: u64,
        writer: W,
        progress: F,
    ) -> Result<()> {
        exts::peek(self, port, addr, length, writer, progress)
    }

    fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: u64,
        reader: R,
        progress: F,
    ) -> Result<()> {
        exts::poke(self, port, addr, length, reader, progress)
    }

    fn read_register<P: MtkPort>(&mut self, port: &mut P, addr: u64) -> Result<u32> {
        exts::read_register(self, port, addr)
    }

    fn write_register<P: MtkPort>(&mut self, port: &mut P, addr: u64, value: u32) -> Result<()> {
        exts::write_register(self, port, addr, value)
    }

    fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: crate::RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        writer: W,
        progress: F,
    ) -> Result<()> {
        exts::read_rpmb(self, port, region, start_sector, num_sectors, writer, progress)
    }

    fn write_rpmb<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: crate::storage::RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        reader: R,
        progress: F,
    ) -> Result<()> {
        exts::write_rpmb(self, port, region, start_sector, num_sectors, reader, progress)
    }

    fn erase_rpmb<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: crate::storage::RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        progress: F,
    ) -> Result<()> {
        exts::erase_rpmb(self, port, region, start_sector, num_sectors, progress)
    }

    fn auth_rpmb<P: MtkPort>(
        &mut self,
        port: &mut P,
        region: crate::storage::RpmbRegion,
        key: &[u8],
    ) -> Result<()> {
        exts::auth_rpmb(self, port, region, key)
    }

    fn sej_aes<R: Reader, W: Writer, P: MtkPort>(
        &mut self,
        port: &mut P,
        params: extensions::SejParams,
        reader: R,
        writer: W,
    ) -> Result<()> {
        exts::sej_aes(self, port, &params, reader, writer)
    }

    fn derive_key<P: MtkPort>(
        &mut self,
        port: &mut P,
        params: extensions::KeyDeriveParams,
    ) -> Result<Vec<u8>> {
        exts::derive_key(self, port, params)
    }

    fn patch_da(&mut self, da: &mut DaEntry) -> Result<()> {
        patch::patch_da(da)
    }

    fn patch_da1(&mut self, da: &mut DaEntry) -> Result<()> {
        patch::patch_da1(da)
    }

    fn patch_da2(&mut self, da: &mut DaEntry) -> Result<()> {
        patch::patch_da2(da)
    }
}
