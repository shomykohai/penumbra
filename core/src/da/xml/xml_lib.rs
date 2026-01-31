/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::time::{Duration, timeout};

use crate::VERSION;
use crate::connection::Connection;
use crate::core::auth::{AuthManager, SignData, SignPurpose, SignRequest};
use crate::core::devinfo::DeviceInfo;
use crate::core::storage::Storage;
use crate::da::xml::cmds::{
    CMD_END,
    CMD_START,
    DT_PROTOCOL_FLOW,
    FileSystemOp,
    GetSysProperty,
    HOST_CMDS,
    HostSupportedCommands,
    MAGIC,
    NotifyInitHw,
    SecurityGetDevFwInfo,
    SecuritySetFlashPolicy,
    SetHostInfo,
    SetRuntimeParameter,
    XmlCmdLifetime,
    XmlCommand,
    create_cmd,
};
#[cfg(not(feature = "no_exploits"))]
use crate::da::xml::exts::boot_extensions;
use crate::da::xml::storage::detect_storage;
use crate::da::{DA, DAProtocol};
use crate::error::{Error, Result, XmlError, XmlErrorKind};
use crate::utilities::xml::{get_tag, get_tag_usize};

pub struct Xml {
    pub conn: Connection,
    pub da: DA,
    pub dev_info: DeviceInfo,
    #[allow(dead_code)]
    pub(super) using_exts: bool,
    #[allow(dead_code)]
    pub(super) read_packet_length: Option<usize>,
    pub(super) write_packet_length: Option<usize>,
    pub(super) patch: bool,
    pub(super) verbose: bool,
}

impl Xml {
    pub fn new(conn: Connection, da: DA, dev_info: DeviceInfo, verbose: bool) -> Self {
        Xml {
            conn,
            da,
            dev_info,
            using_exts: false,
            read_packet_length: None,
            write_packet_length: None,
            patch: true,
            verbose,
        }
    }

    /// Reads data of arbitrary length taken from the header sent by the device.
    pub async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 12];
        self.conn.port.read_exact(&mut hdr).await?;

        let len = self.parse_header(&hdr)?;

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;

        Ok(data)
    }

    pub(super) fn generate_header(&self, data: &[u8]) -> [u8; 12] {
        let mut hdr = [0u8; 12];

        // efeeeefe | 010000000 | 04000000 (Data Length)
        hdr[0..4].copy_from_slice(&(MAGIC).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DT_PROTOCOL_FLOW).to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!("[TX] Data Header: {:02X?}, Data Length: {}", hdr, data.len());

        hdr
    }

    pub(super) fn parse_header(&self, hdr: &[u8; 12]) -> Result<u32> {
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

        if magic != MAGIC {
            return Err(Error::io("Invalid magic"));
        }

        debug!("[RX] Data Length from Header: 0x{:X}", len);

        Ok(len)
    }

    /// Checks for the lifetime acknowledgment (CMD:START or CMD:END).
    async fn check_lifetime(&mut self, lifetime: XmlCmdLifetime) -> Result<bool> {
        match timeout(Duration::from_millis(700), self.read_data()).await {
            Ok(Ok(data)) => {
                let pattern: &[u8] = match lifetime {
                    XmlCmdLifetime::CmdStart => CMD_START,
                    XmlCmdLifetime::CmdEnd => CMD_END,
                };

                if data.windows(20).any(|window| window == b"<result>ERR</result>") {
                    // We need to ack before returning, or the device will hang.
                    self.ack(None).await?;
                    return Ok(false);
                }

                Ok(data.windows(pattern.len()).any(|window| window == pattern))
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // HACK: Since we might reinit before reading the START lifetime,
                // if we timeout, we assume the lifetime is valid.
                // TODO: Consider sending CANCEL to restart the handler loop instead.
                Ok(true)
            }
        }
    }

    /// Sends an acknowledgment to the device.
    /// By default, it sends "OK\0".
    /// If a value is provided, it sends "OK@0x{value}\0".
    pub async fn ack(&mut self, value: Option<String>) -> Result<bool> {
        let mut ack_str: String = "OK\0".to_string();
        if let Some(v) = value {
            ack_str = format!("OK@0x{v}\0");
        }

        self.send(ack_str.as_bytes()).await?;
        Ok(true)
    }

    /// Reads an acknowledgment from the device.
    pub async fn read_ack(&mut self) -> Result<bool> {
        let resp = self.read_data().await?;
        let s = String::from_utf8_lossy(&resp);

        // Check for OK or OK@0x0 (Ok with error code 0)
        if s == "OK\u{0}" || s == "OK@0x0\u{0}" {
            return Ok(true);
        }

        if s.contains("ERR!UNSUPPORTED") {
            return Err(Error::Xml(XmlError::from_message(&resp)));
        }

        Err(Error::proto("Invalid acknowledgment"))
    }

    /// Acknowledges the lifetime of an XML command (CMD:START or CMD:END).
    pub async fn lifetime_ack(&mut self, lifetime: XmlCmdLifetime) -> Result<bool> {
        let is_valid = self.check_lifetime(lifetime).await?;
        if !is_valid {
            return Err(Error::io("Invalid lifetime acknowledgment"));
        }
        self.ack(None).await
    }

    /// Sends an XML command to the device.
    pub async fn send_cmd<C: XmlCommand>(&mut self, cmd: &C) -> Result<bool> {
        let xml_str = create_cmd(cmd);
        let xml_bytes = xml_str.as_bytes();

        self.lifetime_ack(XmlCmdLifetime::CmdStart).await?;
        self.send(xml_bytes).await?;

        debug!("Sent XML Command: CMD:{}", cmd.cmd_name());

        // Read the ack back.
        // We don't wait for CMD:END here, because each CMD might
        // perform different actions in between.
        match self.read_ack().await {
            Ok(_) => Ok(true),
            Err(Error::Xml(err)) if err.kind == XmlErrorKind::UnsupportedCmd => {
                self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Sends a file to the device.
    pub async fn download_file<R>(
        &mut self,
        size: usize,
        mut reader: R,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        /*
         * Device sends CMD:DOWNLOAD command
         * Read and parse it
         * Download flow:
         * Device: CMD:DOWNLOAD-FILE
         * Host: OK!
         * Device: OK@0x<size in hex>
         * Host: OK!
         * Device: OK@0x0 (status 0)
         * Host: <data packets>
         * Device: OK! (each packet)
         */
        let resp = self.read_data().await?;
        let resp_string = String::from_utf8_lossy(&resp);

        let cmd: String = get_tag(&resp_string, "command")?;
        if cmd != "CMD:DOWNLOAD-FILE" {
            debug!("Invalid xml response for CMD:DOWNLOAD-FILE: {}", resp_string);
            return Err(Error::proto("Expected CMD:DOWNLOAD-FILE"));
        }

        // Acknowledge we received the command
        self.ack(None).await?;

        // Tell the device the size we want to send
        self.ack(format!("{:x}", size).into()).await?;
        // Read the response
        self.read_ack().await?;

        let packet_length: usize = get_tag_usize(&resp_string, "arg/packet_length")?;

        let mut chunk = vec![0u8; packet_length];
        let mut bytes_sent = 0;

        while bytes_sent < size {
            let to_read = packet_length.min(size - bytes_sent);
            reader.read_exact(&mut chunk[..to_read]).await?;

            // Status
            self.ack("0".to_string().into()).await?;
            self.read_ack().await?;

            self.send(&chunk[..to_read]).await?;
            self.read_ack().await?;

            bytes_sent += to_read;
            progress(bytes_sent, size);
        }

        debug!("File download completed, 0x{:X} bytes sent.", size);
        Ok(())
    }

    /// Receives a file from the device.
    pub async fn upload_file<W>(
        &mut self,
        mut writer: W,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<bool>
    where
        W: AsyncWrite + Unpin,
    {
        /*
         * Flow:
         * Device sends CMD:UPLOAD-FILE
         * Host: OK!
         * Device: OK@0x<hex size>\0
         * Host: OK!
         * Device: OK! (how cute!)
         * Host: OK!
         * Device: <data packets>
         */
        let resp = self.read_data().await?;
        let resp_string = String::from_utf8_lossy(&resp);

        let cmd: String = get_tag(&resp_string, "command")?;
        if cmd != "CMD:UPLOAD-FILE" {
            debug!("Invalid xml response for CMD:UPLOAD-FILE: {}", resp_string);
            return Err(Error::proto("Expected CMD:UPLOAD-FILE"));
        }

        self.ack(None).await?;

        let length_resp = self.read_data().await?;
        let length_str = String::from_utf8_lossy(&length_resp);

        let size = {
            let trimmed = length_str.trim_end_matches('\0').trim();
            let hex = trimmed
                .strip_prefix("OK@0x")
                .ok_or_else(|| Error::proto("Invalid response format, expected OK@0x<hex>\\0"))?;

            usize::from_str_radix(hex, 16)
                .map_err(|_| Error::proto("Invalid hex number in OK@0x<...>\\0"))?
        };

        self.ack(None).await?;

        let packet_length: usize = get_tag_usize(&resp_string, "arg/packet_length")?;
        let mut bytes_received = 0;

        while bytes_received < size {
            let to_read = packet_length.min(size - bytes_received);
            self.read_ack().await?;
            self.ack(None).await?;
            let data = self.read_data().await?;
            writer.write_all(&data).await?;
            self.ack(None).await?;

            bytes_received += to_read;
            progress(bytes_received, size);
        }

        debug!("File upload completed, 0x{:X} bytes received.", size);

        Ok(true)
    }

    /// Waits for the device to finish a certain operation, reporting progress.
    pub async fn progress_report(
        &mut self,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<bool> {
        let resp = self.read_data().await?;
        let resp_string = String::from_utf8_lossy(&resp);

        let cmd: String = get_tag(&resp_string, "command")?;
        if cmd != "CMD:PROGRESS-REPORT" {
            return Err(Error::proto("Expected CMD:PROGRESS-REPORT"));
        }

        self.ack(None).await?;

        let mut resp: Vec<u8> = Vec::new();
        while resp != b"OK!EOT\0" {
            resp = self.read_data().await?;
            self.ack(None).await?;

            let resp_string = String::from_utf8_lossy(&resp);

            if !resp_string.starts_with("OK!PROGRESS@") {
                continue;
            }

            let prog = resp_string
                .trim_end_matches('\0')
                .split('@')
                .nth(1)
                .ok_or_else(|| Error::proto("Invalid progress format"))?;

            let progress_value: usize =
                prog.parse().map_err(|_| Error::proto("Invalid progress value"))?;

            progress(progress_value, 100);
        }

        progress(100, 100);

        Ok(true)
    }

    /// Perform a (fake) file system operation
    /// This is used in SPFT for asking the tool to do stuff like creating directories,
    /// checking file existence, etc.
    /// We don't need it.
    pub async fn file_system_op(&mut self, op: FileSystemOp) -> Result<bool> {
        let resp = self.read_data().await?;
        let resp_string = String::from_utf8_lossy(&resp);

        let cmd: String = get_tag(&resp_string, "command")?;
        if cmd != "CMD:FILE-SYS-OPERATION" {
            return Err(Error::proto("Expected CMD:FILE-SYS-OPERATION"));
        }

        self.ack(None).await?;
        self.ack(Some(op.default())).await?;

        Ok(true)
    }

    pub(super) async fn upload_stage1(
        &mut self,
        addr: u32,
        length: u32,
        data: Vec<u8>,
        sig_len: u32,
    ) -> Result<bool> {
        info!(
            "[Penumbra] Uploading XML DA1 region to address 0x{:08X} with length 0x{:X}",
            addr, length
        );

        self.conn.send_da(&data, length, addr, sig_len).await?;
        info!("[Penumbra] Sent XML DA1, jumping to address 0x{:08X}...", addr);
        self.conn.jump_da(addr).await?;

        let log_level = if self.verbose { "DEBUG" } else { "INFO" };

        xmlcmd_e!(
            self,
            SetRuntimeParameter,
            "NONE",
            "AUTO-DETECT",
            log_level,
            "UART",
            "LINUX",
            "YES"
        )?;
        xmlcmd_e!(self, HostSupportedCommands, HOST_CMDS)?;
        // Wait for the device to initialize DRAM
        xmlcmd!(self, NotifyInitHw)?;
        let mut mock_progress = |_, _| {};
        self.progress_report(&mut mock_progress).await?;
        self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

        xmlcmd_e!(self, SetHostInfo, format!("Penumbra v{}", VERSION))?;

        Ok(true)
    }

    pub(super) async fn get_or_detect_storage(&mut self) -> Option<Arc<dyn Storage>> {
        if let Some(storage) = self.dev_info.storage().await {
            return Some(storage);
        }

        if let Some(storage) = detect_storage(self).await {
            self.dev_info.set_storage(storage.clone()).await;
            return Some(storage);
        }

        None
    }

    pub async fn get_upload_file_resp(&mut self) -> Result<String> {
        let mut buffer = Vec::new();
        let mut writer = BufWriter::new(&mut buffer);
        let mut progress = |_, _| {};

        self.upload_file(&mut writer, &mut progress).await?;
        writer.flush().await?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    pub(super) async fn handle_sla(&mut self) -> Result<bool> {
        xmlcmd!(self, GetSysProperty, "DA.SLA", "0")?;

        let response = self.get_upload_file_resp().await?;
        self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

        let sla_enabled = response.contains("ENABLED");
        if !sla_enabled {
            return Ok(true);
        }

        info!("DA SLA is enabled");

        xmlcmd!(self, SecurityGetDevFwInfo, "0")?;
        let fw_info = self.get_upload_file_resp().await?;
        self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

        debug!("Firmware info: {}", fw_info);
        let rnd_str = get_tag::<String>(&fw_info, "rnd")?;
        let hrid_str = get_tag::<String>(&fw_info, "hrid")?;
        let socid_str = get_tag::<String>(&fw_info, "socid")?;
        let rnd = hex::decode(rnd_str).map_err(|_| Error::proto("Invalid rnd response"))?;
        let hrid = hex::decode(hrid_str).map_err(|_| Error::proto("Invalid hrid response"))?;
        let soc_id = hex::decode(socid_str).map_err(|_| Error::proto("Invalid socid response"))?;

        let da2_data = match self.da.get_da2() {
            Some(da2) => da2.data.clone(),
            None => Vec::new(),
        };

        let auth = AuthManager::get();
        let sign_data = SignData { rnd, hrid, soc_id, raw: fw_info.into() };
        let sign_req =
            SignRequest { data: sign_data, purpose: SignPurpose::DaSla, pubk_mod: da2_data };

        let mut progress = |_, _| {};
        if auth.can_sign(&sign_req) {
            info!("Found signer for DA SLA!");
            let signed_rnd = auth.sign(&sign_req).await?;
            info!("Signed DA SLA challenge. Uploading to device...");

            xmlcmd!(self, SecuritySetFlashPolicy, "Penumbra SLA challenge")?;
            self.download_file(signed_rnd.len(), signed_rnd.as_slice(), &mut progress).await?;
            self.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;
            info!("DA SLA signature accepted!");
            return Ok(true);
        }

        info!("No signer available for DA SLA! Trying dummy signature...");
        let dummy_sig = vec![0u8; 256];
        xmlcmd!(self, SecuritySetFlashPolicy, "Penumbra Dummy SLA challenge")?;
        self.download_file(dummy_sig.len(), dummy_sig.as_slice(), &mut progress).await?;
        match self.lifetime_ack(XmlCmdLifetime::CmdEnd).await {
            Ok(a) => {
                info!("DA SLA signature accepted (dummy) {}!", a);
                Ok(true)
            }
            Err(e) => {
                error!("DA SLA signature rejected (dummy), can't proceed! {}", e);
                Err(e)
            }
        }
    }

    #[cfg(not(feature = "no_exploits"))]
    pub(super) async fn boot_extensions(&mut self) -> Result<bool> {
        if self.using_exts {
            warn!("DA extensions already in use, skipping re-upload");
            return Ok(true);
        }
        info!("Booting DA extensions...");
        self.using_exts = boot_extensions(self).await?;
        Ok(true)
    }
}
