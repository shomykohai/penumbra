/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::time::Duration;

use hacc::{DaEntry, Preloader};
#[cfg(feature = "exploits")]
use hacc::{TryRead, TryWrite};
use log::{debug, error, info, trace};

use crate::activity::{Activity, DeviceActivity};
#[cfg(feature = "exploits")]
use crate::da::DownloadProtocolExt;
#[cfg(feature = "exploits")]
use crate::da::extensions;
use crate::da::protocol::{DaProtocolParams, DataType, NOOP_PROGRESS, PacketHeader};
use crate::da::storage::{get_aux_gpt_parts, get_gpt_parts};
use crate::da::xflash::cmd::Cmd;
#[cfg(feature = "exploits")]
use crate::da::xflash::exts;
use crate::da::xflash::flash;
#[cfg(feature = "exploits")]
use crate::da::xflash::patch::{self};
use crate::da::xflash::storage::detect_storage;
use crate::da::xflash::structs::{
    AddressLengthParams,
    EnvParams,
    PacketLenParams,
    PartTableCat,
    RebootParams,
    SlaChallengeData,
};
use crate::da::{BootMode, DaLogLevel, DownloadProtocol};
use crate::devinfo::DevInfo;
use crate::error::{AuthError, PenumbraError, ProtocolError, XFlashError};
#[cfg(feature = "exploits")]
use crate::exploit::*;
use crate::port::{MAX_TIMEOUT, MIN_TIMEOUT, MtkPort};
use crate::preloader::PlProtocol;
use crate::storage::{PartitionKind, Partitions, Storage, StorageKind, StorageType};
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
use crate::utils::hash::{HashType, hash};
use crate::{AuthManager, DeviceLog, Error, Result, SignData, SignPurpose, SignRequest, exploit};

const MAX_PACKET: u32 = 16 * 1024 * 1024;

pub struct XFlash<'a> {
    pub pl: Option<Preloader<'a>>,
    pub(super) read_packet_length: Option<usize>,
    pub(super) write_packet_length: Option<usize>,
    #[cfg(feature = "exploits")]
    pub(super) patched: bool,
    devinfo: DevInfo,
    storage: Option<StorageKind>,
    pub(super) log_level: DaLogLevel,
    pub(super) usb_log_channel: bool,
    pub(super) device_log: DeviceLog,
    pub(super) activity: DeviceActivity,
}

impl<'a> XFlash<'a> {
    const PROGRESS_COMPLETE: u32 = 0x40040005;
    const PROGRESS_TICK: u32 = 0x40040004;

    pub fn new(params: DaProtocolParams<'a>) -> Self {
        XFlash {
            pl: params.preloader,
            devinfo: params.devinfo,
            log_level: params.log_level,
            usb_log_channel: params.usb_log_channel,
            device_log: params.device_log,
            activity: params.activity,
            read_packet_length: None,
            write_packet_length: None,
            storage: None,
            #[cfg(feature = "exploits")]
            patched: false,
        }
    }

    pub fn get_status<P: MtkPort>(&mut self, port: &mut P) -> Result<u32> {
        let data = self.read_data(port)?;

        if data.is_empty() {
            debug!("[RX] Status: empty data");
            return Err(Error::XFlash(XFlashError::from_code(0xFFFFFFFF)));
        }

        let status = u32::from_le_bytes(data[..4].try_into().unwrap_or([0u8; 4]));

        debug!("[RX] Status: 0x{:08X}", status);
        match status {
            0 => Ok(status),
            sync if sync == Cmd::SyncSignal as u32 => Ok(status),
            _ => Err(Error::XFlash(XFlashError::from_code(status))),
        }
    }

    pub fn devctrl<P: MtkPort>(
        &mut self,
        port: &mut P,
        cmd: Cmd,
        params: Option<&[&[u8]]>,
    ) -> Result<Vec<u8>> {
        self.send_cmd(port, Cmd::DeviceCtrl)?;
        self.send_cmd(port, cmd)?;

        if let Some(p) = params {
            self.send_data(port, p)?;
            return Ok(vec![]);
        }

        let read = self.read_data(port);
        status_ok!(self, port)?;

        read
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
        if length > MAX_PACKET {
            return Err(ProtocolError::InvalidResponseLength.into());
        }
        let mut payload = vec![0u8; length as usize];
        port.read_exact(&mut payload)?;

        let body = String::from_utf8_lossy(&payload[4..]).into_owned();

        trace!("[DA Message] {}", body);

        if self.usb_log_channel {
            self.device_log.push(body);
        }

        Ok(())
    }

    pub fn send_cmd<P: MtkPort>(&mut self, port: &mut P, cmd: Cmd) -> Result<()> {
        let cmd_bytes = (cmd as u32).to_le_bytes();
        debug!("[TX] Sending Command: 0x{:08X}", cmd as u32);
        self.send(port, &cmd_bytes[..])
    }

    pub fn get_packet_length<P: MtkPort>(&mut self, port: &mut P) -> Result<(usize, usize)> {
        let packet_length_bytes = self.devctrl(port, Cmd::GetPacketLength, None)?;

        let pkt_len = PacketLenParams::from_bytes(&packet_length_bytes)
            .ok_or(ProtocolError::InvalidPacketLength)?;

        let write_len = pkt_len.write_pkt_len as usize;
        let read_len = pkt_len.read_pkt_len as usize;

        self.write_packet_length = Some(write_len);
        self.read_packet_length = Some(read_len);

        Ok((write_len, read_len))
    }

    pub(super) fn upload_stage1<P: MtkPort>(&mut self, port: &mut P, da: &DaEntry) -> Result<bool> {
        let da1 = da.da1();
        let da1_data = da.da1_data();

        let da1_addr = da1.addr();
        let da1_length = da1.length();
        let da1_sig_len = da1.sig_len();

        info!("Uploading XFlash DA1 to address 0x{:08X} with length 0x{:X}", da1_addr, da1_length);

        let mut pl = PlProtocol::new(port);

        pl.send_da(da1_data, da1_length as u32, da1_addr, da1_sig_len as u32)?;
        info!("Sent DA1, jumping to address 0x{:08X}...", da1_addr);
        pl.jump_da(da1_addr)?;

        let sync_byte = port.read_u8()?;

        if sync_byte != 0xC0 {
            return Err(ProtocolError::InvalidSyncByte.into());
        }

        debug!("Received sync byte");

        let hdr = PacketHeader::new(DataType::Flow, 4).to_bytes();
        port.write_all(&hdr)?;
        port.write_all(&(Cmd::SyncSignal as u32).to_le_bytes())?;

        let da_log_level = self.log_level as u32;

        //log_channel = 1: UART, 2: Usb, 3: Both
        let log_channel: u32 = 1 + self.usb_log_channel as u32;
        let system_os = cfg_select! {
            target_os = "windows" => 0,
            target_os = "linux" => 1,
            _ => 1,
        };

        let env_params =
            EnvParams { da_log_level, log_channel, system_os, ufs_provision: 0, reserved: 0 };

        self.send_data(port, &[&Cmd::SetupEnvironment.to_bytes(), &env_params.to_bytes()])?;

        self.send_data(port, &[&Cmd::SetupHwInitParams.to_bytes(), &[0u8; 4]])?;

        status_any!(self, port, Cmd::SyncSignal as u32)?;

        info!("Received DA1 sync signal.");

        self.handle_emi(port)?;
        self.devctrl(port, Cmd::SetChecksumLevel, Some(&[&0u32.to_le_bytes()]))?;

        #[cfg(feature = "reenumerate")]
        {
            info!("Reenumerating USB to DA");
            self.send_cmd(port, Cmd::SwitchUsbSpeed)?;
            self.send(port, &0u32.to_le_bytes())?;
            port.reenumerate(0x0E8D, 0x2001)?;
        }

        Ok(true)
    }

    fn handle_emi<P: MtkPort>(&mut self, port: &mut P) -> Result<()> {
        let conn_agent = self.devctrl(port, Cmd::GetConnectionAgent, None)?;

        debug!("Connection agent is {}", String::from_utf8_lossy(&conn_agent));

        // If the connection agent is "preloader", there's no need to upload EMI settings
        if conn_agent == b"preloader" {
            return Ok(());
        }

        let pl = self.pl.as_ref().ok_or(ProtocolError::PreloaderNeeded)?;

        let emi = pl.emi().ok_or(ProtocolError::EmiNotFound)?;

        port.set_timeout(MAX_TIMEOUT)?;

        info!("Uploading EMI settings to device...");
        self.send_cmd(port, Cmd::InitExtRam)?;
        let result = self.send_data(port, &[&(emi.len() as u32).to_le_bytes(), emi]);

        port.set_timeout(MIN_TIMEOUT)?;

        result?;

        info!("EMI settings uploaded successfully.");

        Ok(())
    }

    /// Same as `download_data`, but with a custom chunk size and timeout.
    /// Useful for limiting the packet size when needed.
    pub fn download_data_with<R, F, P>(
        &mut self,
        port: &mut P,
        size: usize,
        chunk_size: usize,
        max_timeout: Duration,
        mut reader: R,
        mut progress: F,
    ) -> Result<usize>
    where
        P: MtkPort,
        R: Reader,
        F: ProgressCallback,
    {
        let mut buffer = vec![0u8; chunk_size];
        let mut bytes_written = 0;

        port.set_timeout(max_timeout)?;
        progress(0, size);

        let result = (|| -> Result<()> {
            while bytes_written < size {
                let to_read = (size - bytes_written).min(chunk_size);
                let chunk = &mut buffer[..to_read];

                reader.read_exact_fill(chunk)?;

                // DA expects an additive 16-bit checksum of the data chunk before the actual chunk
                let checksum = chunk.iter().map(|&b| b as u32).sum::<u32>() & 0xFFFF;

                let zero_bytes = 0u32.to_le_bytes();
                let checksum_bytes = checksum.to_le_bytes();

                self.send_data(port, &[&zero_bytes, &checksum_bytes, chunk])?;

                bytes_written += chunk.len();
                progress(bytes_written, size);
                debug!("Written {}/{} bytes...", bytes_written, size);
            }

            Ok(())
        })();

        let final_status = match &result {
            Ok(_) | Err(Error::XFlash(_)) => status_ok!(self, port),
            _ => Ok(()),
        };

        port.set_timeout(MIN_TIMEOUT)?;

        result?;
        final_status?;

        Ok(bytes_written)
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

        Ok(true)
    }
}

impl<'a> DownloadProtocol for XFlash<'a> {
    fn upload_da<P: MtkPort>(&mut self, port: &mut P, da: &mut DaEntry) -> Result<()> {
        exploit!(Unfused, self, port, da);
        exploit!(Linecode, self, port, da);

        self.activity.set(Activity::UploadingDa);
        self.upload_stage1(port, da)?;

        self.get_packet_length(port)?;

        exploit!(Carbonara, self, port, da);

        let da2 = da.da2();
        let da2_data = &da.da2_code();

        info!(
            "Uploading XFlash DA2 to address 0x{:08X} with length 0x{:X}",
            da2.addr(),
            da2.length()
        );

        if let Err(e) = self.boot_to(port, da2.addr(), da2_data) {
            self.reboot(port, BootMode::Normal).ok();
            return Err(e);
        };

        info!("Successfully uploaded and booted to XFlash DA2");

        self.handle_sla(port, da)?;
        self.get_packet_length(port)?;

        #[cfg(feature = "exploits")]
        {
            self.boot_extensions(port, da).ok();
        }

        self.activity.set(Activity::Idle);

        Ok(())
    }

    fn boot_to<P: MtkPort>(&mut self, port: &mut P, addr: u32, data: &[u8]) -> Result<()> {
        self.send_cmd(port, Cmd::BootTo)?;

        let param = AddressLengthParams { addr: addr as u64, length: data.len() as u64 }.to_bytes();

        port.set_timeout(MAX_TIMEOUT)?;

        self.send_data(port, &[&param, data])?;
        let result = status_any!(self, port, 0, Cmd::SyncSignal as u32);

        port.set_timeout(MIN_TIMEOUT)?;

        result
    }

    fn read_data<P: MtkPort>(&mut self, port: &mut P) -> Result<Vec<u8>> {
        let hdr = self.read_next_flow_header(port)?;

        debug!("[RX] Packet header received: 0x{:X} bytes", hdr.length);

        if hdr.length > MAX_PACKET {
            return Err(ProtocolError::InvalidResponseLength.into());
        }
        let mut data = vec![0u8; hdr.length as usize];
        port.read_exact(&mut data)?;
        Ok(data)
    }

    fn send<P: MtkPort>(&mut self, port: &mut P, data: &[u8]) -> Result<()> {
        self.send_data(port, &[data])
    }

    fn send_data<P: MtkPort>(&mut self, port: &mut P, data: &[&[u8]]) -> Result<()> {
        let mut hdr: [u8; 12];

        self.flush_usb_logs(port);

        for param in data {
            hdr = PacketHeader::new(DataType::Flow, param.len() as u32).to_bytes();

            port.write_all(&hdr)?;

            let mut pos = 0;
            let max_chunk_size = self.write_packet_length.unwrap_or(0x8000);

            while pos < param.len() {
                let end = param.len().min(pos + max_chunk_size);
                let chunk = &param[pos..end];
                debug!("[TX] Sending chunk (0x{:X} bytes)", chunk.len());
                port.write_all(chunk)?;
                pos = end;
            }

            debug!("[TX] Completed sending 0x{:X} bytes", param.len());
        }

        let result = status_ok!(self, port);

        result?;

        Ok(())
    }

    fn shutdown<P: MtkPort>(&mut self, port: &mut P) -> Result<()> {
        self.send_cmd(port, Cmd::Shutdown)?;

        let params = RebootParams {
            is_dev_reboot: 0,
            timeout_ms: 0,
            async_flag: 0,
            bootup: BootMode::Normal as u32,
            dlbit: 0,
            not_reset_rtc_time: 0,
            not_disconnect_usb: 0,
        };

        info!("Shutting down device...");

        self.send(port, &params.to_bytes())?;

        port.close().ok();
        Ok(())
    }

    fn reboot<P: MtkPort>(&mut self, port: &mut P, bootmode: BootMode) -> Result<()> {
        self.send_cmd(port, Cmd::Shutdown)?;

        let bootup = match bootmode {
            BootMode::Normal | BootMode::HomeScreen | BootMode::Fastboot => bootmode as u32,
            _ => 0,
        };

        let params = RebootParams {
            is_dev_reboot: 1,
            timeout_ms: 0,
            async_flag: 0,
            bootup,
            dlbit: 0,
            not_reset_rtc_time: 0,
            not_disconnect_usb: 0,
        };

        info!("Rebooting device into {:?} mode...", bootmode);

        self.send(port, &params.to_bytes())?;

        port.close().ok();
        Ok(())
    }

    fn download_data<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: usize,
        reader: R,
        progress: F,
    ) -> Result<usize> {
        let chunk_size = self.write_packet_length.unwrap_or(0x8000);
        self.download_data_with(port, size, chunk_size, MAX_TIMEOUT, reader, progress)
    }

    fn upload_data<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: usize,
        mut writer: W,
        mut progress: F,
    ) -> Result<usize> {
        let mut bytes_read = 0;

        port.set_timeout(MAX_TIMEOUT)?;

        progress(0, size);

        let result = loop {
            let chunk = match self.read_data(port) {
                Ok(chunk) => chunk,
                Err(e) => break Err(e),
            };

            if chunk.is_empty() {
                debug!("No data received, breaking.");
                break Ok(());
            }

            if let Err(e) = writer.write_all(&chunk) {
                break Err(e.into());
            }

            bytes_read += chunk.len();

            if let Err(e) = self.send(port, &[0u8; 4]) {
                break Err(e);
            }

            progress(bytes_read, size);

            if bytes_read >= size {
                debug!("Requested size read. Breaking.");
                break Ok(());
            }

            debug!("Read {:X}/{:X} bytes...", bytes_read, size);
        };

        port.set_timeout(MIN_TIMEOUT)?;
        result?;

        Ok(bytes_read)
    }

    fn progress_report<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: usize,
        mut progress: F,
    ) -> Result<()> {
        port.set_timeout(MAX_TIMEOUT)?;

        progress(0, size);

        let result = loop {
            let packet = match self.read_data(port) {
                Ok(packet) => packet,
                Err(e) => break Err(e),
            };

            let Some(prg_status) =
                packet.get(..4).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes)
            else {
                break Err(ProtocolError::InvalidResponseLength.into());
            };

            match prg_status {
                Self::PROGRESS_COMPLETE => {
                    progress(size, size);
                    break Ok(());
                }
                Self::PROGRESS_TICK => {}
                code => {
                    break Err(Error::XFlash(XFlashError::from_code(code)));
                }
            }

            let progress_percent = match self.read_data(port) {
                Ok(packet) => packet
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0),
                Err(e) => break Err(e),
            };

            let ack = [0u8; 4];
            let hdr = PacketHeader::new(DataType::Flow, ack.len() as u32).to_bytes();
            if let Err(e) = port.write_all(&hdr) {
                break Err(e);
            }
            if let Err(e) = port.write_all(&ack) {
                break Err(e);
            }

            let progress_bytes = (progress_percent as usize * size) / 100;
            progress(progress_bytes, size);
            debug!("Progress: {}% ({}/{})", progress_percent, progress_bytes, size);
        };

        port.set_timeout(MIN_TIMEOUT)?;

        result
    }

    fn read_flash<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: usize,
        section: PartitionKind,
        writer: W,
        progress: F,
    ) -> Result<()> {
        flash::read_flash(self, port, addr, size, section, writer, progress)
    }

    fn write_flash<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: usize,
        section: PartitionKind,
        reader: R,
        progress: F,
    ) -> Result<()> {
        flash::write_flash(self, port, addr, size, section, reader, progress)
    }

    fn erase_flash<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: usize,
        section: PartitionKind,
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
        size: usize,
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

    fn get_storage_type<P: MtkPort>(&mut self, port: &mut P) -> StorageType {
        self.get_storage(port).as_ref().map(|s| s.kind()).unwrap_or(StorageType::Unknown)
    }

    fn partitions<P: MtkPort>(&mut self, port: &mut P) -> Partitions {
        let Some(storage) = self.get_storage(port).cloned() else {
            return vec![].into_iter();
        };

        let cat = self
            .devctrl(port, Cmd::GetPartitionTblCata, None)
            .ok()
            .and_then(|cat| PartTableCat::from_bytes(&cat))
            .unwrap_or_default();

        let parts = match cat {
            PartTableCat::Gpt => {
                let aux = get_aux_gpt_parts(&storage);
                let mut parts = aux.to_vec();
                let mut gpt_parts = get_gpt_parts(self, port, &storage);

                parts.append(&mut gpt_parts);
                parts
            }
            PartTableCat::Pmt => vec![],
        };

        parts.into_iter()
    }

    fn read_efuses<W: Writer, P: MtkPort>(&mut self, port: &mut P, mut writer: W) -> Result<()> {
        let yield_arg = [0u8; 0xF8];

        self.send_cmd(port, Cmd::ReadEfuse)?;
        self.send(port, &yield_arg)?;

        let efuse_data = self.read_data(port)?;

        writer.write_all(&efuse_data)?;

        self.send(port, &0u32.to_le_bytes())?;

        Ok(())
    }

    fn write_efuses<R: Reader, P: MtkPort>(
        &mut self,
        port: &mut P,
        mut reader: R,
        size: usize,
    ) -> Result<()> {
        let yield_arg = [0u8; 0xF8];

        let mut efuse_data = [0u8; 0x42D4];

        if size < efuse_data.len() {
            return Err(PenumbraError::BufferTooSmall.into());
        }

        reader.read_exact(&mut efuse_data)?;

        self.send_cmd(port, Cmd::WriteEfuse)?;
        self.send_data(port, &[&efuse_data, &yield_arg])?;

        // Efuse writing can take a bit, so
        port.set_timeout(MAX_TIMEOUT)?;
        let result = status_ok!(self, port);
        port.set_timeout(MIN_TIMEOUT)?;

        result
    }

    fn handle_sla<P: MtkPort>(&mut self, port: &mut P, da: &DaEntry) -> Result<()> {
        let Ok(resp) = self.devctrl(port, Cmd::SlaEnabledStatus, None) else {
            return Ok(());
        };

        let sla_enabled = resp.starts_with(&1u32.to_le_bytes());

        if !sla_enabled {
            debug!("DA SLA is not enabled.");
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
                if self.devctrl(port, Cmd::SetRemoteSecPolicy, Some(&[&dummy_sig])).is_ok() {
                    info!("DA SLA signature accepted (dummy)!");
                    return Ok(());
                } else {
                    error!("DA SLA signature rejected (dummy)!");
                }
            }

            error!("No signer available for DA SLA! Can't proceed any further.");
            return Err(AuthError::NoSignerAvailable.into());
        };

        let data = self.devctrl(port, Cmd::GetDevFwInfo, None)?;
        let mut data = SignData { raw: data, ..Default::default() };

        if let Some(sla_challenge) = SlaChallengeData::from_bytes(&data.raw) {
            data.hrid = sla_challenge.hrid.to_vec();
            data.rnd = sla_challenge.rnd.to_vec();
            data.soc_id = sla_challenge.soc_id.to_vec();
        }

        let sign_req = SignRequest { data, purpose: SignPurpose::DaSla, pubk_mod: da2.to_vec() };

        info!("Found signer for DA SLA!");
        let signed = auth.sign(&sign_req)?;
        info!("Signed DA SLA challenge. Uploading to device...");
        self.devctrl(port, Cmd::SetRemoteSecPolicy, Some(&[&signed]))?;
        info!("DA SLA signature accepted!");

        Ok(())
    }

    fn get_devinfo(&mut self) -> &DevInfo {
        &self.devinfo
    }
}

#[cfg(feature = "exploits")]
impl<'a> DownloadProtocolExt for XFlash<'a> {
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
            seccfg_data.len(),
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

        let mut sej_params =
            extensions::SejParams { length: 32, encrypt: false, ..Default::default() };

        let mut dec_hash = [0u8; 32];
        let mut verified_algo = None;

        for algo in [SecCfgAlgo::Sha, SecCfgAlgo::SW, SecCfgAlgo::HWv3, SecCfgAlgo::HWv4] {
            let flags = match algo {
                SecCfgAlgo::Sha => None,
                SecCfgAlgo::SW => Some((false, false)),
                SecCfgAlgo::HWv3 => Some((true, true)),
                SecCfgAlgo::HWv4 => Some((true, false)),
                _ => continue,
            };

            if let Some((anti_clone, legacy)) = flags {
                sej_params.anti_clone = anti_clone;
                sej_params.legacy = legacy;
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
            seccfg_data.len(),
            seccfg_data.as_slice(),
            NOOP_PROGRESS,
        )?;

        Ok(())
    }

    fn set_rpmb_lock_state<P: MtkPort>(
        &mut self,
        _port: &mut P,
        _state: hacc::LockState,
    ) -> Result<()> {
        /* V5 does not support the default RPMB mtk lock state */
        Err(PenumbraError::RpmbLockStateNotSupported.into())
    }

    fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: usize,
        writer: W,
        progress: F,
    ) -> Result<()> {
        exts::peek(self, port, addr, length, writer, progress)
    }

    fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: usize,
        reader: R,
        progress: F,
    ) -> Result<()> {
        exts::poke(self, port, addr, length, reader, progress)
    }

    fn read_register<P: MtkPort>(&mut self, port: &mut P, addr: u64) -> Result<u32> {
        // TODO: Support 64bit addresses
        exts::read_register(self, port, addr as u32)
    }

    fn write_register<P: MtkPort>(&mut self, port: &mut P, addr: u64, value: u32) -> Result<()> {
        // TODO: Support 64bit addresses
        exts::write_register(self, port, addr as u32, value)
    }

    fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: crate::storage::RpmbRegion,
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
