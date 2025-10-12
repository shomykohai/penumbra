/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
mod cmds;
mod exts;
pub mod flash;
use crate::connection::Connection;
use crate::connection::port::ConnectionType;
use crate::core::device::DeviceInfo;
use crate::da::xflash::cmds::*;
use crate::da::xflash::exts::{boot_extensions, read32_ext, write32_ext};
use crate::da::{DA, DAProtocol};
use crate::error::{Error, Result, XFlashError};
use crate::exploit::Exploit;
use crate::exploit::carbonara::Carbonara;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio::time::timeout;

pub struct XFlash {
    pub conn: Connection,
    pub da: DA,
    pub dev_info: Arc<Mutex<DeviceInfo>>,
    using_exts: bool,
}

#[async_trait::async_trait]
impl DAProtocol for XFlash {
    async fn upload_da(&mut self) -> Result<bool> {
        let (da1addr, da1length, da1data, da1sig_len) = match self.da.get_da1() {
            Some(da1) => (da1.addr, da1.length, da1.data.clone(), da1.sig_len),
            None => return Err(Error::penumbra("DA1 region not found")),
        };

        self.upload_stage1(da1addr, da1length, da1data, da1sig_len)
            .await
            .map_err(|e| Error::proto(format!("Failed to upload DA1: {}", e)))?;

        let da2 = match self.da.get_da2() {
            Some(da2) => da2.clone(),
            None => return Err(Error::penumbra("DA2 region not found")),
        };
        let da2addr = da2.addr;
        let da2sig_len = da2.sig_len as usize;

        let da2_original_data = da2.data[..da2.data.len().saturating_sub(da2sig_len)].to_vec();

        // TODO: Patch DA2 with Carbonara
        let carbonara_da = Arc::new(Mutex::new(self.da.clone()));
        let mut carbonara = Carbonara::new(carbonara_da);

        let da2data = match carbonara.run(self).await {
            Ok(_) => match carbonara.get_patched_da2() {
                Some(patched_da2) => patched_da2.data.clone(),
                None => da2_original_data,
            },
            Err(_) => da2_original_data,
        };

        match self.boot_to(da2addr, &da2data).await {
            Ok(true) => {
                info!("[Penumbra] Successfully uploaded and executed DA2");
                self.boot_extensions().await?;
                Ok(true)
            }
            Ok(false) => Err(Error::proto("Failed to execute DA2")),
            Err(e) => Err(Error::proto(format!("Error uploading DA2: {}", e))),
        }
    }

    async fn boot_to(&mut self, addr: u32, data: &[u8]) -> Result<bool> {
        info!(
            "[Penumbra] Sending BOOT_TO command to address 0x{:08X} with {} bytes",
            addr,
            data.len()
        );

        self.send_cmd(Cmd::BootTo).await?;

        let status = self.get_status().await?;
        if status != 0 {
            let xflash_err = XFlashError::from_code(status);
            error!(
                "BOOT_TO command failed with status: 0x{:08X} ({})",
                status, xflash_err
            );
            return Err(Error::XFlash(xflash_err));
        }

        // Addr (LE) | Padding | Length (LE) | Padding
        // 00000040000000002c83050000000000 -> addr=0x4000000, len=0x0005832c
        let mut param = Vec::new();
        param.extend_from_slice(&addr.to_le_bytes());
        param.extend_from_slice(&[0, 0, 0, 0]);
        param.extend_from_slice(&(data.len() as u32).to_le_bytes());
        param.extend_from_slice(&[0, 0, 0, 0]);

        // TODO: Use send_data instead of reconstructing header manually
        let mut hdr = [0u8; 12];
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        hdr[8..12].copy_from_slice(&(param.len() as u32).to_le_bytes());

        debug!(
            "[TX] Parameter Header: {:02X?}, Data Length: {}",
            hdr,
            param.len()
        );

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&param).await?;
        self.conn.port.flush().await?;

        // We just need to change the data size,
        // so let us just reuse what we've got already ;P
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        debug!(
            "[TX] DA2 Data Header: {:02X?}, Data Length: {}",
            hdr,
            data.len()
        );

        self.conn.port.write_all(&hdr).await?;

        // Chunks of 1KB
        let chunk_size = 1024;
        let mut pos = 0;
        while pos < data.len() {
            let end = std::cmp::min(pos + chunk_size, data.len());
            self.conn.port.write_all(&data[pos..end]).await?;
            pos = end;

            if pos % (chunk_size * 20) == 0 && pos > 0 {
                debug!("[TX] Progress: {}/{} bytes sent", pos, data.len());
            }
        }

        self.conn.port.flush().await?;
        debug!("[TX] Completed sending {} bytes", data.len());

        let status = self.get_status().await?;
        if status != 0 {
            let xflash_err = XFlashError::from_code(status);
            error!(
                "BOOT_TO status1 is not 0: 0x{:08X} ({})",
                status, xflash_err
            );
            return Err(Error::XFlash(xflash_err));
        }

        // It needs to receive the SYNC signal as well
        let status = self.get_status().await?;
        if status != Cmd::SyncSignal as u32 && status != 0 {
            let xflash_err = XFlashError::from_code(status);
            error!(
                "BOOT_TO status2 is not SYNC: 0x{:08X} ({})",
                status, xflash_err
            );
            return Err(Error::XFlash(xflash_err));
        }

        info!("[Penumbra] Successfully booted to DA2");
        Ok(true)
    }

    async fn send_data(&mut self, data: &[u8]) -> Result<bool> {
        let mut hdr = [0u8; 12];

        // MAGIC | DataType (1) | Data Length
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!(
            "[TX] Data Header: {:02X?}, Data Length: {}",
            hdr,
            data.len()
        );

        self.conn.port.write_all(&hdr).await?;

        let mut pos = 0;
        while pos < data.len() {
            let end = std::cmp::min(pos + 64, data.len());
            let chunk = &data[pos..end];
            debug!("[TX] Sending chunk ({} bytes): {:02X?}", chunk.len(), chunk);
            self.conn.port.write_all(chunk).await?;
            pos += chunk.len();
        }

        self.conn.port.flush().await?;

        let status = self.get_status().await?;
        if status != 0 {
            error!("Data send failed with status: 0x{:08X}", status);
            return Err(Error::XFlash(XFlashError::from_code(status)));
        }

        Ok(true)
    }

    async fn get_status(&mut self) -> Result<u32> {
        let mut hdr = [0u8; 12];
        match timeout(
            Duration::from_millis(500),
            self.conn.port.read_exact(&mut hdr),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(Error::io("Status read timed out")),
        };
        debug!("[RX] Status Header: {:02X?}", hdr);
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

        if magic != Cmd::Magic as u32 {
            return Err(Error::io("Invalid magic"));
        }

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;
        let status = match len {
            2 => u16::from_le_bytes(data[0..2].try_into().unwrap()) as u32,
            4 => {
                let val = u32::from_le_bytes(data[0..4].try_into().unwrap());
                if val == Cmd::Magic as u32 { 0 } else { val }
            }
            _ if data.len() >= 4 => u32::from_le_bytes(data[0..4].try_into().unwrap()),
            _ if !data.is_empty() => data[0] as u32,
            _ => 0xFFFFFFFF,
        };

        debug!("[RX] Status: 0x{:08X}", status);
        match status {
            0 => Ok(status),
            _ => Err(Error::XFlash(XFlashError::from_code(status))),
        }
    }

    async fn send(&mut self, data: &[u8], datatype: u32) -> Result<bool> {
        let mut hdr = [0u8; 12];

        // efeeeefe | 010000000 | 04000000 (Data Length)
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&datatype.to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!(
            "[TX] Header: {:02X?}, Payload: [{}]",
            hdr,
            data.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(data).await?;

        self.conn.port.flush().await?;

        Ok(true)
    }

    async fn read_flash(
        &mut self,
        addr: u64,
        size: usize,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<Vec<u8>> {
        flash::read_flash(self, addr, size, progress).await
    }

    async fn write_flash(
        &mut self,
        addr: u64,
        size: usize,
        data: &[u8],
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        flash::write_flash(self, addr, size, data, progress).await
    }

    async fn download(&mut self, part_name: String, data: &[u8]) -> Result<()> {
        flash::download(self, part_name, data).await
    }

    async fn get_usb_speed(&mut self) -> Result<u32> {
        let usb_speed = self.devctrl(Cmd::GetUsbSpeed, None).await?;
        let status = self.get_status().await?;
        if status != 0 {
            return Err(Error::proto(format!(
                "Device returned error status: {:#X}",
                status
            )));
        }
        debug!("USB Speed Data: {:?}", usb_speed);
        Ok(u32::from_le_bytes(usb_speed[0..4].try_into().unwrap()))
    }

    fn get_connection(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()> {
        self.conn.connection_type = conn_type;
        Ok(())
    }

    async fn read32(&mut self, addr: u32) -> Result<u32> {
        if self.using_exts {
            return read32_ext(self, addr).await;
        }
        debug!("Reading 32-bit register at address 0x{:08X}", addr);
        let param = addr.to_le_bytes();
        let resp = self
            .devctrl(Cmd::DeviceCtrlReadRegister, Some(&param))
            .await?;
        debug!("[RX] Read Register Response: {:02X?}", resp);
        if resp.len() < 4 {
            debug!("Short read: expected 4 bytes, got {}", resp.len());
            return Err(Error::io("Short register read"));
        }
        Ok(u32::from_le_bytes(resp[0..4].try_into().unwrap()))
    }

    async fn write32(&mut self, addr: u32, value: u32) -> Result<()> {
        if self.using_exts {
            return write32_ext(self, addr, value).await;
        }
        let mut param = Vec::new();
        param.extend_from_slice(&addr.to_le_bytes());
        param.extend_from_slice(&value.to_le_bytes());
        debug!(
            "[TX] Writing 32-bit value 0x{:08X} to address 0x{:08X}",
            value, addr
        );
        self.devctrl(Cmd::SetRegisterValue, Some(&param)).await?;
        Ok(())
    }
}

impl XFlash {
    async fn send_cmd(&mut self, cmd: Cmd) -> Result<bool> {
        let cmd_bytes = (cmd as u32).to_le_bytes();
        self.send(&cmd_bytes[..], DataType::ProtocolFlow as u32)
            .await
    }

    pub fn new(conn: Connection, da: DA, dev_info: Arc<Mutex<DeviceInfo>>) -> Self {
        XFlash {
            conn,
            da,
            dev_info,
            using_exts: false,
        }
    }

    async fn devctrl(&mut self, cmd: Cmd, param: Option<&[u8]>) -> Result<Vec<u8>> {
        self.send_cmd(Cmd::DeviceCtrl).await?;

        let status = self.get_status().await?;
        if status != 0 {
            error!(
                "Device control command failed with status: 0x{:08X}",
                status
            );
            return Err(Error::XFlash(XFlashError::from_code(status)));
        }

        self.send_cmd(cmd).await?;
        let status = self.get_status().await?;
        if status != 0 {
            error!(
                "Device control sub-command failed with status: 0x{:08X}",
                status
            );
            return Err(Error::XFlash(XFlashError::from_code(status)));
        }

        if let Some(p) = param {
            self.send_data(p).await?;
            return Ok(Vec::new());
        }

        self.read_data().await
    }

    async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 12];
        self.conn.port.read_exact(&mut hdr).await?;

        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

        if magic != Cmd::Magic as u32 {
            return Err(Error::io("Invalid magic"));
        }

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;

        Ok(data)
    }

    async fn upload_stage1(
        &mut self,
        addr: u32,
        length: u32,
        data: Vec<u8>,
        sig_len: u32,
    ) -> Result<bool> {
        info!(
            "[Penumbra] Uploading DA1 region to address 0x{:08X} with length {}",
            addr, length
        );

        self.conn.send_da(&data, length, addr, sig_len).await?;
        info!("[Penumbra] Sent DA1, jumping to address 0x{:08X}...", addr);
        self.conn.jump_da(addr).await?;

        // Without this, it timed out during my tests, so leave it here for now
        // self.conn.port.set_timeout(Duration::from_secs(10))?;

        let sync_byte = {
            let mut sync_buf = [0u8; 1];
            match self.conn.port.read_exact(&mut sync_buf).await {
                Ok(_) => sync_buf[0],
                Err(e) => return Err(Error::io(e.to_string())),
            }
        };

        info!("[Penumbra] Received sync byte");

        if sync_byte != 0xC0 {
            return Err(Error::proto("Incorrect sync byte received"));
        }

        self.send_cmd(Cmd::SyncSignal).await?;
        self.send_cmd(Cmd::SetupEnvironment).await?;

        let mut env_param = Vec::new();
        env_param.extend_from_slice(&2u32.to_le_bytes()); // da_log_level = 2 (UART)
        env_param.extend_from_slice(&1u32.to_le_bytes()); // log_channel = 1
        env_param.extend_from_slice(&1u32.to_le_bytes()); // system_os = 1 (OS_LINUX)
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ufs_provision = 0
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ...

        self.send_data(&env_param).await?;
        self.send_cmd(Cmd::SetupHwInitParams).await?;
        let hw_param = [0x00, 0x00, 0x00, 0x00];
        self.send_data(&hw_param).await?;

        let (magic, dtype, len) = {
            let mut sync_hdr = [0u8; 12];
            match self.conn.port.read_exact(&mut sync_hdr).await {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::proto(format!("Failed to read sync header: {}", e)));
                }
            }

            (
                u32::from_le_bytes(sync_hdr[0..4].try_into().unwrap()),
                u32::from_le_bytes(sync_hdr[4..8].try_into().unwrap()),
                u32::from_le_bytes(sync_hdr[8..12].try_into().unwrap()),
            )
        };

        if magic != Cmd::Magic as u32 || dtype != DataType::ProtocolFlow as u32 || len != 4 {
            return Err(Error::proto("DA sync header mismatch"));
        }

        let sync_signal_value = {
            let mut sync_signal_buf = [0u8; 4];
            match self.conn.port.read_exact(&mut sync_signal_buf).await {
                Ok(_) => {}
                Err(e) => {
                    return Err(Error::proto(format!("Failed to read sync payload: {}", e)));
                }
            }
            u32::from_le_bytes(sync_signal_buf)
        };

        if sync_signal_value != Cmd::SyncSignal as u32 {
            return Err(Error::proto("Expected SYNC SIGNAL after setup"));
        }

        info!("[Penumbra] Received DA1 sync signal.");
        Ok(true)
    }

    async fn boot_extensions(&mut self) -> Result<bool> {
        if self.using_exts {
            warn!("DA extensions already in use, skipping re-upload");
            return Ok(true);
        }
        info!("Booting DA extensions...");
        self.using_exts = boot_extensions(self).await?;
        Ok(true)
    }
}
