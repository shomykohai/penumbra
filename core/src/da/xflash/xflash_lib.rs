/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;

use log::{debug, error, info, warn};

use crate::connection::Connection;
use crate::core::auth::{AuthManager, SignData, SignPurpose, SignRequest};
use crate::core::devinfo::DeviceInfo;
use crate::core::emi::extract_emi_settings;
use crate::core::storage::Storage;
use crate::da::xflash::cmds::*;
#[cfg(not(feature = "no_exploits"))]
use crate::da::xflash::exts::boot_extensions;
use crate::da::xflash::storage::detect_storage;
use crate::da::{DA, DAProtocol};
use crate::error::{Error, Result, XFlashError};

pub struct XFlash {
    pub conn: Connection,
    pub da: DA,
    pub pl: Option<Vec<u8>>,
    pub dev_info: DeviceInfo,
    pub(super) using_exts: bool,
    pub(super) read_packet_length: Option<usize>,
    pub(super) write_packet_length: Option<usize>,
    pub(super) patch: bool,
    pub(super) verbose: bool,
}

impl XFlash {
    pub async fn send_cmd(&mut self, cmd: Cmd) -> Result<bool> {
        let cmd_bytes = (cmd as u32).to_le_bytes();
        debug!("[TX] Sending Command: 0x{:08X}", cmd as u32);
        self.send(&cmd_bytes[..]).await
    }

    pub fn new(
        conn: Connection,
        da: DA,
        dev_info: DeviceInfo,
        pl: Option<Vec<u8>>,
        verbose: bool,
    ) -> Self {
        XFlash {
            conn,
            da,
            pl,
            dev_info,
            using_exts: false,
            read_packet_length: None,
            write_packet_length: None,
            patch: true,
            verbose,
        }
    }

    // Note: When called with multiple params, this function sends data only and does not read any
    // response. For that, call read_data separately and check status manually.
    // This is to accomodate the protocol, while also not breaking read_data for other operations.
    pub async fn devctrl(&mut self, cmd: Cmd, params: Option<&[&[u8]]>) -> Result<Vec<u8>> {
        self.send_cmd(Cmd::DeviceCtrl).await?;
        self.send_cmd(cmd).await?;

        if let Some(p) = params {
            self.send_data(p).await?;
            return Ok(Vec::new());
        }

        let read = self.read_data().await;
        status_ok!(self);

        read
    }

    // When called after calling a cmd that returns a status too,
    // call status_ok!() macro manually.
    // This function only reads the data, and cannot be used to read status,
    // or functions like read_flash will fail.
    pub async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 12];
        self.conn.port.read_exact(&mut hdr).await?;

        let len = self.parse_header(&hdr)?;

        let mut data = vec![0u8; len as usize];
        self.conn.port.read_exact(&mut data).await?;

        Ok(data)
    }

    pub(super) async fn upload_stage1(
        &mut self,
        addr: u32,
        length: u32,
        data: Vec<u8>,
        sig_len: u32,
    ) -> Result<bool> {
        info!(
            "[Penumbra] Uploading DA1 region to address 0x{:08X} with length 0x{:X}",
            addr, length
        );

        self.conn.send_da(&data, length, addr, sig_len).await?;
        info!("[Penumbra] Sent DA1, jumping to address 0x{:08X}...", addr);
        self.conn.jump_da(addr).await?;

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

        let hdr = self.generate_header(&[0u8; 4]);
        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SyncSignal as u32).to_le_bytes()).await?;

        /// We can only set the environment parameters once, and for whatever reason if we set the
        /// log level to DEBUG and try to send EMI settings in BROM mode, the DA hangs. This
        /// appears to be a MediaTek quirk as usual. As a workaround, we always use INFO
        /// level when in BROM mode, even if verbose logging is requested.
        let da_log_level: u32 = if self.verbose
            && self.conn.connection_type != crate::connection::port::ConnectionType::Brom
        {
            1 // DEBUG
        } else {
            2 // INFO
        };

        let mut env_param = Vec::new();
        env_param.extend_from_slice(&da_log_level.to_le_bytes()); // da_log_level
        env_param.extend_from_slice(&1u32.to_le_bytes()); // log_channel = 1 (UART)
        env_param.extend_from_slice(&1u32.to_le_bytes()); // system_os = 1 (OS_LINUX)
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ufs_provision = 0
        env_param.extend_from_slice(&0u32.to_le_bytes()); // ...

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SetupEnvironment as u32).to_le_bytes()).await?;
        self.send(&env_param).await?;

        self.conn.port.write_all(&hdr).await?;
        self.conn.port.write_all(&(Cmd::SetupHwInitParams as u32).to_le_bytes()).await?;
        let hw_param = [0x00, 0x00, 0x00, 0x00];
        self.send(&hw_param).await?;

        status_any!(self, Cmd::SyncSignal as u32);

        info!("[Penumbra] Received DA1 sync signal.");

        self.handle_emi().await?;
        self.devctrl(Cmd::SetChecksumLevel, Some(&[&0u32.to_le_bytes()])).await?;

        Ok(true)
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

    // This is an internal helper, do not use it directly
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

    pub(super) fn generate_header(&self, data: &[u8]) -> [u8; 12] {
        let mut hdr = [0u8; 12];

        // efeeeefe | 010000000 | 04000000 (Data Length)
        hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());

        debug!("[TX] Data Header: {:02X?}, Data Length: {}", hdr, data.len());

        hdr
    }

    pub(super) fn parse_header(&self, hdr: &[u8; 12]) -> Result<u32> {
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

        if magic != Cmd::Magic as u32 {
            return Err(Error::io("Invalid magic"));
        }

        debug!("[RX] Data Length from Header: 0x{:X}", len);

        Ok(len)
    }

    async fn handle_emi(&mut self) -> Result<()> {
        let conn_agent = self.devctrl(Cmd::GetConnectionAgent, None).await?;

        // If the connection agent is "preloader", there's no need to upload EMI settings
        if conn_agent == b"preloader" {
            return Ok(());
        }

        let pl = self
            .pl
            .as_ref()
            .ok_or_else(|| Error::penumbra("Device is in BROM but no preloader was provided!"))?;

        let emi = extract_emi_settings(pl)
            .ok_or_else(|| Error::penumbra("Failed to extract EMI settings from preloader!"))?;

        info!("[Penumbra] Uploading EMI settings to device...");
        self.send_cmd(Cmd::InitExtRam).await?;
        self.send_data(&[&(emi.len() as u32).to_le_bytes(), emi.as_slice()]).await?;
        info!("[Penumbra] EMI settings uploaded successfully.");

        Ok(())
    }

    pub(super) async fn handle_sla(&mut self) -> Result<bool> {
        let resp = match self.devctrl(Cmd::SlaEnabledStatus, None).await {
            Ok(r) => r,
            Err(_) => {
                // The CMD might not be supported on some devices, so we just assume SLA is disabled
                return Ok(true);
            }
        };

        let sla_enabled = u32::from_le_bytes(resp[0..4].try_into().unwrap()) != 0;

        if !sla_enabled {
            return Ok(true);
        }

        info!("DA SLA is enabled");

        let da2_data = match self.da.get_da2() {
            Some(da2) => da2.data.clone(),
            None => Vec::new(),
        };

        let auth = AuthManager::get();
        if !auth.can_sign(&da2_data) {
            #[cfg(not(feature = "no_exploits"))]
            {
                info!("No available signers for DA SLA, trying dummy signature...");
                let dummy_sig = vec![0u8; 256];
                if self.devctrl(Cmd::SetRemoteSecPolicy, Some(&[&dummy_sig])).await.is_ok() {
                    info!("DA SLA signature accepted (dummy)!");
                    return Ok(true);
                }
            }

            error!("No signer available for DA SLA! Can't proceed.");
            return Err(Error::penumbra(
                "DA SLA is enabled, but no signer is available. Can't continue.",
            ));
        }

        let firmware_info = self.devctrl(Cmd::GetDevFwInfo, None).await?;
        debug!("Firmware Info: {:02X?}", firmware_info);
        let rnd = &firmware_info[4..4 + 0x10];
        let hrid = &firmware_info[4 + 0x10..4 + 0x10 + 16];
        let soc_id = &firmware_info[4 + 0x10 + 16..4 + 0x10 + 16 + 32];

        let sign_data = SignData {
            rnd: rnd.to_vec(),
            hrid: hrid.to_vec(),
            soc_id: soc_id.to_vec(),
            raw: firmware_info.to_vec(),
        };
        let sign_req =
            SignRequest { data: sign_data, purpose: SignPurpose::DaSla, pubk_mod: da2_data };

        info!("Found signer for DA SLA!");
        let signed_rnd = auth.sign(&sign_req).await?;
        info!("Signed DA SLA challenge. Uploading to device...");
        self.devctrl(Cmd::SetRemoteSecPolicy, Some(&[&signed_rnd])).await?;
        info!("DA SLA signature accepted!");
        Ok(true)
    }
}
