/*
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::connection::port::MTKPort;
use crate::connection::{Connection, port::ConnectionType};
use crate::core::crypto::config::{CryptoConfig, CryptoIO};
use crate::core::crypto::sej::SEJCrypto;
use crate::error::{Error, Result};
use crate::core::seccfg::LockFlag;
use crate::core::seccfg::SecCfgV4;
use crate::core::storage::{Partition, StorageType, parse_gpt};
use crate::da::{DAFile, DAProtocol, DAType, XFlash};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub chipset: String,
    pub soc_id: Vec<u8>,
    pub meid: Vec<u8>,
    pub hw_code: u16,
    pub storage: StorageType,
    pub partitions: Vec<Partition>,
}

pub struct Device<'a> {
    pub dev_info: Option<Arc<Mutex<DeviceInfo>>>,
    connection: Option<Connection>,
    protocol: Option<Box<dyn DAProtocol + 'a + Send>>,
    connected: bool,
}

#[async_trait::async_trait]
impl CryptoIO for Device<'_> {
    async fn read32(&mut self, addr: u32) -> u32 {
        if let Some(protocol) = &mut self.protocol {
            match protocol.read32(addr).await {
                Ok(val) => val,
                Err(e) => {
                    error!("Failed to read32 from protocol at 0x{:08X}: {}", addr, e);
                    0
                }
            }
        } else {
            error!("No protocol available for read32 at 0x{:08X}!", addr);
            0
        }
    }
    async fn write32(&mut self, addr: u32, val: u32) {
        if let Some(protocol) = &mut self.protocol {
            if let Err(e) = protocol.write32(addr, val).await {
                error!("Failed to write32 to protocol at 0x{:08X}: {}", addr, e);
            }
        } else {
            error!("No protocol available for write32 at 0x{:08X}!", addr);
        }
    }
}

impl<'a> Device<'a> {
    pub async fn init(mtk_port: Box<dyn MTKPort>, da_data: Vec<u8>) -> Result<Self> {
        let mut connection = Connection::new(mtk_port);

        connection.handshake().await?;

        let soc_id = connection.get_soc_id().await?;
        let meid = connection.get_meid().await?;
        let hw_code = connection.get_hw_code().await? as u16;

        let device_info = Arc::new(Mutex::new(DeviceInfo {
            soc_id,
            meid,
            hw_code,
            chipset: String::from("Unknown"),
            storage: StorageType::Unknown,
            partitions: vec![],
        }));

        if !da_data.is_empty() {
            let da_file = DAFile::parse_da(&da_data)?;
            let da = match da_file.get_da_from_hw_code(hw_code) {
                Some(da) => da,
                None => {
                    return Err(Error::penumbra(format!(
                        "No suitable DA found for HW code {:02X}",
                        hw_code
                    )));
                }
            };

            info!("Using DA for HW code {:02X}", da.hw_code);

            let protocol: Box<dyn DAProtocol> = match da.da_type {
                DAType::V5 => Box::new(XFlash::new(connection, da, Arc::clone(&device_info))),
                _ => return Err(Error::penumbra("Unsupported DA type!")),
            };

            let device = Device {
                dev_info: Some(device_info),
                protocol: Some(protocol),
                connection: None,
                connected: true,
            };

            Ok(device)
        } else {
            warn!("No Download Agent was provided, only preloader commands will be available.");

            Ok(Device {
                dev_info: Some(device_info),
                protocol: None,
                connection: Some(connection),
                connected: true,
            })
        }
    }

    pub async fn enter_da_mode(&mut self) -> Result<()> {
        if !self.connected {
            return Err(Error::conn("Device not connected"));
        }

        if self.protocol.is_none() {
            return Err(Error::proto("No DA protocol available"));
        }

        let protocol = self.protocol.as_mut().unwrap();
        match protocol.upload_da().await {
            Ok(_) => info!("Successfully entered DA mode"),
            Err(e) => {
                error!("Failed to enter DA mode: {}", e);
                return Err(e);
            }
        }
        protocol.set_connection_type(ConnectionType::Da)?;

        // We don't care about progress here ;D
        let mut progress = |_read: usize, _total: usize| {};
        let pgpt_data = protocol.read_flash(0x0, 0x8000, &mut progress).await?;
        let partitions = parse_gpt(&pgpt_data, StorageType::Emmc)?;

        if let Some(dev_info_rc) = &self.dev_info {
            let mut dev_info = dev_info_rc.lock().await;
            dev_info.partitions = partitions;
            dev_info.storage = StorageType::Emmc; // Assuming eMMC for now
        }

        Ok(())
    }

    pub async fn read_partition(
        &mut self,
        name: &str,
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<Vec<u8>> {
        if self.protocol.is_none() {
            return Err(Error::proto("No DA protocol available"));
        }

        let conn = self.get_connection()?;
        if conn.connection_type != ConnectionType::Da {
            info!("Not in DA mode, entering now");
            self.enter_da_mode().await?;
        }

        let dev_info_rc = match &self.dev_info {
            Some(info) => Arc::clone(info),
            None => return Err(Error::penumbra("Device info not available")),
        };

        let dev_info = dev_info_rc.lock().await;
        let partition = match dev_info.partitions.iter().find(|p| p.name == name) {
            Some(part) => part,
            None => {
                return Err(Error::proto(format!("Partition '{}' not found", name)));
            }
        };

        let protocol = self.protocol.as_mut().unwrap();
        protocol
            .read_flash(partition.address, partition.size, progress)
            .await
    }

    pub async fn write_partition(
        &mut self,
        name: &str,
        data: &[u8],
        progress: &mut (dyn FnMut(usize, usize) + Send),
    ) -> Result<()> {
        if self.protocol.is_none() {
            return Err(Error::proto("No DA protocol available"));
        }

        let conn = self.get_connection()?;
        if conn.connection_type != ConnectionType::Da {
            info!("Not in DA mode, entering now");
            self.enter_da_mode().await?;
        }

        let dev_info_rc = match &self.dev_info {
            Some(info) => Arc::clone(info),
            None => return Err(Error::penumbra("Device info not available")),
        };

        let dev_info = dev_info_rc.lock().await;
        let partition = match dev_info.partitions.iter().find(|p| p.name == name) {
            Some(part) => part,
            None => {
                return Err(Error::proto(format!("Partition '{}' not found", name)));
            }
        };

        if data.len() > partition.size {
            return Err(Error::penumbra(format!(
                "Data size {} exceeds partition size {}",
                data.len(),
                partition.size
            )));
        }

        let protocol = self.protocol.as_mut().unwrap();
        protocol
            .write_flash(partition.address, data.len(), data, progress)
            .await
    }

    pub fn get_connection(&mut self) -> Result<&mut Connection> {
        if let Some(conn) = &mut self.connection {
            Ok(conn)
        } else if let Some(protocol) = &mut self.protocol {
            Ok(protocol.get_connection())
        } else {
            Err(Error::conn("No connection available"))
        }
    }

    pub fn get_protocol(&mut self) -> Option<&mut Box<dyn DAProtocol + 'a + Send>> {
        self.protocol.as_mut()
    }

    pub async fn set_seccfg_lock_state(&mut self, lock_state: LockFlag) -> Option<Vec<u8>> {
        self.protocol.as_ref()?;

        let conn = self.get_connection().ok()?;
        if conn.connection_type != ConnectionType::Da {
            info!("Not in DA mode, entering now");
            self.enter_da_mode().await.ok()?;
        }

        let mut progress = |_read: usize, _total: usize| {};

        let sej_base = 0x1000A000; // TODO: Dynamically determine SEJ base (maybe through preloader)
        let seccfg_raw = self.read_partition("seccfg", &mut progress).await.ok()?;

        let new_seccfg = {
            let mut crypto_config = CryptoConfig::new(sej_base, self);
            let mut sej = SEJCrypto::new(&mut crypto_config);
            let mut seccfg = SecCfgV4::parse(&seccfg_raw, &mut sej).await.ok()?;

            seccfg.create(&mut sej, lock_state).await
        };

        self.write_partition("seccfg", &new_seccfg, &mut progress)
            .await
            .ok()?;
        Some(new_seccfg)
    }
}
