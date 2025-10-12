/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::connection::port::{ConnectionType, KNOWN_PORTS, MTKPort};
use crate::error::{Error, Result};
use log::{debug, error, info};
use rusb::{Context, Device, DeviceHandle, GlobalContext, UsbContext};
use rusb::{Direction, Recipient, RequestType};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;

#[derive(Debug, Clone)]
pub struct UsbMTKPort {
    handle: Arc<Mutex<DeviceHandle<Context>>>,
    baudrate: u32,
    connection_type: ConnectionType,
    is_open: bool,
    port_name: String,
    in_endpoint: u8,
    out_endpoint: u8,
    in_max_packet_size: usize,
    out_max_packet_size: usize,
    vid: u16,
    pid: u16,
}

impl UsbMTKPort {
    pub fn new(
        handle: DeviceHandle<Context>,
        connection_type: ConnectionType,
        port_name: String,
        baudrate: u32,
        in_endpoint: u8,
        out_endpoint: u8,
        in_max_packet_size: usize,
        out_max_packet_size: usize,
        vid: u16,
        pid: u16,
    ) -> Self {
        Self {
            handle: Arc::new(Mutex::new(handle)),
            baudrate,
            connection_type,
            is_open: false,
            port_name,
            in_endpoint,
            out_endpoint,
            in_max_packet_size,
            out_max_packet_size,
            vid,
            pid,
        }
    }

    // This just serve the purpose of finding bEndpointAddress for bulk IN and OUT, as well
    // as their max packet sizes.
    fn find_bulk_endpoints(device: &Device<Context>) -> Option<(u8, usize, u8, usize)> {
        let config = device.active_config_descriptor().ok()?;
        let mut in_ep = None;
        let mut in_sz = None;
        let mut out_ep = None;
        let mut out_sz = None;

        for interface in config.interfaces() {
            for interface_desc in interface.descriptors() {
                for endpoint in interface_desc.endpoint_descriptors() {
                    if endpoint.transfer_type() == rusb::TransferType::Bulk {
                        match endpoint.direction() {
                            rusb::Direction::In if in_ep.is_none() => {
                                in_ep = Some(endpoint.address());
                                in_sz = Some(endpoint.max_packet_size() as usize);
                            }
                            rusb::Direction::Out if out_ep.is_none() => {
                                out_ep = Some(endpoint.address());
                                out_sz = Some(endpoint.max_packet_size() as usize);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Some((in_ep?, in_sz?, out_ep?, out_sz?))
    }

    pub async fn setup_cdc(&self) -> Result<()> {
        let handle = self.handle.clone();

        task::spawn_blocking(move || -> Result<()> {
            let handle = handle.blocking_lock();

            const CDC_INTERFACE: u16 = 1;
            const SET_LINE_CODING: u8 = 0x20;
            const SET_CONTROL_LINE_STATE: u8 = 0x22;
            const LINE_CODING: [u8; 7] = [0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x08];
            const CONTROL_LINE_STATE: u16 = 0x03;

            let request_type =
                rusb::request_type(Direction::Out, RequestType::Class, Recipient::Interface);

            handle
                .write_control(
                    request_type,
                    SET_LINE_CODING,
                    0,
                    CDC_INTERFACE,
                    &LINE_CODING,
                    Duration::from_millis(100),
                )
                .ok();

            handle
                .write_control(
                    request_type,
                    SET_CONTROL_LINE_STATE,
                    CONTROL_LINE_STATE,
                    CDC_INTERFACE,
                    &[],
                    Duration::from_millis(100),
                )
                .ok();

            Ok(())
        })
        .await?
    }

    pub fn from_device(device: Device<Context>) -> Option<Self> {
        let descriptor = device.device_descriptor().ok()?;
        let (vid, pid) = (descriptor.vendor_id(), descriptor.product_id());

        let connection_type = match (vid, pid) {
            (0x0e8d, 0x0003) => ConnectionType::Brom,
            (0x0e8d, 0x2000) => ConnectionType::Preloader,
            (0x0e8d, 0x2001) => ConnectionType::Da,
            _ => return None,
        };

        let baudrate = match connection_type {
            ConnectionType::Brom => 115_200,
            ConnectionType::Preloader | ConnectionType::Da => 921_600,
        };

        let port_name = format!("USB:{:04x}:{:04x}", vid, pid);

        let handle = tokio::task::block_in_place(|| device.open().ok())?;

        let (in_endpoint, in_max_packet_size, out_endpoint, out_max_packet_size) =
            Self::find_bulk_endpoints(&device)?;

        Some(Self::new(
            handle,
            connection_type,
            port_name,
            baudrate,
            in_endpoint,
            out_endpoint,
            in_max_packet_size,
            out_max_packet_size,
            vid,
            pid,
        ))
    }
}

#[async_trait::async_trait]
impl MTKPort for UsbMTKPort {
    async fn open(&mut self) -> Result<()> {
        if self.is_open {
            return Ok(());
        }

        let handle = self.handle.clone();
        let port_name = self.port_name.clone();

        // RUSB is sync, so we need to spawn blocking here
        tokio::task::spawn_blocking(move || -> Result<()> {
            let handle = handle.blocking_lock();

            for interface in 0..=1 {
                #[cfg(not(target_os = "windows"))]
                {
                    match handle.kernel_driver_active(interface) {
                        Ok(true) => {
                            if let Err(e) = handle.detach_kernel_driver(interface) {
                                error!(
                                    "Failed to detach kernel driver on interface {}: {:?}",
                                    interface, e
                                );
                                return Err(Error::Io("Failed to detach kernel driver (USB)"));
                            }
                        }
                        Ok(false) => {}
                        Err(e) => {
                            error!(
                                "Error checking kernel driver on interface {}: {:?}",
                                interface, e
                            );
                            return Err(Error::Io("Kernel driver check failed (USB)"));
                        }
                    }
                }

                if let Err(e) = handle.claim_interface(interface) {
                    error!("Failed to claim interface {}: {:?}", interface, e);
                    return Err(Error::Io("Failed to claim interface (USB)"));
                }
            }

            Ok(())
        })
        .await?
        .map_err(|e| Error::Io("USB open task failed"));

        #[cfg(target_os = "windows")]
        {
            if let Err(e) = self.setup_cdc().await {
                debug!("Windows CDC Setup failed!!");
            }
        }

        self.is_open = true;
        info!("Opened USB MTK port: {}", port_name);

        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        if !self.is_open {
            return Ok(());
        }

        let handle = self.handle.clone();
        let port_name = self.port_name.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let handle = handle.blocking_lock();

            for iface in 0..=1 {
                if let Err(e) = handle.release_interface(iface) {
                    error!("Failed to release interface {}: {:?}", iface, e);
                }

                if let Err(e) = handle.attach_kernel_driver(iface) {
                    error!(
                        "Failed to reattach kernel driver on interface {}: {:?}",
                        iface, e
                    );
                }
            }

            Ok(())
        })
        .await
        .unwrap()?;

        self.is_open = false;
        info!("Closed USB MTK port: {}", port_name);

        Ok(())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        let handle = self.handle.clone();
        let endpoint = self.in_endpoint;
        let timeout = Duration::from_millis(5000);

        let mut total_read = 0;
        while total_read < buf.len() {
            let to_read = buf.len() - total_read;
            let mut temp_buf = vec![0u8; to_read];
            let result = tokio::task::spawn_blocking({
                let handle = handle.clone();
                move || {
                    let locked = handle.blocking_lock();
                    match locked.read_bulk(endpoint, &mut temp_buf, timeout) {
                        Ok(n) => Ok((temp_buf, n)),
                        Err(rusb::Error::Timeout) => Err(Error::Io("USB timeout")),
                        Err(e) => Err(Error::io(e.to_string())),
                    }
                }
            })
            .await
            .unwrap()?;

            let (temp_buf, n) = result;
            if n == 0 {
                continue;
            }
            buf[total_read..total_read + n].copy_from_slice(&temp_buf[..n]);
            total_read += n;
        }
        Ok(total_read)
    }

    async fn handshake(&mut self) -> Result<()> {
        let startcmd = [0xA0u8, 0x0A, 0x50, 0x05];
        let mut i = 0;

        while i < startcmd.len() {
            self.write_all(&[startcmd[i]]).await?;

            let handle = self.handle.clone();
            let endpoint = self.in_endpoint;
            let timeout = Duration::from_millis(5000);

            let (response, n) = tokio::task::spawn_blocking(move || {
                let mut response = vec![0u8; 5];
                let locked = handle.blocking_lock();
                match locked.read_bulk(endpoint, &mut response, timeout) {
                    Ok(count) => Ok((response, count)),
                    Err(e) => Err(Error::Io("Bulk read failed")),
                }
            })
            .await
            .map_err(|e| Error::Io("USB bulk read task failed"))?;

            if n == 0 {
                return Err(Error::Io("USB returned 0 bytes"));
            }

            let expected = !startcmd[i] & 0xFF;
            let handshake_byte = response[n - 1];

            if handshake_byte == expected {
                i += 1;
            } else {
                i = 0;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let handle = self.handle.clone();
        let endpoint = self.out_endpoint;
        let timeout = Duration::from_millis(5000);
        let data = buf.to_vec();

        tokio::task::spawn_blocking(move || {
            let locked = handle.blocking_lock();
            let res = locked.write_bulk(endpoint, &data, timeout);
            res.map_err(|e| Error::Io("Bulk write failed"))
        })
        .await
        .unwrap()?;

        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_connection_type(&self) -> ConnectionType {
        self.connection_type.clone()
    }

    fn get_baudrate(&self) -> u32 {
        self.baudrate
    }

    fn get_port_name(&self) -> String {
        self.port_name.clone()
    }
}
