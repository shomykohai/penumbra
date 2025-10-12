/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

use crate::error::Result;
use std::fmt::Debug;

pub const KNOWN_PORTS: &[(u16, u16)] = &[
    (0x0e8d, 0x0003), // Mediatek USB Port (BROM)
    (0x0e8d, 0x2000), // Mediatek USB Port (Preloader)
    (0x0e8d, 0x2001), // Mediatek USB Port (DA)
];

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ConnectionType {
    Brom,
    Preloader,
    Da,
}

#[async_trait::async_trait]
pub trait MTKPort: Send + Debug {
    async fn open(&mut self) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize>;
    async fn write_all(&mut self, buf: &[u8]) -> Result<()>;
    async fn flush(&mut self) -> Result<()>;

    async fn handshake(&mut self) -> Result<()>;
    fn get_connection_type(&self) -> ConnectionType;
    fn get_baudrate(&self) -> u32;
    fn get_port_name(&self) -> String;
}

pub async fn find_mtk_port() -> Option<Box<dyn MTKPort>> {
    #[cfg(not(feature = "libusb"))]
    {
        use crate::connection::backend::serial_backend;
        let serial_ports = serial_backend::find_mtk_serial_ports();
        if !serial_ports.is_empty() {
            if let Some(port) =
                serial_backend::SerialMTKPort::from_port_info(serial_ports[0].clone())
            {
                let mut boxed_port: Box<dyn MTKPort> = Box::new(port);
                if boxed_port.open().await.is_ok() {
                    return Some(boxed_port);
                }
            }
        }
    }

    #[cfg(feature = "libusb")]
    {
        use crate::connection::backend::libusb_backend::UsbMTKPort;
        use rusb::{Context, UsbContext};
        use tokio::task;

        let usb_ports = task::spawn_blocking(|| {
            let context = Context::new().ok()?;
            let devices = context.devices().ok()?;

            let mut found_ports = Vec::new();

            for device_ref in devices.iter() {
                let device = device_ref.clone();
                if let Some(usb_port) = UsbMTKPort::from_device(device) {
                    found_ports.push(usb_port);
                }
            }

            Some(found_ports)
        })
        .await
        .ok()
        .flatten();

        if let Some(mut ports) = usb_ports {
            for usb_port in ports.drain(..) {
                let mut boxed_port: Box<dyn MTKPort> = Box::new(usb_port);
                if boxed_port.open().await.is_ok() {
                    return Some(boxed_port);
                }
            }
        }
    }

    None
}
