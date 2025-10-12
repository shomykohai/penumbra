/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::connection::port::{ConnectionType, KNOWN_PORTS, MTKPort};
use crate::error::{Error, Result};
use log::{error, info};
// use std::io::{Error, ErrorKind};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::{
    SerialPort, SerialPortBuilderExt, SerialPortInfo, SerialPortType, SerialStream,
};

#[derive(Debug)]
pub struct SerialMTKPort {
    port: Option<SerialStream>,
    port_info: SerialPortInfo,
    baudrate: u32,
    connection_type: ConnectionType,
    is_open: bool,
}

impl SerialMTKPort {
    pub fn new(port_info: SerialPortInfo, baudrate: u32, connection_type: ConnectionType) -> Self {
        Self {
            port: None,
            port_info,
            baudrate,
            connection_type,
            is_open: false,
        }
    }

    pub fn from_port_info(port_info: SerialPortInfo) -> Option<Self> {
        let connection_type = match &port_info.port_type {
            SerialPortType::UsbPort(usb_info) => match (usb_info.vid, usb_info.pid) {
                (0x0e8d, 0x0003) => ConnectionType::Brom,
                (0x0e8d, 0x2000) => ConnectionType::Preloader,
                (0x0e8d, 0x2001) => ConnectionType::Da,
                _ => {
                    error!(
                        "Unknown MTK port type: {:04x}:{:04x}",
                        usb_info.vid, usb_info.pid
                    );
                    return None;
                }
            },
            _ => {
                error!("Not a USB serial port");
                return None;
            }
        };

        let baudrate: u32 = match connection_type {
            ConnectionType::Brom => 115_200,
            ConnectionType::Preloader | ConnectionType::Da => 921_600,
        };

        Some(SerialMTKPort::new(port_info, baudrate, connection_type))
    }
}

#[async_trait::async_trait]
impl MTKPort for SerialMTKPort {
    async fn open(&mut self) -> Result<()> {
        if !self.is_open {
            self.port = Some(
                tokio_serial::new(&self.port_info.port_name, self.baudrate)
                    .timeout(Duration::from_millis(1000))
                    .open_native_async()
                    .map_err(|e| Error::io(e.to_string()))?,
            );
            self.is_open = true;
            info!(
                "Opened MTK serial port: {} with baudrate {}",
                self.port_info.port_name, self.baudrate
            );
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        if self.is_open {
            self.port.take();
            self.is_open = false;
        }
        Ok(())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(port) = &mut self.port {
            port.read_exact(buf)
                .await
                .map_err(|e| Error::Io(e.to_string()))
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if let Some(port) = &mut self.port {
            port.write_all(buf)
                .await
                .map_err(|e| Error::Io(e.to_string()))
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    async fn flush(&mut self) -> Result<()> {
        if let Some(port) = &mut self.port {
            port.clear(tokio_serial::ClearBuffer::Input)
                .map_err(|e| Error::Io(e.to_string()));
            Ok(())
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    async fn handshake(&mut self) -> Result<()> {
        if let Some(port) = &mut self.port {
            loop {
                port.write_all(&[0xA0]).await?;

                let mut response = [0u8; 1];
                match port.read_exact(&mut response).await {
                    Ok(_) if response[0] == 0x5F => break,
                    Ok(_) | Err(_) => {
                        info!("Received byte: 0x{:02X}", response[0]);
                    }
                }
            }

            port.write_all(&[0x0A]).await?;
            let mut r1 = [0u8; 1];
            port.read_exact(&mut r1).await?;
            if r1 != [0xF5] {
                return Err(Error::io("Handshake failed: Expected 0xF5"));
            }

            port.write_all(&[0x50]).await?;
            let mut r2 = [0u8; 1];
            port.read_exact(&mut r2).await?;
            if r2 != [0xAF] {
                return Err(Error::io("Handshake failed: Expected 0xAF"));
            }

            port.write_all(&[0x05]).await?;
            let mut r3 = [0u8; 1];
            port.read_exact(&mut r3).await?;
            if r3 != [0xFA] {
                return Err(Error::io("Handshake failed: Expected 0xFA"));
            }

            Ok(())
        } else {
            Err(Error::io("Port is not open"))
        }
    }

    fn get_connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    fn get_baudrate(&self) -> u32 {
        self.baudrate
    }

    fn get_port_name(&self) -> String {
        self.port_info.port_name.clone()
    }
}

pub fn find_mtk_serial_ports() -> Vec<SerialPortInfo> {
    match serialport::available_ports() {
        Ok(ports) => ports
            .into_iter()
            .filter(|p| match &p.port_type {
                SerialPortType::UsbPort(usb_info) => KNOWN_PORTS
                    .iter()
                    .any(|(vid, pid)| usb_info.vid == *vid && usb_info.pid == *pid),
                _ => false,
            })
            .collect(),
        Err(e) => {
            error!("Error listing serial ports: {}", e);
            vec![]
        }
    }
}
