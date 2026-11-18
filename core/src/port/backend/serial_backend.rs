/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use std::fmt;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use log::error;
#[cfg(all(feature = "nusb", not(windows)))]
use nusb::MaybeFuture;
#[cfg(all(feature = "nusb", not(windows)))]
use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient};
use serialport::{ClearBuffer, SerialPort, SerialPortInfo, SerialPortType};

use crate::error::{ConnectionError, Error, Result};
use crate::port::{
    ConnectionType,
    KNOWN_PORTS,
    MAX_TIMEOUT,
    MIN_TIMEOUT,
    MtkPort,
    PORT_OPEN_TIMEOUT,
    PORT_RETRY_INTERVAL,
};
#[cfg(unix)]
pub type NativeSerial = serialport::TTYPort;
#[cfg(windows)]
pub type NativeSerial = serialport::COMPort;

pub struct SerialMTKPort {
    port_info: SerialPortInfo,
    port: Option<NativeSerial>,
    #[cfg(all(feature = "nusb", not(windows)))]
    ctrl_device: Option<nusb::Device>,
    baudrate: u32,
    conn_type: ConnectionType,
    is_open: bool,
}

impl fmt::Debug for SerialMTKPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SerialMTKPort {{ port_name: {}, is_open: {} }}",
            self.port_info.port_name, self.is_open
        )
    }
}

impl SerialMTKPort {
    pub const fn new(port_info: SerialPortInfo, baudrate: u32, conn_type: ConnectionType) -> Self {
        Self {
            port_info,
            port: None,
            #[cfg(all(feature = "nusb", not(windows)))]
            ctrl_device: None,
            baudrate,
            conn_type,
            is_open: false,
        }
    }

    #[cfg(all(feature = "nusb", not(windows)))]
    const fn parse_ctrl_type(request_type: u8) -> (ControlType, Recipient) {
        let control_type = match (request_type >> 5) & 0b11 {
            0 => ControlType::Standard,
            1 => ControlType::Class,
            2 => ControlType::Vendor,
            _ => ControlType::Standard,
        };

        let recipient = match request_type & 0b11111 {
            0 => Recipient::Device,
            1 => Recipient::Interface,
            2 => Recipient::Endpoint,
            _ => Recipient::Other,
        };

        (control_type, recipient)
    }

    #[cfg(all(feature = "nusb", not(windows)))]
    fn ensure_ctrl_device(&mut self) -> Option<&nusb::Device> {
        if self.ctrl_device.is_none() {
            let SerialPortType::UsbPort(usb_info) = &self.port_info.port_type else {
                return None;
            };
            let devices = nusb::list_devices().wait().ok()?;
            let info = devices
                .into_iter()
                .find(|d| d.vendor_id() == usb_info.vid && d.product_id() == usb_info.pid)?;
            self.ctrl_device = info.open().wait().ok();
        }
        self.ctrl_device.as_ref()
    }

    #[cfg(feature = "libusb")]
    fn libusb_ctrl_handle(&self) -> Option<rusb::DeviceHandle<rusb::Context>> {
        use rusb::UsbContext;

        let SerialPortType::UsbPort(usb_info) = &self.port_info.port_type else {
            return None;
        };
        let context = rusb::Context::new().ok()?;
        let devices = context.devices().ok()?;
        for device in devices.iter() {
            if let Ok(desc) = device.device_descriptor()
                && desc.vendor_id() == usb_info.vid
                && desc.product_id() == usb_info.pid
            {
                return device.open().ok();
            }
        }
        None
    }

    pub fn from_port_info(port_info: &SerialPortInfo) -> Option<Self> {
        let SerialPortType::UsbPort(usb_info) = &port_info.port_type else {
            error!("Not a USB serial port");
            return None;
        };

        let connection_type = KNOWN_PORTS
            .iter()
            .find(|&&(vid, pid, _)| vid == usb_info.vid && pid == usb_info.pid)
            .map(|&(_, _, ct)| ct)
            .unwrap_or(ConnectionType::Preloader);

        let baudrate = match connection_type {
            ConnectionType::Brom => 115_200,
            ConnectionType::Preloader | ConnectionType::Da => 921_600,
        };

        Some(Self::new(port_info.clone(), baudrate, connection_type))
    }

    pub fn find_device(vid: Option<u16>, pid: Option<u16>) -> Result<Option<Self>> {
        let serial_ports = serialport::available_ports().unwrap_or_default();

        for port_info in serial_ports.iter().rev() {
            #[cfg(target_os = "macos")]
            if port_info.port_name.starts_with("/dev/tty.") {
                continue;
            }

            let SerialPortType::UsbPort(usb_info) = &port_info.port_type else {
                continue;
            };

            let dev_vid = usb_info.vid;
            let dev_pid = usb_info.pid;

            if vid.is_none_or(|v| v == dev_vid)
                && pid.is_none_or(|p| p == dev_pid)
                && (vid.is_some() || pid.is_some())
                && let Some(port) = Self::from_port_info(port_info)
            {
                return Ok(Some(port));
            }

            if KNOWN_PORTS.iter().any(|&(k_vid, k_pid, _)| dev_vid == k_vid && dev_pid == k_pid)
                && let Some(port) = Self::from_port_info(port_info)
            {
                return Ok(Some(port));
            }
        }

        Ok(None)
    }
}

impl MtkPort for SerialMTKPort {
    fn open(&mut self) -> Result<()> {
        if self.is_open {
            return Ok(());
        }

        let mut port = {
            let start = Instant::now();

            loop {
                match serialport::new(&self.port_info.port_name, self.baudrate)
                    .timeout(MIN_TIMEOUT)
                    .open_native()
                {
                    Ok(port) => break port,
                    Err(e) => {
                        let should_retry = matches!(
                            e.kind(),
                            serialport::ErrorKind::Io(std::io::ErrorKind::PermissionDenied)
                                | serialport::ErrorKind::NoDevice
                        );
                        if !should_retry || start.elapsed() >= PORT_OPEN_TIMEOUT {
                            return Err(ConnectionError::OpenFailed(e.to_string()).into());
                        }

                        std::thread::sleep(PORT_RETRY_INTERVAL);
                    }
                }
            }
        };

        if self.conn_type != ConnectionType::Brom {
            let _ = port.write_data_terminal_ready(true);
            let _ = port.write_request_to_send(true);
        }

        self.port = Some(port);
        self.is_open = true;

        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if !self.is_open {
            return Ok(());
        }

        if let Some(port) = self.port.take() {
            port.clear(ClearBuffer::All)?;
            drop(port);
        }

        #[cfg(all(feature = "nusb", not(windows)))]
        {
            self.ctrl_device = None;
        }

        self.is_open = false;

        Ok(())
    }

    fn reenumerate(&mut self, vid: u16, pid: u16) -> Result<()> {
        self.close()?;

        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(200);

        while start.elapsed() < MAX_TIMEOUT {
            if let Ok(ports) = serialport::available_ports()
                && let Some(found_port) = ports.into_iter().find(|p| {
                    #[cfg(target_os = "macos")]
                    if p.port_name.starts_with("/dev/tty.") {
                        return false;
                    }
                    if let SerialPortType::UsbPort(usb_info) = &p.port_type {
                        usb_info.vid == vid && usb_info.pid == pid
                    } else {
                        false
                    }
                })
                && let Some(port) = Self::from_port_info(&found_port)
            {
                *self = port;
                return self.open();
            }
            std::thread::sleep(poll_interval);
        }

        Err(Error::Connection(ConnectionError::Timeout))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        let port = self.port.as_mut().ok_or(Error::Connection(ConnectionError::PortNotOpen))?;

        match port.read_exact(buf) {
            Ok(()) => Ok(buf.len()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err(Error::Timeout),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let port = self.port.as_mut().ok_or(Error::Connection(ConnectionError::PortNotOpen))?;

        match port.write_all(buf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err(Error::Timeout),
            Err(e) => Err(Error::Io(e)),
        }
    }

    fn flush(&mut self) -> Result<()> {
        let port = self.port.as_mut().ok_or(Error::Connection(ConnectionError::PortNotOpen))?;

        port.clear(ClearBuffer::Input).map_err(|e| Error::Io(std::io::Error::other(e)))?;

        Ok(())
    }

    fn get_baudrate(&self) -> u32 {
        self.baudrate
    }

    fn get_port_name(&self) -> String {
        self.port_info.port_name.clone()
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        let port = self.port.as_mut().ok_or(Error::Connection(ConnectionError::PortNotOpen))?;

        port.set_timeout(timeout).map_err(|e| Error::Io(e.into()))?;
        Ok(())
    }

    fn get_timeout(&self) -> Duration {
        let port = self.port.as_ref().ok_or(Error::Connection(ConnectionError::PortNotOpen));

        port.map_or(MIN_TIMEOUT, |p| p.timeout())
    }

    fn connection_type(&self) -> ConnectionType {
        self.conn_type
    }

    fn set_connection_type(&mut self, connection_type: ConnectionType) -> Result<()> {
        self.conn_type = connection_type;
        Ok(())
    }

    #[allow(unused_variables)]
    fn ctrl_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()> {
        #[cfg(all(feature = "nusb", not(windows)))]
        if let Some(dev) = self.ensure_ctrl_device() {
            let (control_type, recipient) = Self::parse_ctrl_type(request_type);
            if dev
                .control_out(
                    ControlOut { control_type, recipient, request, value, index, data },
                    Duration::from_secs(1),
                )
                .wait()
                .is_ok()
            {
                return Ok(());
            }
        }

        #[cfg(feature = "libusb")]
        if let Some(handle) = self.libusb_ctrl_handle()
            && handle
                .write_control(request_type, request, value, index, data, Duration::from_secs(1))
                .is_ok()
        {
            return Ok(());
        }

        Err(Error::Connection(ConnectionError::CtrlTransferOutFailed))
    }

    #[allow(unused_variables)]
    fn ctrl_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        len: usize,
    ) -> Result<Vec<u8>> {
        #[cfg(all(feature = "nusb", not(windows)))]
        if let Some(dev) = self.ensure_ctrl_device() {
            let (control_type, recipient) = Self::parse_ctrl_type(request_type);
            if let Ok(buf) = dev
                .control_in(
                    ControlIn {
                        control_type,
                        recipient,
                        request,
                        value,
                        index,
                        length: len as u16,
                    },
                    Duration::from_secs(1),
                )
                .wait()
            {
                return Ok(buf);
            }
        }

        #[cfg(feature = "libusb")]
        if let Some(handle) = self.libusb_ctrl_handle() {
            let mut buf = vec![0u8; len];
            if let Ok(n) = handle.read_control(
                request_type,
                request,
                value,
                index,
                &mut buf,
                Duration::from_secs(1),
            ) {
                buf.truncate(n);
                return Ok(buf);
            }
        }

        Err(Error::Connection(ConnectionError::CtrlTransferInFailed))
    }
}
