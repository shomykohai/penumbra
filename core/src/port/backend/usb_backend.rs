/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use std::fmt;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

use log::debug;
use nusb::descriptors::TransferType;
use nusb::io::{EndpointRead, EndpointWrite};
use nusb::transfer::{Bulk, ControlIn, ControlOut, ControlType, Direction, In, Out, Recipient};
use nusb::{Device, DeviceInfo, Interface, MaybeFuture};

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

pub struct UsbMTKPort {
    info: DeviceInfo,
    device: Option<Device>,
    ctrl_num: u8,
    interface: Option<Interface>,
    ctrl_interface: Option<Interface>,
    reader: Option<EndpointRead<Bulk>>,
    writer: Option<EndpointWrite<Bulk>>,
    ep_out: u8,
    ep_in: u8,
    in_max_packet_size: usize,
    out_max_packet_size: usize,
    conn_type: ConnectionType,
    is_open: bool,
    timeout: Duration,
}

impl fmt::Debug for UsbMTKPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UsbMTKPort {{ info: {:?}, is_open: {} }}", self.info, self.is_open)
    }
}

impl UsbMTKPort {
    const BULK_IN_SZ: usize = 0x80000;
    const BULK_OUT_SZ: usize = 0x80000;

    pub const fn new(info: DeviceInfo, conn_type: ConnectionType) -> Self {
        Self {
            info,
            device: None,
            ctrl_num: 0,
            interface: None,
            ctrl_interface: None,
            writer: None,
            reader: None,
            ep_out: 0,
            ep_in: 0,
            in_max_packet_size: 0,
            out_max_packet_size: 0,
            conn_type,
            is_open: false,
            timeout: MIN_TIMEOUT,
        }
    }

    fn select_endpoints(&mut self, iface: &Interface) -> Result<()> {
        for alt in iface.descriptors() {
            let mut in_ep = None;
            let mut out_ep = None;

            for ep in alt.endpoints() {
                if !matches!(ep.transfer_type(), TransferType::Bulk) {
                    continue;
                }

                match ep.direction() {
                    Direction::In => {
                        in_ep = Some(ep.address());
                        self.in_max_packet_size = ep.max_packet_size();
                    }
                    Direction::Out => {
                        out_ep = Some(ep.address());
                        self.out_max_packet_size = ep.max_packet_size();
                    }
                }
            }

            if let (Some(i), Some(o)) = (in_ep, out_ep) {
                self.ep_in = i;
                self.ep_out = o;
                return Ok(());
            }
        }

        Err(Error::Connection(ConnectionError::InterfaceNotFound))
    }

    fn control_out(
        &self,
        data: ControlOut,
        timeout: Duration,
    ) -> std::result::Result<(), nusb::transfer::TransferError> {
        match (&self.ctrl_interface, &self.device) {
            (Some(iface), _) => iface.control_out(data, timeout).wait(),
            #[cfg(not(windows))]
            (None, Some(dev)) => dev.control_out(data, timeout).wait(),
            _ => Err(nusb::transfer::TransferError::Disconnected),
        }
    }

    fn control_in(
        &self,
        data: ControlIn,
        timeout: Duration,
    ) -> std::result::Result<Vec<u8>, nusb::transfer::TransferError> {
        match (&self.ctrl_interface, &self.device) {
            (Some(iface), _) => iface.control_in(data, timeout).wait(),
            #[cfg(not(windows))]
            (None, Some(dev)) => dev.control_in(data, timeout).wait(),
            _ => Err(nusb::transfer::TransferError::Disconnected),
        }
    }

    fn setup_cdc(&self) -> Result<()> {
        // The control interface the device declares, not necessarily 0.
        let cdc_interface_num = self.ctrl_num as u16;
        const SET_LINE_CODING: u8 = 0x20;
        const SET_CONTROL_LINE_STATE: u8 = 0x22;
        const LINE_CODING: [u8; 7] = [0x00, 0x10, 0x0E, 0x00, 0x00, 0x00, 0x08];
        const CONTROL_LINE_STATE: u16 = 0x03; // DTR | RTS

        self.control_out(
            ControlOut {
                control_type: ControlType::Class,
                recipient: Recipient::Interface,
                request: SET_LINE_CODING,
                value: 0,
                index: cdc_interface_num,
                data: &LINE_CODING,
            },
            MIN_TIMEOUT,
        )
        .map_err(|_| ConnectionError::CdcSetupFailed)?;

        self.control_out(
            ControlOut {
                control_type: ControlType::Class,
                recipient: Recipient::Interface,
                request: SET_CONTROL_LINE_STATE,
                value: CONTROL_LINE_STATE,
                index: cdc_interface_num,
                data: &[],
            },
            MIN_TIMEOUT,
        )
        .map_err(|_| ConnectionError::CdcSetupFailed)?;

        debug!("CDC Setup complete");
        Ok(())
    }

    /*
     * Some devices don't have the bulk iface on 1, but on 0, so we gotta adapt!!
     */
    fn find_cdc_interface_numbers(device: &Device) -> Result<(u8, u8)> {
        let settings: Vec<(u8, u8)> = device
            .configurations()
            .flat_map(|c| c.interfaces())
            .flat_map(|i| {
                i.alt_settings().map(|a| (a.class(), a.interface_number())).collect::<Vec<_>>()
            })
            .collect();

        let ctrl_num = settings.iter().find(|(class, _)| *class == 2).map(|(_, n)| *n);
        let bulk_num = settings.iter().find(|(class, _)| *class == 10).map(|(_, n)| *n);

        match (ctrl_num, bulk_num) {
            (Some(c), Some(b)) => Ok((c, b)),
            _ => Err(Error::Connection(ConnectionError::InterfaceNotFound)),
        }
    }
}

impl MtkPort for UsbMTKPort {
    fn open(&mut self) -> Result<()> {
        if self.is_open {
            return Ok(());
        }

        let device = {
            let start = Instant::now();

            loop {
                match self.info.open().wait() {
                    Ok(handle) => break handle,
                    Err(e) => {
                        if e.kind() != nusb::ErrorKind::PermissionDenied
                            || start.elapsed() >= PORT_OPEN_TIMEOUT
                        {
                            return Err(ConnectionError::OpenFailed(e.to_string()).into());
                        }

                        std::thread::sleep(PORT_RETRY_INTERVAL);
                    }
                }
            }
        };

        let (ctrl_num, bulk_num) = Self::find_cdc_interface_numbers(&device)?;

        self.ctrl_interface = match device.detach_and_claim_interface(ctrl_num).wait() {
            Ok(i) => Some(i),
            Err(e) => {
                debug!("CDC control interface {ctrl_num} not claimed ({e})");
                None
            }
        };
        self.ctrl_num = ctrl_num;
        let bulk_iface = device.detach_and_claim_interface(bulk_num).wait()?;

        self.select_endpoints(&bulk_iface)?;

        self.reader = Some(
            bulk_iface
                .endpoint::<Bulk, In>(self.ep_in)?
                .reader(Self::BULK_IN_SZ)
                .with_read_timeout(MIN_TIMEOUT),
        );

        self.writer = Some(
            bulk_iface
                .endpoint::<Bulk, Out>(self.ep_out)?
                .writer(Self::BULK_OUT_SZ)
                .with_write_timeout(MIN_TIMEOUT),
        );

        self.interface = Some(bulk_iface);
        self.device = Some(device);

        if self.conn_type != ConnectionType::Brom
            && let Err(e) = self.setup_cdc()
        {
            debug!("CDC Setup failed (may be ok): {:?}", e);
        }

        self.is_open = true;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if !self.is_open {
            return Ok(());
        }

        // NUSB automatically releases interfaces on drop
        self.reader = None;
        self.writer = None;
        self.interface = None;
        self.ctrl_interface = None;
        self.device = None;
        self.is_open = false;

        Ok(())
    }

    fn reenumerate(&mut self, vid: u16, pid: u16) -> Result<()> {
        self.close()?;

        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(200);

        let conn_type = KNOWN_PORTS
            .iter()
            .find(|&&(k_vid, k_pid, _)| k_vid == vid && k_pid == pid)
            .map(|&(_, _, ct)| ct)
            .unwrap_or(self.conn_type);

        while start.elapsed() < MAX_TIMEOUT {
            if let Ok(devices) = nusb::list_devices().wait()
                && let Some(dev) =
                    devices.into_iter().find(|d| d.vendor_id() == vid && d.product_id() == pid)
            {
                self.info = dev;
                self.conn_type = conn_type;
                if self.open().is_ok() {
                    return Ok(());
                }
            }

            std::thread::sleep(poll_interval);
        }

        Err(Error::Connection(ConnectionError::Timeout))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        let reader = self.reader.as_mut().ok_or(ConnectionError::PortNotOpen)?;

        match reader.read_exact(buf) {
            Ok(()) => Ok(buf.len()),
            // Error::Timeout, not ConnectionError::Timeout: the libusb and serial
            // backends already report I/O timeouts that way, and code that has to
            // tell a timeout apart from a real failure only matches the one
            // variant. ConnectionError::Timeout stays for enumeration timeouts.
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err(Error::Timeout),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let writer = self.writer.as_mut().ok_or(ConnectionError::PortNotOpen)?;

        match writer.write_all(buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(Error::Timeout),
            Err(e) => return Err(Error::from(e)),
        }

        match writer.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err(Error::Timeout),
            Err(e) => Err(Error::from(e)),
        }
    }

    /// USB doesn't need flushing
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_baudrate(&self) -> u32 {
        0
    }

    fn get_port_name(&self) -> String {
        format!("USB {:04X}:{:04X}", self.info.vendor_id(), self.info.product_id())
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        let writer = self.writer.as_mut().ok_or(ConnectionError::PortNotOpen)?;
        let reader = self.reader.as_mut().ok_or(ConnectionError::PortNotOpen)?;

        reader.set_read_timeout(timeout);
        writer.set_write_timeout(timeout);

        self.timeout = timeout;

        Ok(())
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn connection_type(&self) -> ConnectionType {
        self.conn_type
    }

    fn set_connection_type(&mut self, connection_type: ConnectionType) -> Result<()> {
        self.conn_type = connection_type;
        Ok(())
    }

    fn ctrl_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<()> {
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

        self.control_out(
            ControlOut { control_type, recipient, request, value, index, data },
            Duration::from_secs(1),
        )
        .map_err(|_| ConnectionError::CtrlTransferOutFailed)?;

        Ok(())
    }

    fn ctrl_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        len: usize,
    ) -> Result<Vec<u8>> {
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

        let buf = self
            .control_in(
                ControlIn { control_type, recipient, request, value, index, length: len as u16 },
                Duration::from_secs(1),
            )
            .map_err(|_| ConnectionError::CtrlTransferInFailed)?;

        Ok(buf)
    }
}

impl UsbMTKPort {
    pub fn find_device(vid: Option<u16>, pid: Option<u16>) -> Result<Option<Self>> {
        let devices = nusb::list_devices().wait()?;

        for device in devices {
            let dev_vid = device.vendor_id();
            let dev_pid = device.product_id();

            if vid.is_none_or(|v| v == dev_vid)
                && pid.is_none_or(|p| p == dev_pid)
                && (vid.is_some() || pid.is_some())
            {
                return Ok(Some(Self::new(device, ConnectionType::Preloader)));
            }

            if let Some((_, _, conn)) =
                KNOWN_PORTS.iter().find(|(k_vid, k_pid, _)| dev_vid == *k_vid && dev_pid == *k_pid)
            {
                return Ok(Some(Self::new(device, conn.to_owned())));
            }
        }

        Ok(None)
    }
}
