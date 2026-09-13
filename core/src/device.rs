/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use acon::{MMIO, SoC};
#[cfg(feature = "exploits")]
use hacc::LockState;
use hacc::gfh::{GfhFile, GfhKind, GfhType};
use hacc::{
    BootControl,
    BootControlError,
    Da,
    DaEntry,
    DaVersion,
    OFFSET_SLOT_SUFFIX,
    Preloader,
    TryRead,
};
use log::{info, warn};

use crate::activity::DeviceActivity;
#[cfg(feature = "exploits")]
use crate::da::extensions::{KeyDeriveId, KeySize};
use crate::da::*;
use crate::devinfo::{DevInfo, DevInfoData};
use crate::error::{ConnectionError, PenumbraError};
use crate::log_buffer::DeviceLog;
use crate::port::{ConnectionType, MtkPort};
use crate::preloader::PlProtocol;
use crate::storage::PartitionKind;
use crate::traits::{ProgressCallback, Reader, ReaderSource, Writer, WriterSink};
use crate::{Error, Partition, Result, StorageKind};

/// A builder for creating a new [`Device`].
///
/// This struct allows for configuring various parameters before constructing the device instance.
/// You can optionally (mas recommended) provide DA data to enable DA protocol support.
/// When no DA data is provided, only preloader commands will be available, limiting functionality.
/// A MtkPort must be provided to build the device.
///
/// # Example
/// ```no_run
/// use penumbra_mtk::{Device, DeviceBuilder, port::{PortType, PortBackend}};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let vid = Some(0x0E8D);
/// let pid = Some(0x2000);
/// // Finds a Port filtered by VID and PID, and automatically selects the backend (USB, Serial or LibUsb)
/// let port = PortType::find_device(vid, pid, PortBackend::Auto).expect("Port should open").ok_or("No MTK port found")?;
/// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
/// let device =
///     DeviceBuilder::new(port).with_da_data(&da_data).build()?;
///
/// Ok(())
/// # }
/// ```
pub struct DeviceBuilder<'a, P: MtkPort> {
    /// MTK port to use during connection. It can be either a serial port or a USB port.
    /// This field is required to build a Device.
    mtk_port: P,
    /// DA data to use for the device. This field is optional, but recommended.
    /// If not provided, the device will not be able to use DA protocol, and instead
    /// Only preloader commands will be available.
    da_data: Option<&'a [u8]>,
    /// Preloader data to use for the device. This field is optional.
    /// If provided, it can be used to extract EMI settings or other information.
    /// Only needed if told to do so, like when the device is in BROM mode.
    preloader_data: Option<&'a [u8]>,
    /// Authentication data for DAA enabled devices. This field is optional.
    /// If the device has DAA enabled and is in BROM mode, this data will be
    /// sent during initialization to be able to load the DA.
    auth_data: Option<&'a [u8]>,
    /// Whether to enable verbose logging.
    da_log_level: DaLogLevel,
    /// Whether to use USB as the DA log channel instead of UART.
    /// When enabled, DA log messages are captured into a [`DeviceLog`] buffer
    /// instead of being sent over UART.
    usb_log_channel: bool,
    /// A buffer to store DA log messages when `usb_log_channel` is enabled.
    /// This allows for capturing logs from devices without needing UART.
    device_log: Option<DeviceLog>,
    activity: Option<DeviceActivity>,
}

impl<'a, P: MtkPort> DeviceBuilder<'a, P> {
    /// Assigns the MTK port to be used for the device connection.
    pub const fn new(port: P) -> Self {
        Self {
            mtk_port: port,
            da_data: None,
            preloader_data: None,
            auth_data: None,
            da_log_level: DaLogLevel::Info,
            usb_log_channel: false,
            device_log: None,
            activity: None,
        }
    }

    /// Assigns the DA data to be used for the device.
    pub const fn with_da_data(mut self, data: &'a [u8]) -> Self {
        self.da_data = Some(data);
        self
    }

    /// Assigns the preloader data to be used for the device.
    pub const fn with_preloader(mut self, data: &'a [u8]) -> Self {
        self.preloader_data = Some(data);
        self
    }

    /// Assigns the authentication data for DAA enabled devices.
    pub const fn with_auth(mut self, data: &'a [u8]) -> Self {
        self.auth_data = Some(data);
        self
    }

    /// Enables verbose logging mode.
    pub const fn with_log_level(mut self, level: DaLogLevel) -> Self {
        self.da_log_level = level;
        self
    }

    /// Enable USB logging
    pub const fn with_usb_log_channel(mut self, enabled: bool) -> Self {
        self.usb_log_channel = enabled;
        self
    }

    /// Assigns a [`DeviceLog`] buffer to capture DA log messages
    /// when `usb_log_channel` is enabled.
    /// This allows to attach an optional Callback to the log buffer
    /// (i.e. to save to a file).
    pub fn with_device_log(mut self, log: DeviceLog) -> Self {
        self.device_log = Some(log);
        self
    }

    pub fn with_activity(mut self, activity: DeviceActivity) -> Self {
        self.activity = Some(activity);
        self
    }

    /// Builds and returns a new `Device` instance.
    pub fn build(self) -> Result<Device<'a, P>> {
        let device_log = self.device_log.unwrap_or_default();

        let da = match self.da_data {
            Some(data) => Some(Da::try_read(data)?),
            None => None,
        };
        let pl = match self.preloader_data {
            Some(data) => Some(Preloader::try_read(data)?),
            None => None,
        };

        Ok(Device {
            da,
            pl,
            port: self.mtk_port,
            da_log_level: self.da_log_level,
            devinfo: DevInfo::default(),
            protocol: None,
            connected: false,
            auth_data: self.auth_data,
            usb_log_channel: self.usb_log_channel,
            device_log,
            activity: self.activity.unwrap_or_default(),
        })
    }
}

pub struct Device<'a, P: MtkPort> {
    port: P,
    da: Option<Da<'a>>,
    pl: Option<Preloader<'a>>,
    auth_data: Option<&'a [u8]>,
    devinfo: DevInfo,
    da_log_level: DaLogLevel,
    usb_log_channel: bool,
    device_log: DeviceLog,
    activity: DeviceActivity,
    protocol: Option<DaProtocol<'a>>,
    connected: bool,
}

impl<'a, P: MtkPort> Device<'a, P> {
    /// Initializes the device by performing the initial handshake with Preloader/BROM and
    /// retrieving device information.
    ///
    /// If the device has DAA enabled, the provided auth file will be sent to the device to allow
    /// loading the DA.
    /// If the device has SLA enabled, the SLA challenge will be performed using the public key from
    /// the auth file.
    ///
    /// # Example
    /// ```no_run
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let vid = Some(0x0E8D);
    /// let pid = Some(0x2000);
    ///
    /// let auth_file = std::fs::read("path/to/auth/file").expect("Failed to read auth file");
    /// let mtk_port = PortType::find_device(vid, pid, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    ///
    /// let mut device =
    ///     DeviceBuilder::new(mtk_port).with_da_data(&da_data).with_auth(&auth_file).build()?;
    ///
    /// device.init()?;
    ///
    /// Ok(())
    /// # }
    /// ```
    pub fn init(&mut self) -> Result<()> {
        let conn_type = self.port().connection_type();
        let mut pl = PlProtocol::new(&mut self.port);

        pl.handshake()?;

        // TODO: Return a target config struct instead.
        let target_config = pl.get_target_config()?;
        let hw_code = pl.get_hw_code()?;
        let (hw_subcode, ..) = pl.get_hw_sw_ver()?;
        // Some old devices don't support this command.
        let soc_id = pl.get_soc_id().unwrap_or_default();
        // MTK removed MEID on newer preloaders.
        let meid = pl.get_meid().unwrap_or_default();

        // Might look redundant, but most devices can work even without knowing
        // the SoC. While we prefer to know, it's better to allow the device to work
        // in stock mode than failing. Features like extensions or some exploits will fail,
        // but that's expected.
        let chip = SoC::try_from_hwcode(hw_code).map_or_else(
            || {
                warn!("Unknown hardware code 0x{:04X}.", hw_code);
                warn!("Please report this hw code to the developers.");
                warn!("Some features may not work correctly on this device.");
                None
            },
            Some,
        );

        let devinfo = DevInfoData {
            soc_id,
            meid,
            partitions: vec![],
            chip,
            bootctrl: None,
            hw_code,
            hw_subcode,
            target_config,
        };

        let devinfo = DevInfo::new(devinfo);

        if (devinfo.sla_enabled() || devinfo.daa_enabled())
            && conn_type == ConnectionType::Brom
            && let Some(auth) = &self.auth_data
        {
            pl.send_auth(auth)?;
            if devinfo.sla_enabled() {
                let file = GfhFile::try_read(auth)?;

                let Some(GfhKind::ToolAuth(tool_auth)) = file.get_gfh(GfhType::ToolAuth) else {
                    return Err(PenumbraError::InvalidAuthFile.into());
                };

                let sla_pubk: &[u8] = tool_auth.sla_public_key.n_key();

                // If we have exploits enabled, we can ignore the result of the SLA challenge since
                // we can bypass it in some cases, and if the latter fails, we can't continue
                // anyway and we'll get an error about SLA during DA upload.
                #[cfg(feature = "exploits")]
                pl.sla_challenge(sla_pubk).ok();
                #[cfg(not(feature = "exploits"))]
                pl.sla_challenge(sla_pubk)?;
            }
        }

        self.devinfo = devinfo;

        self.connected = true;

        Ok(())
    }

    /// Re-initialises the device connection using a previously gathered `DevInfoData`.
    /// Useful for resuming a session without repeating the full handshake.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let devinfo_data = device.devinfo().data();
    /// device.reinit(devinfo_data)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reinit(&mut self, dev_info: DevInfoData) -> Result<()> {
        self.devinfo = DevInfo::new(dev_info);

        match self.port().connection_type() {
            ConnectionType::Preloader | ConnectionType::Brom => {
                let mut pl = PlProtocol::new(self.port_mut());
                pl.handshake()?;
            }
            ConnectionType::Da => {
                let protocol = self.init_da_protocol()?;
                self.protocol = Some(protocol);
            }
        };

        self.connected = true;

        Ok(())
    }

    /// Returns a reference to the underlying MTK port.
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// Returns a mutable reference to the underlying MTK port.
    pub const fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    /// Returns the current connection type for the port.
    pub fn get_connection_type(&self) -> ConnectionType {
        self.port().connection_type()
    }

    /// Sets the current connection type for the port.
    /// Use this before `reinit` or it might cause issues with the protocol initialization.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend, ConnectionType}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// device.set_connection_type(ConnectionType::Da)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_connection_type(&mut self, conn_type: ConnectionType) -> Result<()> {
        self.port_mut().set_connection_type(conn_type)
    }

    /// Uploads the provided Download Agent to the device and switches the connection type to DA
    /// mode.
    /// If the device is already in DA mode, this function will do nothing.
    /// If no DA file was provided during device creation, this function will return an error.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend, ConnectionType}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// device.enter_da_mode()?;
    /// assert_eq!(device.get_connection_type(), ConnectionType::Da);
    /// # Ok(())
    /// # }
    /// ```
    pub fn enter_da_mode(&mut self) -> Result<()> {
        if !self.connected {
            return Err(ConnectionError::PortNotOpen.into());
        }

        let mut proto = self.init_da_protocol()?;

        let mut da = Self::get_da_entry(self.da.as_ref(), self.devinfo())?;

        if self.get_connection_type() != ConnectionType::Da {
            proto.upload_da(&mut self.port, &mut da)?;
            self.set_connection_type(ConnectionType::Da)?;
        }

        self.protocol = Some(proto);

        self.partitions();
        self.get_bootctrl().ok();

        Ok(())
    }

    fn get_da_entry<'da>(da: Option<&'da Da<'da>>, devinfo: &DevInfo) -> Result<DaEntry<'da>> {
        let hw_code = devinfo.chip().map_or_else(|| devinfo.hw_code(), |c| c.to_dacode());
        let hw_subcode = devinfo.hw_subcode();

        let entry = da
            .ok_or(PenumbraError::DaNotProvided)?
            .entries()
            .find(|entry| entry.hw_code() == hw_code && entry.hw_sub_code() == hw_subcode)
            .ok_or(PenumbraError::NoCompatibleDa(hw_code, hw_subcode))?;

        Ok(entry)
    }

    fn init_da_protocol(&mut self) -> Result<DaProtocol<'a>> {
        let da_entry = Self::get_da_entry(self.da.as_ref(), self.devinfo())?;

        let da_type = da_entry.version();

        let params = DaProtocolParams {
            devinfo: self.devinfo.clone(),
            device_log: self.device_log.clone(),
            activity: self.activity.clone(),
            log_level: self.da_log_level,
            usb_log_channel: self.usb_log_channel,
            preloader: self.pl.take(),
        };

        let protocol = match da_type {
            DaVersion::V5 => DaProtocol::V5(XFlash::new(params)),
            DaVersion::V6 => DaProtocol::V6(Xml::new(params)),
            DaVersion::V3 => return Err(PenumbraError::UnsupportedDevice.into()),
        };

        Ok(protocol)
    }

    /// Guarantees the device is in DA mode. If it is not currently in DA mode,
    /// it will automatically invoke `enter_da_mode()`.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend, ConnectionType}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// device.ensure_da_mode()?;
    /// assert_eq!(device.get_connection_type(), ConnectionType::Da);
    /// # Ok(())
    /// # }
    /// ```
    pub fn ensure_da_mode(&mut self) -> Result<()> {
        if !self.connected {
            return Err(ConnectionError::PortNotOpen.into());
        }

        if self.protocol.is_some() && self.get_connection_type() == ConnectionType::Da {
            return Ok(());
        }

        self.enter_da_mode()
    }

    /// Returns a mutable reference to the initialized DA protocol, if available.
    pub const fn get_protocol(&mut self) -> Option<&mut DaProtocol<'a>> {
        self.protocol.as_mut()
    }

    /// Provides scoped access to both the DA protocol and the MtkPort simultaneously.
    /// Useful when requiring direct access to protocol specific commands that are not
    /// exposed in the `DaProtocol` abstraction.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::da::DaProtocol;
    /// use penumbra_mtk::da::xflash::set_rsc_info;
    /// device.with_protocol(|proto, port| {
    ///     let DaProtocol::V5(xflash) = proto else {
    ///         return Err(penumbra_mtk::error::PenumbraError::WrongProtocolVersion.into());
    ///     };
    ///
    ///     let file = std::fs::File::open("path/to/rsc/file").expect("Failed to open RSC file");
    ///     let file_size =
    ///         std::fs::metadata("path/to/rsc/file").expect("Failed to get RSC file metadata").len();
    ///     let mut reader = std::io::BufReader::new(file);
    ///     let mut progress = |written: u64, total: u64| {
    ///         println!("Written: {}/{}", written, total);
    ///     };
    ///
    ///     set_rsc_info(xflash, port, "lk", file_size, &mut reader, &mut progress)?;
    ///     Ok(())
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_protocol<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce(&mut DaProtocol<'a>, &mut P) -> Result<R>,
    {
        let port = &mut self.port;
        let proto = self.protocol.as_mut().ok_or(PenumbraError::ProtocolNotInitialized)?;

        f(proto, port)
    }

    /// Retrieves info about the device storage.
    pub fn get_storage(&mut self) -> Option<StorageKind> {
        self.ensure_da_mode().ok()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.get_storage(&mut self.port).cloned()
    }

    /// Returns a reference to the DevInfo struct, containing information about
    /// the chip, efuses and more, fetched during the device life cycle.
    pub const fn devinfo(&self) -> &DevInfo {
        &self.devinfo
    }

    /// Returns an iterator over the device's partitions.
    /// If the partition table has not been read yet, it will fetch it from the device first.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// for partition in device.partitions_iter() {
    ///     println!("Found partition: {}", partition.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn partitions_iter(&mut self) -> impl Iterator<Item = Partition> {
        if self.devinfo.partitions().is_empty()
            && let Some(protocol) = self.protocol.as_mut()
        {
            info!("Retrieving partition information...");
            let parts: Vec<Partition> = protocol.partitions(&mut self.port).collect();
            self.devinfo.set_partitions(parts);
        }

        self.devinfo.partitions().into_iter()
    }

    /// Returns a `Vec` containing all the device's partitions.
    /// Will automatically fetch the partition table from the device if not already cached.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let parts = device.partitions();
    /// println!("Device has {} partitions", parts.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn partitions(&mut self) -> Vec<Partition> {
        self.partitions_iter().collect()
    }

    /// Returns a particular partition by name, if it exists.
    /// Will automatically fetch the partition table from the device if not already cached.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let part = device.get_partition("lk_a");
    /// assert!(part.is_some());
    ///
    /// println!("Lk partition size: {}", part.unwrap().size);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_partition(&mut self, name: &str) -> Option<Partition> {
        self.partitions_iter().find(|p| p.name == name)
    }

    /// Returns a particular partition by name, if it exists, while being aware of the device active
    /// slot. Will automatically fetch the partition table from the device if not already
    /// cached.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// // If device is in slot A, this will return the partition for "lk_a", otherwise "lk_b"
    /// let part = device.get_partition_active("lk");
    /// assert!(part.is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_partition_active(&mut self, name: &str) -> Option<Partition> {
        // Ensure the partition table is loaded and cached
        self.partitions();

        if self.devinfo().bootctrl().is_none() {
            self.get_bootctrl().ok();
        }

        self.devinfo.get_partition(name)
    }

    /// Retrieves and parses the Boot Control partition
    /// It generally searches for the `misc` or `para` partition to read the slot status.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let boot_ctrl = device.get_bootctrl()?;
    /// println!("Active slot: {:?}", boot_ctrl.get_active_slot());
    /// # Ok(())
    /// # }
    pub fn get_bootctrl(&mut self) -> Result<BootControl> {
        if let Some(cached) = self.devinfo.bootctrl() {
            return Ok(cached);
        }

        let target_partition =
            self.partitions_iter().find(|p| p.name == "misc" || p.name == "para").map(|p| p.name);

        let Some(part_name) = target_partition else {
            return Err(PenumbraError::PartitionNotFound("misc or para".into()).into());
        };

        let mut buffer = Vec::new();

        // We need to use protocol to read the partition, or we will enter a loop of reading the
        // partition and trying to get boot control again.
        let proto = self.protocol.as_mut().ok_or(PenumbraError::ProtocolNotInitialized)?;
        proto.read_partition(&mut self.port, &part_name, &mut buffer, NOOP_PROGRESS)?;

        if buffer.len() < OFFSET_SLOT_SUFFIX + size_of::<BootControl>() {
            return Err(Error::Hacc(BootControlError::InvalidSize.into()));
        }

        let bootctrl = BootControl::try_read(&buffer[OFFSET_SLOT_SUFFIX..])?;
        self.devinfo.set_bootctrl(bootctrl.clone());

        Ok(bootctrl)
    }

    /// Reads data from a specified partition on the device.
    /// This function assumes the partition to be part of the user section.
    /// To read from other sections, use `read_offset` with appropriate address.
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use std::fs::File;
    /// use std::io::BufWriter;
    ///
    /// let file = File::create("boot.img")?;
    /// let mut writer = BufWriter::new(file);
    /// let mut progress = |read: u64, total: u64| {
    ///     println!("Read {}/{}", read, total);
    /// };
    /// device.read_flash("boot", &mut writer, &mut progress)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_flash<W, F>(&mut self, name: &str, writer: W, progress: F) -> Result<()>
    where
        W: Writer,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let part = self
            .devinfo
            .get_partition(name)
            .ok_or_else(|| PenumbraError::PartitionNotFound(name.into()))?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_flash(&mut self.port, part.address, part.size, part.kind, writer, progress)
    }

    /// Writes data to a specified partition on the device.
    /// This function assumes the partition to be part of the user section.
    /// To write to other sections, use `write_offset` with appropriate address.
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let firmware_data = std::fs::read("boot.img")?;
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written {}/{}", written, total);
    /// };
    /// device.write_flash("boot", firmware_data.as_slice(), &mut progress)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_flash<R, F>(&mut self, name: &str, reader: R, progress: F) -> Result<()>
    where
        R: Reader,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let part = self
            .devinfo
            .get_partition(name)
            .ok_or_else(|| PenumbraError::PartitionNotFound(name.into()))?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_flash(&mut self.port, part.address, part.size, part.kind, reader, progress)
    }

    /// Erases a specified partition on the device.
    /// This function assumes the partition to be part of the user section.
    /// To erase other sections, use `erase_offset` with the appropriate address.
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    /// let mut device = DeviceBuilder::new(mtk_port).with_da_data(&da_data).build()?;
    ///
    /// device.init()?;
    /// let mut progress = |erased: u64, total: u64| {
    ///     println!("Erased: {}/{}", erased, total);
    /// };
    /// device.erase_flash("userdata", &mut progress)?;
    /// Ok(())
    /// # }
    /// ```
    pub fn erase_flash<F>(&mut self, name: &str, progress: F) -> Result<()>
    where
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let part = self
            .devinfo
            .get_partition(name)
            .ok_or_else(|| PenumbraError::PartitionNotFound(name.into()))?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.erase_flash(&mut self.port, part.address, part.size, part.kind, progress)
    }

    /// Reads data from a specified offset and size on the device.
    /// This allows reading from arbitrary locations of the flash.
    /// To specify the section (e.g., user, pl_part1, pl_part2), provide the appropriate
    /// `PartitionKind`.
    ///
    /// # Examples
    /// ```no_run
    /// // Let's assume we want to read preloader
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    /// use penumbra_mtk::storage::{EmmcPartition, PartitionKind};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let mut device = DeviceBuilder::new(mtk_port).build()?;
    ///
    /// device.init()?;
    ///
    /// let mut progress = |read: u64, total: u64| {
    ///     println!("Read: {}/{}", read, total);
    /// };
    /// let mut preloader_data = Vec::new();
    /// device.read_offset(
    ///     0x0,
    ///     0x40000,
    ///     PartitionKind::Emmc(EmmcPartition::Boot1),
    ///     &mut preloader_data,
    ///     &mut progress,
    /// )?;
    /// Ok(())
    /// # }
    /// ```
    pub fn read_offset<W, F>(
        &mut self,
        address: u64,
        size: u64,
        section: PartitionKind,
        writer: W,
        progress: F,
    ) -> Result<()>
    where
        W: Writer,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_flash(&mut self.port, address, size, section, writer, progress)
    }

    /// Writes data to a specified offset and size on the device.
    /// This allows writing to arbitrary locations of the flash, as long as the region is writable.
    /// To specify the section (e.g., user, pl_part1, pl_part2), provide the appropriate
    /// `PartitionKind`.
    ///
    /// # Examples
    /// ```no_run
    /// // Let's assume we want to write to preloader
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    /// use penumbra_mtk::storage::{EmmcPartition, PartitionKind};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let mut device = DeviceBuilder::new(mtk_port).build()?;
    ///
    /// device.init()?;
    ///
    /// let preloader_data =
    ///     std::fs::read("path/to/preloader_penangf.bin").expect("Failed to read preloader");
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written: {}/{}", written, total);
    /// };
    /// device.write_offset(
    ///     0x1000, // Actual preloader offset is 0x0, but we skip the header to ensure correct writing
    ///     preloader_data.len() as u64,
    ///     PartitionKind::Emmc(EmmcPartition::Boot1),
    ///     preloader_data.as_slice(),
    ///     &mut progress,
    /// )?;
    /// Ok(())
    /// # }
    /// ```
    pub fn write_offset<R, F>(
        &mut self,
        address: u64,
        size: u64,
        section: PartitionKind,
        reader: R,
        progress: F,
    ) -> Result<()>
    where
        R: Reader,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_flash(&mut self.port, address, size, section, reader, progress)
    }

    /// Erases data at a specified offset and size on the device.
    /// This allows erasing arbitrary locations, as long as the region is erasable.
    /// To specify the section (e.g., user, pl_part1, pl_part2), provide the appropriate
    /// `PartitionKind`.
    ///
    /// # Examples
    /// ```no_run
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    /// use penumbra_mtk::storage::{EmmcPartition, PartitionKind};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    /// let mut device = DeviceBuilder::new(mtk_port).with_da_data(&da_data).build()?;
    ///
    /// device.init()?;
    /// let mut progress = |erased: u64, total: u64| {
    ///     println!("Erased: {}/{}", erased, total);
    /// };
    /// device.erase_offset(0x0, 0x40000, PartitionKind::Emmc(EmmcPartition::Boot1), &mut progress)?;
    /// Ok(())
    /// # }
    /// ```
    pub fn erase_offset<F>(
        &mut self,
        address: u64,
        size: u64,
        section: PartitionKind,
        progress: F,
    ) -> Result<()>
    where
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.erase_flash(&mut self.port, address, size, section, progress)
    }

    /// Like `write_flash`, but instead of writing using offsets and sizes from GPT,
    /// it uses the partition name directly.
    ///
    /// This is the same method uses by SP Flash Tool when flashing firmware files.
    /// On locked bootloader, this is the only method that works for flashing stock firmware
    /// without hitting security checks, since the data is first uploaded and then verified as a
    /// whole.
    ///
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let mut device = DeviceBuilder::new(mtk_port).build()?;
    ///
    /// device.init()?;
    /// let firmware_data = std::fs::read("logo.bin").expect("Failed to read firmware");
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written: {}/{}", written, total);
    /// };
    /// device.write_partition(
    ///     "logo",
    ///     firmware_data.len() as u64,
    ///     firmware_data.as_slice(),
    ///     &mut progress,
    /// )?;
    /// Ok(())
    /// # }
    /// ```
    pub fn write_partition<R, F>(
        &mut self,
        partition: &str,
        size: u64,
        reader: R,
        progress: F,
    ) -> Result<()>
    where
        R: Reader,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_partition(&mut self.port, partition, size, reader, progress)
    }

    /// Like `read_flash`, but instead of reading using offsets and sizes from GPT,
    /// it uses the partition name directly.
    ///
    /// This is the same method uses by SP Flash Tool when reading back without scatter.
    ///
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::BufWriter;
    ///
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    /// let mut device = DeviceBuilder::new(mtk_port).with_da_data(&da_data).build()?;
    ///
    /// device.init()?;
    /// // Readsback "logo" partition to "logo.bin"
    /// let file = File::create("logo.bin")?;
    /// let mut writer = BufWriter::new(file);
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written: {}/{}", written, total);
    /// };
    /// device.read_partition("logo", &mut writer, &mut progress)?;
    /// Ok(())
    /// # }
    /// ```
    pub fn read_partition<W, F>(&mut self, partition: &str, writer: W, progress: F) -> Result<()>
    where
        W: Writer,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_partition(&mut self.port, partition, writer, progress)
    }

    /// Formats a specified partition on the device.
    ///
    /// This is NOT AB aware.
    ///
    /// # Examples
    /// ```no_run
    /// use penumbra_mtk::DeviceBuilder;
    /// use penumbra_mtk::port::{PortBackend, PortType};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    ///     .expect("Port should open")
    ///     .ok_or("No MTK port found")?;
    /// let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    /// let mut device = DeviceBuilder::new(mtk_port).with_da_data(&da_data).build()?;
    ///
    /// device.init()?;
    /// let mut progress = |erased: u64, total: u64| {
    ///     println!("Erased: {}/{}", erased, total);
    /// };
    /// device.erase_partition("userdata", &mut progress)?;
    /// Ok(())
    /// # }
    /// ```
    pub fn erase_partition<F>(&mut self, partition: &str, progress: F) -> Result<()>
    where
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.format_partition(&mut self.port, partition, progress)
    }

    /// Flashes the device partition using a scatter file.
    /// The scatter file describes the layout of the partitions and their corresponding files to be
    /// flashed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use std::io::{BufReader, BufWriter};
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto)
    /// #     .expect("Port should open")
    /// #     .ok_or("No MTK port found")?;
    /// # let da_data = std::fs::read("path/to/da/file").expect("Failed to read DA file");
    /// # let mut device = DeviceBuilder::new(mtk_port).with_da_data(&da_data).build()?;
    /// # device.init()?;
    ///
    /// let scatter_content = std::fs::read_to_string("scatter.txt")?;
    ///
    /// let reader_source = |path: &str| {
    ///     let file = File::open(path)?;
    ///     let size = file.metadata()?.len();
    ///     Ok((BufReader::new(file), size))
    /// };
    ///
    /// let writer_sink = |path: &str| {
    ///     let file = File::create(path)?;
    ///     Ok(BufWriter::new(file))
    /// };
    ///
    /// device.flash_scatter(&scatter_content, reader_source, writer_sink, |written, total| {
    ///     println!("Progress: {written}/{total}")
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn flash_scatter<F, R, W, S, K>(
        &mut self,
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
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.flash_scatter(&mut self.port, scatter, reader_source, writer_sink, progress)
    }

    /// Powers down the device and closes the connection when in DA mode.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// device.shutdown()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn shutdown(&mut self) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.shutdown(&mut self.port)
    }

    /// Reboots the device into the requested `BootMode` (e.g., Normal, Fastboot, Recovery).
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::da::BootMode;
    /// device.reboot(BootMode::Normal)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reboot(&mut self, bootmode: BootMode) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.reboot(&mut self.port, bootmode)
    }

    /// Dumps efuse data from DA mode to a file.
    /// The format of the dumped efuse data is protocol specific.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use std::fs::File;
    /// let file = File::create("efuse.bin")?;
    /// device.read_efuses(file)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_efuses<W: Writer>(&mut self, writer: W) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_efuses(&mut self.port, writer)
    }

    /// Blows efuses on the device from DA mode using data from a reader.
    /// The data format is protocol specific and should match what is expected by the device.
    /// DO NOT write back efuse data read from `read_efuses` as the format may differ between
    /// operations, causing irreversible damage to the device.
    ///
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let efuse_data = std::fs::read("efuses.bin")?;
    /// device.write_efuses(efuse_data.as_slice(), efuse_data.len() as u64)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_efuses<R: Reader>(&mut self, reader: R, size: u64) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_efuses(&mut self.port, reader, size)
    }
}

#[cfg(feature = "exploits")]
impl<'a, P: MtkPort> Device<'a, P> {
    /// Sets the desired lock state for the seccfg partition.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    /// This does not guarantee that the device will be unlocked completely, as other security
    /// measures may still be in place, like RPMB lock and auto relock on boot.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::hacc::LockState;
    /// device.set_seccfg_lock_state(LockState::Unlock)?;
    /// # Ok(())
    /// # }
    pub fn set_seccfg_lock_state(&mut self, state: LockState) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.set_seccfg_lock_state(&mut self.port, state)
    }

    /// Sets the desired lock state for the RPMB partition.
    /// This assumes the device is in DA mode and exploitable, and that the default MediaTek RPMB
    /// lock state is used. This won't unlock devices with custom RPMB lock states or not
    /// compatible with it.
    /// This only works on devices with UFS storage.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use hacc::LockState;
    /// device.set_rpmb_lock_state(LockState::Unlock)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_rpmb_lock_state(&mut self, state: LockState) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.set_rpmb_lock_state(&mut self.port, state)
    }

    /// Reads memory at the specified address.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let mut buffer = Vec::new();
    /// let mut progress = |read: u64, total: u64| {
    ///     println!("Read: {}/{}", read, total);
    /// };
    /// device.peek(0x100000, 1024, &mut buffer, &mut progress)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn peek<W, F>(&mut self, addr: u64, size: u64, writer: W, progress: F) -> Result<()>
    where
        W: Writer,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.peek(&mut self.port, addr, size, writer, progress)
    }

    /// Writes memory to the specified address.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let payload = vec![0x44; 1024]; // 1kb of As
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written: {}/{}", written, total);
    /// };
    /// device.poke(0x100000, payload.len() as u64, payload.as_slice(), &mut progress)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn poke<R, F>(&mut self, addr: u64, size: u64, reader: R, progress: F) -> Result<()>
    where
        R: Reader,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.poke(&mut self.port, addr, size, reader, progress)
    }

    /// Reads a 32bit value from a specific register.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// let register_val = device.read_register(0x1000A000)?;
    /// println!("Register: 0x{:08X}", register_val);
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_register(&mut self, addr: u64) -> Result<u32> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_register(&mut self.port, addr)
    }

    /// Writes a 32bit value to a specific register.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// device.write_register(0x1000A000, 0x2)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_register(&mut self, addr: u64, value: u32) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_register(&mut self.port, addr, value)
    }

    /// Reads blocks from the specified RPMB region.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::storage::RpmbRegion;
    /// let mut buffer = Vec::new();
    /// let mut progress = |read: u64, total: u64| {
    ///     println!("Read: {}/{}", read, total);
    /// };
    /// // Read 1 sector from region 0 of RPMB starting from sector 0
    /// device.read_rpmb(RpmbRegion::R0, 0, 1, &mut buffer, &mut progress)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_rpmb<W, F>(
        &mut self,
        region: crate::storage::RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        writer: W,
        progress: F,
    ) -> Result<()>
    where
        W: Writer,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.read_rpmb(&mut self.port, region, start_sector, sectors_count, writer, progress)
    }

    /// Writes blocks to the specified RPMB region.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::storage::RpmbRegion;
    /// let payload = vec![0u8; 512]; // 1 sector
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Written: {}/{}", written, total);
    /// };
    /// device.write_rpmb(RpmbRegion::R0, 0, 1, payload.as_slice(), &mut progress)?;
    /// # Ok(())
    /// # }
    pub fn write_rpmb<R, F>(
        &mut self,
        region: crate::storage::RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        reader: R,
        progress: F,
    ) -> Result<()>
    where
        R: Reader,
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.write_rpmb(&mut self.port, region, start_sector, sectors_count, reader, progress)
    }

    /// Writes blocks to the specified RPMB region.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::storage::RpmbRegion;
    /// let mut progress = |written: u64, total: u64| {
    ///     println!("Erased: {}/{}", written, total);
    /// };
    /// device.erase_rpmb(RpmbRegion::R0, 0, 1, &mut progress)?;
    /// # Ok(())
    /// # }
    pub fn erase_rpmb<F>(
        &mut self,
        region: crate::storage::RpmbRegion,
        start_sector: u32,
        sectors_count: u32,
        progress: F,
    ) -> Result<()>
    where
        F: ProgressCallback,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.erase_rpmb(&mut self.port, region, start_sector, sectors_count, progress)
    }

    /// Authenticates the RPMB region with the provided key.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    /// If the key is incorrect, subsequent RPMB operations will fail.
    /// If the key has already been set, this will suceed regardless of the input.
    /// If `read_rpmb` or `write_rpmb` already authenticated the derived key from the crypto engine,
    /// this will also succeed regardless of the input.
    ///
    /// Each RPMB region has its own key, so you must authenticate each region separately.
    /// On EMMC, the region will always default to R0.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::storage::RpmbRegion;
    /// let auth_key = [0xAA; 32];
    /// device.auth_rpmb(RpmbRegion::R0, &auth_key)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn auth_rpmb(&mut self, region: crate::storage::RpmbRegion, key: &[u8]) -> Result<()> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.auth_rpmb(&mut self.port, region, key)
    }

    /// Performs AES crypto operations with the device's crypto engine "SEJ"
    /// The device must be in DA mode and exploitable for this operation to succeed.
    /// If anti-clone is enabled, the key_id and key_sz parameters will be ignored, and
    /// the device HUK (Hardware Unique Key) will be used instead.
    ///
    /// If legacy is enabled with anti-clone or HwKey, the device will use the legacy SEJ
    /// initialization, deriving a key from a fixed pattern.
    ///
    /// If legacy is disabled, the device will perform KDF. This is supported only on modern V5
    /// (XFlash) and V6 (XML) devices.
    ///
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::da::extensions::SejParams;
    /// let mut output = Vec::new();
    /// let input = b"Hello, World!";
    /// let params = SejParams::default();
    /// device.sej_aes(params, &input[..], &mut output)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sej_aes<R, W>(
        &mut self,
        params: extensions::SejParams,
        reader: R,
        writer: W,
    ) -> Result<()>
    where
        R: Reader,
        W: Writer,
    {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();
        protocol.sej_aes(&mut self.port, params, reader, writer)
    }

    /// Derives a key using the device crypto engine (TZCC or SSR on newer V6 devices).
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::da::extensions::{KeyDeriveId, KeySize};
    /// let derived_key = device.derive_key_by_id(KeyDeriveId::Rpmb, KeySize::Key256)?;
    /// println!("Key length: {}", derived_key.len());
    /// println!("Key: {:02X?}", derived_key);
    /// # Ok(())
    /// # }
    /// ```
    pub fn derive_key_by_id(&mut self, id: KeyDeriveId, len: KeySize) -> Result<Vec<u8>> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();

        let params = extensions::KeyDeriveParams::Id { id, len };
        protocol.derive_key(&mut self.port, params)
    }

    /// Derives a key using the device crypto engine (TZCC or SSR on newer V6 devices) with a custom
    /// label and salt.
    /// The device must be in DA mode and exploitable for this operation to succeed.
    ///
    /// The input label and salt must not exceed 32 bytes each.
    ///
    /// # Examples
    /// ```no_run
    /// # use penumbra_mtk::{DeviceBuilder, port::{PortType, PortBackend}};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mtk_port = PortType::find_device(None, None, PortBackend::Auto).unwrap().unwrap();
    /// # let mut device = DeviceBuilder::new(mtk_port).build()?;
    /// # device.init()?;
    /// use penumbra_mtk::da::extensions::KeySize;
    /// let derived_key = device.derive_key_by_input(b"custom_label", b"salt_123", KeySize::Key256)?;
    /// println!("Key length: {}", derived_key.len());
    /// assert_eq!(derived_key.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn derive_key_by_input(
        &mut self,
        label: &[u8],
        salt: &[u8],
        len: KeySize,
    ) -> Result<Vec<u8>> {
        self.ensure_da_mode()?;

        let protocol = self.protocol.as_mut().unwrap();

        let params = extensions::KeyDeriveParams::Input { label, salt, len };
        protocol.derive_key(&mut self.port, params)
    }
}
