/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::time::Duration;

use enum_dispatch::enum_dispatch;
use hacc::{DaEntry, Preloader};
use penumbra_macros::ToBytes;
use wincode::{Deserialize, SchemaRead, SchemaWrite};

use crate::activity::DeviceActivity;
use crate::da::{DaLogLevel, XFlash, Xml};
use crate::devinfo::DevInfo;
use crate::log_buffer::DeviceLog;
use crate::port::MtkPort;
#[cfg(feature = "exploits")]
use crate::storage::RpmbRegion;
use crate::storage::{PartitionKind, Partitions, StorageKind, StorageType};
use crate::traits::{FromBytes, ProgressCallback, Reader, ReaderSource, Writer, WriterSink};
use crate::{BootMode, Partition, Result};

/// MAGIC value for V5/V6 packets.
pub const MAGIC: u32 = 0xFEEEEEEF;
/// Bad design choices require bad workarounds.
pub const NOOP_PROGRESS: fn(u64, u64) = |_, _| {};
// On some devices, the DA will hang while writing a sparse image (or just lag generally a lot),
// even with the generous timeout of 10s. To account for this, a longer timeout can help the
// unnecessary failures.
pub const SPARSE_TIMEOUT: Duration = Duration::from_mins(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[repr(u32)]
pub enum DataType {
    #[wincode(tag = 1)]
    Flow = 0x1,
    #[wincode(tag = 2)]
    Message = 0x2,
}

impl From<u32> for DataType {
    fn from(v: u32) -> Self {
        match v {
            0x1 => Self::Flow,
            0x2 => Self::Message,
            _ => Self::Flow,
        }
    }
}

/// 12 byte packet header shared by all packet types.
///
/// Format:
/// ```text
/// [0..4]   magic      (must be 0xFEEEEEEF)
/// [4..8]   data_type  (1 = Flow, 2 = Message)
/// [8..12]  length     (byte count of the payload that follows)
/// ```
///
/// For `Message` packets, the payload starts with a 4 byte priority
/// field followed by the actual message body.
/// The length of a `Message` packet also includes the 4 byte from priority.
#[derive(Debug, Clone, Copy, SchemaRead, SchemaWrite, ToBytes)]
pub struct PacketHeader {
    pub magic: u32,
    pub data_type: DataType,
    pub length: u32,
}

impl PacketHeader {
    pub const SIZE: usize = size_of::<Self>();

    pub const fn new(data_type: DataType, length: u32) -> Self {
        Self { magic: MAGIC, data_type, length }
    }

    pub const fn flow(length: u32) -> Self {
        Self::new(DataType::Flow, length)
    }
}

impl FromBytes for PacketHeader {
    const SIZE: usize = size_of::<Self>();

    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::SIZE {
            return None;
        }

        let hdr = Self::deserialize(raw).ok()?;

        if hdr.magic != MAGIC {
            return None;
        }

        Some(hdr)
    }
}

#[non_exhaustive]
pub struct DaProtocolParams<'a> {
    pub devinfo: DevInfo,
    pub device_log: DeviceLog,
    pub activity: DeviceActivity,
    pub log_level: DaLogLevel,
    pub usb_log_channel: bool,
    pub preloader: Option<Preloader<'a>>,
}

#[enum_dispatch(DownloadProtocol)]
#[enum_dispatch(DownloadProtocolExt)]
pub enum DaProtocol<'a> {
    V5(XFlash<'a>),
    V6(Xml),
}

#[enum_dispatch]
pub trait DownloadProtocol {
    /* Upload and boot a Download Agent */
    fn upload_da<P: MtkPort>(&mut self, port: &mut P, da: &mut DaEntry<'_>) -> Result<()>;
    /* Run and jump to code */
    fn boot_to<P: MtkPort>(&mut self, port: &mut P, addr: u32, data: &[u8]) -> Result<()>;
    /* Read data from the device, size is automatically determined by the protocol */
    fn read_data<P: MtkPort>(&mut self, port: &mut P) -> Result<Vec<u8>>;
    /* Send data to the device */
    fn send<P: MtkPort>(&mut self, port: &mut P, data: &[u8]) -> Result<()>;
    /* Send multiple data buffers to the device */
    fn send_data<P: MtkPort>(&mut self, port: &mut P, data: &[&[u8]]) -> Result<()>;
    /* Shutdown the device */
    fn shutdown<P: MtkPort>(&mut self, port: &mut P) -> Result<()>;
    /* Reboot the device to the specified BootMode */
    fn reboot<P: MtkPort>(&mut self, port: &mut P, mode: BootMode) -> Result<()>;

    /* Sends data to the device in chunks, with progress reporting,
     * using the protocol specific loop logic.
     */
    fn download_data<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: u64,
        reader: R,
        progress: F,
    ) -> Result<u64>;

    /* Receives data from the device in chunks, with progress reporting,
     * using the protocol specific loop logic.
     */
    fn upload_data<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: u64,
        writer: W,
        progress: F,
    ) -> Result<u64>;

    /* Reports progress to the device, using the protocol specific loop logic.
     * This is used for operations that don't involve data transfer, but still need to report
     * progress.
     */
    fn progress_report<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        size: u64,
        progress: F,
    ) -> Result<()>;

    /* Flash RW */

    /* Reads the flash at the given address with the given size, in the specified section */
    fn read_flash<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: PartitionKind,
        writer: W,
        progress: F,
    ) -> Result<()>;

    /* Writes the flash at the given address with the given size, in the specified section */
    fn write_flash<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: PartitionKind,
        reader: R,
        progress: F,
    ) -> Result<()>;

    /* Erases the flash at the given address with the given size, in the specified section */
    fn erase_flash<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        size: u64,
        section: PartitionKind,
        progress: F,
    ) -> Result<()>;

    /* Reads the specified partition (like read flash, but with partition names) */
    fn read_partition<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        writer: W,
        progress: F,
    ) -> Result<()>;

    /* Writes the specified partition (like write flash, but with partition names) */
    fn write_partition<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        size: u64,
        reader: R,
        progress: F,
    ) -> Result<()>;

    fn format_partition<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        name: &str,
        progress: F,
    ) -> Result<()>;

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
        F: ProgressCallback;

    fn get_storage<P: MtkPort>(&mut self, port: &mut P) -> Option<&StorageKind>;
    fn get_storage_type<P: MtkPort>(&mut self, port: &mut P) -> StorageType;
    fn partitions<P: MtkPort>(&mut self, port: &mut P) -> Partitions;
    fn get_partition(&mut self, name: &str) -> Option<Partition> {
        self.get_devinfo().get_partition(name)
    }

    /* Efuses */

    /* Reads efuses and writes the raw response into the provided buffer */
    fn read_efuses<W: Writer, P: MtkPort>(&mut self, port: &mut P, writer: W) -> Result<()>;
    /* Writes efuses from the provided buffer */
    fn write_efuses<R: Reader, P: MtkPort>(
        &mut self,
        port: &mut P,
        reader: R,
        size: u64,
    ) -> Result<()>;

    /* Security */

    /* Handles DA SLA.
     * If the `exploits` feature flag is enabled, it will attempt to bypass SLA
     * with dummy signature.
     */
    fn handle_sla<P: MtkPort>(&mut self, port: &mut P, da: &DaEntry) -> Result<()>;

    fn get_devinfo(&mut self) -> &DevInfo;
}

#[allow(dead_code)]
#[cfg(not(feature = "exploits"))]
#[enum_dispatch]
pub trait DownloadProtocolExt: DownloadProtocol {}

#[cfg(feature = "exploits")]
#[enum_dispatch]
pub trait DownloadProtocolExt {
    /* Security */

    /* Sets the lock state in the `seccfg` partition */
    fn set_seccfg_lock_state<P: MtkPort>(
        &mut self,
        port: &mut P,
        state: hacc::LockState,
    ) -> Result<()>;

    /* Sets the lock state in RPMB (UFS only) */
    fn set_rpmb_lock_state<P: MtkPort>(
        &mut self,
        port: &mut P,
        state: hacc::LockState,
    ) -> Result<()>;

    /* Memory */

    /* Read memory at the given address with the given length */
    fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: u64,
        writer: W,
        progress: F,
    ) -> Result<()>;

    /* Write memory at the given address with the given length */
    fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        addr: u64,
        length: u64,
        reader: R,
        progress: F,
    ) -> Result<()>;

    /* Return the value of the register at the given address */
    fn read_register<P: MtkPort>(&mut self, port: &mut P, addr: u64) -> Result<u32>;
    /* Writes value to the register at the given address */
    fn write_register<P: MtkPort>(&mut self, port: &mut P, addr: u64, value: u32) -> Result<()>;

    /* RPMB */

    /* Read the specified RPMB region with `num_sectors` starting at `start_sector` */
    fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        writer: W,
        progress: F,
    ) -> Result<()>;

    /* Write the specified RPMB region with `num_sectors` starting at `start_sector` */
    fn write_rpmb<R: Reader, F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        reader: R,
        progress: F,
    ) -> Result<()>;

    /* Erase the specified RPMB region with `num_sectors` starting at `start_sector` */
    fn erase_rpmb<F: ProgressCallback, P: MtkPort>(
        &mut self,
        port: &mut P,
        region: RpmbRegion,
        start_sector: u32,
        num_sectors: u32,
        progress: F,
    ) -> Result<()>;

    /* Authenticates the given key for the specified RPMB region.
     * If the RPMB region is already authenticated, it will return Ok */
    fn auth_rpmb<P: MtkPort>(&mut self, port: &mut P, region: RpmbRegion, key: &[u8])
    -> Result<()>;

    /* Crypto */

    /* Encrypts / Decrypts, based on params, the given data in reader and writes the result to
     * writer */
    fn sej_aes<R: Reader, W: Writer, P: MtkPort>(
        &mut self,
        port: &mut P,
        params: super::extensions::SejParams,
        reader: R,
        writer: W,
    ) -> Result<()>;

    /* Derives the specified key */
    fn derive_key<P: MtkPort>(
        &mut self,
        port: &mut P,
        params: super::extensions::KeyDeriveParams,
    ) -> Result<Vec<u8>>;

    /* Da patching */

    fn patch_da(&mut self, da: &mut DaEntry) -> Result<()>;
    fn patch_da1(&mut self, da: &mut DaEntry) -> Result<()>;
    fn patch_da2(&mut self, da: &mut DaEntry) -> Result<()>;
}
