/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::io::Read;

use acon::MMIO;
use hacc::DaEntry;
use log::{debug, info, warn};

use crate::da::extensions::{KeyDeriveId, KeyDeriveParams, KeySize, SejParams};
use crate::da::protocol::NOOP_PROGRESS;
use crate::da::xflash::Cmd;
use crate::da::xflash::structs::AddressLengthParams;
use crate::da::xflash::structs::extensions::{DaCtx, ExtPointerTable, RpmbParams};
use crate::da::{DownloadProtocolExt, XFlash};
use crate::error::{PenumbraError, ProtocolError, Result};
use crate::port::{MAX_TIMEOUT, MtkPort};
use crate::storage::RPMB_FRAME_DATA_SZ;
use crate::traits::{ProgressCallback, Reader, ToBytes, Writer};
use crate::utils::analysis::{ArchAnalyzer, Thumb2Analyzer};
use crate::{DownloadProtocol, RpmbRegion, Storage};

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_x.bin");
// Won't go faster, and bigger packets makes the device hang
const RPMB_WRITE_PKT_LEN: usize = 32 * 1024;
const POINTER_TABLE_MAGIC: u32 = 0x54525450;

pub fn boot_extensions<P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    da: &DaEntry<'_>,
) -> Result<bool> {
    debug!("Trying booting XFlash extensions...");
    let Some(chip) = xflash.get_devinfo().chip() else {
        warn!("Failed to get chip info, continuing without extensions");
        return Ok(false);
    };

    let Some(exts) = prepare_extensions(xflash, da) else {
        warn!("Failed to prepare DA extensions");
        return Ok(false);
    };

    let ext_addr = 0x68000000;
    let ext_size = exts.len() as u32;

    info!("Uploading DA extensions to 0x{:08X} (0x{:X} bytes)", ext_addr, ext_size);

    if xflash.boot_to(port, ext_addr, &exts).is_err() {
        // If DA extensions fail to upload, we just return false, not a fatal error
        warn!("Failed to upload DA extensions, continuing without extensions");
        return Ok(false);
    }

    let ack = xflash.devctrl(port, Cmd::ExtAck, None)?;

    debug!("Received extension ack: {:?}", ack);

    let sej_base = chip.hacc();
    // return 0 if None
    let tzcc_base = chip.tzcc().map(|n| n.get()).unwrap_or_default();
    let da2_base = da.da2().addr();
    let da2_size = da.da2_code().len() as u32;
    let storage_type = xflash.get_storage_type(port) as u32;
    let read_pkt_len = xflash.read_packet_length.unwrap_or(0x100) as u32;
    let write_pkt_len = xflash.write_packet_length.unwrap_or(0x100) as u32;
    let usb_log = xflash.usb_log_channel as u32;

    let ctx = DaCtx {
        sej_base,
        tzcc_base,
        da2_base,
        da2_size,
        storage_type,
        read_pkt_len,
        write_pkt_len,
        usb_log,
    };

    debug!("Sending DA context to device:");
    debug!("  SEJ base: 0x{:08X}", ctx.sej_base);
    debug!("  TZCC base: 0x{:08X}", ctx.tzcc_base);
    debug!("  DA2 base: 0x{:08X}", ctx.da2_base);
    debug!("  DA2 size: 0x{:08X}", ctx.da2_size);
    debug!("  Storage type: 0x{:08X}", ctx.storage_type);
    debug!("  Read packet length: 0x{:08X}", ctx.read_pkt_len);
    debug!("  Write packet length: 0x{:08X}", ctx.write_pkt_len);
    debug!("  USB log channel: 0x{:08X}", ctx.usb_log);

    xflash.devctrl(port, Cmd::ExtSetupDaCtx, Some(&[&ctx.to_bytes()]))?;

    Ok(true)
}

fn prepare_extensions(xflash: &mut XFlash, da: &DaEntry<'_>) -> Option<Vec<u8>> {
    let da2 = da.da2_code();
    let da2address = da.da2().addr() as u64;

    let mut da_ext_data = DA_EXT.to_vec();

    let analyzer = Thumb2Analyzer::new(da2.into(), da2address);

    let off = analyzer.fn_from_str("allocation was %zd bytes long at ptr %p\n")?;
    let free = analyzer.off_to_va(off)? as u32 | 1;

    debug!("Found free at 0x{:08X}", free);

    // kernel main
    let off = analyzer.str_xref("\n***10.dagent_register_commands.\n")?;
    let off = analyzer.next_bl_from_off(off + 6)?; // Skip dprintf
    let off = analyzer.bl_target(off)?;
    let off = analyzer.va_to_off(off)?;
    // + 0x20 to account of the extloader just in case
    let off = analyzer.next_bl_from_off(off)?;
    let reg_devc = analyzer.bl_target(off)? as u32 | 1;

    debug!("Found register_device_ctrl at 0x{:08X}", reg_devc);

    let off = analyzer.va_to_off(reg_devc as u64)?;
    let off = analyzer.next_bl_from_off(off)?;
    let malloc = analyzer.bl_target(off)? as u32 | 1;

    debug!("Found malloc at 0x{:08X}", malloc);

    let off = analyzer.fn_from_str("%s, mmc_set_part_config done!!\n")?;
    let off = analyzer.next_bl_from_off(off)?; // Skip dprintf

    let off = analyzer.bl_target(off)?;
    let mmc_get_card = off as u32 | 1;

    debug!("Found mmc_get_card at 0x{:08X}", mmc_get_card);

    let uart_base = xflash.get_devinfo().chip()?.uart0();

    debug!("UART base address at 0x{:X}", uart_base);

    let table = ExtPointerTable {
        magic: POINTER_TABLE_MAGIC,
        uart_base,
        reg_devc,
        malloc,
        free,
        mmc_get_card,
    };

    let off = da_ext_data.len() - ExtPointerTable::SIZE;

    da_ext_data[off..].copy_from_slice(&table.to_bytes());

    Some(da_ext_data)
}

pub(super) fn read_register(
    xflash: &mut XFlash,
    port: &mut impl MtkPort,
    addr: u32,
) -> Result<u32> {
    xflash.devctrl(port, Cmd::ExtReadRegister, Some(&[&addr.to_le_bytes()]))?;
    let data = xflash.read_data(port)?;

    status_ok!(xflash, port)?;

    Ok(u32::from_le_bytes(data[0..4].try_into().map_err(|_| ProtocolError::InvalidResponseLength)?))
}

pub(super) fn write_register(
    xflash: &mut XFlash,
    port: &mut impl MtkPort,
    addr: u32,
    value: u32,
) -> Result<()> {
    let addr_bytes = addr.to_le_bytes();
    let value_bytes = value.to_le_bytes();

    xflash.devctrl(port, Cmd::ExtWriteRegister, Some(&[&addr_bytes, &value_bytes]))?;
    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    addr: u64,
    length: u64,
    writer: W,
    progress: F,
) -> Result<()> {
    let range = AddressLengthParams { addr, length };

    xflash.devctrl(port, Cmd::ExtReadMem, Some(&[&range.to_bytes()]))?;
    xflash.upload_data(port, length, writer, progress)?;

    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    addr: u64,
    length: u64,
    reader: R,
    progress: F,
) -> Result<()> {
    let range = AddressLengthParams { addr, length };

    xflash.devctrl(port, Cmd::ExtWriteMem, Some(&[&range.to_bytes()]))?;
    xflash.download_data(port, length, reader, progress)?;

    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn sej_aes<R: Reader, W: Writer, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    params: &SejParams,
    reader: R,
    writer: W,
) -> Result<()> {
    xflash.devctrl(port, Cmd::ExtSej, Some(&[&params.to_bytes()]))?;

    xflash.download_data(port, u64::from(params.length), reader, NOOP_PROGRESS)?;
    xflash.upload_data(port, u64::from(params.length), writer, NOOP_PROGRESS)?;

    status_ok!(xflash, port)?;

    Ok(())
}

fn init_rpmb<P: MtkPort>(xflash: &mut XFlash, port: &mut P, region: RpmbRegion) -> Result<()> {
    let params = KeyDeriveParams::Id { id: KeyDeriveId::Rpmb, len: KeySize::Key256 };
    let key = xflash.derive_key(port, params)?;

    // If the RPMB is already initialized (even with another key), this will succeed
    // without actually changing the key.
    xflash.auth_rpmb(port, region, &key)?;

    Ok(())
}

pub(super) fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    region: crate::storage::RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    writer: W,
    progress: F,
) -> Result<()> {
    init_rpmb(xflash, port, region)?;

    let storage = xflash.get_storage(port).ok_or(ProtocolError::CannotGetStorageInfo)?;

    let rpmb_size = storage.get_rpmb_size();
    let max_sectors = (rpmb_size / RPMB_FRAME_DATA_SZ as u64) as u32;
    if start_sector.checked_add(num_sectors).is_none_or(|end| end > max_sectors) {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    }

    let params = RpmbParams { start_sector, sectors_count: num_sectors }.to_bytes();
    let region = (region as u32).to_le_bytes();
    let data_len = u64::from(num_sectors) * RPMB_FRAME_DATA_SZ as u64;

    xflash.devctrl(port, Cmd::ExtRpmbRead, Some(&[&region, &params]))?;
    xflash.upload_data(port, data_len, writer, progress)?;
    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn write_rpmb<R: Reader, F: ProgressCallback, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    region: crate::storage::RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    reader: R,
    progress: F,
) -> Result<()> {
    init_rpmb(xflash, port, region)?;

    let storage = xflash.get_storage(port).ok_or(ProtocolError::CannotGetStorageInfo)?;

    let rpmb_size = storage.get_rpmb_size();
    let max_sectors = (rpmb_size / RPMB_FRAME_DATA_SZ as u64) as u32;
    if start_sector.checked_add(num_sectors).is_none_or(|end| end > max_sectors) {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    }

    let params = RpmbParams { start_sector, sectors_count: num_sectors }.to_bytes();
    let region = (region as u32).to_le_bytes();
    let data_len = u64::from(num_sectors) * RPMB_FRAME_DATA_SZ as u64;

    xflash.devctrl(port, Cmd::ExtRpmbWrite, Some(&[&region, &params]))?;
    xflash.download_data_with(port, data_len, RPMB_WRITE_PKT_LEN, MAX_TIMEOUT, reader, progress)?;
    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn erase_rpmb<F: ProgressCallback, P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    progress: F,
) -> Result<()> {
    let total_bytes = num_sectors as u64 * RPMB_FRAME_DATA_SZ as u64;

    let zero_reader = std::io::repeat(0).take(total_bytes);

    xflash.write_rpmb(port, region, start_sector, num_sectors, zero_reader, progress)
}

pub(super) fn auth_rpmb<P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    region: RpmbRegion,
    key: &[u8],
) -> Result<()> {
    xflash.devctrl(port, Cmd::ExtRpmbInit, Some(&[&(region as u32).to_le_bytes(), key]))?;
    status_ok!(xflash, port)?;

    Ok(())
}

pub(super) fn derive_key<P: MtkPort>(
    xflash: &mut XFlash,
    port: &mut P,
    params: KeyDeriveParams,
) -> Result<Vec<u8>> {
    const MAX_DATA_LEN: usize = 0x20;

    match params {
        KeyDeriveParams::Id { id, len } => {
            let key_type = (id as u32).to_le_bytes();
            let key_len = (len.to_bytes() as u32).to_le_bytes();

            xflash.devctrl(port, Cmd::ExtKeyDerive, Some(&[&key_type, &key_len]))?;
        }
        KeyDeriveParams::Input { label, salt, len } => {
            if label.len() > MAX_DATA_LEN || salt.len() > MAX_DATA_LEN {
                return Err(PenumbraError::InvalidKeySourceLength.into());
            }

            let key_type = (KeyDeriveId::Input as u32).to_le_bytes();
            let key_len = (len.to_bytes() as u32).to_le_bytes();
            let label_len = (label.len() as u32).to_le_bytes();
            let salt_len = (salt.len() as u32).to_le_bytes();

            xflash.devctrl(
                port,
                Cmd::ExtKeyDerive,
                Some(&[&key_type, &key_len, &label_len, &salt_len, label, salt]),
            )?;
        }
    }

    let key = xflash.read_data(port)?;
    status_ok!(xflash, port)?;

    Ok(key)
}
