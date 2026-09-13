/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

use acon::{MMIO, SoC};
use hacc::DaEntry;
use log::{debug, info, warn};
use penumbra_macros::XmlCommand;
use wincode::SchemaWrite;

use crate::da::extensions::{KeyDeriveId, KeyDeriveParams, KeySize, SejParams};
use crate::da::xml::Xml;
use crate::da::xml::cmd::{XmlCmdLifetime, XmlCommand};
use crate::da::{DownloadProtocol, NOOP_PROGRESS};
use crate::error::{PenumbraError, ProtocolError, Result};
use crate::exploit::{DaEntryExt, get_v6_payload};
use crate::port::MtkPort;
use crate::storage::{RPMB_FRAME_DATA_SZ, RpmbRegion, Storage};
use crate::traits::{ProgressCallback, Reader, ToBytes, Writer};
use crate::utils::analysis::{Aarch64Analyzer, Analyzer, Arch, ArchAnalyzer, ArmAnalyzer};
use crate::utils::xml::{get_tag, get_tag_usize};

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_xml.bin");
const POINTER_TABLE_MAGIC: u32 = 0x54525450;

#[derive(SchemaWrite, ToBytes)]
#[repr(C)]
struct ExtPointerTable {
    magic: u32,
    uart_base: u32,
    reg_cmd: u32,
    clear_err_msg: u32,
    set_err_msg: u32,
    malloc: u32,
    free: u32,
    mmc_get_card: u32,
}

#[derive(XmlCommand)]
pub struct ExtAck;

#[derive(XmlCommand)]
pub struct ExtDaCtx {
    #[xml(tag = "sej_base", fmt = "0x{sej_base:X}")]
    sej_base: u32,
    #[xml(tag = "tzcc_base", fmt = "0x{tzcc_base:X}")]
    tzcc_base: u32,
    #[xml(tag = "ssr_base", fmt = "0x{ssr_base:X}")]
    ssr_base: u32,
    #[xml(tag = "da2_base", fmt = "0x{da2_base:X}")]
    da2_base: u32,
    #[xml(tag = "da2_size", fmt = "0x{da2_size:X}")]
    da2_size: u32,
    #[xml(tag = "storage")]
    storage: String,
    #[xml(tag = "usb_log")]
    usb_log: String,
}

#[derive(XmlCommand)]
pub struct ExtReadMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u64,
}

#[derive(XmlCommand)]
pub struct ExtWriteMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u64,
}

#[derive(XmlCommand)]
pub struct ExtReadReg {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u64,
}

#[derive(XmlCommand)]
pub struct ExtWriteReg {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u64,
    #[xml(tag = "value", fmt = "0x{value:X}")]
    value: u32,
}

#[derive(XmlCommand)]
pub struct ExtKeyDerive {
    #[xml(tag = "key_type")]
    pub key_type: String,
    #[xml(tag = "key_length", fmt = "0x{key_length:X}")]
    pub key_length: u32,
    #[xml(tag = "label")]
    pub label: String,
    #[xml(tag = "salt")]
    pub salt: String,
}

#[derive(XmlCommand)]
pub struct ExtSej {
    #[xml(tag = "encrypt")]
    encrypt: String,
    #[xml(tag = "ac")]
    anti_clone: String,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u32,
    #[xml(tag = "cbc")]
    cbc: String,
    #[xml(tag = "key_id")]
    key_id: String,
    #[xml(tag = "key_size")]
    key_size: String,
}

#[derive(XmlCommand)]
pub struct ExtRpmbInit {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "key")]
    key: String,
}

#[derive(XmlCommand)]
pub struct ExtRpmbRead {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "start_sector", fmt = "{start_sector}")]
    start_sector: u32,
    #[xml(tag = "sectors_count", fmt = "{sectors_count}")]
    sectors_count: u32,
}

#[derive(XmlCommand)]
pub struct ExtRpmbWrite {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "start_sector", fmt = "{start_sector}")]
    start_sector: u32,
    #[xml(tag = "sectors_count", fmt = "{sectors_count}")]
    sectors_count: u32,
}

pub fn boot_extensions<P: MtkPort>(xml: &mut Xml, port: &mut P, da: &DaEntry<'_>) -> Result<bool> {
    let Some(chip) = xml.get_devinfo().chip() else {
        warn!("Failed to get chip info, continuing without extensions");
        return Ok(false);
    };

    let Some(ext_data) = prepare_extensions(da, chip) else {
        warn!("Failed to prepare XML extensions. Continuing without.");
        return Ok(false);
    };

    debug!("Trying booting XML extensions...");

    let ext_addr = 0x68000000;
    let ext_size = DA_EXT.len() as u32;

    info!("Uploading XML DA extensions to 0x{:08X} (0x{:X} bytes)", ext_addr, ext_size);

    if xml.boot_to(port, ext_addr, &ext_data).is_err() {
        warn!("Failed to upload XML extensions, continuing without extensions");
        return Ok(false);
    }

    if xmlcmd!(xml, port, ExtAck).is_err() {
        warn!("Extensions did not reply, continuing without extensions");
        return Ok(false);
    }

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    if response.is_err() {
        warn!("Failed to get extension ack response, continuing without extensions");
        return Ok(false);
    };

    let ack: String = get_tag(&response?, "status")?;
    if ack != "OK" {
        warn!("DA extensions failed to start: {}", ack);
        return Ok(false);
    }

    let sej_base = chip.hacc();
    let tzcc_base = chip.tzcc().map(|n| n.get()).unwrap_or_default();
    let ssr_base = chip.ssr().map(|n| n.get()).unwrap_or_default();
    let da2_base = da.da2().addr();
    let da2_size = da.da2().region_length() as u32;
    let storage = xml.get_storage(port).map_or("Unknown", |s| s.as_str());
    let usb_log = if xml.usb_log_channel { "yes" } else { "no" };

    xmlcmd_e!(
        xml, port, ExtDaCtx, sej_base, tzcc_base, ssr_base, da2_base, da2_size, storage, usb_log
    )?;

    info!("Successfully booted XML extensions");

    Ok(true)
}

fn prepare_extensions(da: &DaEntry<'_>, chip: SoC) -> Option<Vec<u8>> {
    let da2address = da.da2().addr() as u64;
    let da2data = da.da2_code();

    let analyzer = match da.arch() {
        Arch::Aarch64 => Analyzer::Aarch64(Aarch64Analyzer::new(da2data.into(), da2address)),
        Arch::Arm => Analyzer::Arm(ArmAnalyzer::new(da2data.into(), da2address)),
        _ => unreachable!(),
    };

    let is_arm64 = matches!(da.arch(), Arch::Aarch64);
    let mut da_ext_data = get_v6_payload(DA_EXT, is_arm64).to_vec();

    let reg_cmd_addr = analyzer
        .fn_from_str("CMD:REBOOT")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("Reg CMD function at VA 0x{:X}", reg_cmd_addr);

    let malloc_addr = analyzer
        .va_to_off(reg_cmd_addr as u64)
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("Malloc function at VA 0x{:X}", malloc_addr);

    let free_addr = analyzer
        .str_xref("Bad %s")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|bl_off| analyzer.next_bl_from_off(bl_off + 4))
        .and_then(|bl_off| analyzer.bl_target(bl_off))? as u32;

    debug!("Free function at VA 0x{:X}", free_addr);

    // On newer devices, MMC is not compiled at all.
    let mmc_get_card = analyzer
        .fn_from_str("mmc_switch_part")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|bl_off| analyzer.bl_target(bl_off))
        .unwrap_or(0) as u32;

    debug!("mmc_get_card function at VA 0x{:X}", mmc_get_card);

    let unsup_cmd = analyzer.str_xref("Unsupported command.")?;

    let set_err_msg =
        analyzer.next_bl_from_off(unsup_cmd).and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("set_err_msg function at VA 0x{:X}", set_err_msg);

    let clear_err_msg =
        analyzer.next_bl_from_off(unsup_cmd - 0x10).and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("clear_err_msg function at VA 0x{:X}", clear_err_msg);

    let uart_base = chip.uart0();

    debug!("UART base address at 0x{:X}", uart_base);

    let table = ExtPointerTable {
        magic: POINTER_TABLE_MAGIC,
        uart_base,
        reg_cmd: reg_cmd_addr,
        clear_err_msg,
        set_err_msg,
        malloc: malloc_addr,
        free: free_addr,
        mmc_get_card,
    };

    let off = da_ext_data.len() - ExtPointerTable::SIZE;

    da_ext_data[off..off + ExtPointerTable::SIZE].copy_from_slice(&table.to_bytes());

    Some(da_ext_data)
}

pub(super) fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    length: u64,
    writer: W,
    progress: F,
) -> Result<()> {
    let addr32 = u32::try_from(addr).map_err(|_| PenumbraError::ArithmeticOverflow)?;
    xmlcmd!(xml, port, ExtReadMem, addr32, length)?;

    xml.upload_data(port, length, writer, progress)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    length: u64,
    reader: R,
    progress: F,
) -> Result<()> {
    let addr32 = u32::try_from(addr).map_err(|_| PenumbraError::ArithmeticOverflow)?;
    xmlcmd!(xml, port, ExtWriteMem, addr32, length)?;

    xml.download_data(port, length, reader, progress)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn read_register<P: MtkPort>(xml: &mut Xml, port: &mut P, addr: u64) -> Result<u32> {
    xmlcmd!(xml, port, ExtReadReg, addr)?;

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    let resp = response?;

    let value: u32 = get_tag_usize(&resp, "value")? as u32;

    Ok(value)
}

pub(super) fn write_register<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    value: u32,
) -> Result<()> {
    xmlcmd_e!(xml, port, ExtWriteReg, addr, value)
}

pub(super) fn derive_key<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    params: KeyDeriveParams,
) -> Result<Vec<u8>> {
    const MAX_DATA_LEN: usize = 0x20;

    let (key_type, key_length, label, salt) = match params {
        KeyDeriveParams::Id { id, len } => {
            (id.to_string(), len.to_bytes() as u32, String::new(), String::new())
        }
        KeyDeriveParams::Input { label, salt, len } => {
            if label.len() > MAX_DATA_LEN || salt.len() > MAX_DATA_LEN {
                return Err(PenumbraError::InvalidKeySourceLength.into());
            }

            (
                KeyDeriveId::Input.to_string(),
                len.to_bytes() as u32,
                hex::encode(label),
                hex::encode(salt),
            )
        }
    };

    xmlcmd!(xml, port, ExtKeyDerive, key_type, key_length, label, salt)?;

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    let resp = response?;

    let key_hex: String = get_tag(&resp, "result")?;

    let key = hex::decode(&key_hex).map_err(|_| ProtocolError::InvalidResponseFormat)?;

    Ok(key)
}

pub(super) fn sej_aes<R: Reader, W: Writer, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    params: &SejParams,
    reader: R,
    writer: W,
) -> Result<()> {
    let encrypt_str = if params.encrypt { "yes" } else { "no" };
    let ac_str = if params.anti_clone { "yes" } else { "no" };
    let cbc_str = if params.cbc { "yes" } else { "no" };

    xmlcmd!(
        xml,
        port,
        ExtSej,
        encrypt_str,
        ac_str,
        params.length,
        cbc_str,
        params.key_id.to_string(),
        params.key_sz.to_string()
    )?;

    xml.download_data(port, u64::from(params.length), reader, NOOP_PROGRESS)?;
    xml.upload_data(port, u64::from(params.length), writer, NOOP_PROGRESS)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

fn init_rpmb<P: MtkPort>(xml: &mut Xml, port: &mut P, region: RpmbRegion) -> Result<()> {
    let key =
        derive_key(xml, port, KeyDeriveParams::Id { id: KeyDeriveId::Rpmb, len: KeySize::Key256 })?;

    // If the RPMB is already initialized (even with another key), this will succeed
    // without actually changing the key.
    xmlcmd_e!(xml, port, ExtRpmbInit, region as u32, hex::encode(&key))
}

pub(super) fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    writer: W,
    progress: F,
) -> Result<()> {
    init_rpmb(xml, port, region)?;

    let Some(storage) = xml.get_storage(port) else {
        return Err(ProtocolError::CannotGetStorageInfo.into());
    };

    let rpmb_size = storage.get_rpmb_size();
    let max_sectors = (rpmb_size / RPMB_FRAME_DATA_SZ as u64) as u32;
    if start_sector.checked_add(num_sectors).is_none_or(|end| end > max_sectors) {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    };

    xmlcmd!(xml, port, ExtRpmbRead, region as u32, start_sector, num_sectors)?;
    xml.upload_data(port, u64::from(num_sectors) * RPMB_FRAME_DATA_SZ as u64, writer, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn write_rpmb<R: Reader, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    reader: R,
    progress: F,
) -> Result<()> {
    init_rpmb(xml, port, region)?;

    let Some(storage) = xml.get_storage(port) else {
        return Err(ProtocolError::CannotGetStorageInfo.into());
    };

    let rpmb_size = storage.get_rpmb_size();
    let max_sectors = (rpmb_size / RPMB_FRAME_DATA_SZ as u64) as u32;
    if start_sector.checked_add(num_sectors).is_none_or(|end| end > max_sectors) {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    };

    let data_len = u64::from(num_sectors) * RPMB_FRAME_DATA_SZ as u64;

    xmlcmd!(xml, port, ExtRpmbWrite, region as u32, start_sector, num_sectors)?;
    xml.download_data(port, data_len, reader, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn erase_rpmb<F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    progress: F,
) -> Result<()> {
    let total_bytes = num_sectors as u64 * RPMB_FRAME_DATA_SZ as u64;

    let zero_reader = std::io::repeat(0).take(total_bytes);

    write_rpmb(xml, port, region, start_sector, num_sectors, zero_reader, progress)
}

pub(super) fn auth_rpmb<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    key: &[u8],
) -> Result<()> {
    let key_hex = hex::encode(key);
    xmlcmd_e!(xml, port, ExtRpmbInit, region as u32, key_hex)
}
