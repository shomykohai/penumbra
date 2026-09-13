/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use crc32fast::hash as crc32;
use uuid::Uuid;
use wincode::{Deserialize, SchemaRead, SchemaWrite, Serialize};

use crate::error::{PenumbraError, Result};
use crate::storage::{Partition, Storage, StorageKind, is_pl_part};
use crate::traits::ToBytes;

const EFI_PART_SIGNATURE: &[u8; 8] = b"EFI PART";
pub const GPT_SIZE: usize = 32 * 1024; // 32KB
pub const MAX_GPT_PARTS: usize = 128;
const GPT_HEADER_SIZE: usize = 92;
const PART_ARRAY_SIZE: usize = MAX_GPT_PARTS * GptEntry::SIZE;
const BASIC_DATA_GUID: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptType {
    Pgpt,
    Sgpt,
}

#[derive(SchemaRead, SchemaWrite, Debug, Clone)]
struct EfiGuid([u8; 16]);

impl EfiGuid {
    fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

#[repr(C)]
#[derive(SchemaRead, SchemaWrite, Debug, Clone)]
pub struct GptHeader {
    signature: [u8; 8],
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    reserved: u32,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: EfiGuid,
    part_entry_lba: u64,
    num_entries: u32,
    entry_size: u32,
    part_array_crc32: u32,
    #[wincode(skip)]
    sector_size: usize,
}

impl GptHeader {
    fn compute_crc(&self) -> Option<u32> {
        let mut tmp = self.clone();
        tmp.header_crc32 = 0;

        let buf = Self::serialize(&tmp).ok()?;
        let size = self.header_size as usize;

        if size != GPT_HEADER_SIZE || size != buf.len() {
            return None;
        }

        Some(crc32(&buf[..size]))
    }
}

#[derive(SchemaRead, SchemaWrite, Debug, ToBytes)]
pub struct GptEntry {
    part_type_guid: EfiGuid,
    unique_guid: EfiGuid,
    start_lba: u64,
    end_lba: u64,
    attributes: u64,
    name: [u16; 36],
}

impl GptEntry {
    pub fn name(&self) -> String {
        String::from_utf16_lossy(&self.name).trim_end_matches('\0').into()
    }

    fn is_unused(&self) -> bool {
        self.part_type_guid.is_zero() || self.start_lba == 0
    }
}

#[derive(Debug)]
pub struct Gpt {
    gpt_type: GptType,
    header: GptHeader,
    entries: Vec<GptEntry>,
    entries_crc32: u32,
}

impl Gpt {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (gpt_type, sector_size, header_offset) =
            Self::detect_type(data).ok_or(PenumbraError::GptHeaderInvalid)?;

        let mut header = GptHeader::deserialize(&data[header_offset..])?;
        header.sector_size = sector_size;

        let num_entries = header.num_entries as usize;
        let entry_size = header.entry_size as usize;

        if entry_size == 0 || entry_size > GPT_SIZE {
            return Err(PenumbraError::GptEntrySizeInvalid.into());
        }

        let len =
            num_entries.checked_mul(entry_size).ok_or(PenumbraError::GptEntryArrayOverflow)?;

        let entries_data = match gpt_type {
            GptType::Pgpt => {
                let start = usize::try_from(
                    header
                        .part_entry_lba
                        .checked_mul(sector_size as u64)
                        .ok_or(PenumbraError::GptEntryArrayOverflow)?,
                )
                .map_err(|_| PenumbraError::GptEntryArrayOverflow)?;
                let end = start.checked_add(len).ok_or(PenumbraError::GptEntryArrayOverflow)?;

                data.get(start..end).ok_or(PenumbraError::PartitionArrayOutOfBounds)?
            }
            GptType::Sgpt => {
                let start =
                    header_offset.checked_sub(len).ok_or(PenumbraError::SgptBufferTooSmall)?;

                data.get(start..header_offset).ok_or(PenumbraError::PartitionArrayOutOfBounds)?
            }
        };

        let entries_crc32 = crc32(entries_data);

        let mut entries = Vec::with_capacity(num_entries.min(MAX_GPT_PARTS));

        for i in 0..num_entries {
            let off = i * entry_size;
            if off + entry_size > entries_data.len() {
                return Err(PenumbraError::PartitionEntryOutOfBounds.into());
            }

            let entry = GptEntry::deserialize(&entries_data[off..off + entry_size])?;
            if entry.is_unused() {
                continue;
            }

            entries.push(entry);
        }

        let gpt = Self { gpt_type, header, entries, entries_crc32 };

        if !gpt.is_valid() {
            return Err(PenumbraError::GptChecksumMismatch.into());
        }

        Ok(gpt)
    }

    fn detect_type(data: &[u8]) -> Option<(GptType, usize, usize)> {
        let end = data.len();
        let sector_sizes = [512, 1024, 2048, 4096, 8192];

        for &sector_size in &sector_sizes {
            if end >= sector_size + 8
                && &data[end - sector_size..end - sector_size + 8] == EFI_PART_SIGNATURE
            {
                return Some((GptType::Sgpt, sector_size, end - sector_size));
            }
        }

        for &sector_size in &sector_sizes {
            if data.len() >= sector_size + 8
                && &data[sector_size..sector_size + 8] == EFI_PART_SIGNATURE
            {
                return Some((GptType::Pgpt, sector_size, sector_size));
            }
        }

        None
    }

    pub fn to_partitions(self, storage: &StorageKind) -> Vec<Partition> {
        let user_section = storage.get_user_part();

        let mut partitions = Vec::with_capacity(MAX_GPT_PARTS);

        for entry in &self.entries {
            if entry.end_lba < entry.start_lba {
                continue;
            }

            let Some(blocks) =
                entry.end_lba.checked_sub(entry.start_lba).and_then(|b| b.checked_add(1))
            else {
                continue;
            };

            let Some(part_size) = blocks.checked_mul(self.header.sector_size as u64) else {
                continue;
            };

            let Some(address) = entry.start_lba.checked_mul(self.header.sector_size as u64) else {
                continue;
            };

            partitions.push(Partition::new(&entry.name(), part_size, address, user_section));
        }

        partitions
    }

    pub fn is_valid(&self) -> bool {
        self.header.compute_crc().unwrap_or_default() == self.header.header_crc32
            && self.entries_crc32 == self.header.part_array_crc32
    }

    fn build_part_array(entries: &[GptEntry]) -> Option<([u8; PART_ARRAY_SIZE], u32)> {
        if entries.len() > MAX_GPT_PARTS {
            return None;
        }

        let mut part_array = [0u8; PART_ARRAY_SIZE];

        for (i, entry) in entries.iter().enumerate() {
            let offset = i * GptEntry::SIZE;
            let bytes = GptEntry::serialize(entry).ok()?;

            if bytes.len() != GptEntry::SIZE {
                return None;
            }

            part_array[offset..offset + GptEntry::SIZE].copy_from_slice(&bytes);
        }

        let crc = crc32(&part_array);

        Some((part_array, crc))
    }

    const fn part_array_blocks(block_size: u64) -> u64 {
        (PART_ARRAY_SIZE as u64).div_ceil(block_size)
    }

    pub fn from_partitions(
        value: &[Partition],
        storage: &StorageKind,
        gpt_type: GptType,
    ) -> Option<Self> {
        if storage.block_size() == 0 {
            return None;
        }

        let block_size = storage.block_size() as u64;
        let mut gpt_entries = Vec::with_capacity(MAX_GPT_PARTS);

        for part in value {
            if is_pl_part(&part.name) || ["PGPT", "SGPT"].contains(&part.name.as_str()) {
                continue;
            }

            let uuid = Uuid::new_v4().into_bytes();

            if part.size == 0 {
                continue;
            }

            let blocks = part.size.div_ceil(block_size);
            let start_lba = part.address / block_size;
            let Some(end_lba) = start_lba.checked_add(blocks).and_then(|e| e.checked_sub(1)) else {
                continue;
            };
            let mut name_raw = [0u16; 36];

            for (dest, src) in name_raw.iter_mut().zip(part.name.encode_utf16()) {
                *dest = src;
            }

            let entry = GptEntry {
                part_type_guid: EfiGuid(BASIC_DATA_GUID),
                unique_guid: EfiGuid(uuid),
                start_lba,
                end_lba,
                attributes: 0,
                name: name_raw,
            };

            gpt_entries.push(entry);
        }

        let array_blocks = Self::part_array_blocks(block_size);

        let total_size = storage.get_user_size();
        let block_size_u64 = storage.block_size() as u64;

        let last_lba = (total_size / block_size_u64).saturating_sub(1);

        let last_usable_lba =
            ((total_size.saturating_sub(GPT_SIZE as u64)) / block_size_u64).saturating_sub(1);

        let (current_lba, backup_lba, part_lba) = match gpt_type {
            GptType::Pgpt => (1, last_lba, 2),
            GptType::Sgpt => (last_lba, 1, last_usable_lba + 1),
        };

        let (_, part_array_crc) = Self::build_part_array(&gpt_entries)?;

        let mut header = GptHeader {
            signature: EFI_PART_SIGNATURE.to_owned(),
            revision: 0x10000,
            header_size: GPT_HEADER_SIZE as u32,
            header_crc32: 0,
            reserved: 0,
            current_lba,
            backup_lba,
            first_usable_lba: 2 + array_blocks,
            last_usable_lba,
            disk_guid: EfiGuid([0u8; 16]),
            part_entry_lba: part_lba,
            num_entries: MAX_GPT_PARTS as u32,
            entry_size: GptEntry::SIZE as u32,
            part_array_crc32: part_array_crc,
            sector_size: block_size as usize,
        };

        header.header_crc32 = header.compute_crc()?;

        Some(Self { gpt_type, header, entries: gpt_entries, entries_crc32: part_array_crc })
    }

    pub fn to_bytes(&self) -> Option<[u8; GPT_SIZE]> {
        let (part_array, part_array_crc) = Self::build_part_array(&self.entries)?;

        let mut header = self.header.clone();
        header.header_size = GPT_HEADER_SIZE as u32;
        header.num_entries = MAX_GPT_PARTS as u32;
        header.entry_size = GptEntry::SIZE as u32;
        header.part_array_crc32 = part_array_crc;
        header.header_crc32 = header.compute_crc()?;

        let header_bytes = GptHeader::serialize(&header).ok()?;

        let block_size = header.sector_size;
        if block_size == 0 || header_bytes.len() > block_size {
            return None;
        }

        let mut gpt = [0u8; GPT_SIZE];

        match self.gpt_type {
            GptType::Pgpt => {
                /* TODO: ADD MBR to offset 0 */
                let header_off = block_size;
                let entries_off = block_size * 2;

                if entries_off + PART_ARRAY_SIZE > GPT_SIZE {
                    return None;
                }

                gpt[header_off..header_off + header_bytes.len()].copy_from_slice(&header_bytes);
                gpt[entries_off..entries_off + PART_ARRAY_SIZE].copy_from_slice(&part_array);
            }
            GptType::Sgpt => {
                let header_off = GPT_SIZE.checked_sub(block_size)?;
                let entries_off = header_off.checked_sub(PART_ARRAY_SIZE)?;

                gpt[entries_off..entries_off + PART_ARRAY_SIZE].copy_from_slice(&part_array);
                gpt[header_off..header_off + header_bytes.len()].copy_from_slice(&header_bytes);
            }
        }

        Some(gpt)
    }
}
