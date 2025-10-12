/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::error::{Error, Result};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    Unknown = 0, // How do you even-
    Emmc = 0x1,
    Ufs = 0x30,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmmcPartition {
    Boot1 = 1,
    Boot2 = 2,
    Rpmb = 3,
    Gp1 = 4,
    Gp2 = 5,
    Gp3 = 6,
    Gp4 = 7,
    User = 8,
    End = 9,
    Boot1Boot2 = 10,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsPartition {
    Lu0 = 0,
    Lu1 = 1,
    Lu2 = 2,
    Lu3 = 3,
    Lu4 = 4,
    Lu5 = 5,
    Lu6 = 6,
    Lu7 = 7,
    Lu8 = 8,
}

#[derive(Debug, Clone)]
pub enum PartitionKind {
    Emmc(EmmcPartition),
    Ufs(UfsPartition),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub size: usize,
    pub address: u64,
    pub kind: PartitionKind,
}

impl Partition {
    pub fn new(name: &str, size: usize, address: u64, kind: PartitionKind) -> Self {
        Self {
            name: name.to_string(),
            size,
            address,
            kind,
        }
    }
}

// Oh dear Mediatek! Why make me lose 2 hours over this!
// Why in the scatter file you have reserved partitions prefixed with 0xFFFF,
// but then I can just dump them with non reserved addresses? <3
// Over such a simple task, I lost too much time ._.
pub fn parse_gpt(data: &[u8], storage_type: StorageType) -> Result<Vec<Partition>> {
    let mut sector_size: Option<usize> = None;

    let sector_sizes = [512, 4096, 0x8000, 0x10000, 0x20000];
    for &ss in &sector_sizes {
        if data.len() >= ss + 8 && &data[ss..ss + 8] == b"EFI PART" {
            sector_size = Some(ss);
            break;
        }
    }

    let sector_size = match sector_size {
        Some(size) => 512,
        None => {
            return Err(Error::penumbra("No valid GPT header found"));
        }
    };

    let hdr = &data[sector_size..sector_size * 2];
    let partition_entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap());

    if entry_size as usize != 128 {
        return Err(Error::penumbra("Unsupported partition entry size"));
    }

    let start_offset = (partition_entry_lba as usize) * sector_size;
    let mut partitions: Vec<Partition> = Vec::new();
    let part_kind = match storage_type {
        StorageType::Emmc => PartitionKind::Emmc(EmmcPartition::User),
        StorageType::Ufs => PartitionKind::Ufs(UfsPartition::Lu2),
        _ => PartitionKind::Unknown,
    };

    for i in 0..num_entries {
        let current_offset = start_offset + (i as usize * entry_size as usize);

        let entry = &data[current_offset..current_offset + entry_size as usize];

        // Yeet empty entries
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }

        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());

        if last_lba < first_lba {
            return Err(Error::io("Partition last_lba < first_lba"));
        }

        let part_size = (last_lba - first_lba + 1) * sector_size as u64;
        let part_addr = first_lba * sector_size as u64;

        let part_name = String::from_utf16_lossy(
            &entry[56..128]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|&c| c != 0)
                .collect::<Vec<u16>>(),
        );

        partitions.push(Partition::new(
            &part_name,
            part_size as usize,
            part_addr,
            part_kind.clone(),
        ));
    }

    Ok(partitions)
}
