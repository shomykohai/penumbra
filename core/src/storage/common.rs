/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use enum_dispatch::enum_dispatch;

use super::{EmmcPartition, UfsPartition};
use crate::error::PenumbraError;
use crate::storage::emmc::EmmcStorage;
use crate::storage::ufs::UfsStorage;

pub const RPMB_FRAME_DATA_SZ: usize = 0x100;

pub type Partitions = std::vec::IntoIter<Partition>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmbRegion {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
}

impl TryFrom<u8> for RpmbRegion {
    type Error = PenumbraError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::R0),
            1 => Ok(Self::R1),
            2 => Ok(Self::R2),
            3 => Ok(Self::R3),
            _ => Err(PenumbraError::InvalidRpmbRegion),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PartitionKind {
    Emmc(EmmcPartition),
    Ufs(UfsPartition),
    Unknown,
}

impl PartialEq for PartitionKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Emmc(a), Self::Emmc(b)) => a == b,
            (Self::Ufs(a), Self::Ufs(b)) => a == b,
            (Self::Unknown, Self::Unknown) => true,
            _ => false,
        }
    }
}
impl From<PartitionKind> for StorageType {
    fn from(val: PartitionKind) -> Self {
        match val {
            PartitionKind::Emmc(_) => Self::Emmc,
            PartitionKind::Ufs(_) => Self::Ufs,
            PartitionKind::Unknown => Self::Unknown,
        }
    }
}

impl core::fmt::Display for PartitionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl From<PartitionKind> for &'static str {
    fn from(val: PartitionKind) -> Self {
        match val {
            PartitionKind::Emmc(emmc) => emmc.into(),
            PartitionKind::Ufs(ufs) => ufs.into(),
            PartitionKind::Unknown => "Unknown",
        }
    }
}

impl From<PartitionKind> for String {
    fn from(val: PartitionKind) -> Self {
        let s: &'static str = val.into();
        s.to_string()
    }
}

impl From<PartitionKind> for u32 {
    fn from(val: PartitionKind) -> Self {
        match val {
            PartitionKind::Emmc(emmc) => emmc as Self,
            PartitionKind::Ufs(ufs) => ufs as Self,
            PartitionKind::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub size: u64,
    pub address: u64,
    pub kind: PartitionKind,
}

impl Partition {
    pub fn new(name: &str, size: u64, address: u64, kind: PartitionKind) -> Self {
        Self { name: name.to_string(), size, address, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    Unknown = 0,
    Emmc = 0x1,
    Sdmmc = 0x2,
    Nand = 0x10,
    NandSlc = 0x11,
    NandMlc = 0x12,
    NandTlc = 0x13,
    NandAmlc = 0x14,
    NandSpi = 0x15,
    Nand3dMlc = 0x16,
    Ufs = 0x30,
}

impl StorageType {
    pub const fn is_nand(&self) -> bool {
        matches!(
            self,
            Self::Nand
                | Self::NandSlc
                | Self::NandMlc
                | Self::NandTlc
                | Self::NandAmlc
                | Self::NandSpi
                | Self::Nand3dMlc
        )
    }
}

#[enum_dispatch(Storage)]
#[derive(Clone)]
pub enum StorageKind {
    Emmc(EmmcStorage),
    Ufs(UfsStorage),
}

#[enum_dispatch]
pub trait Storage {
    fn as_str(&self) -> &'static str {
        "Unknown"
    }

    fn kind(&self) -> StorageType;
    fn block_size(&self) -> u32;
    fn total_size(&self) -> u64;

    fn get_user_part(&self) -> PartitionKind;
    fn get_pl_part1(&self) -> PartitionKind;
    fn get_pl_part2(&self) -> PartitionKind;

    fn get_pl1_size(&self) -> u64;
    fn get_pl2_size(&self) -> u64;
    fn get_user_size(&self) -> u64;
    fn get_rpmb_size(&self) -> u64;
}

pub fn is_pl_part(name: &str) -> bool {
    matches!(name, "preloader" | "preloader_backup")
}

pub fn is_sparse(magic: &[u8]) -> bool {
    const SPARSE_MAGIC: [u8; 4] = [0x3A, 0xFF, 0x26, 0xED];
    magic == SPARSE_MAGIC
}
