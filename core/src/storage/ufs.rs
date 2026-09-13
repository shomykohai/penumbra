/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use wincode::{Deserialize, SchemaRead, SchemaWrite};

use crate::error::Result;
use crate::storage::{PartitionKind, Storage, StorageType};
use crate::traits::FromBytes;
use crate::utils::xml::{get_tag, get_tag_hex, get_tag_u64};

#[repr(C)]
#[derive(Debug, SchemaRead, SchemaWrite, Clone, FromBytes)]
pub struct UfsInfoV2 {
    pub kind: u32,
    pub block_size: u32,
    pub lu0_size: u64,
    pub lu1_size: u64,
    pub lu2_size: u64,
    pub vendor_id: u16,
    pub cid: [u8; 20],
    pub fwver: [u8; 8],
    pub serial: [u8; 132],
    reserved: [u8; 8],
}

impl Default for UfsInfoV2 {
    fn default() -> Self {
        Self {
            kind: StorageType::Ufs as u32,
            block_size: 0,
            lu0_size: 0,
            lu1_size: 0,
            lu2_size: 0,
            vendor_id: 0,
            cid: [0u8; 20],
            fwver: [0u8; 8],
            serial: [0u8; 132],
            reserved: [0u8; 8],
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, SchemaRead, SchemaWrite, Clone, FromBytes)]
pub struct UfsInfoV1 {
    pub kind: u32,
    pub block_size: u32,
    pub lu0_size: u64,
    pub lu1_size: u64,
    pub lu2_size: u64,
    pub cid: [u8; 16],
    pub fwver: [u8; 4],
}

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
pub enum UfsInfo {
    V1(UfsInfoV1),
    V2(UfsInfoV2),
}

impl Default for UfsInfo {
    fn default() -> Self {
        Self::V2(UfsInfoV2::default())
    }
}

impl FromBytes for UfsInfo {
    // Minimal size
    const SIZE: usize = UfsInfoV1::SIZE;

    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::SIZE {
            return None;
        }

        let kind = u32::from_le_bytes(raw[0..4].try_into().ok()?);
        if kind != StorageType::Ufs as u32 {
            return None;
        }

        if raw.len() > UfsInfoV1::SIZE {
            Some(Self::V2(UfsInfoV2::from_bytes(raw)?))
        } else {
            Some(Self::V1(UfsInfoV1::from_bytes(raw)?))
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsPartition {
    /// Fallback case, should not be used
    Unknown = 0,
    /// Logical Unit 0, usually preloader
    Lu0 = 1,
    /// Logical Unit 1, usually preloader backup
    Lu1 = 2,
    /// Logical Unit 2, same as USER from EMMC
    Lu2 = 3,
    /// Logical Unit 3, RPMB
    Lu3 = 4,
    Lu4 = 5,
    Lu5 = 6,
    Lu6 = 7,
    Lu7 = 8,
    /// Both Logical Unit 0 and Logical Unit 1
    Lu0Lu1 = 9,
}

impl From<UfsPartition> for &'static str {
    fn from(val: UfsPartition) -> Self {
        match val {
            UfsPartition::Lu0 => "UFS-LUA0",
            UfsPartition::Lu1 => "UFS-LUA1",
            UfsPartition::Lu2 => "UFS-LUA2",
            UfsPartition::Lu3 => "UFS-LUA3",
            UfsPartition::Lu4 => "UFS-LUA4",
            UfsPartition::Lu5 => "UFS-LUA5",
            UfsPartition::Lu6 => "UFS-LUA6",
            UfsPartition::Lu7 => "UFS-LUA7",
            UfsPartition::Lu0Lu1 => "UFS-LUA0LUA1",
            UfsPartition::Unknown => "UFS-UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UfsStorage {
    pub info: UfsInfo,
    pub lu3_size: u64,
}

impl FromBytes for UfsStorage {
    const SIZE: usize = 0xC8;

    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < Self::SIZE {
            return None;
        }

        let info = UfsInfo::from_bytes(raw)?;
        Some(Self { info, lu3_size: 0 })
    }
}

impl Storage for UfsStorage {
    fn as_str(&self) -> &'static str {
        "UFS"
    }

    fn kind(&self) -> StorageType {
        StorageType::Ufs
    }

    fn block_size(&self) -> u32 {
        match self {
            Self { info: UfsInfo::V1(info), .. } => info.block_size,
            Self { info: UfsInfo::V2(info), .. } => info.block_size,
        }
    }

    fn total_size(&self) -> u64 {
        match self {
            Self { info: UfsInfo::V1(info), lu3_size } => {
                info.lu0_size + info.lu1_size + info.lu2_size + lu3_size
            }
            Self { info: UfsInfo::V2(info), lu3_size } => {
                info.lu0_size + info.lu1_size + info.lu2_size + lu3_size
            }
        }
    }

    fn get_user_part(&self) -> PartitionKind {
        PartitionKind::Ufs(UfsPartition::Lu2)
    }

    fn get_pl_part1(&self) -> PartitionKind {
        PartitionKind::Ufs(UfsPartition::Lu0)
    }

    fn get_pl_part2(&self) -> PartitionKind {
        PartitionKind::Ufs(UfsPartition::Lu1)
    }

    fn get_pl1_size(&self) -> u64 {
        match self {
            Self { info: UfsInfo::V1(info), .. } => info.lu0_size,
            Self { info: UfsInfo::V2(info), .. } => info.lu0_size,
        }
    }

    fn get_pl2_size(&self) -> u64 {
        match self {
            Self { info: UfsInfo::V1(info), .. } => info.lu1_size,
            Self { info: UfsInfo::V2(info), .. } => info.lu1_size,
        }
    }

    fn get_user_size(&self) -> u64 {
        match self {
            Self { info: UfsInfo::V1(info), .. } => info.lu2_size,
            Self { info: UfsInfo::V2(info), .. } => info.lu2_size,
        }
    }

    fn get_rpmb_size(&self) -> u64 {
        self.lu3_size
    }
}

impl UfsStorage {
    pub fn from_xml(xml: &str) -> Result<Self> {
        let block_size = get_tag_hex::<u32>(xml, "ufs/block_size")?;
        let lu0_size = get_tag_u64(xml, "ufs/lua0_size")?;
        let lu1_size = get_tag_u64(xml, "ufs/lua1_size")?;
        let lu2_size = get_tag_u64(xml, "ufs/lua2_size")?;
        let lu3_size = get_tag_u64(xml, "ufs/lua3_size").unwrap_or(0);

        // Older devices use ufs_cid, newer ones use id
        let cid_str: String = get_tag(xml, "ufs/ufs_cid").or_else(|_| get_tag(xml, "ufs/id"))?;
        let mut cid = [0u8; 20];

        hex::decode_to_slice(cid_str.trim_start_matches("0x"), &mut cid)?;

        Ok(Self {
            info: UfsInfo::V2(UfsInfoV2 {
                kind: StorageType::Ufs as u32,
                block_size,
                lu0_size,
                lu1_size,
                lu2_size,
                vendor_id: 0,
                cid,
                fwver: [0u8; 8],
                serial: [0u8; 132],
                reserved: [0u8; 8],
            }),
            lu3_size,
        })
    }
}
