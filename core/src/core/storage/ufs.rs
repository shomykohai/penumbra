/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use wincode::{Deserialize, SchemaRead, SchemaWrite};

use crate::core::storage::{PartitionKind, Storage, StorageType};
use crate::error::{Error, Result};
use crate::utilities::xml::{get_tag, get_tag_u64, get_tag_usize};

#[repr(C)]
#[derive(Debug, SchemaRead, SchemaWrite, Clone)]
pub struct UfsInfo {
    pub kind: u32,
    pub block_size: u32,
    pub lu0_size: u64,
    pub lu1_size: u64,
    pub lu2_size: u64,
    #[wincode(skip)]
    pub lu3_size: u64,
    pub vendor_id: u16,
    pub cid: [u8; 20],
    pub fwver: [u8; 8],
    pub serial: [u8; 132],
    reserved: [u8; 8],
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

impl UfsPartition {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Lu0 => "UFS-LUA0",
            Self::Lu1 => "UFS-LUA1",
            Self::Lu2 => "UFS-LUA2",
            Self::Lu3 => "UFS-LUA3",
            Self::Lu4 => "UFS-LUA4",
            Self::Lu5 => "UFS-LUA5",
            Self::Lu6 => "UFS-LUA6",
            Self::Lu7 => "UFS-LUA7",
            Self::Lu0Lu1 => "UFS-LUA0LUA1",
            Self::Unknown => "UFS-UNKNOWN", // Assumed to be unreachable
        }
    }
}

#[derive(Debug, Clone)]
pub struct UfsStorage {
    pub info: UfsInfo,
}

impl Storage for UfsStorage {
    fn as_str(&self) -> &'static str {
        "UFS"
    }

    fn kind(&self) -> StorageType {
        StorageType::Ufs
    }

    fn block_size(&self) -> u32 {
        self.info.block_size
    }

    fn total_size(&self) -> u64 {
        self.info.lu2_size
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
        self.info.lu0_size
    }

    fn get_pl2_size(&self) -> u64 {
        self.info.lu1_size
    }

    fn get_user_size(&self) -> u64 {
        self.info.lu2_size
    }

    fn get_rpmb_size(&self) -> u64 {
        self.info.lu3_size
    }
}

impl UfsStorage {
    pub fn from_response(data: &[u8]) -> Result<Self> {
        if data.len() < 0xA8 {
            return Err(Error::io("UFS response data too short"));
        }

        let mut ufs_info = UfsInfo::deserialize(data)?;
        // On XFlash, MTK was so nice to not expose LU3 (RPMB) size on the
        // response payload, thus we have to hardcode it to 0 :(
        ufs_info.lu3_size = 0;

        Ok(Self { info: ufs_info })
    }

    pub fn from_xml_response(xml: &str) -> Result<Self> {
        let block_size = get_tag_usize(xml, "ufs/block_size")? as u32;
        let lu0_size = get_tag_u64(xml, "ufs/lua0_size")?;
        let lu1_size = get_tag_u64(xml, "ufs/lua1_size")?;
        let lu2_size = get_tag_u64(xml, "ufs/lua2_size")?;
        let lu3_size = get_tag_u64(xml, "ufs/lua3_size").unwrap_or(0);

        // Older devices use ufs_cid, newer ones use id
        let cid_str: String = get_tag(xml, "ufs/ufs_cid").or_else(|_| get_tag(xml, "ufs/id"))?;
        let mut cid = [0u8; 20];

        hex::decode_to_slice(cid_str.trim_start_matches("0x"), &mut cid)?;

        Ok(Self {
            info: UfsInfo {
                kind: 0x30,
                block_size,
                lu0_size,
                lu1_size,
                lu2_size,
                lu3_size,
                vendor_id: 0,
                cid,
                fwver: [0u8; 8],
                serial: [0u8; 132],
                reserved: [0u8; 8],
            },
        })
    }
}
