/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use wincode::{Deserialize, SchemaRead, SchemaWrite};

use crate::core::storage::{PartitionKind, Storage, StorageType};
use crate::error::{Error, Result};
use crate::utilities::xml::{get_tag, get_tag_u64, get_tag_usize};

/// Represents eMMC storage information.
#[derive(Debug, SchemaRead, SchemaWrite, Clone)]
pub struct EmmcInfo {
    /// eMMC kind (EMMC or SDMMC)
    pub kind: u32,
    /// eMMC block size in bytes.
    pub block_size: u32,
    /// Size of Boot1 section in bytes.
    pub boot1_size: u64,
    /// Size of Boot2 section in bytes.
    pub boot2_size: u64,
    /// Size of RPMB section in bytes.
    pub rpmb_size: u64,
    /// Size of GP1 in bytes.,
    pub gp1_size: u64,
    /// Size of GP2 in bytes.
    pub gp2_size: u64,
    /// Size of GP3 in bytes.
    pub gp3_size: u64,
    /// Size of GP4 in bytes.
    pub gp4_size: u64,
    /// Size of User section in bytes.
    pub user_size: u64,
    /// eMMC CID (Card Identification) register value.
    pub cid: [u8; 16],
    /// eMMC firmware version.
    pub fwver: [u8; 8],
    /// Other fields
    reserved: [u8; 8],
}

/// Represents eMMC partitions types.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmmcPartition {
    /// Boot1 partition, usually contains preloader.
    Boot1 = 1,
    /// Boot2 partition, usually contains preloader backup.
    Boot2 = 2,
    /// Replay Protected Memory Block partition, used for secure data storage.
    Rpmb = 3,
    /// General Purpose partition 1.
    Gp1 = 4,
    /// General Purpose partition 2.
    Gp2 = 5,
    /// General Purpose partition 3.
    Gp3 = 6,
    /// General Purpose partition 4.
    Gp4 = 7,
    /// User data partition, ths main storage area for user data and scatter partitions.
    User = 8,
    End = 9,
    /// Both Boot1 and Boot2 partitions.
    Boot1Boot2 = 10,
}

impl EmmcPartition {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Boot1 => "EMMC-BOOT1",
            Self::Boot2 => "EMMC-BOOT2",
            Self::Rpmb => "EMMC-RPMB",
            Self::Gp1 => "EMMC-GP1",
            Self::Gp2 => "EMMC-GP2",
            Self::Gp3 => "EMMC-GP3",
            Self::Gp4 => "EMMC-GP4",
            Self::User => "EMMC-USER",
            Self::End => "EMMC-END",
            Self::Boot1Boot2 => "EMMC-BOOT1BOOT2",
        }
    }
}

/// Represents eMMC storage device.
#[derive(Debug, Clone)]
pub struct EmmcStorage {
    /// eMMC storage information.
    pub info: EmmcInfo,
}

impl Storage for EmmcStorage {
    fn as_str(&self) -> &'static str {
        "EMMC"
    }

    fn kind(&self) -> StorageType {
        StorageType::Emmc
    }

    fn block_size(&self) -> u32 {
        self.info.block_size
    }

    fn total_size(&self) -> u64 {
        self.info.user_size
            + self.info.boot1_size
            + self.info.boot2_size
            + self.info.rpmb_size
            + self.info.gp1_size
            + self.info.gp2_size
            + self.info.gp3_size
            + self.info.gp4_size
    }

    fn get_user_part(&self) -> PartitionKind {
        PartitionKind::Emmc(EmmcPartition::User)
    }

    fn get_pl_part1(&self) -> PartitionKind {
        PartitionKind::Emmc(EmmcPartition::Boot1)
    }

    fn get_pl_part2(&self) -> PartitionKind {
        PartitionKind::Emmc(EmmcPartition::Boot2)
    }

    fn get_pl1_size(&self) -> u64 {
        self.info.boot1_size
    }

    fn get_pl2_size(&self) -> u64 {
        self.info.boot2_size
    }

    fn get_user_size(&self) -> u64 {
        self.info.user_size
    }

    fn get_rpmb_size(&self) -> u64 {
        self.info.rpmb_size
    }
}

impl EmmcStorage {
    pub fn from_response(data: &[u8]) -> Result<Self> {
        if data.len() < 96 {
            return Err(Error::penumbra("Emmc response data too short"));
        }

        let storage = Self { info: EmmcInfo::deserialize(data).unwrap() };

        Ok(storage)
    }

    pub fn from_xml_response(xml: &str) -> Result<Self> {
        let block_size = get_tag_usize(xml, "emmc/block_size")? as u32;

        let boot1_size = get_tag_u64(xml, "emmc/boot1_size")?;
        let boot2_size = get_tag_u64(xml, "emmc/boot2_size")?;
        let rpmb_size = get_tag_u64(xml, "emmc/rpmb_size")?;
        let gp1_size = get_tag_u64(xml, "emmc/gp1_size")?;
        let gp2_size = get_tag_u64(xml, "emmc/gp2_size")?;
        let gp3_size = get_tag_u64(xml, "emmc/gp3_size")?;
        let gp4_size = get_tag_u64(xml, "emmc/gp4_size")?;
        let user_size = get_tag_u64(xml, "emmc/user_size")?;

        let cid_str: String = get_tag(xml, "emmc/id")?;
        let mut cid = [0u8; 16];
        hex::decode_to_slice(cid_str, &mut cid)?;

        Ok(Self {
            info: EmmcInfo {
                kind: 0x1,
                block_size,
                boot1_size,
                boot2_size,
                rpmb_size,
                gp1_size,
                gp2_size,
                gp3_size,
                gp4_size,
                user_size,
                cid,
                fwver: [0; 8],
                reserved: [0; 8],
            },
        })
    }
}
