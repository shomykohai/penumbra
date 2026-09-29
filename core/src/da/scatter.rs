/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::path::PathBuf;

use rust_yaml::{Value, Yaml};

use crate::error::PenumbraError;
use crate::storage::{EmmcPartition, UfsPartition};
use crate::utils::xml::{get_tag, get_tag_u64};
use crate::utils::yaml::YamlValueExt;
use crate::{Partition, PartitionKind, Result, Storage, StorageKind, StorageType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScatterOp {
    // In theory deprecated and defaults to "Update"
    Bootloader,
    Invisible,
    Update,
    Protected,
    BinRegion,
    Reserved,
    Logic,
    NeedResize,
}

impl From<ScatterOp> for &'static str {
    fn from(val: ScatterOp) -> Self {
        match val {
            ScatterOp::Bootloader => "BOOTLOADERS",
            ScatterOp::Invisible => "INVISIBLE",
            ScatterOp::Update => "UPDATE",
            ScatterOp::Protected => "PROTECTED",
            ScatterOp::BinRegion => "BINREGION",
            ScatterOp::Reserved => "RESERVED",
            ScatterOp::Logic => "LOGIC",
            ScatterOp::NeedResize => "NEEDRESIZE",
        }
    }
}

impl From<&str> for ScatterOp {
    fn from(val: &str) -> Self {
        match val {
            "BOOTLOADERS" => Self::Bootloader,
            "INVISIBLE" => Self::Invisible,
            "UPDATE" => Self::Update,
            "PROTECTED" => Self::Protected,
            "BINREGION" => Self::BinRegion,
            "RESERVED" => Self::Reserved,
            "LOGIC" => Self::Logic,
            "NEEDRESIZE" => Self::NeedResize,
            _ => Self::Invisible,
        }
    }
}

/// Represents a partition in a scatter file.
#[derive(Debug, Clone)]
pub struct ScatterPartition {
    /// The partition information.
    pub part: Partition,
    /// The path to the partition file.
    pub path: Option<PathBuf>,
    /// The operation to perform on the partition.
    pub op: ScatterOp,
    /// Whether the partition should be downloaded to the device.
    pub download: bool,
    /// The storage type of the partition.
    pub storage: StorageType,
    /// UFS host ID. Only available on newer scatters.
    pub host: Option<u32>,
}

impl ScatterPartition {
    pub const fn new(
        part: Partition,
        path: Option<PathBuf>,
        op: ScatterOp,
        download: bool,
        storage: StorageType,
        host: Option<u32>,
    ) -> Self {
        Self { part, path, op, download, host, storage }
    }

    pub const fn is_reserved(&self) -> bool {
        // Partitions after userdata are usually reserved, and their address is set to the
        // 0xFFFFXXXX range, so that tools will resize userdata correctly.
        matches!(self.op, ScatterOp::Reserved)
            && (self.part.address & 0xFFFF0000 == 0xFFFF0000
                || self.part.address & 0xFFFF000000000000 == 0xFFFF000000000000)
    }

    pub const fn is_protected(&self) -> bool {
        matches!(self.op, ScatterOp::Protected | ScatterOp::BinRegion)
    }

    pub const fn is_invisible(&self) -> bool {
        matches!(self.op, ScatterOp::Invisible)
    }

    pub const fn is_virtual(&self) -> bool {
        matches!(self.op, ScatterOp::Logic)
    }

    pub const fn need_resize(&self) -> bool {
        matches!(self.op, ScatterOp::NeedResize)
    }

    fn match_part_kind(region: &str) -> PartitionKind {
        if region.starts_with("UFS") {
            match region {
                "UFS_LU0" => PartitionKind::Ufs(UfsPartition::Lu0),
                "UFS_LU1" => PartitionKind::Ufs(UfsPartition::Lu1),
                "UFS_LU2" => PartitionKind::Ufs(UfsPartition::Lu2),
                // Mtk broke ABI, so on older devices this maps to what
                // on newer is LU3, so better stay safe and set to LU0
                "UFS_LU0_LU1" => PartitionKind::Ufs(UfsPartition::Lu0),
                _ => PartitionKind::Ufs(UfsPartition::Lu2),
            }
        } else {
            match region {
                "EMMC_BOOT1" => PartitionKind::Emmc(EmmcPartition::Boot1),
                "EMMC_BOOT2" => PartitionKind::Emmc(EmmcPartition::Boot2),
                "EMMC_BOOT1_BOOT2" => PartitionKind::Emmc(EmmcPartition::Boot1Boot2),
                "EMMC_USER" => PartitionKind::Emmc(EmmcPartition::User),
                _ => PartitionKind::Emmc(EmmcPartition::User),
            }
        }
    }

    pub fn from_yaml(item: &Value) -> Result<Self> {
        let part_name = item.get_str("partition_name").and_then(|v| v.as_str()).unwrap_or_default();
        let file_name = item.get_str("file_name").and_then(|v| v.as_str()).unwrap_or("NONE");
        let region_str = item.get_str("region").and_then(|v| v.as_str()).unwrap_or("");
        let is_download = item.get_bool("is_download").unwrap_or(false);
        let start_addr = item.get_num::<u64>("linear_start_addr").unwrap_or(0);
        let size = item.get_num::<u64>("partition_size").unwrap_or(0);

        let op =
            item.get_str("operation_type").and_then(|v| v.as_str()).unwrap_or("INVISIBLE").into();

        let path = if file_name == "NONE" { None } else { Some(PathBuf::from(file_name)) };

        let kind = Self::match_part_kind(region_str);
        let storage: StorageType = kind.into();

        let part = Partition { name: part_name.into(), address: start_addr, size, kind };

        let host = item.get_num::<u32>("host");

        Ok(Self::new(part, path, op, is_download, storage, host))
    }

    pub fn from_xml(xml: &str) -> Result<Self> {
        let part_name = get_tag(xml, "partition_name")?;
        let file_name: String = get_tag(xml, "file_name")?;
        let region_str: String = get_tag(xml, "region")?;
        let is_download = get_tag::<String>(xml, "is_download")? == "true";
        let start_addr = get_tag_u64(xml, "linear_start_addr")?;
        let size = get_tag_u64(xml, "partition_size")?;

        let op_str: String = get_tag(xml, "operation_type").unwrap_or_default();
        let op = if op_str.is_empty() { ScatterOp::Invisible } else { op_str.as_str().into() };

        let path = (file_name != "NONE").then(|| PathBuf::from(file_name));

        let kind = Self::match_part_kind(&region_str);
        let storage = kind.into();

        let part = Partition { name: part_name, address: start_addr, size, kind };

        let host = get_tag(xml, "host").ok();

        Ok(Self::new(part, path, op, is_download, storage, host))
    }

    pub const fn kind(&self) -> PartitionKind {
        self.part.kind
    }
}

#[derive(Debug)]
pub struct ScatterFile {
    pub parts: Vec<ScatterPartition>,
}

impl Default for ScatterFile {
    fn default() -> Self {
        Self::new()
    }
}

impl ScatterFile {
    pub const fn new() -> Self {
        Self { parts: vec![] }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let parser = Yaml::new();
        let parsed = parser.load_str(yaml)?;

        let parts = parsed
            .as_sequence()
            .into_iter()
            .flatten()
            .flat_map(|item| {
                if item.get_str("partition_index").is_some()
                    || item.get_str("partition_name").is_some()
                {
                    vec![item]
                } else {
                    item.get_str("description")
                        .and_then(|v| v.as_sequence())
                        .map(|seq| seq.iter().collect())
                        .unwrap_or_default()
                }
            })
            .filter_map(|item| ScatterPartition::from_yaml(item).ok())
            .collect();

        Ok(Self { parts })
    }

    pub fn from_xml(xml: &str) -> Result<Self> {
        let root = simple_xml::from_string(xml).map_err(|_| PenumbraError::InvalidScatterFile)?;

        // TODO: Remove to_string and parse the node directly
        let parts = root
            .get_nodes("partition_index")
            .into_iter()
            .flatten()
            .chain(
                root.get_nodes("storage_type")
                    .into_iter()
                    .flatten()
                    .flat_map(|n| n.get_nodes("partition_index").into_iter().flatten()),
            )
            .filter_map(|node| ScatterPartition::from_xml(&node.to_string()).ok())
            .collect();

        Ok(Self { parts })
    }

    pub fn partitions(&self) -> &[ScatterPartition] {
        &self.parts
    }

    /// Returns a vector of `ScatterPartition` matching the specified storage type.
    /// If the scatter file contains no partitions of the specified storage type, an empty vector is
    /// returned.
    pub fn partitions_by_storage(&self, storage: StorageType) -> Vec<&ScatterPartition> {
        self.parts.iter().filter(|p| p.storage == storage).collect()
    }

    /// Returns a vector of `ScatterPartition` after resizing partitions like userdata.
    pub fn partitions_resized(&self, storage: &StorageKind) -> Vec<ScatterPartition> {
        let mut parts: Vec<_> =
            self.parts.iter().filter(|p| p.storage == storage.kind()).cloned().collect();

        let user_size = storage.get_user_size();

        for idx in (0..parts.len()).rev() {
            if parts[idx].is_reserved() {
                let size = parts[idx].part.size;
                let current = parts[idx].part.address;

                parts[idx].part.address = if idx + 1 == parts.len() {
                    user_size.checked_sub(size).unwrap_or(current)
                } else {
                    parts[idx + 1].part.address.checked_sub(size).unwrap_or(current)
                };
            } else if (parts[idx].need_resize() || parts[idx].part.size == 0)
                && let Some(next) = parts.get(idx + 1)
            {
                let current = parts[idx].part.address;
                if let Some(sz) = next.part.address.checked_sub(current) {
                    parts[idx].part.size = sz;
                }
            }
        }

        parts
    }
}
