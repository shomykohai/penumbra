/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use log::debug;

use crate::da::xml::Xml;
use crate::da::xml::cmd::{GetHwInfo, XmlCmdLifetime};
use crate::port::MtkPort;
use crate::storage::{EmmcStorage, StorageKind, UfsStorage};
use crate::utils::xml::get_tag;

pub fn detect_storage<P: MtkPort>(xml: &mut Xml, port: &mut P) -> Option<StorageKind> {
    xmlcmd!(xml, port, GetHwInfo).ok();

    let reponse = xml.get_upload_file_resp(port).ok()?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd).ok()?;
    let storage_str: String = get_tag(&reponse, "storage").ok()?;

    match storage_str.as_str() {
        "EMMC" => {
            debug!("eMMC storage detected.");
            match EmmcStorage::from_xml(&reponse) {
                Ok(storage) => return Some(StorageKind::Emmc(storage)),
                Err(e) => debug!("Failed to parse eMMC HW-INFO response: {e}\n{reponse}"),
            }
        }
        "UFS" => {
            debug!("UFS storage detected.");
            match UfsStorage::from_xml(&reponse) {
                Ok(storage) => return Some(StorageKind::Ufs(storage)),
                Err(e) => debug!("Failed to parse UFS HW-INFO response: {e}\n{reponse}"),
            }
        }
        _ => {}
    }

    None
}
