/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use log::debug;

use crate::core::storage::StorageKind;
use crate::core::storage::emmc::EmmcStorage;
use crate::core::storage::ufs::UfsStorage;
use crate::da::xml::Xml;
use crate::da::xml::cmds::{GetHwInfo, XmlCmdLifetime};
use crate::utilities::xml::get_tag;

pub fn detect_storage(xml: &mut Xml) -> Option<StorageKind> {
    xmlcmd!(xml, GetHwInfo).ok();

    let reponse = xml.get_upload_file_resp().ok()?;

    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).ok()?;
    let storage_str: String = get_tag(&reponse, "storage").ok()?;

    match storage_str.as_str() {
        "EMMC" => {
            debug!("eMMC storage detected.");
            match EmmcStorage::from_xml_response(&reponse) {
                Ok(storage) => return Some(StorageKind::Emmc(storage)),
                Err(e) => debug!("Failed to parse eMMC HW-INFO response: {e}\n{reponse}"),
            }
        }
        "UFS" => {
            debug!("UFS storage detected.");
            match UfsStorage::from_xml_response(&reponse) {
                Ok(storage) => return Some(StorageKind::Ufs(storage)),
                Err(e) => debug!("Failed to parse UFS HW-INFO response: {e}\n{reponse}"),
            }
        }
        _ => {}
    }

    None
}
