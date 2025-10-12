/*
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy

    Derived from:
    https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/DA/xflash/extension/xflash.py
    Original SPDX-License-Identifier: GPL-3.0-or-later
    Original SPDX-FileCopyrightText: 2018–2024 bkerler

    This file remains under the GPL-3.0-or-later license.
    However, as part of a larger project licensed under the AGPL-3.0-or-later,
    the combined work is subject to the networking terms of the AGPL-3.0-or-later,
    as for term 13 of the GPL-3.0-or-later license.
*/
use crate::error::{Error, Result};
use crate::core::utilities::find_pattern;
use crate::da::DAProtocol;
use crate::da::xflash::{Cmd, DataType, XFlash};
use log::{debug, info};

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_x.bin");

pub async fn boot_extensions(xflash: &mut XFlash) -> Result<bool> {
    debug!("Trying booting XFlash extensions...");

    let ext_data = prepare_extensions(xflash)
        .ok_or_else(|| Error::proto("Failed to prepare DA extensions"))?;

    let ext_addr = 0x68000000;
    let ext_size = ext_data.len() as u32;

    info!(
        "Uploading DA extensions to {:08X} ({} bytes)",
        ext_addr, ext_size
    );
    match xflash.boot_to(ext_addr, &ext_data).await {
        Ok(_) => {}
        // If DA extensions fail to upload, we just return false, not a fatal error
        Err(_) => {
            return Ok(false);
        }
    }
    info!("DA extensions uploaded");

    let ack = xflash.devctrl(Cmd::ExtAck, None).await?;
    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::proto(format!(
            "DA extensions failed to start: {:#X}",
            status
        )));
    }

    // Ack must be 0xA1A2A3A4
    if ack.len() < 4 || ack[0..4] != [0xA4, 0xA3, 0xA2, 0xA1] {
        return Err(Error::proto("DA extensions failed to start (invalid ACK)"));
    } else {
        info!("Received ack: {:02X?}", &ack[0..4]);
    }

    Ok(true)
}

fn prepare_extensions(xflash: &XFlash) -> Option<Vec<u8>> {
    let da2 = &xflash.da.get_da2()?.data;
    let da2address = xflash.da.get_da2()?.addr;

    let mut da_ext_data = DA_EXT.to_vec();

    // This allows to register DA Extensions custom commands (0x0F000X)
    let register_devctrl = find_pattern(da2, &[0x38, 0xB5, 0x05, 0x46, 0x0C, 0x20], 0);

    // TODO: Mess below, needs cleanup, consider replacing byte arrays with b"..."
    let mut mmc_get_card =
        find_pattern(da2, &[0x4B, 0x4F, 0xF4, 0x3C, 0x72], 0).map(|pos| pos.saturating_sub(1));

    if mmc_get_card.is_none() {
        mmc_get_card = find_pattern(
            da2,
            &[0xA3, 0xEB, 0x00, 0x13, 0x18, 0x1A, 0x02, 0xEB, 0x00, 0x10],
            0,
        )
        .map(|pos| pos.saturating_sub(10));
    }

    let mut mmc_set_part_config = None;
    let mut search_offset = 0;

    while let Some(pos) = find_pattern(da2, &[0xC3, 0x69, 0x0A, 0x46, 0x10, 0xB5], search_offset) {
        search_offset = pos + 1;

        if da2.len() >= pos + 22 && da2[pos + 20..pos + 22] == [0xB3, 0x21] {
            mmc_set_part_config = Some(pos);
            break;
        }
    }

    if mmc_set_part_config.is_none() {
        mmc_set_part_config = find_pattern(da2, &[0xC3, 0x69, 0x13, 0xF0, 0x01, 0x03], 0);
    }

    let mmc_rpmb_send_command =
        find_pattern(da2, &[0xF8, 0xB5, 0x06, 0x46, 0x9D, 0xF8, 0x18, 0x50], 0)
            .or_else(|| find_pattern(da2, &[0x2D, 0xE9, 0xF0, 0x41, 0x4F, 0xF6, 0xFD, 0x74], 0));

    let mut g_ufs_hba = None;
    let mut ptr_g_ufs_hba = find_pattern(
        da2,
        &[0x20, 0x46, 0x0B, 0xB0, 0xBD, 0xE8, 0xF0, 0x83, 0x00, 0xBF],
        0,
    );

    if let Some(ptr) = ptr_g_ufs_hba {
        if da2.len() >= ptr + 14 {
            g_ufs_hba = Some(u32::from_le_bytes([
                da2[ptr + 10],
                da2[ptr + 11],
                da2[ptr + 12],
                da2[ptr + 13],
            ]));
        }
    } else {
        ptr_g_ufs_hba = find_pattern(da2, &[0x20, 0x46, 0x0D, 0xB0, 0xBD, 0xE8, 0xF0, 0x83], 0);

        if let Some(ptr) = ptr_g_ufs_hba {
            if da2.len() >= ptr + 12 {
                g_ufs_hba = Some(u32::from_le_bytes([
                    da2[ptr + 8],
                    da2[ptr + 9],
                    da2[ptr + 10],
                    da2[ptr + 11],
                ]));
            }
        } else {
            ptr_g_ufs_hba = find_pattern(
                da2,
                &[0x21, 0x46, 0x02, 0xF0, 0x02, 0xFB, 0x1B, 0xE6, 0x00, 0xBF],
                0,
            );

            if let Some(ptr) = ptr_g_ufs_hba {
                if da2.len() >= ptr + 22 {
                    g_ufs_hba = Some(u32::from_le_bytes([
                        da2[ptr + 18],
                        da2[ptr + 19],
                        da2[ptr + 20],
                        da2[ptr + 21],
                    ]));
                }
            }
        }
    }

    let (ufshcd_get_free_tag, ufshcd_queuecommand) = if ptr_g_ufs_hba.is_some() {
        (
            find_pattern(da2, &[0xB5, 0x2E, 0xB1, 0x90, 0xF8], 0),
            find_pattern(da2, &[0x2D, 0xE9, 0xF8, 0x43, 0x01, 0x27], 0),
        )
    } else {
        (None, None)
    };

    // Actual patching starts here btw
    let register_ptr = find_pattern(&da_ext_data, &[0x11, 0x11, 0x11, 0x11], 0);
    let mmc_get_card_ptr = find_pattern(&da_ext_data, &[0x22, 0x22, 0x22, 0x22], 0);
    let mmc_set_part_config_ptr = find_pattern(&da_ext_data, &[0x33, 0x33, 0x33, 0x33], 0);
    let mmc_rpmb_send_command_ptr = find_pattern(&da_ext_data, &[0x44, 0x44, 0x44, 0x44], 0);
    let ufshcd_queuecommand_ptr = find_pattern(&da_ext_data, &[0x55, 0x55, 0x55, 0x55], 0);
    let ufshcd_get_free_tag_ptr = find_pattern(&da_ext_data, &[0x66, 0x66, 0x66, 0x66], 0);
    let ptr_g_ufs_hba_ptr = find_pattern(&da_ext_data, &[0x77, 0x77, 0x77, 0x77], 0);
    // let efuse_addr_ptr = find_pattern(&da_ext_data, &[0x88, 0x88, 0x88, 0x88], 0);

    if let (Some(register_ptr), Some(mmc_get_card_ptr)) = (register_ptr, mmc_get_card_ptr) {
        let register_devctrl = register_devctrl
            .map(|val| (val as u32 + da2address) | 1)
            .unwrap_or(0);
        let mmc_get_card = mmc_get_card
            .map(|val| (val as u32 + da2address) | 1)
            .unwrap_or(0);
        let mmc_set_part_config = mmc_set_part_config
            .map(|val| (val as u32 + da2address) | 1)
            .unwrap_or(0);
        let mmc_rpmb_send_command = mmc_rpmb_send_command
            .map(|val| (val as u32 + da2address) | 1)
            .unwrap_or(0);

        let ufshcd_get_free_tag = ufshcd_get_free_tag
            .map(|val| (val as u32 + da2address - 1) | 1)
            .unwrap_or(0);

        let ufshcd_queuecommand = ufshcd_queuecommand
            .map(|val| (val as u32 + da2address) | 1)
            .unwrap_or(0);

        let g_ufs_hba = g_ufs_hba.unwrap_or(0);

        da_ext_data[register_ptr..register_ptr + 4]
            .copy_from_slice(&(register_devctrl.to_le_bytes()));
        da_ext_data[mmc_get_card_ptr..mmc_get_card_ptr + 4]
            .copy_from_slice(&(mmc_get_card.to_le_bytes()));
        if let Some(p) = mmc_set_part_config_ptr {
            da_ext_data[p..p + 4].copy_from_slice(&(mmc_set_part_config.to_le_bytes()));
        }
        if let Some(p) = mmc_rpmb_send_command_ptr {
            da_ext_data[p..p + 4].copy_from_slice(&(mmc_rpmb_send_command.to_le_bytes()));
        }
        if let Some(p) = ufshcd_get_free_tag_ptr {
            da_ext_data[p..p + 4].copy_from_slice(&(ufshcd_get_free_tag.to_le_bytes()));
        }
        if let Some(p) = ufshcd_queuecommand_ptr {
            da_ext_data[p..p + 4].copy_from_slice(&(ufshcd_queuecommand.to_le_bytes()));
        }
        if let Some(p) = ptr_g_ufs_hba_ptr {
            da_ext_data[p..p + 4].copy_from_slice(&(g_ufs_hba.to_le_bytes()));
        }
        // TODO: Add efuse address

        return Some(da_ext_data);
    }
    None
}

// TODO: Rewrite these
pub async fn read32_ext(xflash: &mut XFlash, addr: u32) -> Result<u32> {
    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    if xflash.get_status().await? != 0 {
        return Err(Error::proto("DEVICE_CTRL failed"));
    }

    xflash.send_cmd(Cmd::ExtReadRegister).await?;
    if xflash.get_status().await? != 0 {
        return Err(Error::proto("ExtReadRegister failed"));
    }

    let addr_bytes = addr.to_le_bytes();

    let mut hdr = [0u8; 12];
    hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
    hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
    hdr[8..12].copy_from_slice(&4u32.to_le_bytes()); // length = 4

    debug!("[TX] Ext: sending address: 0x{:08X}", addr);
    xflash.conn.port.write_all(&hdr).await?;
    xflash.conn.port.write_all(&addr_bytes).await?;
    xflash.conn.port.flush().await?;

    let payload = xflash.read_data().await?;
    if payload.len() >= 4 {
        let status = xflash.get_status().await?;
        if status != 0 {
            return Err(Error::proto(format!(
                "ExtReadRegister failed: {:#X}",
                status
            )));
        }
        Ok(u32::from_le_bytes(payload[0..4].try_into().unwrap()))
    } else {
        let value = xflash.get_status().await?;
        Ok(value)
    }
}

pub async fn write32_ext(xflash: &mut XFlash, addr: u32, value: u32) -> Result<()> {
    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    if xflash.get_status().await? != 0 {
        return Err(Error::proto("DEVICE_CTRL failed"));
    }

    xflash.send_cmd(Cmd::ExtWriteRegister).await?;
    if xflash.get_status().await? != 0 {
        return Err(Error::proto("ExtWriteRegister failed"));
    }

    let addr_bytes = addr.to_le_bytes();

    let mut hdr1 = [0u8; 12];
    hdr1[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
    hdr1[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
    hdr1[8..12].copy_from_slice(&4u32.to_le_bytes());

    debug!("[TX] Ext: sending address: 0x{:08X}", addr);
    xflash.conn.port.write_all(&hdr1).await?;
    xflash.conn.port.write_all(&addr_bytes).await?;
    xflash.conn.port.flush().await?;

    let value_bytes = value.to_le_bytes();

    let mut hdr2 = [0u8; 12];
    hdr2[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
    hdr2[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
    hdr2[8..12].copy_from_slice(&4u32.to_le_bytes());

    debug!("[TX] Ext: sending value: 0x{:08X}", value);
    xflash.conn.port.write_all(&hdr2).await?;
    xflash.conn.port.write_all(&value_bytes).await?;
    xflash.conn.port.flush().await?;

    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::proto(format!(
            "ExtWriteRegister failed: {:#X}",
            status
        )));
    }

    Ok(())
}
