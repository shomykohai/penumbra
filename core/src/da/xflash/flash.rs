/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use crate::da::DAProtocol;
use crate::da::xflash::XFlash;
use crate::da::xflash::cmds::*;
use crate::error::{Error, Result, XFlashError};
use log::{debug, error, info};

pub async fn read_flash<F>(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    mut progress: F,
) -> Result<Vec<u8>>
where
    F: FnMut(usize, usize),
{
    info!("Reading flash at address {:#X} with size {:#X}", addr, size);

    // Format:
    // Storage Type (EMMC, UFS, NAND) u32
    // PartType u32 (BOOT or USER for EMMC)
    // Address u32
    // Size u32
    // Nand Specific
    //
    // 01000000 u32
    // 08000000 u32
    // 0000000000000000 u64
    // 4400000000000000 u64
    // 0000000000000000000000000000000000000000000000000000000000000000 8u32
    // The payload above is sent when reading PGPT (addr: 0x0, size: 0x44)
    let storage_type = 1u32; // TODO: Add support for other storage types
    let partition_type = 8u32; // USER partition
    let nand_ext = [0u32; 8]; // Nand specific, set to 0 for non-nand storage types

    let mut param = Vec::new();
    param.extend_from_slice(&storage_type.to_le_bytes());
    param.extend_from_slice(&partition_type.to_le_bytes());
    param.extend_from_slice(&addr.to_le_bytes());
    param.extend_from_slice(&(size as u64).to_le_bytes());
    // Which basically means: append it! Improvements are welcome.
    param.extend_from_slice(
        &nand_ext
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>(),
    );

    xflash.send_cmd(Cmd::ReadData).await?;

    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    xflash.send_data(&param).await?;

    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    let mut buffer = Vec::with_capacity(size);
    let mut bytes_read = 0;

    // Read chunk, send acknowledgment, status, repeat until profit
    loop {
        let chunk = xflash.read_data().await?;
        if chunk.is_empty() {
            debug!("No data received, breaking.");
            break;
        }
        buffer.extend_from_slice(&chunk);
        bytes_read += chunk.len();

        // As always, header + payload.
        // TODO: Consider using self.send() for this.
        let mut ack_hdr = [0u8; 12];
        ack_hdr[0..4].copy_from_slice(&(Cmd::Magic as u32).to_le_bytes());
        ack_hdr[4..8].copy_from_slice(&(DataType::ProtocolFlow as u32).to_le_bytes());
        ack_hdr[8..12].copy_from_slice(&4u32.to_le_bytes());
        let ack_payload = [0u8; 4];

        xflash.conn.port.write_all(&ack_hdr).await?;
        xflash.conn.port.write_all(&ack_payload).await?;
        xflash.conn.port.flush().await?;

        let status = xflash.get_status().await?;
        debug!("Status after chunk: 0x{:08X}", status);

        if status != 0 {
            debug!("Breaking loop, status: 0x{:08X}", status);
            break;
        }
        if bytes_read >= size {
            debug!("Requested size read. Breaking.");
            break;
        }

        progress(bytes_read, size);

        debug!("Read {}/{} bytes...", bytes_read, size);
    }

    Ok(buffer)
}

// TODO: Actually verify if the partition allows writing data.len() bytes
pub async fn write_flash<F>(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    data: &[u8],
    mut progress: F,
) -> Result<()>
where
    F: FnMut(usize, usize),
{
    info!(
        "Writing flash at address {:#X} with size {:#X}",
        addr,
        data.len()
    );

    // Note to self:
    // Next time, don't put this after Cmd::WriteData,
    // or don't expect it to work :/
    let chunk_size = get_write_packet_length(xflash).await?;
    // let chunk_size = 0x2000;
    info!("Using chunk size of {} bytes", chunk_size);

    // It is mandatory to make data size the same as size, or we will be leaving
    // older data in the partition. Usually, this is not an issue for partitions
    // with an header, like LK (which stores the start and length of the lk image),
    // but for other partitions, this might make the partition unusable.
    // This issue only arises when flashing stuff that is not coming from a dump made
    // with read_flash() or any other tool like mtkclient.
    let mut actual_data = Vec::with_capacity(size);
    actual_data.extend_from_slice(data);
    if actual_data.len() < size {
        actual_data.resize(size, 0);
        debug!(
            "Data to write at {:#X} was smaller than size, padding with zeros.",
            addr
        );
    } else if actual_data.len() > size {
        actual_data.truncate(size);
        debug!(
            "Data to write at {:#X} was larger than size, truncating.",
            addr
        );
    }

    let storage_type = 1u32; // TODO: Add support for other storage types
    let partition_type = 8u32;
    let nand_ext = [0u32; 8];
    let mut param = Vec::new();
    param.extend_from_slice(&storage_type.to_le_bytes());
    param.extend_from_slice(&partition_type.to_le_bytes());
    param.extend_from_slice(&addr.to_le_bytes());
    param.extend_from_slice(&(size as u64).to_le_bytes());
    param.extend_from_slice(
        &nand_ext
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>(),
    );

    debug!("Sending write data cmd!");
    // TODO: Consider making a send_cmd_with_payload function
    xflash.send_cmd(Cmd::WriteData).await?;
    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    debug!("actual_data.len() = {}, size = {}", actual_data.len(), size);
    debug!("Write data cmd sent, sending parameters...");
    // Note to self: send_data already checks the status, so DON'T check it again!!
    // Also, perhaps make it return the status DUH!
    xflash.send_data(&param).await?;

    debug!("Parameters sent!");
    let mut bytes_written = 0;
    let mut pos = 0;

    debug!(
        "Starting to write data in chunks of {} bytes...",
        chunk_size
    );
    loop {
        if pos >= actual_data.len() {
            break;
        }

        let packet_end = std::cmp::min(pos + chunk_size, actual_data.len());
        let chunk = &actual_data[pos..packet_end];

        // DA expects a checksum of the data chunk before the actual data
        // The actual checksum is a additive 16-bit checksum (Good job MTK!!)
        // For whoever is reading this code and has no clue what this is doing:
        // Just sum all bytes then AND with 0xFFFF :D!!!
        let checksum = chunk.iter().fold(0u32, |total, &byte| total + byte as u32) & 0xFFFF;

        // Mediatek be like: "Coherent protocol? What is that?"
        // And that's why here instead of doing the usual of sending the header (checksum included)
        // then the data, we need to send three different parts, with one being all zeros (why???).
        // But alas, who am I to judge, at least they didn't make an XML protocol... right?
        xflash
            .send(&0u32.to_be_bytes(), DataType::ProtocolFlow as u32)
            .await?;

        debug!("Sending checksum {} for chunk {}", checksum, pos);
        xflash
            .send(&checksum.to_le_bytes(), DataType::ProtocolFlow as u32)
            .await?;

        debug!("Sending chunk of {} bytes", chunk.len());
        xflash.send_data(chunk).await?;

        bytes_written += chunk.len();
        pos = packet_end;

        progress(bytes_written, size);

        debug!("Written {}/{} bytes...", bytes_written, actual_data.len());
    }

    let status = xflash.get_status().await?;
    if status != 0 {
        error!("Device returned status {:#X} after writing data!", status);
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    info!("Flash write completed, {} bytes written.", bytes_written);

    Ok(())
}

pub async fn download(xflash: &mut XFlash, part_name: String, data: &[u8]) -> Result<()> {
    // Works like write_flash, but instead of address and size, it takes a partition name
    // and writes the whole data to it.
    // The main difference betwen write_flash and this function is that this one
    // relies on the DA to find the partition by name.
    // Also, this command doesn't support writing only a part of the partition,
    // it will always write the whole partition with the data provided.

    // let chunk_size = get_write_packet_length(xflash).await?;

    xflash.send_cmd(Cmd::Download).await?;
    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    let data_len = data.len();

    xflash
        .send(part_name.as_bytes(), DataType::ProtocolFlow as u32)
        .await?;

    xflash
        .send(&data_len.to_le_bytes()[..], DataType::ProtocolFlow as u32)
        .await?;

    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    // TODO: Figure out what this is actually? The same happens in write_flash
    xflash
        .send(&0u32.to_le_bytes(), DataType::ProtocolFlow as u32)
        .await?;

    let checksum = data.iter().fold(0u32, |total, &byte| total + byte as u32) & 0xFFFF;
    xflash
        .send(&checksum.to_le_bytes(), DataType::ProtocolFlow as u32)
        .await?;

    xflash.send(data, DataType::ProtocolFlow as u32).await?;

    debug!("Upload completed, {} bytes sent.", data_len);

    let status = xflash.get_status().await?;
    if status != 0 {
        error!("Device returned {:#X} after data upload", status);
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    Ok(())
}

async fn get_packet_length(xflash: &mut XFlash) -> Result<(usize, usize)> {
    let packet_length = xflash.devctrl(Cmd::GetPacketLength, None).await?;
    let status = xflash.get_status().await?;
    if status != 0 {
        return Err(Error::XFlash(XFlashError::from_code(status)));
    }

    if packet_length.len() < 8 {
        return Err(Error::proto("Received packet length is too short"));
    }

    // TODO: Find a better way of doing this, currently, this is bad
    let mut write_buf = [0u8; 4];
    let mut read_buf = [0u8; 4];

    write_buf.copy_from_slice(&packet_length[0..4]);
    read_buf.copy_from_slice(&packet_length[4..8]);

    let write_len = u32::from_le_bytes(write_buf) as usize;
    let read_len = u32::from_le_bytes(read_buf) as usize;

    Ok((write_len, read_len))
}

async fn get_write_packet_length(xflash: &mut XFlash) -> Result<usize> {
    let (write_len, _) = get_packet_length(xflash).await?;
    Ok(write_len)
}

async fn get_read_packet_length(xflash: &mut XFlash) -> Result<usize> {
    let (_, read_len) = get_packet_length(xflash).await?;
    Ok(read_len)
}
