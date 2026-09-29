/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use log::debug;

use super::structs::FlashOpParams;
use crate::da::protocol::{PacketHeader, SPARSE_TIMEOUT};
use crate::da::xflash::XFlash;
use crate::da::xflash::cmd::*;
use crate::da::xflash::structs::PartTableCat;
use crate::da::{DownloadProtocol, NOOP_PROGRESS, ScatterFile};
use crate::error::{Error, PenumbraError, ProtocolError, Result, XFlashError, XFlashErrorKind};
use crate::port::{MAX_TIMEOUT, MtkPort};
use crate::storage::gpt::GPT_SIZE;
use crate::storage::{GptType, PartitionKind, is_sparse};
use crate::traits::{
    FromBytes,
    Peekable,
    ProgressCallback,
    Reader,
    ReaderSource,
    ToBytes,
    Writer,
    WriterSink,
};
use crate::{Gpt, Partition, Storage};

pub fn read_flash<P: MtkPort, W, F>(
    xflash: &mut XFlash,
    port: &mut P,
    addr: u64,
    size: u64,
    section: PartitionKind,
    writer: W,
    progress: F,
) -> Result<()>
where
    W: Writer,
    F: ProgressCallback,
{
    debug!("Reading flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type(port) as u32;
    let partition_type = section.into();

    let params = FlashOpParams { storage_type, partition_type, addr, size, ..Default::default() };

    xflash.send_cmd(port, Cmd::ReadData)?;
    xflash.send(port, &params.to_bytes())?;
    status_ok!(xflash, port)?;

    xflash.upload_data(port, size, writer, progress)?;

    debug!("Flash read completed, 0x{:X} bytes read.", size);

    Ok(())
}

pub fn write_flash<P: MtkPort, R, F>(
    xflash: &mut XFlash,
    port: &mut P,
    addr: u64,
    size: u64,
    section: PartitionKind,
    reader: R,
    progress: F,
) -> Result<()>
where
    R: Reader,
    F: ProgressCallback,
{
    xflash.get_packet_length(port)?;

    debug!("Writing flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type(port) as u32;
    let partition_type: u32 = section.into();

    let params = FlashOpParams { storage_type, partition_type, addr, size, ..Default::default() };

    xflash.send_cmd(port, Cmd::WriteData)?;
    xflash.send(port, &params.to_bytes())?;

    xflash.download_data(port, size, reader, progress)?;

    debug!("Flash write completed, 0x{:X} bytes written.", size);

    Ok(())
}

pub fn erase_flash<P: MtkPort, F>(
    xflash: &mut XFlash,
    port: &mut P,
    addr: u64,
    size: u64,
    section: PartitionKind,
    progress: F,
) -> Result<()>
where
    F: ProgressCallback,
{
    debug!("Erasing flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type(port) as u32;
    let partition_type = section.into();

    let params = FlashOpParams { storage_type, partition_type, addr, size, ..Default::default() };

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::StartDlInfo)?;
    status_ok!(xflash, port)?;

    xflash.send_cmd(port, Cmd::Format)?;
    xflash.send(port, &params.to_bytes())?;

    xflash.progress_report(port, size, progress)?;

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::EndDlInfo)?;
    status_ok!(xflash, port)?;

    debug!("Flash erase completed.");
    Ok(())
}

pub fn write_partition<P: MtkPort, R, F>(
    xflash: &mut XFlash,
    port: &mut P,
    part_name: &str,
    size: u64,
    reader: R,
    progress: F,
) -> Result<()>
where
    R: Reader,
    F: ProgressCallback,
{
    // Works like write_flash, but instead of address and size, it takes a partition name
    // and writes the whole data to it.
    // The main difference betwen write_flash and this function is that this one
    // relies on the DA to find the partition by name, and also handles sparse images and
    // Brom Layout header generation.
    // Also, this command doesn't support writing only a part of the partition,
    // it will always write the whole partition with the data provided.

    let reader = reader.peek_bytes::<4>()?;

    let timeout = if is_sparse(reader.peeked_bytes()) { SPARSE_TIMEOUT } else { MAX_TIMEOUT };

    let (write_len, _) = xflash.get_packet_length(port)?;

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::StartDlInfo)?;
    status_ok!(xflash, port)?;

    xflash.send_cmd(port, Cmd::Download)?;
    xflash.send_data(port, &[part_name.as_bytes(), &size.to_le_bytes()])?;

    debug!("Starting download to partition '{}' with size {:#X}", part_name, size);

    xflash.download_data_with(port, size, write_len, timeout, reader, progress)?;

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::EndDlInfo)?;
    status_ok!(xflash, port)?;

    debug!("Download completed, {:#X} bytes sent.", size);

    Ok(())
}

pub fn read_partition<P: MtkPort, W, F>(
    xflash: &mut XFlash,
    port: &mut P,
    part_name: &str,
    writer: W,
    progress: F,
) -> Result<()>
where
    W: Writer,
    F: ProgressCallback,
{
    xflash.send_cmd(port, Cmd::Upload)?;
    xflash.send(port, part_name.as_bytes())?;

    let size = {
        let size_data = xflash.read_data(port)?;
        status_ok!(xflash, port)?;
        if size_data.len() < 8 {
            return Err(ProtocolError::InvalidResponseLength.into());
        }
        u64::from_le_bytes(size_data[0..8].try_into().unwrap())
    };

    debug!("Starting readback of partition '{}'", part_name);

    xflash.upload_data(port, size, writer, progress)?;

    debug!("Upload completed, 0x{:X} bytes received.", size);

    Ok(())
}

pub fn format_partition<P: MtkPort, F>(
    xflash: &mut XFlash,
    port: &mut P,
    part_name: &str,
    progress: F,
) -> Result<()>
where
    F: ProgressCallback,
{
    let part = xflash
        .partitions(port)
        .find(|p| p.name == part_name)
        .ok_or_else(|| PenumbraError::PartitionNotFound(part_name.into()))?;

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::StartDlInfo)?;
    status_ok!(xflash, port)?;

    xflash.send_cmd(port, Cmd::FormatPartition)?;
    // The device starts sending statuses right after sending the partition name,
    // because MTK forgot to put a status write after the command :/
    // so we have to send it manually through the port and not through send()
    let hdr = PacketHeader::flow(part_name.len() as u32).to_bytes();
    port.write_all(&hdr)?;
    port.write_all(part_name.as_bytes())?;

    debug!("Formatting partition '{}'", part_name);

    xflash.progress_report(port, part.size, progress)?;

    xflash.send_cmd(port, Cmd::DeviceCtrl)?;
    xflash.send_cmd(port, Cmd::EndDlInfo)?;
    status_ok!(xflash, port)?;

    debug!("Partition '{}' formatted.", part_name);
    Ok(())
}

pub fn set_rsc_info<P: MtkPort, F, R>(
    xflash: &mut XFlash,
    port: &mut P,
    part_name: &str,
    size: u64,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: Reader,
    F: ProgressCallback,
{
    // Split in chunks of 256 bytes
    // The payload structure is like this:
    // u64 offset LE (each iteration, it increases by 1)
    // 64 bytes partition name (null-terminated)
    // 256 bytes (data)

    let mut offset = 0u64;

    let mut buffer = [0u8; 256];
    let mut payload = [0u8; 328];
    let mut part_name_bytes = [0u8; 64];

    let name_bytes = part_name.as_bytes();
    let name_len = name_bytes.len().min(63);
    part_name_bytes[..name_len].copy_from_slice(&name_bytes[..name_len]);

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let offset_bytes = offset.to_le_bytes();
        payload[1..8].copy_from_slice(&offset_bytes[..7]);
        payload[8..72].copy_from_slice(&part_name_bytes);
        payload[72..328].fill(0); // Better to avoid stale data
        payload[72..72 + bytes_read].copy_from_slice(&buffer[..bytes_read]);

        xflash.devctrl(port, Cmd::SetRscInfo, Some(&[&payload]))?;

        let done = offset
            .checked_mul(256)
            .and_then(|v| v.checked_add(bytes_read as u64))
            .ok_or(PenumbraError::ProgressOverflow)?;
        progress(done, size);
        offset += 1;
    }

    Ok(())
}
pub fn flash_scatter<P, F, R, W, S, K>(
    xflash: &mut XFlash,
    port: &mut P,
    scatter: &str,
    mut reader_source: S,
    mut writer_sink: K,
    mut progress: F,
) -> Result<()>
where
    P: MtkPort,
    R: Reader,
    W: Writer,
    S: ReaderSource<R>,
    K: WriterSink<W>,
    F: ProgressCallback,
{
    fn wrapped_progress<'a>(
        progress: &'a mut impl FnMut(u64, u64),
        base: u64,
        total_bytes: u64,
    ) -> impl FnMut(u64, u64) + 'a {
        move |written_now: u64, _: u64| {
            progress(base.saturating_add(written_now), total_bytes);
        }
    }

    let scatter_file = ScatterFile::from_yaml(scatter)?;

    let random_id = xflash.devctrl(port, Cmd::GetRandomId, None)?;
    let random_id = hex::encode(&random_id);

    let storage = xflash.get_storage(port).ok_or(ProtocolError::CannotGetStorageInfo)?;
    let user_section = storage.get_user_part();
    let block_size = storage.block_size();

    debug!("Flashing from scatter file");

    let parts = scatter_file.partitions_resized(storage);

    if parts.is_empty() {
        return Err(PenumbraError::ScatterFileNoParts.into());
    }

    let protected: Vec<_> = parts.iter().filter(|p| p.is_protected()).collect();
    let downloadable: Vec<_> = parts.iter().filter(|p| p.download).collect();

    let protected_bytes: u64 = protected.iter().map(|p| p.part.size).sum();

    let mut download_bytes = 0u64;
    for part in &downloadable {
        if let Some(path) = &part.path
            && let Ok((_, size)) = reader_source(&path.to_string_lossy())
        {
            download_bytes =
                download_bytes.checked_add(size).ok_or(PenumbraError::TotalSizeOverflow)?;
        }
    }

    let sgpt_sz = GPT_SIZE / 2 + block_size as usize;
    let gpt_bytes = GPT_SIZE + sgpt_sz;

    let total_bytes = protected_bytes
        .checked_mul(2)
        .and_then(|v| v.checked_add(download_bytes))
        .and_then(|v| v.checked_add(gpt_bytes as u64))
        .ok_or(PenumbraError::TotalSizeOverflow)?;
    let mut global_written = 0u64;

    let mut download_only = false;

    let cat = xflash
        .devctrl(port, Cmd::GetPartitionTblCata, None)
        .ok()
        .and_then(|cat| PartTableCat::from_bytes(&cat))
        .unwrap_or_default();

    match cat {
        PartTableCat::Gpt => {
            let mut valid_gpt = false;
            let mut data = vec![0u8; GPT_SIZE];

            // If GPT is invalid, trying to backing up protected parts will result
            // on 0xc0030008, which on newer DAs will result on a dead cmd loop.
            for part in ["PGPT", "SGPT"] {
                if xflash.read_partition(port, part, data.as_mut_slice(), NOOP_PROGRESS).is_ok()
                    && Gpt::from_bytes(&data).is_ok()
                {
                    valid_gpt = true;
                    break;
                }
            }

            if !valid_gpt {
                download_only = true;
            }
        }
        PartTableCat::Pmt => {}
    }

    progress(0, total_bytes);

    if !download_only {
        for part in &protected {
            debug!("Backing up protected partition: {}", part.part.name);
            let writer = writer_sink(&format!("{random_id}/{}.bin", part.part.name))?;

            let res = xflash.read_partition(
                port,
                &part.part.name,
                writer,
                wrapped_progress(&mut progress, global_written, total_bytes),
            );

            if matches!(
                res,
                Err(Error::XFlash(XFlashError {
                    kind: XFlashErrorKind::InvalidGpt | XFlashErrorKind::InvalidPmt,
                    ..
                }))
            ) {
                download_only = true;
                break;
            }

            res?;
            global_written = global_written
                .checked_add(part.part.size)
                .ok_or(PenumbraError::TotalSizeOverflow)?;
        }
    }

    match cat {
        PartTableCat::Gpt => {
            let gpt_parts: Vec<Partition> = parts
                .iter()
                .filter(|p| {
                    p.part.kind == user_section
                        && !matches!(p.part.name.to_lowercase().as_str(), "pgpt" | "sgpt")
                })
                .map(|p| p.part.clone())
                .collect();

            let storage = xflash.get_storage(port).ok_or(ProtocolError::CannotGetStorageInfo)?;

            let pgpt = Gpt::from_partitions(&gpt_parts, storage, GptType::Pgpt)
                .and_then(|g| g.to_bytes())
                .ok_or(PenumbraError::GptHeaderInvalid)?;

            let sgpt = Gpt::from_partitions(&gpt_parts, storage, GptType::Sgpt)
                .and_then(|g| g.to_bytes())
                .ok_or(PenumbraError::GptHeaderInvalid)?;

            // The GPT parser makes the SGPT size equal to the PGPT size, as that how MTK defines it
            // in the DA and scatter file. However, when flashing, SGPT size is actually
            // just half of GPT_SIZE + block_size (for the header).
            let sgpt = &sgpt[sgpt.len() - sgpt_sz..];

            debug!("Writing PGPT & SGPT...");

            writer_sink(&format!("{random_id}/PGPT.bin"))?.write_all(&pgpt)?;
            writer_sink(&format!("{random_id}/SGPT.bin"))?.write_all(sgpt)?;

            xflash.write_partition(
                port,
                "PGPT",
                GPT_SIZE as u64,
                pgpt.as_slice(),
                wrapped_progress(&mut progress, global_written, total_bytes),
            )?;
            global_written = global_written
                .checked_add(pgpt.len() as u64)
                .ok_or(PenumbraError::TotalSizeOverflow)?;

            xflash.write_partition(
                port,
                "SGPT",
                sgpt_sz as u64,
                sgpt,
                wrapped_progress(&mut progress, global_written, total_bytes),
            )?;
            global_written = global_written
                .checked_add(sgpt.len() as u64)
                .ok_or(PenumbraError::TotalSizeOverflow)?;
        }
        PartTableCat::Pmt => {}
    }

    if !download_only {
        for part in &protected {
            debug!("Restoring protected partition: {}", part.part.name);
            let backup_path = format!("{random_id}/{}.bin", part.part.name);
            let (reader, size) = reader_source(&backup_path)?;

            xflash.write_partition(
                port,
                &part.part.name,
                size,
                reader,
                wrapped_progress(&mut progress, global_written, total_bytes),
            )?;
            global_written =
                global_written.checked_add(size).ok_or(PenumbraError::TotalSizeOverflow)?;
        }
    }

    for part in &downloadable {
        if let Some(path) = &part.path {
            debug!("Flashing partition: {}", part.part.name);
            let (reader, size) = reader_source(&path.to_string_lossy())?;

            xflash.write_partition(
                port,
                &part.part.name,
                size,
                reader,
                wrapped_progress(&mut progress, global_written, total_bytes),
            )?;
            global_written =
                global_written.checked_add(size).ok_or(PenumbraError::TotalSizeOverflow)?;
        }
    }

    progress(total_bytes, total_bytes);

    Ok(())
}
