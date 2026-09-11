/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use log::debug;
use memchr::memmem;

use crate::activity::Activity;
use crate::da::protocol::SPARSE_TIMEOUT;
use crate::da::xml::structs::{PartitionChangedStatus, ProtectedRecord};
use crate::da::xml::{
    CMD_DOWNLOAD_FILE,
    CMD_END,
    CMD_FILE_SYSTEM_OP,
    CMD_PROGRESS_REPORT,
    CMD_UPLOAD_FILE,
    EraseFlash,
    ErasePartition,
    FileSystemOp,
    FlashUpdate,
    ReadFlash,
    ReadPartition,
    WriteFlash,
    WritePartition,
    XmlCmdLifetime,
};
use crate::da::{NOOP_PROGRESS, ScatterFile, Xml};
use crate::error::{PenumbraError, ProtocolError, XmlErrorKind};
use crate::port::{MAX_TIMEOUT, MtkPort};
use crate::storage::is_sparse;
use crate::traits::{
    FromBytes,
    Peekable,
    ProgressCallback,
    Reader,
    ReaderSource,
    Writer,
    WriterSink,
};
use crate::utils::xml::get_tag;
use crate::{DownloadProtocol, PartitionKind, Result, Storage};

pub fn read_flash<P, W, F>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    size: usize,
    section: PartitionKind,
    writer: W,
    progress: F,
) -> Result<()>
where
    P: MtkPort,
    W: Writer,
    F: ProgressCallback,
{
    debug!("Reading flash at address {:#X} with size {:#X}", addr, size);

    xmlcmd!(xml, port, ReadFlash, section, section, size, addr)?;
    xml.upload_data(port, size, writer, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    debug!("Flash read completed, 0x{:X} bytes read.", size);

    Ok(())
}

pub fn write_flash<P, R, F>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    size: usize,
    section: PartitionKind,
    reader: R,
    progress: F,
) -> Result<()>
where
    P: MtkPort,
    R: Reader,
    F: ProgressCallback,
{
    debug!("Writing flash at address {:#X} with size {:#X}", addr, size);

    xmlcmd!(xml, port, WriteFlash, section, size, addr)?;
    xml.file_system_op(port, FileSystemOp::FileSize(size))?;
    xml.progress_report(port, size, NOOP_PROGRESS)?; // Pre-erase
    xml.download_data(port, size, reader, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    debug!("Flash write completed, 0x{:X} bytes written.", size);

    Ok(())
}

pub fn erase_flash<P, F>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    size: usize,
    section: PartitionKind,
    progress: F,
) -> Result<()>
where
    P: MtkPort,
    F: ProgressCallback,
{
    debug!("Erasing flash at address {:#X} with size {:#X}", addr, size);

    xmlcmd!(xml, port, EraseFlash, section, size, addr)?;
    xml.progress_report(port, size, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    debug!("Flash erase completed, 0x{:X} bytes erased.", size);

    Ok(())
}

pub fn read_partition<P, W, F>(
    xml: &mut Xml,
    port: &mut P,
    part_name: &str,
    writer: W,
    progress: F,
) -> Result<()>
where
    P: MtkPort,
    W: Writer,
    F: ProgressCallback,
{
    debug!("Starting readback of partition '{}'", part_name);

    xmlcmd!(xml, port, ReadPartition, part_name, part_name)?;
    let read = xml.upload_data(port, 0, writer, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    debug!("Upload completed, 0x{:X} bytes received.", read);

    Ok(())
}

pub fn write_partition<P, R, F>(
    xml: &mut Xml,
    port: &mut P,
    part_name: &str,
    size: usize,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    P: MtkPort,
    R: Reader,
    F: ProgressCallback,
{
    debug!("Starting download to partition '{}' with size {:#X}", part_name, size);

    xmlcmd!(xml, port, WritePartition, part_name, part_name)?;

    loop {
        let resp = xml.read_data(port)?;
        if memmem::find(&resp, CMD_END).is_some() {
            xml.ack(port, None)?;

            let resp = String::from_utf8_lossy(&resp);
            let result = get_tag::<String>(&resp, "arg/result")?;

            if result != "OK" {
                let err_msg = get_tag::<String>(&resp, "arg/message").unwrap_or_default();
                return Err(XmlErrorKind::Other(err_msg).into());
            }

            break;
        }

        let resp = String::from_utf8_lossy(&resp);
        let cmd: String = get_tag(&resp, "command")?;

        match cmd.as_str() {
            CMD_PROGRESS_REPORT => {
                xml.process_progress_report(port, &resp, NOOP_PROGRESS)?;
            }
            CMD_FILE_SYSTEM_OP => {
                let op: String = get_tag(&resp, "arg/key")?;
                let op = FileSystemOp::from(op.as_str());

                xml.process_file_sys_op(port, &resp, op)?;
            }
            CMD_DOWNLOAD_FILE => {
                xml.process_download_data(
                    port,
                    &resp,
                    size,
                    MAX_TIMEOUT,
                    &mut reader,
                    &mut progress,
                )?;
            }
            _ => return Err(XmlErrorKind::UnsupportedCmd.into()),
        }
    }

    debug!("Download completed, {:#X} bytes sent.", size);
    Ok(())
}

pub fn format_partition<P, F>(
    xml: &mut Xml,
    port: &mut P,
    part_name: &str,
    progress: F,
) -> Result<()>
where
    P: MtkPort,
    F: ProgressCallback,
{
    debug!("Formatting partition '{}'", part_name);

    xmlcmd!(xml, port, ErasePartition, part_name)?;
    xml.progress_report(port, 0, progress)?;
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    debug!("Partition '{}' formatted.", part_name);

    Ok(())
}

pub fn flash_scatter<P, F, R, W, S, K>(
    xml: &mut Xml,
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
    const RECORD_FILE: &str = "record-file";

    let scatter_file = ScatterFile::from_xml(scatter)?;
    let storage = xml.get_storage(port).ok_or(ProtocolError::CannotGetStorageInfo)?;

    debug!("Flashing from scatter file");

    let parts = scatter_file.partitions_by_storage(storage.kind());

    if parts.is_empty() {
        return Err(PenumbraError::ScatterFileNoParts.into());
    }

    let protected_parts = parts.iter().filter(|p| p.is_protected()).count();

    debug!(
        "Scatter file contains {} partitions for storage type {:?}, {} of which are protected.",
        parts.len(),
        storage.kind(),
        protected_parts
    );

    xmlcmd!(xml, port, FlashUpdate)?;

    xml.download_data(port, scatter.len(), scatter.as_bytes(), NOOP_PROGRESS)?;

    let mut total_bytes = 0u64;
    for part in parts.iter().filter(|p| p.download) {
        if let Some(path) = &part.path
            && let Ok((_, size)) = reader_source(&path.to_string_lossy())
        {
            total_bytes += size as u64;
        }
    }

    let mut rcd: Option<ProtectedRecord> = None;
    let mut global_written: u64 = 0;

    let partition_name = |resp: &str| -> String {
        get_tag::<String>(resp, "arg/info")
            .unwrap_or_default()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned()
    };

    progress(0, total_bytes as usize);

    loop {
        let resp = xml.read_data(port)?;
        if memmem::find(&resp, CMD_END).is_some() {
            // Force the protocol to refetch PGPT on new operations
            xml.get_devinfo().set_partitions(vec![]);
            // Final ack so the DA can send CMD:START next
            xml.ack(port, None)?;

            let resp = String::from_utf8_lossy(&resp);
            let result = get_tag::<String>(&resp, "arg/result")?;

            if result != "OK" {
                let err_msg = get_tag::<String>(&resp, "arg/message").unwrap_or_default();
                return Err(XmlErrorKind::Other(err_msg).into());
            }

            break Ok(());
        }

        let resp = String::from_utf8_lossy(&resp);
        let cmd: String = get_tag(&resp, "command")?;

        debug!("Received {} command.", cmd);

        let mut file_progress = |file_written: usize, _file_total: usize| {
            progress((global_written + file_written as u64) as usize, total_bytes as usize);
        };

        match cmd.as_str() {
            CMD_DOWNLOAD_FILE => {
                let file_path = get_tag::<String>(&resp, "arg/source_file")?;

                xml.activity.set(Activity::Flashing { partition: partition_name(&resp) });

                let (reader, size) = reader_source(&file_path)?;

                let reader = reader.peek_bytes::<4>()?;

                let is_sparse = is_sparse(reader.peeked_bytes());

                // The DA can hang during sparse image flashing while unsparsing, an opeartion
                // that can take long (from tests even more than 40s!!).
                // To avoid this, setting a longer timeout will prevent the chunk from being
                // dropped.
                let timeout = if is_sparse { SPARSE_TIMEOUT } else { MAX_TIMEOUT };

                xml.process_download_data(port, &resp, size, timeout, reader, &mut file_progress)?;

                global_written += size as u64;

                // The DA, after writing a sparse image, will hang for a few seconds, more than
                // the default MIN_TIMEOUT.
                // This will cause the next read in the loop to timeout, interrupting the flashing
                // process. As a fix, we set the timeout to MAX before we start the
                // next read in the loop.
                if is_sparse {
                    port.set_timeout(MAX_TIMEOUT)?;
                }
            }

            CMD_UPLOAD_FILE => {
                let file_path = get_tag::<String>(&resp, "arg/target_file")?;
                let info = get_tag::<String>(&resp, "arg/info").unwrap_or_default();

                xml.activity.set(Activity::Reading { partition: partition_name(&resp) });

                let uploaded_bytes = if info == RECORD_FILE && rcd.is_none() {
                    let mut record_bytes = [0u8; size_of::<ProtectedRecord>()];

                    let bytes = xml.process_upload_data(
                        port,
                        &resp,
                        record_bytes.as_mut_slice(),
                        &mut file_progress,
                    )?;

                    if let Some(parsed_record) = ProtectedRecord::from_bytes(&record_bytes) {
                        for section in parsed_record.list.iter().take(parsed_record.count as usize)
                        {
                            if section.changed == PartitionChangedStatus::Unchanged {
                                continue;
                            }

                            let part_name = section.part_name();

                            if let Some(part) =
                                parts.iter().find(|part| part.part.name == part_name)
                            {
                                total_bytes += part.part.size as u64 * 2;
                            }
                        }

                        rcd = Some(parsed_record);

                        progress((global_written + bytes as u64) as usize, total_bytes as usize);
                    }

                    bytes
                } else {
                    let writer = writer_sink(&file_path)?;

                    xml.process_upload_data(port, &resp, writer, &mut file_progress)?
                };

                global_written += uploaded_bytes as u64;
            }
            CMD_PROGRESS_REPORT => {
                let message = get_tag::<String>(&resp, "arg/message").unwrap_or_default();

                xml.activity.set(Activity::Erasing { partition: message });
                xml.process_progress_report(port, &resp, NOOP_PROGRESS)?
            }
            CMD_FILE_SYSTEM_OP => {
                let op: String = get_tag(&resp, "arg/key")?;
                let op = FileSystemOp::from(op.as_str());

                port.set_timeout(MAX_TIMEOUT)?;
                xml.process_file_sys_op(port, &resp, op)?;
            }
            _ => return Err(XmlErrorKind::UnsupportedCmd.into()),
        }
    }
}
