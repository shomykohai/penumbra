/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use crate::da::NOOP_PROGRESS;
use crate::storage::gpt::{GPT_SIZE, MAX_GPT_PARTS};
use crate::{DownloadProtocol, Gpt, MtkPort, Partition, Storage, StorageKind};

pub(super) fn get_aux_gpt_parts(storage: &StorageKind) -> [Partition; 2] {
    let pl1_size = storage.get_pl1_size();
    let pl1_part = storage.get_pl_part1();
    let pl2_size = storage.get_pl2_size();
    let pl2_part = storage.get_pl_part2();

    [
        Partition::new("preloader", pl1_size, 0, pl1_part),
        Partition::new("preloader_backup", pl2_size, 0, pl2_part),
    ]
}

pub(super) fn get_gpt_parts<P: MtkPort, D: DownloadProtocol>(
    proto: &mut D,
    port: &mut P,
    storage: &StorageKind,
) -> Vec<Partition> {
    let user_section = storage.get_user_part();
    let user_size = storage.get_user_size();

    let gpt_size = GPT_SIZE;

    let mut gpt_parts = Vec::with_capacity(MAX_GPT_PARTS + 2);

    let pgpt = Partition::new("PGPT", gpt_size as u64, 0, user_section);

    let sgpt = Partition::new(
        "SGPT",
        gpt_size as u64,
        user_size.checked_sub(gpt_size as u64).unwrap_or(user_size),
        user_section,
    );

    gpt_parts.push(pgpt);

    for gpt_name in ["PGPT", "SGPT"] {
        let mut data = Vec::new();

        if proto.read_partition(port, gpt_name, &mut data, NOOP_PROGRESS).is_ok()
            && let Ok(gpt) = Gpt::from_bytes(&data)
        {
            let mut parsed = gpt.to_partitions(storage);
            if !parsed.is_empty() {
                gpt_parts.append(&mut parsed);
                break;
            }
        }
    }

    if user_size >= gpt_size as u64 {
        gpt_parts.push(sgpt);
    }

    gpt_parts
}
