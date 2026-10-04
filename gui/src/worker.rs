/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Dedicated background worker thread that owns the device connection
//! and executes hardware I/O without blocking the GUI.

use std::fs::{File, create_dir_all};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Result, anyhow};
use log::{error, info, warn};
use penumbra::da::BootMode;
use penumbra::hacc::LockState;
use penumbra::port::{PortBackend, PortType};
use penumbra::storage::RpmbRegion;
use penumbra::DeviceBuilder;

use crate::messages::{Command, ConnStatus, DeviceSummary, Event, LockAction};

pub struct WorkerHandle {
    pub cmd_tx: Sender<Command>,
    pub cancel: Arc<AtomicBool>,
}

pub fn spawn(evt_tx: Sender<Event>) -> WorkerHandle {
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<Command>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_worker = cancel.clone();

    thread::Builder::new()
        .name("penumbra-gui-worker".into())
        .spawn(move || run_worker(cmd_rx, evt_tx, cancel_worker))
        .expect("Failed to spawn penumbra-gui worker thread");

    WorkerHandle { cmd_tx, cancel }
}

fn run_worker(cmd_rx: Receiver<Command>, evt_tx: Sender<Event>, cancel: Arc<AtomicBool>) {
    loop {
        match cmd_rx.recv() {
            Ok(Command::Connect {
                da_path,
                preloader_path,
                auth_path,
                backend,
            }) => {
                cancel.store(false, Ordering::SeqCst);
                let _ = evt_tx.send(Event::StatusChanged(ConnStatus::Connecting));
                let _ = evt_tx.send(Event::InputEnabled(false));

                match connect_and_serve(
                    &cmd_rx,
                    &evt_tx,
                    &cancel,
                    da_path,
                    preloader_path,
                    auth_path,
                    backend,
                ) {
                    Ok(()) => {
                        let _ = evt_tx.send(Event::StatusChanged(ConnStatus::Disconnected));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("cancelled by user") {
                            info!("Device connection cancelled by user");
                            let _ = evt_tx.send(Event::Info("Connection cancelled".into()));
                        } else {
                            error!("{e}");
                            let _ = evt_tx.send(Event::Error(msg));
                        }
                        let _ = evt_tx.send(Event::StatusChanged(ConnStatus::Disconnected));
                    }
                }
                let _ = evt_tx.send(Event::InputEnabled(true));
                while let Ok(_) = cmd_rx.try_recv() {}
            }
            Ok(Command::Disconnect) => {
                let _ = evt_tx.send(Event::StatusChanged(ConnStatus::Disconnected));
            }
            Ok(_) => {
                // Ignore commands received while disconnected
            }
            Err(_) => break,
        }
    }
}

fn connect_and_serve(
    cmd_rx: &Receiver<Command>,
    evt_tx: &Sender<Event>,
    cancel: &Arc<AtomicBool>,
    da_path: Option<PathBuf>,
    preloader_path: Option<PathBuf>,
    auth_path: Option<PathBuf>,
    backend: PortBackend,
) -> Result<()> {
    let da_data = da_path.map(std::fs::read).transpose()?;
    let pl_data = preloader_path.map(std::fs::read).transpose()?;
    let auth_data = auth_path.map(std::fs::read).transpose()?;

    info!("Searching for MediaTek port...");
    let mut tries: u32 = 0;
    let port = loop {
        if let Ok(Some(port)) = PortType::find_and_open(None, None, backend) {
            info!("Found MediaTek port");
            break port;
        }

        if cancel.load(Ordering::SeqCst) {
            return Err(anyhow!("Connection cancelled by user"));
        }

        tries += 1;
        if tries % 20 == 0 {
            info!("Still waiting for device... (Hold Vol- / Vol+ while plugging in USB)");
        }

        thread::sleep(Duration::from_millis(150));
        if tries > 400 {
            return Err(anyhow!("Timed out waiting for MediaTek device"));
        }
    };

    let mut builder = DeviceBuilder::new(port);
    if let Some(ref da) = da_data {
        builder = builder.with_da_data(da.as_slice());
    }
    if let Some(ref pl) = pl_data {
        builder = builder.with_preloader(pl.as_slice());
    }
    if let Some(ref auth) = auth_data {
        builder = builder.with_auth(auth.as_slice());
    }

    info!("Initializing device handshake...");
    let mut dev = builder.build()?;
    dev.init()?;

    info!("Entering DA stage...");
    dev.enter_da_mode()?;

    let (chip_name, hw_code, hw_subcode, soc_id, meid, target_cfg) = {
        let info = dev.devinfo();
        let name = info
            .chip()
            .map(|c| {
                if let Some(m) = c.marketing_name() {
                    format!("{} ({})", c.segment_name(), m)
                } else {
                    c.segment_name().to_string()
                }
            })
            .unwrap_or_else(|| format!("0x{:04X}", info.hw_code()));
        (
            name,
            info.hw_code(),
            info.hw_subcode(),
            info.soc_id().to_vec(),
            info.meid().to_vec(),
            info.target_config(),
        )
    };

    let storage_type = dev
        .get_storage()
        .map(|s| match s {
            penumbra::storage::StorageKind::Emmc(_) => "eMMC".to_string(),
            penumbra::storage::StorageKind::Ufs(_) => "UFS".to_string(),
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let summary = DeviceSummary {
        chip_name: chip_name.clone(),
        hw_code,
        hw_subcode,
        soc_id,
        meid,
        target_config: target_cfg,
        sbc: (target_cfg & 0x1) != 0,
        sla: (target_cfg & 0x2) != 0,
        daa: (target_cfg & 0x4) != 0,
        storage_type,
    };

    let _ = evt_tx.send(Event::DeviceInfo(summary));
    let _ = evt_tx.send(Event::StatusChanged(ConnStatus::Connected(chip_name)));

    let partitions = dev.partitions().to_vec();
    let _ = evt_tx.send(Event::PartitionsLoaded(partitions));
    let _ = evt_tx.send(Event::InputEnabled(true));

    info!("Device connected and ready for operations");

    // Connected command loop
    loop {
        let cmd = match cmd_rx.recv() {
            Ok(c) => c,
            Err(_) => break,
        };

        let _ = evt_tx.send(Event::InputEnabled(false));
        cancel.store(false, Ordering::SeqCst);

        let mut need_disconnect = false;

        match cmd {
            Command::Disconnect => {
                info!("Disconnecting from device");
                break;
            }
            Command::LoadPartitions => {
                dev.devinfo().set_partitions(vec![]);
                let parts = dev.partitions().to_vec();
                let _ = evt_tx.send(Event::PartitionsLoaded(parts));
                let _ = evt_tx.send(Event::Info("Partitions refreshed".into()));
            }
            Command::ReadPartition { name, output_path } => {
                info!("Reading partition '{name}' to {}", output_path.display());
                if let Some(parent) = output_path.parent() {
                    let _ = create_dir_all(parent);
                }
                match File::create(&output_path) {
                    Ok(f) => {
                        let mut writer = BufWriter::new(f);
                        let tx = evt_tx.clone();
                        let cancel_ref = cancel.clone();
                        let p_name = name.clone();
                        let mut started = false;

                        let progress = move |written: u64, total: u64| {
                            if cancel_ref.load(Ordering::SeqCst) {
                                return;
                            }
                            if !started {
                                let _ = tx.send(Event::ProgressStart {
                                    total_bytes: total as u64,
                                    message: format!("Reading '{p_name}'..."),
                                });
                                started = true;
                            }
                            let _ = tx.send(Event::ProgressUpdate {
                                written: written as u64,
                                total_bytes: Some(total as u64),
                                message: Some(format!("Reading '{p_name}'...")),
                            });
                        };

                        match dev.read_partition(&name, &mut writer, progress) {
                            Ok(()) => {
                                let msg = format!("Partition '{name}' successfully saved!");
                                info!("{msg}");
                                let _ = evt_tx.send(Event::ProgressFinish { message: msg.clone() });
                                let _ = evt_tx.send(Event::Info(msg));
                            }
                            Err(e) => {
                                error!("Failed reading partition: {e}");
                                let _ = evt_tx.send(Event::Error(format!("Read '{name}' failed: {e}")));
                                let _ = evt_tx.send(Event::ProgressFinish { message: "Failed".into() });
                            }
                        }
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Event::Error(format!("Cannot create output file: {e}")));
                    }
                }
            }
            Command::WritePartition { name, input_path } => {
                info!("Writing image {} to partition '{name}'", input_path.display());
                match File::open(&input_path) {
                    Ok(f) => {
                        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                        let mut reader = BufReader::new(f);
                        let tx = evt_tx.clone();
                        let cancel_ref = cancel.clone();
                        let p_name = name.clone();
                        let mut started = false;

                        let progress = move |written: u64, total: u64| {
                            if cancel_ref.load(Ordering::SeqCst) {
                                return;
                            }
                            if !started {
                                let _ = tx.send(Event::ProgressStart {
                                    total_bytes: total as u64,
                                    message: format!("Flashing '{p_name}'..."),
                                });
                                started = true;
                            }
                            let _ = tx.send(Event::ProgressUpdate {
                                written: written as u64,
                                total_bytes: Some(total as u64),
                                message: Some(format!("Flashing '{p_name}'...")),
                            });
                        };

                        match dev.write_partition(&name, size, &mut reader, progress) {
                            Ok(()) => {
                                let _ = evt_tx.send(Event::ProgressUpdate {
                                    written: size as u64,
                                    total_bytes: Some(size as u64),
                                    message: Some(format!("Flashing '{name}'... 100%")),
                                });
                                let msg = format!("Partition '{name}' successfully flashed!");
                                info!("{msg}");
                                let _ = evt_tx.send(Event::ProgressFinish { message: msg.clone() });
                                let _ = evt_tx.send(Event::Info(msg));
                            }
                            Err(e) => {
                                error!("Failed writing partition: {e}");
                                let _ = evt_tx.send(Event::Error(format!("Flash '{name}' failed: {e}")));
                                let _ = evt_tx.send(Event::ProgressFinish { message: "Failed".into() });
                            }
                        }
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Event::Error(format!("Cannot open image file: {e}")));
                    }
                }
            }
            Command::ErasePartition { name } => {
                if crate::messages::is_critical_partition(&name) {
                    let msg = format!("Erasing critical partition '{name}' (LK / Preloader) is forbidden to prevent permanent device brick.");
                    warn!("{msg}");
                    let _ = evt_tx.send(Event::Error(msg));
                    let _ = evt_tx.send(Event::InputEnabled(true));
                    continue;
                }
                info!("Erasing partition '{name}'");
                let _ = evt_tx.send(Event::ProgressStart {
                    total_bytes: 100,
                    message: format!("Erasing '{name}'..."),
                });
                let tx = evt_tx.clone();
                let p_name = name.clone();
                let cancel_ref = cancel.clone();
                let progress = move |written: u64, total: u64| {
                    if cancel_ref.load(Ordering::SeqCst) {
                        return;
                    }
                    let _ = tx.send(Event::ProgressUpdate {
                        written: written as u64,
                        total_bytes: Some(total as u64),
                        message: Some(format!("Erasing '{p_name}'...")),
                    });
                };

                match dev.erase_partition(&name, progress) {
                    Ok(()) => {
                        let msg = format!("Partition '{name}' erased!");
                        info!("{msg}");
                        let _ = evt_tx.send(Event::ProgressFinish { message: msg.clone() });
                        let _ = evt_tx.send(Event::Info(msg));
                    }
                    Err(e) => {
                        error!("Failed erasing partition: {e}");
                        let _ = evt_tx.send(Event::Error(format!("Erase '{name}' failed: {e}")));
                        let _ = evt_tx.send(Event::ProgressFinish { message: "Failed".into() });
                    }
                }
            }
            Command::BatchBackup { names, output_dir } => {
                info!("Starting backup of {} partitions to {}", names.len(), output_dir.display());
                let _ = create_dir_all(&output_dir);
                let mut success_count = 0;
                let total_parts = names.len();

                let _ = evt_tx.send(Event::ProgressStart {
                    total_bytes: total_parts as u64,
                    message: format!("Starting backup of {total_parts} partitions..."),
                });

                for (idx, name) in names.iter().enumerate() {
                    if cancel.load(Ordering::SeqCst) {
                        info!("Backup cancelled by user");
                        break;
                    }

                    let file_path = output_dir.join(format!("{name}.bin"));
                    let Ok(f) = File::create(&file_path) else {
                        warn!("Could not create {}", file_path.display());
                        continue;
                    };

                    let mut writer = BufWriter::new(f);
                    let tx = evt_tx.clone();
                    let p_name = name.clone();
                    let cur_idx = idx + 1;
                    let cancel_ref = cancel.clone();

                    let progress = move |written: u64, total: u64| {
                        if cancel_ref.load(Ordering::SeqCst) {
                            return;
                        }
                        let _ = tx.send(Event::ProgressUpdate {
                            written: written as u64,
                            total_bytes: Some(total as u64),
                            message: Some(format!("[{cur_idx}/{total_parts}] Dumping '{p_name}'...")),
                        });
                    };

                    if let Ok(()) = dev.read_partition(name, &mut writer, progress) {
                        success_count += 1;
                    }
                }

                let msg = format!("Backup complete: {success_count}/{total_parts} partitions dumped.");
                info!("{msg}");
                let _ = evt_tx.send(Event::ProgressFinish { message: msg.clone() });
                let _ = evt_tx.send(Event::Info(msg));
            }
            Command::FlashScatter { files } => {
                info!("Flashing {} partitions from scatter file", files.len());
                let mut success_count = 0;
                let total_files = files.len();

                let _ = evt_tx.send(Event::ProgressStart {
                    total_bytes: total_files as u64,
                    message: format!("Starting flash of {total_files} partitions..."),
                });

                for (idx, (name, img_path)) in files.iter().enumerate() {
                    if cancel.load(Ordering::SeqCst) {
                        warn!("Flashing cancelled by user");
                        break;
                    }

                    let Ok(f) = File::open(img_path) else {
                        warn!("Skipping '{name}': file not found {}", img_path.display());
                        continue;
                    };

                    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                    let mut reader = BufReader::new(f);
                    let tx = evt_tx.clone();
                    let cancel_ref = cancel.clone();
                    let p_name = name.clone();
                    let cur_idx = idx + 1;

                    let progress = move |written: u64, total: u64| {
                        if cancel_ref.load(Ordering::SeqCst) {
                            return;
                        }
                        let _ = tx.send(Event::ProgressUpdate {
                            written: written as u64,
                            total_bytes: Some(total as u64),
                            message: Some(format!("[{cur_idx}/{total_files}] Flashing '{p_name}'...")),
                        });
                    };

                    match dev.write_partition(name, size, &mut reader, progress) {
                        Ok(()) => success_count += 1,
                        Err(e) => {
                            error!("Error flashing '{name}': {e}");
                            let _ = evt_tx.send(Event::Error(format!("Failed flashing '{name}': {e}")));
                        }
                    }
                }

                let msg = format!("Scatter flash complete: {success_count}/{total_files} partitions written.");
                info!("{msg}");
                let _ = evt_tx.send(Event::ProgressFinish { message: msg.clone() });
                let _ = evt_tx.send(Event::Info(msg));
            }
            Command::Seccfg(action) => {
                let state = match action {
                    LockAction::Unlock => LockState::Unlock,
                    LockAction::Lock => LockState::Lock,
                };
                let action_str = match action {
                    LockAction::Unlock => "unlock",
                    LockAction::Lock => "lock",
                };
                info!("Setting seccfg to {action_str}...");
                match dev.set_seccfg_lock_state(state) {
                    Ok(()) => {
                        let msg = format!("Bootloader {action_str} successful!");
                        info!("{msg}");
                        let _ = evt_tx.send(Event::Info(msg));
                    }
                    Err(e) => {
                        error!("Bootloader {action_str} failed: {e}");
                        let _ = evt_tx.send(Event::Error(format!("Bootloader {action_str} failed: {e}")));
                    }
                }
            }
            Command::ReadRpmb { output_path } => {
                info!("Reading RPMB to {}", output_path.display());
                if let Some(_storage) = dev.get_storage() {
                    // Default 4MB / 512 bytes = 8192 sectors
                    let sectors = 8192;
                    if let Ok(f) = File::create(&output_path) {
                        let writer = BufWriter::new(f);
                        let tx = evt_tx.clone();
                        let progress = move |written: u64, total: u64| {
                            let _ = tx.send(Event::ProgressUpdate {
                                written: written as u64,
                                total_bytes: Some(total as u64),
                                message: Some("Reading RPMB...".into()),
                            });
                        };
                        match dev.read_rpmb(RpmbRegion::R0, 0, sectors, writer, progress) {
                            Ok(()) => {
                                let msg = "RPMB read successfully!".to_string();
                                info!("{msg}");
                                let _ = evt_tx.send(Event::Info(msg));
                            }
                            Err(e) => {
                                error!("Failed reading RPMB: {e}");
                                let _ = evt_tx.send(Event::Error(format!("Failed reading RPMB: {e}")));
                            }
                        }
                    }
                } else {
                    let _ = evt_tx.send(Event::Error("Storage not initialized for RPMB".into()));
                }
            }
            Command::WriteRpmb { input_path } => {
                info!("Writing RPMB from {}", input_path.display());
                if let Ok(f) = File::open(&input_path) {
                    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                    let sectors = (size / 512) as u32;
                    let reader = BufReader::new(f);
                    let tx = evt_tx.clone();
                    let progress = move |written: u64, total: u64| {
                        let _ = tx.send(Event::ProgressUpdate {
                            written: written as u64,
                            total_bytes: Some(total as u64),
                            message: Some("Writing RPMB...".into()),
                        });
                    };
                    match dev.write_rpmb(RpmbRegion::R0, 0, sectors, reader, progress) {
                        Ok(()) => {
                            let msg = "RPMB write successfully!".to_string();
                            info!("{msg}");
                            let _ = evt_tx.send(Event::Info(msg));
                        }
                        Err(e) => {
                            error!("Failed writing RPMB: {e}");
                            let _ = evt_tx.send(Event::Error(format!("Failed writing RPMB: {e}")));
                        }
                    }
                }
            }
            Command::EraseRpmb => {
                info!("Erasing RPMB...");
                let sectors = 8192;
                let tx = evt_tx.clone();
                let progress = move |written: u64, total: u64| {
                    let _ = tx.send(Event::ProgressUpdate {
                        written: written as u64,
                        total_bytes: Some(total as u64),
                        message: Some("Erasing RPMB...".into()),
                    });
                };
                match dev.erase_rpmb(RpmbRegion::R0, 0, sectors, progress) {
                    Ok(()) => {
                        let msg = "RPMB erased successfully!".to_string();
                        info!("{msg}");
                        let _ = evt_tx.send(Event::Info(msg));
                    }
                    Err(e) => {
                        error!("Failed erasing RPMB: {e}");
                        let _ = evt_tx.send(Event::Error(format!("Failed erasing RPMB: {e}")));
                    }
                }
            }
            Command::Reboot(mode) => {
                let mode_str = match mode {
                    BootMode::Normal => "Normal",
                    BootMode::Fastboot => "Fastboot",
                    BootMode::Meta => "Meta",
                    BootMode::Test => "Test",
                    BootMode::HomeScreen => "Home Screen",
                };
                info!("Rebooting device into {mode_str}...");
                let _ = dev.reboot(mode);
                need_disconnect = true;
            }
            Command::Shutdown => {
                info!("Shutting down device...");
                let _ = dev.shutdown();
                need_disconnect = true;
            }
            Command::Connect { .. } => {}
        }

        let _ = evt_tx.send(Event::InputEnabled(true));
        if need_disconnect {
            break;
        }
    }

    Ok(())
}
