/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use log::info;
use penumbra::connection::port::ConnectionType;
use penumbra::core::devinfo::DevInfoData;
use penumbra::{Device, DeviceBuilder, find_mtk_port};
use tokio::fs::read;

use crate::cli::CliArgs;
use crate::cli::helpers::logging::setup_file_logger;
use crate::cli::state::PersistedDeviceState;

const DA_LOG_FILE: &str = "da.log";

pub async fn setup_device(args: &CliArgs, state: &mut PersistedDeviceState) -> Result<Device> {
    let usb_log_channel = state.usb_log || args.usb_log;

    let da_data = if let Some(da_path) = &args.da_file {
        let data = read(da_path).await?;
        state.da_file_path = Some(da_path.to_string_lossy().to_string());
        Some(data)
    } else {
        None
    };

    let pl_data = if let Some(pl_path) = &args.preloader_file {
        let data = read(pl_path).await?;
        Some(data)
    } else {
        None
    };

    let auth_data = if let Some(auth_path) = &args.auth_file {
        let data = read(auth_path).await?;
        Some(data)
    } else {
        None
    };

    let mut last_seen = Instant::now();
    let timeout = Duration::from_millis(500);

    info!("Waiting for MTK device...");
    let mtk_port = loop {
        if let Some(port) = find_mtk_port() {
            info!("Found MTK port: {}", port.get_port_name());
            break port;
        } else if last_seen.elapsed() > timeout {
            state.reset().await?;
            last_seen = Instant::now();
        }
    };

    let mut builder = DeviceBuilder::default()
        .with_mtk_port(mtk_port)
        .with_verbose(args.verbose)
        .with_usb_log_channel(usb_log_channel);

    if usb_log_channel
        && let Some(device_log) = setup_file_logger(DA_LOG_FILE).await {
            builder = builder.with_device_log(device_log);
        }

    builder = if let Some(da) = da_data {
        builder.with_da_data(da)
    } else if let Some(da_path_str) = &state.da_file_path {
        let da_path = Path::new(da_path_str);
        let data = read(da_path).await?;
        builder.with_da_data(data)
    } else {
        builder
    };

    builder = if let Some(pl) = pl_data { builder.with_preloader(pl) } else { builder };
    builder = if let Some(auth) = auth_data { builder.with_auth(auth) } else { builder };

    let mut dev = builder.build()?;

    if state.hw_code != 0 {
        let dev_info = DevInfoData {
            soc_id: state.soc_id,
            meid: state.meid,
            hw_code: state.hw_code,
            partitions: vec![],
            target_config: state.target_config,
            bootctrl: None,
        };

        if state.flash_mode != 0 {
            dev.set_connection_type(ConnectionType::Da)?;
        }

        dev.dev_info.set_chip(penumbra::core::chip::chip_from_hw_code(state.hw_code));
        dev.reinit(dev_info)?;
    } else {
        info!("Initializing device...");
        dev.init()?;

        state.soc_id = dev.dev_info.soc_id();
        state.meid = dev.dev_info.meid();
        state.hw_code = dev.dev_info.hw_code();
        state.target_config = dev.dev_info.target_config();
    }

    info!("=====================================");
    info!("SBC: {}", (state.target_config & 0x1) != 0);
    info!("SLA: {}", (state.target_config & 0x2) != 0);
    info!("DAA: {}", (state.target_config & 0x4) != 0);
    info!("=====================================");

    Ok(dev)
}
