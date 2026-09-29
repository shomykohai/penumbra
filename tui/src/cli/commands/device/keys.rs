/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use anyhow::Result;
use clap::Args;
use log::info;
use penumbra::da::extensions::{KeyDeriveId, KeySize};
use penumbra::{Device, MMIO, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct KeysArgs;

impl CommandMetadata for KeysArgs {
    fn about() -> &'static str {
        "Show device specific keys and info."
    }

    fn long_about() -> &'static str {
        Self::about()
    }
}

impl DeviceCommand for KeysArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let chip = dev.devinfo().chip().unwrap();

        let efuse = chip.efuse();
        let sec_fuse = efuse as u64 + 0x60;
        let pubk_fuse = efuse as u64 + 0x90;
        let hrid_fuse = efuse as u64 + 0x140;

        let progress = |_, _| {};

        let mut pubk = [0u8; 0x20];
        let mut hrid = [0u8; 0x10];
        dev.peek(pubk_fuse, size_of_val(&pubk) as u64, &mut pubk[..], progress)?;
        dev.peek(hrid_fuse, size_of_val(&hrid) as u64, &mut hrid[..], progress)?;

        let sec_fuse_val = dev.read_register(sec_fuse)?;
        let rpmb_key = dev.derive_key_by_id(KeyDeriveId::Rpmb, KeySize::Key256)?;
        let fde_key = dev.derive_key_by_id(KeyDeriveId::Fde, KeySize::Key128)?;
        let tee_key = dev.derive_key_by_id(KeyDeriveId::Tee, KeySize::Key256)?;
        let rot_key = dev.derive_key_by_id(KeyDeriveId::Rot, KeySize::Key256)?;

        info!("Device Info:");
        info!("  SEC Fuse: 0x{:X}", sec_fuse_val);
        info!("  SOC ID: {}", hex::encode(state.soc_id.as_ref()));
        info!("  HRID: {}", hex::encode(hrid));
        info!("  MEID: {}", hex::encode(state.meid.as_ref()));
        info!("  Public Key: {}", hex::encode(pubk));
        info!("  RPMB Key: {}", hex::encode(&rpmb_key));
        info!("  FDE Key: {}", hex::encode(&fde_key));
        info!("  TEE Key: {}", hex::encode(&tee_key));
        info!("  ROT Key: {}", hex::encode(&rot_key));

        Ok(())
    }
}
