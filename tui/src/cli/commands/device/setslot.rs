/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

use anyhow::Result;
use clap::{Args, ValueEnum};
use log::info;
use penumbra::hacc::{BootControl, BootPartition, OFFSET_SLOT_SUFFIX, TryWrite};
use penumbra::{Device, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::state::PersistedDeviceState;

#[derive(Debug, ValueEnum, Clone)]
pub enum ActiveSlot {
    A,
    B,
}

impl From<ActiveSlot> for BootPartition {
    fn from(slot: ActiveSlot) -> Self {
        match slot {
            ActiveSlot::A => Self::A,
            ActiveSlot::B => Self::B,
        }
    }
}

impl CommandMetadata for SetActiveSlotArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["setslot"]
    }

    fn about() -> &'static str {
        "Set the active boot slot for AB devices."
    }

    fn long_about() -> &'static str {
        "Set the active boot slot by modifying the Boot Control partition.\n\
        This will determine which slot the device will boot from on the next reboot."
    }
}

#[derive(Args, Debug)]
pub struct SetActiveSlotArgs {
    #[arg(value_enum)]
    pub slot: ActiveSlot,
}

impl DeviceCommand for SetActiveSlotArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        let new_slot: BootPartition = self.slot.clone().into();

        let mut bootctrl = dev.get_bootctrl()?;

        let current_slot = bootctrl.get_active_slot();
        if current_slot == new_slot {
            info!("Active slot is already set to {:?}.", self.slot);
            return Ok(());
        }

        bootctrl.set_active_slot(new_slot);

        let mut new_data = [0u8; OFFSET_SLOT_SUFFIX + size_of::<BootControl>()];

        bootctrl.try_write(&mut new_data[OFFSET_SLOT_SUFFIX..])?;

        dev.write_partition("misc", new_data.len() as u64, &new_data[..], |_, _| {})?;

        info!("Active slot set to {:?}.", self.slot);

        Ok(())
    }
}
