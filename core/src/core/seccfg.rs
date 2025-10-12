/*
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy

    Derived from:
    https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Hardware/seccfg.py
    Original SPDX-License-Identifier: GPL-3.0-or-later
    Original SPDX-FileCopyrightText: 2018–2024 bkerler

    This file remains under the GPL-3.0-or-later license.
    However, as part of a larger project licensed under the AGPL-3.0-or-later,
    the combined work is subject to the networking terms of the AGPL-3.0-or-later,
    as for term 13 of the GPL-3.0-or-later license.
*/
use crate::core::crypto::sej::SEJCrypto;
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind};

const V4_MAGIC_BEGIN: u32 = 0x4D4D4D4D;
const V4_MAGIC_END: u32 = 0x45454545;

pub enum LockFlag {
    Lock,
    Unlock,
}

enum SecCfgV4Algo {
    SW,
    HW,
    HWv3,
    HWv4,
    None,
}

pub struct SecCfgV4 {
    pub seccfg_ver: u32,
    pub seccfg_size: u32,
    pub lock_state: u32,
    pub critical_lock_state: u32,
    pub sboot_runtime: u32,
    algo: Option<SecCfgV4Algo>,
}

impl Default for SecCfgV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl SecCfgV4 {
    pub fn new() -> Self {
        SecCfgV4 {
            seccfg_ver: 4,
            seccfg_size: 20,
            lock_state: 0,
            critical_lock_state: 0,
            sboot_runtime: 0,
            algo: None,
        }
    }

    pub async fn parse<'a>(data: &[u8], sej: &mut SEJCrypto<'a>) -> Result<SecCfgV4, Error> {
        if data.len() < 0x20 + 32 {
            return Err(Error::new(ErrorKind::InvalidData, "Data too short"));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let seccfg_ver = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let seccfg_size = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let lock_state = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let critical_lock_state = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let sboot_runtime = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let endflag = u32::from_le_bytes(data[24..28].try_into().unwrap());

        if magic != V4_MAGIC_BEGIN || endflag != V4_MAGIC_END {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic values"));
        }

        let hash_start = seccfg_size as usize - 32;
        if data.len() < hash_start + 32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Data too short for hash",
            ));
        }
        let hash = &data[hash_start..hash_start + 32];

        let header_data = [
            magic.to_le_bytes(),
            seccfg_ver.to_le_bytes(),
            seccfg_size.to_le_bytes(),
            lock_state.to_le_bytes(),
            critical_lock_state.to_le_bytes(),
            sboot_runtime.to_le_bytes(),
            V4_MAGIC_END.to_le_bytes(),
        ]
        .concat();

        let calculated_hash = Sha256::digest(&header_data);

        let mut matched_algo: Option<SecCfgV4Algo> = None;

        // This is unlikely to happen, but hey
        if hash == calculated_hash.as_slice() {
            matched_algo = Some(SecCfgV4Algo::None);
        } else {
            for algo in [
                SecCfgV4Algo::SW,
                SecCfgV4Algo::HW,
                SecCfgV4Algo::HWv3,
                SecCfgV4Algo::HWv4,
            ] {
                let dec_hash = match algo {
                    SecCfgV4Algo::SW => sej.sej_seccfg_sw(hash, false),
                    SecCfgV4Algo::HW => sej.sej_seccfg_hw(hash, false, false).await,
                    SecCfgV4Algo::HWv3 => sej.sej_seccfg_hw_v3(hash, false).await,
                    SecCfgV4Algo::HWv4 => sej.sej_seccfg_hw_v4(hash, false).await,
                    SecCfgV4Algo::None => continue,
                };
                if calculated_hash.as_slice() == dec_hash.as_slice() {
                    matched_algo = Some(algo);
                    break;
                }
            }
        }

        Ok(SecCfgV4 {
            seccfg_ver,
            seccfg_size,
            lock_state,
            critical_lock_state,
            sboot_runtime,
            algo: matched_algo,
        })
    }

    pub async fn create<'a>(&mut self, sej: &mut SEJCrypto<'a>, lock_flag: LockFlag) -> Vec<u8> {
        // TODO: Check if critical lock state being 0 is valid. Penangf unlock through lk
        // sets it to 0
        match lock_flag {
            LockFlag::Lock => {
                self.lock_state = 1;
                self.critical_lock_state = 1;
            }
            LockFlag::Unlock => {
                self.lock_state = 3;
                self.critical_lock_state = 0;
            }
        }

        let mut seccfg_data = Vec::new();
        seccfg_data.extend(&V4_MAGIC_BEGIN.to_le_bytes());
        seccfg_data.extend(&self.seccfg_ver.to_le_bytes());
        seccfg_data.extend(&self.seccfg_size.to_le_bytes());
        seccfg_data.extend(&self.lock_state.to_le_bytes());
        seccfg_data.extend(&self.critical_lock_state.to_le_bytes());
        seccfg_data.extend(&self.sboot_runtime.to_le_bytes());
        seccfg_data.extend(&V4_MAGIC_END.to_le_bytes());

        let hash = Sha256::digest(&seccfg_data);

        let encrypted_hash = match self.algo {
            Some(SecCfgV4Algo::SW) => sej.sej_seccfg_sw(&hash, true),
            Some(SecCfgV4Algo::HW) => sej.sej_seccfg_hw(&hash, true, false).await,
            Some(SecCfgV4Algo::HWv3) => sej.sej_seccfg_hw_v3(&hash, true).await,
            Some(SecCfgV4Algo::HWv4) => sej.sej_seccfg_hw_v4(&hash, true).await,
            _ => hash.to_vec(),
        };

        seccfg_data.extend_from_slice(&encrypted_hash);

        while seccfg_data.len() % 0x200 != 0 {
            seccfg_data.push(0);
        }

        seccfg_data
    }
}
