/*
    SPDX-License-Identifier: GPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy

    Derived from:
    https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Hardware/hwcrypto_sej.py
    Original SPDX-License-Identifier: GPL-3.0-or-later
    Original SPDX-FileCopyrightText: 2018–2024 bkerler

    This file remains under the GPL-3.0-or-later license.
    However, as part of a larger project licensed under the AGPL-3.0-or-later,
    the combined work is subject to the networking terms of the AGPL-3.0-or-later,
    as for term 13 of the GPL-3.0-or-later license.
*/
use crate::core::crypto::config::CryptoConfig;
use aes::Aes128;
use cbc::{Decryptor, Encryptor}; // TODO: Recheck this crate, as it doesn't receive stable updates for 3+ years
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum SejReg {
    CON = 0x0000,
    ACON = 0x0004,
    ACON2 = 0x0008,
    ACONK = 0x000C,
    ASRC0 = 0x0010,
    ASRC1 = 0x0014,
    ASRC2 = 0x0018,
    ASRC3 = 0x001C,
    AKEY0 = 0x0020,
    AKEY1 = 0x0024,
    AKEY2 = 0x0028,
    AKEY3 = 0x002C,
    AKEY4 = 0x0030,
    AKEY5 = 0x0034,
    AKEY6 = 0x0038,
    AKEY7 = 0x003C,
    ACFG0 = 0x0040,
    ACFG1 = 0x0044,
    ACFG2 = 0x0048,
    ACFG3 = 0x004C,
    AOUT0 = 0x0050,
    AOUT1 = 0x0054,
    AOUT2 = 0x0058,
    AOUT3 = 0x005C,
    SW_OTP0 = 0x0060,
    SW_OTP1 = 0x0064,
    SW_OTP2 = 0x0068,
    SW_OTP3 = 0x006C,
    SW_OTP4 = 0x0070,
    SW_OTP5 = 0x0074,
    SW_OTP6 = 0x0078,
    SW_OTP7 = 0x007C,
    SECINIT0 = 0x0080,
    SECINIT1 = 0x0084,
    SECINIT2 = 0x0088,
    MKJ = 0x00A0,
    UNK = 0x00BC,
}

impl SejReg {
    pub fn offset(self) -> u32 {
        self as u32
    }
}

pub const SEJ_AES_DEC: u32 = 0x00000000;
pub const SEJ_AES_ENC: u32 = 0x00000001;
pub const SEJ_AES_MODE_MASK: u32 = 0x00000002;
pub const SEJ_AES_MODE_ECB: u32 = 0x00000000;
pub const SEJ_AES_MODE_CBC: u32 = 0x00000002;
pub const SEJ_AES_TYPE_MASK: u32 = 0x00000030;
pub const SEJ_AES_TYPE_128: u32 = 0x00000000;
pub const SEJ_AES_TYPE_192: u32 = 0x00000010;
pub const SEJ_AES_TYPE_256: u32 = 0x00000020;
pub const SEJ_AES_CHG_BO_OFF: u32 = 0x00000000;
pub const SEJ_AES_CHG_BO_ON: u32 = 0x00001000;
pub const SEJ_AES_START: u32 = 0x00000001;
pub const SEJ_AES_CLR: u32 = 0x00000002;
pub const SEJ_AES_RDY: u32 = 0x00008000;

pub const SEJ_AES_BK2C: u32 = 0x00000010;
pub const SEJ_AES_R2K: u32 = 0x00000100;

pub const HACC_CFG_1: [u32; 8] = [
    0x9ED40400, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A, 0xFF838E5C, 0xE940A0E3, 0x8D4DECC6, 0x45FC0989,
];

pub const HACC_CFG_2: [u32; 8] = [
    0xAA542CDA, 0x55522114, 0xE3F083BD, 0x55522114, 0xAA542CDA, 0xAA542CDA, 0x55522114, 0xAA542CDA,
];

pub const HACC_CFG_3: [u32; 8] = [
    0x2684B690, 0xEB67A8BE, 0xA113144C, 0x177B1215, 0x168BEE66, 0x1284B684, 0xDF3BCE3A, 0x217F6FA2,
];

// https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Hardware/hwcrypto_sej.py#L134-L147
pub const G_CFG_RANDOM_PATTERN: [u32; 12] = [
    0x2D44BB70, 0xA744D227, 0xD0A9864B, 0x83FFC244, 0x7EC8266B, 0x43E80FB2, 0x01A6348A, 0x2067F9A0,
    0x54536405, 0xD546A6B1, 0x1CC3EC3A, 0xDE377A83,
];

// https://github.com/bkerler/mtkclient/blob/main/mtkclient/Library/Hardware/hwcrypto_sej.py#L671-L685
pub const DEFAULT_IV: &[u8] = b"\x57\x32\x5A\x5A\x12\x54\x97\x66\x12\x54\x97\x66\x57\x32\x5A\x5A";
pub const DEFAULT_KEY: &[u8] = b"\x25\xA1\x76\x3A\x21\xBC\x85\x4C\xD5\x69\xDC\x23\xB4\x78\x2B\x63";

pub struct SEJCrypto<'a> {
    pub config: &'a mut CryptoConfig<'a>,
}

impl<'a> SEJCrypto<'a> {
    pub fn new(config: &'a mut CryptoConfig<'a>) -> Self {
        Self { config }
    }

    fn reg_addr(&self, reg: SejReg) -> u32 {
        self.config.sej_base + reg.offset()
    }

    async fn wreg(&mut self, reg: SejReg, val: u32) {
        let addr = self.reg_addr(reg);
        self.config.write32(addr, val).await;
    }

    async fn rreg(&mut self, reg: SejReg) -> u32 {
        let addr = self.reg_addr(reg);
        self.config.read32(addr).await
    }

    // Note: This modifies the data directly, it does not return a new Vec
    fn xor(&self, data: &mut [u8]) {
        for i in 0..4 {
            let pad = HACC_CFG_1[i];
            let offset = i * 4;
            let orig = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            data[offset..offset + 4].copy_from_slice(&(orig ^ pad).to_le_bytes());
        }
    }

    // Software based AES128 CBC.
    pub fn sej_seccfg_sw(&mut self, data: &[u8], encrypt: bool) -> Vec<u8> {
        let mut buf = data.to_vec();
        let buf_len = buf.len();
        if encrypt {
            let cipher = Encryptor::<Aes128>::new_from_slices(DEFAULT_KEY, DEFAULT_IV)
                .expect("Invalid key/IV");
            cipher
                .encrypt_padded_mut::<Pkcs7>(&mut buf, buf_len)
                .expect("Encrypt failed")
                .to_vec()
        } else {
            let cipher = Decryptor::<Aes128>::new_from_slices(DEFAULT_KEY, DEFAULT_IV)
                .expect("Invalid key/IV");
            match cipher.decrypt_padded_mut::<Pkcs7>(&mut buf) {
                Ok(decrypted) => decrypted.to_vec(),
                Err(_) => buf,
            }
        }
    }

    pub async fn sej_seccfg_hw(&mut self, data: &[u8], encrypt: bool, noxor: bool) -> Vec<u8> {
        let mut working = data.to_vec();
        if encrypt && !noxor {
            self.xor(&mut working);
        }

        self.sej_v3_init(encrypt, &HACC_CFG_1, true).await;
        let mut result = self.sej_run(&working).await;
        self.sej_terminate().await;

        if !encrypt && !noxor {
            self.xor(&mut result);
        }

        result
    }

    pub async fn sej_seccfg_hw_v3(&mut self, data: &[u8], encrypt: bool) -> Vec<u8> {
        self.hw_aes128_cbc_encrypt(data, encrypt, false).await
    }

    pub async fn sej_seccfg_hw_v4(&mut self, data: &[u8], encrypt: bool) -> Vec<u8> {
        self.hw_aes128_cbc_encrypt(data, encrypt, true).await
    }

    async fn hw_aes128_cbc_encrypt(&mut self, data: &[u8], encrypt: bool, legacy: bool) -> Vec<u8> {
        self.sej_v3_init(encrypt, &HACC_CFG_1, legacy).await;
        let ret = self.sej_run(data).await;
        self.sej_terminate().await;
        ret
    }

    async fn sej_run(&mut self, data: &[u8]) -> Vec<u8> {
        let num_blocks = data.len() / 16; // I'm using u8, mtkclient uses u32
        let mut output = Vec::with_capacity(data.len());

        for block in 0..num_blocks {
            for word in 0..4 {
                let offset = block * 16 + word * 4;
                let val = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                self.wreg(
                    match word {
                        0 => SejReg::ASRC0,
                        1 => SejReg::ASRC1,
                        2 => SejReg::ASRC2,
                        _ => SejReg::ASRC3,
                    },
                    val,
                )
                .await;
            }
            self.wreg(SejReg::ACON2, SEJ_AES_START).await;

            for _ in 0..20 {
                if self.rreg(SejReg::ACON2).await & SEJ_AES_RDY != 0 {
                    break;
                }
            }

            for word in 0..4 {
                let out_val = self
                    .rreg(match word {
                        0 => SejReg::AOUT0,
                        1 => SejReg::AOUT1,
                        2 => SejReg::AOUT2,
                        _ => SejReg::AOUT3,
                    })
                    .await;
                output.extend_from_slice(&out_val.to_le_bytes());
            }
        }
        output
    }

    async fn sej_v3_init(&mut self, encrypt: bool, iv: &[u32], legacy: bool) {
        let acon_settings = SEJ_AES_CHG_BO_OFF
            | SEJ_AES_TYPE_128
            | if !iv.is_empty() { SEJ_AES_MODE_CBC } else { 0 }
            | if encrypt { SEJ_AES_ENC } else { SEJ_AES_DEC };

        for reg in [
            SejReg::AKEY0,
            SejReg::AKEY1,
            SejReg::AKEY2,
            SejReg::AKEY3,
            SejReg::AKEY4,
            SejReg::AKEY5,
            SejReg::AKEY6,
            SejReg::AKEY7,
        ] {
            self.wreg(reg, 0).await;
        }

        self.wreg(
            SejReg::ACON,
            SEJ_AES_CHG_BO_OFF | SEJ_AES_MODE_CBC | SEJ_AES_TYPE_128 | SEJ_AES_DEC,
        )
        .await;
        self.wreg(SejReg::ACONK, SEJ_AES_BK2C | SEJ_AES_R2K).await;
        self.wreg(SejReg::ACON2, SEJ_AES_CLR).await;

        for (i, &val) in iv.iter().enumerate().take(4) {
            self.wreg(
                match i {
                    0 => SejReg::ACFG0,
                    1 => SejReg::ACFG1,
                    2 => SejReg::ACFG2,
                    _ => SejReg::ACFG3,
                },
                val,
            )
            .await;
        }

        if legacy {
            let mut val = self.rreg(SejReg::UNK).await | 2;
            self.wreg(SejReg::UNK, val).await;
            val = self.rreg(SejReg::ACON2).await | 0x40000000;
            self.wreg(SejReg::ACON2, val).await;

            for _ in 0..20 {
                if self.rreg(SejReg::ACON2).await > 0x80000000 {
                    break;
                }
            }

            val = self.rreg(SejReg::UNK).await & 0xFFFFFFFE;
            self.wreg(SejReg::UNK, val).await;
            self.wreg(SejReg::ACONK, SEJ_AES_BK2C).await;
            self.wreg(SejReg::ACON, acon_settings).await;
        } else {
            self.wreg(SejReg::UNK, 1).await;

            for i in 0..3 {
                let pos = i * 4;
                self.wreg(SejReg::ASRC0, G_CFG_RANDOM_PATTERN[pos]).await;
                self.wreg(SejReg::ASRC1, G_CFG_RANDOM_PATTERN[pos + 1])
                    .await;
                self.wreg(SejReg::ASRC2, G_CFG_RANDOM_PATTERN[pos + 2])
                    .await;
                self.wreg(SejReg::ASRC3, G_CFG_RANDOM_PATTERN[pos + 3])
                    .await;
                self.wreg(SejReg::ACON2, SEJ_AES_START).await;
                for _ in 0..20 {
                    if self.rreg(SejReg::ACON2).await & SEJ_AES_RDY != 0 {
                        break;
                    }
                }
            }

            self.wreg(SejReg::ACON2, SEJ_AES_CLR).await;

            self.wreg(SejReg::ACFG0, iv[0]).await;
            self.wreg(SejReg::ACFG1, iv[1]).await;
            self.wreg(SejReg::ACFG2, iv[2]).await;
            self.wreg(SejReg::ACFG3, iv[3]).await;

            self.wreg(SejReg::ACON, acon_settings).await;
            self.wreg(SejReg::ACONK, 0).await;
        }
    }

    // Just clears the registers after use, nothing fancy
    async fn sej_terminate(&mut self) {
        self.wreg(SejReg::ACON2, SEJ_AES_CLR).await;

        for reg in [
            SejReg::AKEY0,
            SejReg::AKEY1,
            SejReg::AKEY2,
            SejReg::AKEY3,
            SejReg::AKEY4,
            SejReg::AKEY5,
            SejReg::AKEY6,
            SejReg::AKEY7,
        ] {
            self.wreg(reg, 0).await;
        }
    }
}
