/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use log::debug;
use std::io::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum DAType {
    Legacy,
    V5,
    V6,
}

#[derive(Clone, Debug)]
pub struct DAEntryRegion {
    pub data: Vec<u8>,      // Raw data of the region, including signature if any
    pub offset: u32,        // Offset within the file itself, where the region starts
    pub length: u32,        // Length of the region
    pub addr: u32,          // Address in which the region will be loaded in the device
    pub region_offset: u32, // Same as offset, but without the signature (offset - sig_len)
    pub sig_len: u32,       // Length of the signature, if any
}

#[derive(Clone, Debug)]
pub struct DA {
    pub da_type: DAType,
    pub regions: Vec<DAEntryRegion>,
    pub magic: u16,
    pub hw_code: u16,
    pub hw_sub_code: u16,
}

pub struct DAFile {
    // da_file_path: Path,
    pub da_raw_data: Vec<u8>,
    pub da_type: DAType,
    pub das: Vec<DA>,
}

impl DAFile {
    pub fn parse_da(raw_data: &[u8]) -> Result<DAFile, Error> {
        let hdr = &raw_data[..0x6C];

        let da_type = if &hdr[0..2] == b"\xDA\xDA" {
            DAType::Legacy
        } else if hdr.windows(10).any(|w| w == b"MTK_DA_v6") {
            DAType::V6
        } else {
            DAType::V5
        };

        if da_type != DAType::Legacy && !hdr.windows(0x12).any(|w| w == b"MTK_DOWNLOAD_AGENT") {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid DA file: Missing MTK_DOWNLOAD_AGENT signature",
            ));
        }

        let da_id = String::from_utf8_lossy(&hdr[0x20..0x60])
            .trim_end_matches('\0')
            .to_string();
        let version = u32::from_le_bytes(hdr[0x60..0x64].try_into().unwrap());
        let num_socs = u32::from_le_bytes(hdr[0x68..0x6C].try_into().unwrap());
        let magic_number = &hdr[0x64..0x68];

        let da_entry_size = match da_type {
            DAType::Legacy => 0xD8,
            _ => 0xDC,
        };

        let mut das = Vec::new();
        for i in 0..num_socs {
            // Each one of this is a DA entry in the header
            let start = 0x6C + (i as usize * da_entry_size);
            let end = start + da_entry_size;
            let da_entry = &raw_data[start..end];

            // For each DA, we parse its header entry
            let magic = u16::from_le_bytes(da_entry[0x00..0x02].try_into().unwrap());
            let hw_code = u16::from_le_bytes(da_entry[0x02..0x04].try_into().unwrap());
            let hw_sub_code = u16::from_le_bytes(da_entry[0x04..0x06].try_into().unwrap());
            let hw_version = u16::from_le_bytes(da_entry[0x06..0x08].try_into().unwrap());
            let mut regions: Vec<DAEntryRegion> = Vec::new();
            let region_count = u16::from_le_bytes(da_entry[0x12..0x14].try_into().unwrap());
            // Structure of the DA header entry
            // 0x00	magic	u16
            // 0x02	hw_code	u16
            // 0x04	hw_sub_code	u16
            // 0x06	hw_version	u16
            // 0x08	sw_version	u16 (v5 and v6 only, 0 in legacy)
            // 0x0A	...	u16
            // 0x0C	pagesize	u16
            // 0x0E	...	u16
            // 0x10	entry_region_index	u16
            // 0x12	entry_region_count	u16
            // 0x14	region table starts
            let mut current_region_offset = 0x14; // Starting from 0x14 to skip the data we already parsed
            for _ in 0..region_count {
                // Each region entry is 20 bytes
                // 0x00	offset (m_buf)	u32
                // 0x04	length (m_len)	u32
                // 0x08	addr (m_addr)	u32
                // 0x0C	m_region_offset (m_len - m_sig_len)	u32
                // 0x10	sig_len (m_sig_len)	u32
                let region_header_data =
                    &da_entry[current_region_offset..current_region_offset + 20];
                let offset = u32::from_le_bytes(region_header_data[0x00..0x04].try_into().unwrap());
                let length = u32::from_le_bytes(region_header_data[0x04..0x08].try_into().unwrap());
                let addr = u32::from_le_bytes(region_header_data[0x08..0x0C].try_into().unwrap());
                let sig_len =
                    u32::from_le_bytes(region_header_data[0x10..0x14].try_into().unwrap());
                let region_data: Vec<u8> =
                    raw_data[offset as usize..(offset + length) as usize].to_vec();
                debug!(
                    "Region: offset={:08X}, length={:08X}, addr={:08X}, sig_len={:08X}",
                    offset, length, addr, sig_len
                );
                regions.push(DAEntryRegion {
                    data: region_data,
                    offset,
                    length,
                    addr,
                    region_offset: length - sig_len,
                    sig_len,
                });
                current_region_offset += 20; // Move to the next region header
            }

            das.push(DA {
                da_type: da_type.clone(),
                regions,
                magic,
                hw_code,
                hw_sub_code,
            });
            debug!(
                "Parsed DA entry: hw_code={:04X}, hw_sub_code={:04X}, regions={}",
                hw_code, hw_sub_code, region_count
            );
        }

        Ok(DAFile {
            // da_file_path: Path::new(da_file_path).to_path_buf(),
            da_raw_data: raw_data.to_vec(),
            da_type,
            das,
        })
    }

    // TODO: Make an Hashmap, possibly also including other info about a chip
    pub fn get_da_from_hw_code(&self, hw_code: u16) -> Option<DA> {
        let da_code = match hw_code {
            0x0707 => 0x6768,
            _ => return None,
        };

        // I did the clone, I'm sorry!
        self.das.iter().find(|da| da.hw_code == da_code).cloned()
    }
}

impl DA {
    pub fn get_da1(&self) -> Option<&DAEntryRegion> {
        if self.regions.len() >= 3 {
            Some(&self.regions[1])
        } else {
            None
        }
    }

    pub fn get_da2(&self) -> Option<&DAEntryRegion> {
        if self.regions.len() >= 3 {
            Some(&self.regions[2])
        } else {
            None
        }
    }
}
