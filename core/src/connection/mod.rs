/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
mod backend;
mod command;
pub mod port;
use crate::connection::command::Command;
use crate::connection::port::{ConnectionType, MTKPort};
use crate::error::{Error, Result};
use log::{debug, error, info};

#[derive(Debug)]
pub struct Connection {
    pub port: Box<dyn MTKPort>,
    pub connection_type: ConnectionType,
    pub baudrate: u32,
}

impl Connection {
    pub fn new(port: Box<dyn MTKPort>) -> Self {
        let connection_type = port.get_connection_type();
        let baudrate = port.get_baudrate();

        Connection {
            port,
            connection_type,
            baudrate,
        }
    }

    pub async fn write(&mut self, data: &[u8], size: usize) -> Result<Vec<u8>> {
        self.port.write_all(data).await?;
        let mut buf = vec![0u8; size];
        self.port.read_exact(&mut buf).await?;
        Ok(buf)
    }

    pub fn check(&self, data: &[u8], expected_data: &[u8]) -> Result<()> {
        if data == expected_data {
            Ok(())
        } else {
            error!(
                "Data mismatch. Expected: {:x?}, Got: {:x?}",
                expected_data, data
            );
            Err(Error::conn("Data mismatch"))
        }
    }

    pub async fn echo(&mut self, data: &[u8], size: usize) -> Result<()> {
        self.port.write_all(data).await?;
        let mut buf = vec![0u8; size];
        self.port.read_exact(&mut buf).await?;
        self.check(&buf, data)
    }

    pub async fn handshake(&mut self) -> Result<()> {
        info!("Starting handshake...");
        self.port.handshake().await?;
        info!("Handshake completed!");
        Ok(())
    }

    pub async fn jump_da(&mut self, address: u32) -> Result<()> {
        debug!("Jump to DA at 0x{:08X}", address);

        self.echo(&[Command::JumpDa as u8], 1).await?;
        self.echo(&address.to_le_bytes(), 4).await?;

        let mut status = [0u8; 2];
        self.port.read_exact(&mut status).await?;

        let status_val = u16::from_le_bytes(status);
        if status_val != 0 {
            error!("JumpDA failed with status: {:04X}", status_val);
            return Err(Error::conn("JumpDA failed"));
        }

        Ok(())
    }

    pub async fn send_da(
        &mut self,
        da_data: &[u8],
        da_len: u32,
        address: u32,
        sig_len: u32,
    ) -> Result<()> {
        debug!("Sending DA, size: {}", da_data.len());
        self.echo(&[Command::SendDa as u8], 1).await?;
        self.echo(&address.to_be_bytes(), 4).await?;
        self.echo(&(da_len).to_be_bytes(), 4).await?;
        self.echo(&sig_len.to_be_bytes(), 4).await?;

        let mut status = [0u8; 2];
        self.port.read_exact(&mut status).await?;
        let status_val = u16::from_be_bytes(status);
        debug!("Received status: 0x{:04X}", status_val);

        if status_val != 0 {
            error!("SendDA command failed with status: {:04X}", status_val);
            return Err(Error::conn("SendDA command failed"));
        }

        self.port.write_all(da_data).await?;

        debug!("DA sent!");

        let mut checksum = [0u8; 2];
        self.port.read_exact(&mut checksum).await?;
        debug!("Received checksum: {:02X}{:02X}", checksum[0], checksum[1]);

        let mut status = [0u8; 2];
        self.port.read_exact(&mut status).await?;

        let status_val = u16::from_be_bytes(status);
        debug!("Received final status: 0x{:04X}", status_val);
        if status_val != 0 {
            error!(
                "SendDA data transfer failed with status: {:04X}",
                status_val
            );
            return Err(Error::conn("SendDA data transfer failed"));
        }

        Ok(())
    }

    pub async fn get_hw_code(&mut self) -> Result<u32> {
        self.echo(&[Command::GetHwCode as u8], 1).await?;

        let mut hw_code = [0u8; 2];
        let mut status = [0u8; 2];

        self.port.read_exact(&mut hw_code).await?;
        self.port.read_exact(&mut status).await?;

        let status_val = u16::from_le_bytes(status);
        if status_val != 0 {
            error!("GetHwCode failed with status: {:04X}", status_val);
            return Err(Error::conn("GetHwCode failed"));
        }

        Ok(u16::from_le_bytes(hw_code) as u32)
    }

    pub async fn get_hw_sw_ver(&mut self) -> Result<(u16, u16, u16)> {
        self.echo(&[Command::GetHwSwVer as u8], 1).await?;

        let mut hw_sub_code = [0u8; 2];
        let mut hw_ver = [0u8; 2];
        let mut sw_ver = [0u8; 2];
        let mut status = [0u8; 2];

        self.port.read_exact(&mut hw_sub_code).await?;
        self.port.read_exact(&mut hw_ver).await?;
        self.port.read_exact(&mut sw_ver).await?;
        self.port.read_exact(&mut status).await?;

        let status_val = u16::from_le_bytes(status);
        if status_val != 0 {
            error!("GetHwSwVer failed with status: 0x{:04X}", status_val);
            return Err(Error::conn("GetHwSwVer failed"));
        }

        Ok((
            u16::from_le_bytes(hw_sub_code),
            u16::from_le_bytes(hw_ver),
            u16::from_le_bytes(sw_ver),
        ))
    }

    pub async fn get_soc_id(&mut self) -> Result<Vec<u8>> {
        self.echo(&[Command::GetSocId as u8], 1).await?;

        let mut length_bytes = [0u8; 4];
        self.port.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        let mut soc_id = vec![0u8; length];
        self.port.read_exact(&mut soc_id).await?;

        let mut status_bytes = [0u8; 2];
        self.port.read_exact(&mut status_bytes).await?;
        let status = u16::from_le_bytes(status_bytes);

        if status != 0 {
            error!("GetSocId failed with status: 0x{:04X}", status);
            return Err(Error::conn("GetSocId failed"));
        }

        Ok(soc_id)
    }

    pub async fn get_meid(&mut self) -> Result<Vec<u8>> {
        self.echo(&[Command::GetMeId as u8], 1).await?;

        let mut length_bytes = [0u8; 4];
        self.port.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        let mut meid = vec![0u8; length];
        self.port.read_exact(&mut meid).await?;

        let mut status_bytes = [0u8; 2];
        self.port.read_exact(&mut status_bytes).await?;
        let status = u16::from_le_bytes(status_bytes);

        if status != 0 {
            error!("GetMeid failed with status: 0x{:04X}", status);
            return Err(Error::conn("GetMeid failed"));
        }

        Ok(meid)
    }
}
