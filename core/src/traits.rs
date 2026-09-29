/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
pub use penumbra_macros::{FromBytes, ToBytes};

pub trait ProgressCallback = FnMut(u64, u64) + Send;
pub trait Reader = std::io::Read + Send;
pub trait Writer = std::io::Write + Send;
pub trait ReaderSource<R: Reader> = FnMut(&str) -> crate::Result<(R, u64)> + Send;
pub trait WriterSink<W: Writer> = FnMut(&str) -> crate::Result<W> + Send;

pub trait ToBytes {
    const SIZE: usize;

    type Output;
    fn to_bytes(&self) -> Self::Output;
}

pub trait FromBytes: Sized {
    const SIZE: usize;
    fn from_bytes(raw: &[u8]) -> Option<Self>;
}

pub(crate) struct PeekedReader<R, const N: usize> {
    inner: R,
    buffer: [u8; N],
    valid_len: usize,
    cursor: usize,
}

impl<R: std::io::Read, const N: usize> PeekedReader<R, N> {
    pub fn peeked_bytes(&self) -> &[u8] {
        &self.buffer[..self.valid_len]
    }
}

impl<R: std::io::Read, const N: usize> std::io::Read for PeekedReader<R, N> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total = 0;
        if self.cursor < self.valid_len {
            let remaining = self.valid_len - self.cursor;
            let to_copy = std::cmp::min(buf.len(), remaining);
            buf[..to_copy].copy_from_slice(&self.buffer[self.cursor..self.cursor + to_copy]);
            self.cursor += to_copy;
            total += to_copy;
        }
        if total < buf.len() {
            total += self.inner.read(&mut buf[total..])?;
        }
        Ok(total)
    }
}

pub(crate) trait Peekable: std::io::Read + Sized {
    fn peek_bytes<const N: usize>(mut self) -> std::io::Result<PeekedReader<Self, N>> {
        let mut buffer = [0u8; N];
        let mut valid_len = 0;

        while valid_len < N {
            match self.read(&mut buffer[valid_len..]) {
                Ok(0) => break, // EOF
                Ok(n) => valid_len += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(PeekedReader { inner: self, buffer, valid_len, cursor: 0 })
    }
}

impl<R: std::io::Read> Peekable for R {}

pub(crate) trait ReadExt: std::io::Read {
    fn read_exact_fill(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut total_read = 0;
        while total_read < buf.len() {
            match self.read(&mut buf[total_read..]) {
                Ok(0) => break, // EOF
                Ok(n) => total_read += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total_read < buf.len() {
            buf[total_read..].fill(0);
        }
        Ok(())
    }
}

impl<R: std::io::Read + ?Sized> ReadExt for R {}
