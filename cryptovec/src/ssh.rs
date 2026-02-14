use ssh_encoding::{Reader, Result, Writer};

use crate::CryptoVec;

impl Reader for CryptoVec {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        (&self[..]).read(out)
    }

    fn read_prefixed<T, E, F>(&mut self, f: F) -> core::result::Result<T, E>
    where
        E: From<ssh_encoding::Error>,
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
    {
        // Delegate to the &[u8] implementation by reading the prefix length,
        // extracting the prefixed data into a new CryptoVec, and calling f on it.
        let mut slice = &self[..];
        let prefix_len: usize = ssh_encoding::Decode::decode(&mut slice)?;

        if self.len() < 4 + prefix_len {
            return Err(ssh_encoding::Error::Length.into());
        }

        let mut prefixed = CryptoVec::from_slice(&self[4..4 + prefix_len]);
        let ret = f(&mut prefixed)?;
        Ok(ret)
    }

    fn remaining_len(&self) -> usize {
        self.len()
    }
}

impl Writer for CryptoVec {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes);
        Ok(())
    }
}
