use std::sync::RwLock;

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroize;

use crate::Error;
use crate::wire::MAX_MLS_OBJECT_BYTES;

const MAX_STORAGE_ENTRIES: usize = 65_536;
const MAX_STORAGE_BYTES: usize = 64 * MAX_MLS_OBJECT_BYTES;

#[derive(Debug, Default)]
pub(crate) struct TransactionalOpenMlsProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for TransactionalOpenMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Copy-on-write OpenMLS state used for one Pigeon transaction. Construct from
/// the durable checkpoint, mutate only this candidate, and export it only when
/// the surrounding Pigeon checkpoint is ready to replace atomically.
#[derive(Debug, Default)]
pub struct TransactionalOpenMlsStorage {
    provider: TransactionalOpenMlsProvider,
}

impl TransactionalOpenMlsStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_checkpoint(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_STORAGE_BYTES {
            return Err(Error::ResourceLimit("OpenMLS checkpoint bytes"));
        }
        let mut cursor = Cursor::new(bytes);
        let count = cursor.read_u32()? as usize;
        if count > MAX_STORAGE_ENTRIES {
            return Err(Error::ResourceLimit("OpenMLS storage entries"));
        }
        let mut values = std::collections::HashMap::with_capacity(count);
        for _ in 0..count {
            let key = cursor.read_bytes()?;
            let value = cursor.read_bytes()?;
            values.insert(key, value);
        }
        if !cursor.is_finished() {
            return Err(Error::Serialization);
        }
        Ok(Self {
            provider: TransactionalOpenMlsProvider {
                crypto: RustCrypto::default(),
                storage: MemoryStorage {
                    values: RwLock::new(values),
                },
            },
        })
    }

    pub fn export_checkpoint(&self) -> Result<Vec<u8>, Error> {
        let values = self.provider.storage.values.read().unwrap();
        if values.len() > MAX_STORAGE_ENTRIES {
            return Err(Error::ResourceLimit("OpenMLS storage entries"));
        }
        let mut entries: Vec<_> = values.iter().collect();
        entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut output = Vec::new();
        write_u32(&mut output, entries.len())?;
        for (key, value) in entries {
            write_bytes(&mut output, key)?;
            write_bytes(&mut output, value)?;
            if output.len() > MAX_STORAGE_BYTES {
                return Err(Error::ResourceLimit("OpenMLS checkpoint bytes"));
            }
        }
        Ok(output)
    }

    pub fn entry_count(&self) -> usize {
        self.provider.storage.values.read().unwrap().len()
    }

    pub(crate) fn provider(&self) -> &TransactionalOpenMlsProvider {
        &self.provider
    }
}

impl Drop for TransactionalOpenMlsStorage {
    fn drop(&mut self) {
        let mut values = self.provider.storage.values.write().unwrap();
        for (mut key, mut value) in values.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}

fn write_u32(output: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    let value = u32::try_from(value).map_err(|_| Error::Serialization)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    write_u32(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let end = self.position.checked_add(4).ok_or(Error::Serialization)?;
        let bytes: [u8; 4] = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Serialization)?
            .try_into()
            .map_err(|_| Error::Serialization)?;
        self.position = end;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let length = self.read_u32()? as usize;
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::Serialization)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error::Serialization)?
            .to_vec();
        self.position = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}
