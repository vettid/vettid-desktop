//! A plain-file [`Persist`] for development builds only.
//!
//! It writes the device's keys to a file **unencrypted**. It exists so a
//! developer can pair against the dev stack; it is behind the non-default
//! `dev-file-store` feature, and lib.rs refuses to compile that feature
//! without `debug_assertions`, so no release build can contain it.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::store::{Persist, StoreError};

/// The device state in one file, replaced atomically (written beside it,
/// then renamed over it).
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// A store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileStore { path: path.into() }
    }

    fn temp(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".new");
        p.into()
    }
}

impl Persist for FileStore {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        use std::io::Write;
        let tmp = self.temp();
        let mut f = std::fs::File::create(&tmp).map_err(|_| StoreError::Io)?;
        f.write_all(data).and_then(|()| f.sync_all()).map_err(|_| StoreError::Io)?;
        drop(f);
        // rename replaces an existing file, on Windows too.
        std::fs::rename(&tmp, &self.path).map_err(|_| StoreError::Io)
    }

    fn load(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(Some(Zeroizing::new(b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError::Io),
        }
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_replace_clear() {
        let dir = std::env::temp_dir().join(format!("vettid-device-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = FileStore::new(dir.join("device.json"));
        assert_eq!(s.load().unwrap(), None);
        s.save(b"one").unwrap();
        s.save(b"two").unwrap();
        assert_eq!(s.load().unwrap().unwrap().as_slice(), b"two");
        s.clear().unwrap();
        assert_eq!(s.load().unwrap(), None);
        s.clear().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
