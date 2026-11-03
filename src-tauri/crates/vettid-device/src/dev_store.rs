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

/// Create `path` new, readable and writable by its owner only where the
/// platform has modes (0600). On Windows the file inherits its folder's
/// access list (the user's profile: the user and administrators).
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

impl Persist for FileStore {
    fn save(&mut self, data: &[u8]) -> Result<(), StoreError> {
        use std::io::Write;
        let tmp = self.temp();
        // A temp file left by a crash is removed: create_new must create it.
        let _ = std::fs::remove_file(&tmp);
        let written = create_private(&tmp).and_then(|mut f| {
            f.write_all(data)?;
            f.sync_all()
        });
        // rename replaces an existing file, on Windows too.
        let done = written.and_then(|()| std::fs::rename(&tmp, &self.path));
        if done.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(StoreError::Io);
        }
        // Make the rename itself durable (the directory entry), where the
        // platform allows syncing a directory.
        #[cfg(unix)]
        if let Some(dir) = self.path.parent() {
            std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|_| StoreError::Io)?;
        }
        Ok(())
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
        // A temp file left by a crash doesn't block the next save.
        std::fs::write(dir.join("device.json.new"), b"stale").unwrap();
        s.save(b"three").unwrap();
        assert_eq!(s.load().unwrap().unwrap().as_slice(), b"three");
        assert!(!dir.join("device.json.new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("device.json")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
