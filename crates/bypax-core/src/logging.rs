use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Default maximum bytes per log file before rotating to `<name>.1` (2 MiB x 2 = 4 MiB max).
pub const DEFAULT_MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

struct FileState {
    file: Option<File>,
    len: u64,
}

/// Thread-safe, bounded rotating log file shared across `LogRing` and `tracing_subscriber`.
/// Keeps at most one rotated backup (`<file>.1`) so long-running sessions never fill disk.
pub struct RotatingLogFile {
    path: PathBuf,
    max_bytes: u64,
    state: Mutex<FileState>,
}

impl RotatingLogFile {
    pub fn open(path: PathBuf, max_bytes: u64) -> io::Result<Arc<Self>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Arc::new(Self {
            path,
            max_bytes: max_bytes.max(1024),
            state: Mutex::new(FileState {
                file: Some(file),
                len,
            }),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn backup_path(&self) -> PathBuf {
        let mut s = self.path.as_os_str().to_os_string();
        s.push(".1");
        PathBuf::from(s)
    }

    pub fn writer(self: &Arc<Self>) -> RotatingLogWriter {
        RotatingLogWriter {
            inner: Arc::clone(self),
        }
    }

    pub fn append_entry(&self, level: &str, message: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let clean = message.trim_end_matches(&['\r', '\n'][..]);
        let line = format!("{ts} [{level}] {clean}\n");
        let _ = self.write_bytes(line.as_bytes());
    }

    pub fn write_bytes(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let Ok(mut st) = self.state.lock() else {
            return Err(io::Error::other("log file mutex poisoned"));
        };
        if st.len.saturating_add(buf.len() as u64) > self.max_bytes {
            self.rotate_locked(&mut st)?;
        }
        if st.file.is_none() {
            self.reopen_locked(&mut st)?;
        }
        if let Some(ref mut f) = st.file {
            match f.write_all(buf).and_then(|_| f.flush()) {
                Ok(()) => {
                    st.len = st.len.saturating_add(buf.len() as u64);
                    return Ok(buf.len());
                }
                Err(_) => {
                    // Retry once after reopening in case the log file was removed externally.
                    self.reopen_locked(&mut st)?;
                    if let Some(ref mut f2) = st.file {
                        f2.write_all(buf)?;
                        f2.flush()?;
                        st.len = st.len.saturating_add(buf.len() as u64);
                        return Ok(buf.len());
                    }
                }
            }
        }
        Ok(buf.len())
    }

    fn reopen_locked(&self, st: &mut FileState) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        st.len = f.metadata().map(|m| m.len()).unwrap_or(0);
        st.file = Some(f);
        Ok(())
    }

    fn rotate_locked(&self, st: &mut FileState) -> io::Result<()> {
        st.file = None;
        let backup = self.backup_path();
        let _ = fs::remove_file(&backup);
        if self.path.exists() {
            let _ = fs::rename(&self.path, &backup);
        }
        self.reopen_locked(st)
    }
}

/// `std::io::Write` adapter suitable for `tracing_subscriber::fmt().with_writer(...)`.
#[derive(Clone)]
pub struct RotatingLogWriter {
    inner: Arc<RotatingLogFile>,
}

impl Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_bytes(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Derives the canonical `logs/` directory from a `runtime/` directory (falling back to
/// `<runtime_dir>/logs` if it has no parent). Ensures elevated workers launched with
/// `--runtime-dir` write logs alongside the GUI's own `bypax-app.log`.
pub fn logs_dir_from_runtime_dir(runtime_dir: &Path) -> PathBuf {
    let dir = runtime_dir
        .parent()
        .map(|p| p.join("logs"))
        .unwrap_or_else(|| runtime_dir.join("logs"));
    let _ = fs::create_dir_all(&dir);
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_log_appends_and_rotates_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("logs").join("bypax-test.log");
        let logger = RotatingLogFile::open(log_path.clone(), 1024).unwrap();

        for i in 0..40 {
            logger.append_entry("INFO", &format!("event number {i} payload padding 0123456789abcdef"));
        }

        assert!(log_path.is_file());
        let backup = logger.backup_path();
        assert!(backup.is_file(), "expected rotated backup file {:?}", backup);
        let active_content = fs::read_to_string(&log_path).unwrap();
        assert!(active_content.contains("event number 39"));
        assert!(fs::metadata(&log_path).unwrap().len() <= 1024);
    }

    #[test]
    fn logs_dir_from_runtime_dir_resolves_sibling_logs_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("runtime");
        fs::create_dir_all(&rt).unwrap();
        let logs = logs_dir_from_runtime_dir(&rt);
        assert_eq!(logs, tmp.path().join("logs"));
        assert!(logs.is_dir());
    }
}
