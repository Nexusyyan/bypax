#[cfg(windows)]
pub mod ffi;
#[cfg(windows)]
pub mod iphelper;
#[cfg(windows)]
pub mod loader;
#[cfg(windows)]
pub mod windows_engine;

#[cfg(windows)]
pub use windows_engine::{
    is_elevated, probe_windivert, resolve_windivert_dir, WinDivertCaptureEngine,
    WinDivertProbeReport,
};

#[cfg(not(windows))]
mod unix_stub {
    use anyhow::{bail, Result};
    use bypax_appproxy::capture::{CaptureEngine, CapturedPacket, FiveTuple, PacketMeta};
    use bypax_appproxy::process::ProcessTracker;
    use bypax_ipc::DriverProbeDto;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[derive(Debug, Clone)]
    pub struct WinDivertProbeReport {
        pub dll_loaded: bool,
        pub dll_path: Option<String>,
        pub driver_opened: bool,
        pub driver_version: Option<(u64, u64)>,
        pub error: Option<String>,
        pub error_kind: Option<String>,
    }

    impl WinDivertProbeReport {
        pub fn to_dto(&self) -> DriverProbeDto {
            DriverProbeDto {
                platform: std::env::consts::OS.to_string(),
                elevated: is_elevated(),
                dll_loaded: self.dll_loaded,
                dll_path: self.dll_path.clone(),
                driver_opened: self.driver_opened,
                driver_version: self
                    .driver_version
                    .map(|(maj, min)| format!("{maj}.{min}")),
                error: self.error.clone(),
                error_kind: self.error_kind.clone(),
            }
        }
    }

    pub fn is_elevated() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub fn resolve_windivert_dir(preferred: Option<&Path>) -> PathBuf {
        preferred
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("runtime/windivert"))
    }

    pub fn probe_windivert(_windivert_dir: Option<&Path>) -> WinDivertProbeReport {
        WinDivertProbeReport {
            dll_loaded: false,
            dll_path: None,
            driver_opened: false,
            driver_version: None,
            error: Some("WinDivert is only used on Windows; macOS uses zero-cert launchd + utun path routing".to_string()),
            error_kind: None,
        }
    }

    pub struct WinDivertCaptureEngine;

    impl WinDivertCaptureEngine {
        pub fn new(_windivert_dir: Option<&Path>) -> Result<Self> {
            bail!("WinDivert capture backend is only available on Windows")
        }

        pub fn with_process_tracker(
            _windivert_dir: Option<&Path>,
            _process_tracker: Option<Arc<dyn ProcessTracker>>,
        ) -> Result<Self> {
            bail!("WinDivert capture backend is only available on Windows")
        }
    }

    impl CaptureEngine for WinDivertCaptureEngine {
        fn start(&self, _tx: mpsc::Sender<CapturedPacket>) -> Result<()> {
            bail!("WinDivert capture backend is only available on Windows")
        }

        fn inject(&self, _packet: &[u8], _meta: &PacketMeta) -> Result<()> {
            Ok(())
        }

        fn lookup_pid(&self, _tuple: &FiveTuple) -> Option<u32> {
            None
        }

        fn find_local_tcp_listener_pid(&self, _port: u16) -> Option<u32> {
            None
        }

        fn shutdown(&self) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
pub use unix_stub::{
    is_elevated, probe_windivert, resolve_windivert_dir, WinDivertCaptureEngine,
    WinDivertProbeReport,
};
