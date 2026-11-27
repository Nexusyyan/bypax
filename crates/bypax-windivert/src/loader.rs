use crate::ffi::{Handle, WinDivertAddress, INVALID_HANDLE_VALUE, WINDIVERT_SHUTDOWN_BOTH};
use anyhow::{anyhow, bail, Context, Result};
use bypax_core::storage::DataPaths;
use libloading::Library;
use std::ffi::{c_char, c_void, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const c_char,
    layer: u32,
    priority: i16,
    flags: u64,
) -> Handle;
type FnWinDivertRecv = unsafe extern "system" fn(
    handle: Handle,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WinDivertAddress,
) -> i32;
type FnWinDivertSend = unsafe extern "system" fn(
    handle: Handle,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WinDivertAddress,
) -> i32;
type FnWinDivertShutdown = unsafe extern "system" fn(handle: Handle, how: u32) -> i32;
type FnWinDivertClose = unsafe extern "system" fn(handle: Handle) -> i32;
type FnWinDivertSetParam =
    unsafe extern "system" fn(handle: Handle, param: u32, value: u64) -> i32;
type FnWinDivertGetParam =
    unsafe extern "system" fn(handle: Handle, param: u32, value: *mut u64) -> i32;
type FnWinDivertHelperCalcChecksums = unsafe extern "system" fn(
    packet: *mut c_void,
    packet_len: u32,
    addr: *mut WinDivertAddress,
    flags: u64,
) -> i32;

/// Builds the deterministic search path list for `WinDivert.dll` / `WinDivert64.sys`:
/// custom dir -> `<exe_dir>/runtime/windivert` -> `<data_dir>/runtime/windivert` ->
/// `runtime/windivert` -> `%ProgramData%\Bypax\windivert`.
pub fn windivert_search_dirs(preferred_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let is_default_rel = preferred_dir
        .and_then(|p| p.to_str())
        .map(|s| matches!(s.trim(), "runtime/windivert" | r"runtime\windivert"))
        .unwrap_or(false);

    if let Some(dir) = preferred_dir {
        if !dir.as_os_str().is_empty() && !is_default_rel {
            dirs.push(dir.to_path_buf());
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("runtime").join("windivert"));
            dirs.push(parent.to_path_buf());
            dirs.push(parent.join("windivert"));
            for ancestor in parent.ancestors().skip(1).take(6) {
                dirs.push(ancestor.join("runtime").join("windivert"));
            }
        }
    }

    if let Ok(paths) = DataPaths::resolve() {
        dirs.push(paths.runtime_dir.join("windivert"));
        dirs.push(paths.root_dir.join("runtime").join("windivert"));
    }

    dirs.push(PathBuf::from("runtime").join("windivert"));

    if let Ok(program_data) = std::env::var("ProgramData") {
        dirs.push(PathBuf::from(program_data).join("Bypax").join("windivert"));
    }

    dirs
}

pub fn resolve_windivert_dir(preferred_dir: Option<&Path>) -> PathBuf {
    let dirs = windivert_search_dirs(preferred_dir);
    for d in &dirs {
        if d.join("WinDivert.dll").exists() {
            return d.clone();
        }
    }
    dirs.into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("runtime").join("windivert"))
}

/// Runtime-loaded `WinDivert.dll` symbol table (LGPLv3 Section 4d dynamic loading compliant).
pub struct WinDivertLib {
    _lib: Library,
    dll_path: PathBuf,
    open_fn: FnWinDivertOpen,
    recv_fn: FnWinDivertRecv,
    send_fn: FnWinDivertSend,
    shutdown_fn: FnWinDivertShutdown,
    close_fn: FnWinDivertClose,
    set_param_fn: FnWinDivertSetParam,
    get_param_fn: FnWinDivertGetParam,
    calc_checksums_fn: FnWinDivertHelperCalcChecksums,
}

unsafe impl Send for WinDivertLib {}
unsafe impl Sync for WinDivertLib {}

impl WinDivertLib {
    pub fn load(preferred_dir: Option<&Path>) -> Result<Arc<Self>> {
        let mut candidates: Vec<PathBuf> = windivert_search_dirs(preferred_dir)
            .into_iter()
            .map(|d| d.join("WinDivert.dll"))
            .collect();
        candidates.push(PathBuf::from("WinDivert.dll"));

        let chosen = candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "WinDivert.dll not found. Searched: {:?}. Ensure runtime/windivert contains \
                     WinDivert.dll and WinDivert64.sys.",
                    candidates
                )
            })?;

        let sys_path = chosen.with_file_name("WinDivert64.sys");
        if !sys_path.exists() {
            bail!(
                "Found {} but companion driver {} is missing. Place WinDivert64.sys next to WinDivert.dll.",
                chosen.display(),
                sys_path.display()
            );
        }

        unsafe {
            let lib = Library::new(&chosen).with_context(|| {
                format!(
                    "failed to load {} (ensure x64 WinDivert 2.2.2+ and check Windows Security)",
                    chosen.display()
                )
            })?;

            let open_fn: FnWinDivertOpen = *lib.get(b"WinDivertOpen\0")?;
            let recv_fn: FnWinDivertRecv = *lib.get(b"WinDivertRecv\0")?;
            let send_fn: FnWinDivertSend = *lib.get(b"WinDivertSend\0")?;
            let shutdown_fn: FnWinDivertShutdown = *lib.get(b"WinDivertShutdown\0")?;
            let close_fn: FnWinDivertClose = *lib.get(b"WinDivertClose\0")?;
            let set_param_fn: FnWinDivertSetParam = *lib.get(b"WinDivertSetParam\0")?;
            let get_param_fn: FnWinDivertGetParam = *lib.get(b"WinDivertGetParam\0")?;
            let calc_checksums_fn: FnWinDivertHelperCalcChecksums =
                *lib.get(b"WinDivertHelperCalcChecksums\0")?;

            Ok(Arc::new(Self {
                _lib: lib,
                dll_path: chosen,
                open_fn,
                recv_fn,
                send_fn,
                shutdown_fn,
                close_fn,
                set_param_fn,
                get_param_fn,
                calc_checksums_fn,
            }))
        }
    }

    pub fn dll_path(&self) -> &Path {
        &self.dll_path
    }

    pub fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> Result<WinDivertHandle> {
        let c_filter = CString::new(filter).context("WinDivert filter contains interior NUL")?;
        let raw = unsafe { (self.open_fn)(c_filter.as_ptr(), layer, priority, flags) };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            let os_err = std::io::Error::last_os_error();
            let code = os_err.raw_os_error().unwrap_or(0);
            let hint = match code {
                5 => "Access Denied: Administrator privileges or BypaxService required.",
                2 => "WinDivert64.sys driver file was not found alongside WinDivert.dll.",
                577 => "Driver signature verification failed (check Secure Boot / HVCI / official WinDivert 2.2.2-A).",
                1275 => "Driver blocked by Windows Security / HVCI Memory Integrity or antivirus.",
                87 => "Invalid WinDivert filter expression or parameter (or another WinDivert proxy service is already holding the same layer/priority).",
                1072 => "WinDivert kernel driver service is marked for deletion; stop any conflicting WinDivert service and retry.",
                _ => "Check administrator privileges, WinDivert64.sys presence, and Windows Security logs.",
            };
            bail!("WinDivertOpen(layer={layer}, filter='{filter}') failed with OS error {code} ({os_err}). {hint}");
        }
        Ok(WinDivertHandle {
            lib: Arc::clone(self),
            raw,
        })
    }

    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut WinDivertAddress) -> bool {
        unsafe {
            (self.calc_checksums_fn)(
                packet.as_mut_ptr() as *mut c_void,
                packet.len() as u32,
                addr as *mut WinDivertAddress,
                0,
            ) != 0
        }
    }
}

pub struct WinDivertHandle {
    lib: Arc<WinDivertLib>,
    raw: Handle,
}

unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

impl WinDivertHandle {
    pub fn set_param(&self, param: u32, value: u64) -> Result<()> {
        let ok = unsafe { (self.lib.set_param_fn)(self.raw, param, value) };
        if ok == 0 {
            bail!(
                "WinDivertSetParam({param}, {value}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    pub fn get_param(&self, param: u32) -> Result<u64> {
        let mut val = 0u64;
        let ok = unsafe { (self.lib.get_param_fn)(self.raw, param, &mut val) };
        if ok == 0 {
            bail!(
                "WinDivertGetParam({param}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(val)
    }

    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, WinDivertAddress)> {
        let mut recv_len = 0u32;
        let mut addr = WinDivertAddress::default();
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr() as *mut c_void
        };
        let ok = unsafe {
            (self.lib.recv_fn)(
                self.raw,
                ptr,
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok((recv_len as usize, addr))
        }
    }

    pub fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> std::io::Result<usize> {
        let mut send_len = 0u32;
        let ok = unsafe {
            (self.lib.send_fn)(
                self.raw,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut send_len,
                addr,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(send_len as usize)
        }
    }

    pub fn shutdown(&self) {
        unsafe {
            let _ = (self.lib.shutdown_fn)(self.raw, WINDIVERT_SHUTDOWN_BOTH);
        }
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.lib.shutdown_fn)(self.raw, WINDIVERT_SHUTDOWN_BOTH);
            let _ = (self.lib.close_fn)(self.raw);
        }
    }
}
