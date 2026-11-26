use bypax_core::model::AppProxyRule;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Metadata describing a running OS process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

/// Process spawned outside a macOS `.app` bundle by an enabled App Proxy bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalChildProcess {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Alert grouping external child processes discovered for an enabled `.app` rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalChildAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub app_name: String,
    pub children: Vec<ExternalChildProcess>,
}

/// Installed desktop application entry for the Process / App Picker modal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledAppItem {
    pub name: String,
    pub path: String,
    pub process_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<String>,
}

/// Platform-agnostic process & ancestor-chain tracker.
pub trait ProcessTracker: Send + Sync + 'static {
    fn get_process(&self, pid: u32) -> Option<ProcessInfo>;
    fn ancestor_chain(&self, pid: u32) -> Vec<ProcessInfo>;
    fn list_processes(&self) -> Vec<ProcessInfo>;
    fn warm_pid(&self, pid: u32) {
        let _ = self.get_process(pid);
    }
    fn refresh(&self);
}

struct CachedSnapshot {
    fetched_at: Instant,
    by_pid: HashMap<u32, ProcessInfo>,
}

/// Snapshot-backed cross-platform process tracker with TTL caching and fast single-PID lookup.
pub struct SnapshotProcessTracker {
    ttl: Duration,
    cache: RwLock<CachedSnapshot>,
}

impl SnapshotProcessTracker {
    pub fn new(ttl: Duration) -> Self {
        let initial = take_os_process_snapshot();
        Self {
            ttl,
            cache: RwLock::new(CachedSnapshot {
                fetched_at: Instant::now(),
                by_pid: initial,
            }),
        }
    }

    fn ensure_fresh(&self, force: bool) {
        if !force {
            if let Ok(guard) = self.cache.read() {
                if guard.fetched_at.elapsed() < self.ttl {
                    return;
                }
            }
        }
        let fresh = take_os_process_snapshot();
        if let Ok(mut guard) = self.cache.write() {
            guard.by_pid = fresh;
            guard.fetched_at = Instant::now();
        }
    }
}

impl Default for SnapshotProcessTracker {
    fn default() -> Self {
        Self::new(Duration::from_millis(500))
    }
}

impl ProcessTracker for SnapshotProcessTracker {
    fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        if pid == 0 {
            return None;
        }
        self.ensure_fresh(false);
        if let Ok(guard) = self.cache.read() {
            if let Some(info) = guard.by_pid.get(&pid) {
                return Some(info.clone());
            }
        }
        if let Some(info) = query_single_process(pid) {
            if let Ok(mut guard) = self.cache.write() {
                guard.by_pid.insert(pid, info.clone());
            }
            return Some(info);
        }
        self.ensure_fresh(true);
        self.cache
            .read()
            .ok()
            .and_then(|g| g.by_pid.get(&pid).cloned())
    }

    fn ancestor_chain(&self, pid: u32) -> Vec<ProcessInfo> {
        if pid == 0 {
            return Vec::new();
        }
        self.ensure_fresh(false);

        let mut probe = pid;
        let mut visited_probe = HashSet::new();
        while probe > 1 && visited_probe.insert(probe) && visited_probe.len() < 16 {
            let cached_ppid = self
                .cache
                .read()
                .ok()
                .and_then(|g| g.by_pid.get(&probe).map(|p| p.parent_pid));
            match cached_ppid {
                Some(ppid) => probe = ppid,
                None => {
                    if let Some(info) = query_single_process(probe) {
                        let next_ppid = info.parent_pid;
                        if let Ok(mut guard) = self.cache.write() {
                            guard.by_pid.insert(probe, info);
                        }
                        probe = next_ppid;
                    } else {
                        self.ensure_fresh(true);
                        break;
                    }
                }
            }
        }

        let guard = match self.cache.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let mut chain = Vec::with_capacity(6);
        let mut visited = HashSet::new();
        let mut current = pid;

        while current != 0 && visited.insert(current) && chain.len() < 32 {
            match guard.by_pid.get(&current) {
                Some(info) => {
                    let next = info.parent_pid;
                    chain.push(info.clone());
                    current = next;
                }
                None => break,
            }
        }
        chain
    }

    fn warm_pid(&self, pid: u32) {
        if pid <= 4 {
            return;
        }
        let already_cached = self
            .cache
            .read()
            .ok()
            .map(|g| g.by_pid.contains_key(&pid))
            .unwrap_or(false);
        if !already_cached {
            let _ = self.ancestor_chain(pid);
        }
    }

    fn list_processes(&self) -> Vec<ProcessInfo> {
        self.ensure_fresh(true);
        let mut list: Vec<ProcessInfo> = self
            .cache
            .read()
            .ok()
            .map(|g| g.by_pid.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by_key(|p| p.pid);
        list
    }

    fn refresh(&self) {
        self.ensure_fresh(true);
    }
}

/// In-memory deterministic tracker for cross-platform unit tests.
#[derive(Default)]
pub struct MockProcessTracker {
    by_pid: RwLock<HashMap<u32, ProcessInfo>>,
}

impl MockProcessTracker {
    pub fn with_processes(procs: impl IntoIterator<Item = ProcessInfo>) -> Self {
        let map = procs.into_iter().map(|p| (p.pid, p)).collect();
        Self {
            by_pid: RwLock::new(map),
        }
    }
}

impl ProcessTracker for MockProcessTracker {
    fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        self.by_pid.read().ok()?.get(&pid).cloned()
    }

    fn ancestor_chain(&self, pid: u32) -> Vec<ProcessInfo> {
        let guard = match self.by_pid.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = pid;
        while current != 0 && visited.insert(current) && chain.len() < 32 {
            match guard.get(&current) {
                Some(info) => {
                    let next = info.parent_pid;
                    chain.push(info.clone());
                    current = next;
                }
                None => break,
            }
        }
        chain
    }

    fn list_processes(&self) -> Vec<ProcessInfo> {
        let mut list: Vec<ProcessInfo> = self
            .by_pid
            .read()
            .ok()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by_key(|p| p.pid);
        list
    }

    fn refresh(&self) {}
}

fn norm_unix_path(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_ascii_lowercase()
}

/// Detects running child processes spawned by an enabled `.app` bundle whose executable path
/// lies outside the `.app` bundle (for example `/opt/homebrew/bin/node` spawned by Cursor.app),
/// enabling one-click inclusion or persistent ignore on macOS zero-cert `utun` routing.
pub fn detect_external_children(
    rules: &[AppProxyRule],
    tracker: &dyn ProcessTracker,
) -> Vec<ExternalChildAlert> {
    let procs = tracker.list_processes();
    let mut alerts = Vec::new();

    for rule in rules
        .iter()
        .filter(|r| r.enabled && r.include_children && !r.mac_bundle_paths.is_empty())
    {
        let bundle_norms: Vec<String> = rule
            .mac_bundle_paths
            .iter()
            .map(|b| norm_unix_path(b))
            .filter(|b| !b.is_empty())
            .collect();
        if bundle_norms.is_empty() {
            continue;
        }

        let ignored: HashSet<String> = rule
            .ignored_external_children
            .iter()
            .map(|p| norm_unix_path(p))
            .collect();
        let covered_prefixes: Vec<String> = rule
            .path_prefixes
            .iter()
            .map(|p| norm_unix_path(p))
            .filter(|p| !p.is_empty())
            .collect();
        let covered_contains: Vec<String> = rule
            .path_contains
            .iter()
            .map(|p| norm_unix_path(p))
            .filter(|p| !p.is_empty())
            .collect();

        let mut seen_paths: HashSet<String> = HashSet::new();
        let mut children: Vec<ExternalChildProcess> = Vec::new();

        for proc in &procs {
            let Some(ref exe) = proc.exe_path else {
                continue;
            };
            let exe_norm = norm_unix_path(exe);
            if exe_norm.is_empty() {
                continue;
            }
            // Already inside the .app bundle -> natively matched by process_path_regex.
            if bundle_norms
                .iter()
                .any(|b| exe_norm == *b || exe_norm.starts_with(&format!("{b}/")))
            {
                continue;
            }
            // Already explicitly included or ignored by the user.
            if ignored.contains(&exe_norm)
                || covered_prefixes.iter().any(|p| exe_norm.starts_with(p))
                || covered_contains.iter().any(|sub| exe_norm.contains(sub))
                || rule
                    .process_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(&proc.name))
            {
                continue;
            }

            let chain = tracker.ancestor_chain(proc.pid);
            let spawned_by_bundle = chain.iter().skip(1).any(|anc| {
                anc.exe_path.as_deref().is_some_and(|anc_exe| {
                    let anc_norm = norm_unix_path(anc_exe);
                    bundle_norms
                        .iter()
                        .any(|b| anc_norm == *b || anc_norm.starts_with(&format!("{b}/")))
                })
            });

            if spawned_by_bundle && seen_paths.insert(exe_norm) {
                children.push(ExternalChildProcess {
                    pid: proc.pid,
                    name: proc.name.clone(),
                    exe_path: exe.clone(),
                });
            }
        }

        if !children.is_empty() {
            alerts.push(ExternalChildAlert {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                app_name: rule.name.clone(),
                children,
            });
        }
    }

    alerts
}

/// Lists installed desktop applications for the GUI App Picker modal.
pub fn list_installed_apps() -> Vec<InstalledAppItem> {
    let mut items: Vec<InstalledAppItem> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let mut dirs = vec![std::path::PathBuf::from("/Applications")];
        if let Ok(home) = std::env::var("HOME") {
            dirs.push(Path::new(&home).join("Applications"));
        }
        for dir in dirs {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("app") {
                        let name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("App")
                            .to_string();
                        let bundle = path.to_string_lossy().to_string();
                        items.push(InstalledAppItem {
                            name: name.clone(),
                            path: bundle.clone(),
                            process_name: name,
                            bundle_path: Some(bundle),
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut roots = Vec::new();
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            roots.push(Path::new(&local).join("Programs"));
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            roots.push(std::path::PathBuf::from(pf));
        }
        let mut seen = HashSet::new();
        for root in roots {
            if let Ok(dirs) = std::fs::read_dir(&root) {
                for entry in dirs.flatten().take(80) {
                    let p = entry.path();
                    if !p.is_dir() {
                        continue;
                    }
                    let dir_name = p
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(files) = std::fs::read_dir(&p) {
                        for f in files.flatten() {
                            let fp = f.path();
                            if fp.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
                                let proc_name = fp
                                    .file_name()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or_default()
                                    .to_string();
                                let lower = proc_name.to_ascii_lowercase();
                                if lower.contains("unins") || lower.contains("update") || lower.contains("crash") {
                                    continue;
                                }
                                let full = fp.to_string_lossy().to_string();
                                if seen.insert(full.to_ascii_lowercase()) {
                                    items.push(InstalledAppItem {
                                        name: if dir_name.is_empty() {
                                            proc_name.clone()
                                        } else {
                                            dir_name.clone()
                                        },
                                        path: full,
                                        process_name: proc_name,
                                        bundle_path: None,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    items.sort_by_key(|a| a.name.to_ascii_lowercase());
    items
}

// --- Windows Process Implementation (NtQueryInformationProcess + CreateToolhelp32Snapshot) ---

#[cfg(windows)]
fn query_single_process(pid: u32) -> Option<ProcessInfo> {
    use std::ffi::c_void;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut c_void,
            process_information_class: u32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    if pid <= 4 {
        return None;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let exe_path = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .ok()
        .map(|()| String::from_utf16_lossy(&buf[..size as usize]));

        let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
        let mut ret_len = 0u32;
        let status = NtQueryInformationProcess(
            handle.0,
            0,
            (&mut pbi as *mut ProcessBasicInformation).cast(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(handle);

        let parent_pid = if status >= 0 {
            pbi.inherited_from_unique_process_id as u32
        } else {
            0
        };

        let name = exe_path
            .as_deref()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())?;

        Some(ProcessInfo {
            pid,
            parent_pid,
            name,
            exe_path,
        })
    }
}

#[cfg(windows)]
fn take_os_process_snapshot() -> HashMap<u32, ProcessInfo> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut map = HashMap::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return map,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                let exe_path = if pid > 4 {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                        .ok()
                        .and_then(|handle| {
                            let mut buf = vec![0u16; 1024];
                            let mut size = buf.len() as u32;
                            let res = QueryFullProcessImageNameW(
                                handle,
                                PROCESS_NAME_WIN32,
                                PWSTR(buf.as_mut_ptr()),
                                &mut size,
                            );
                            let _ = CloseHandle(handle);
                            res.ok()
                                .map(|()| String::from_utf16_lossy(&buf[..size as usize]))
                        })
                } else {
                    None
                };

                map.insert(
                    pid,
                    ProcessInfo {
                        pid,
                        parent_pid,
                        name,
                        exe_path,
                    },
                );

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    map
}

// --- macOS Process Implementation (libproc proc_pidpath + proc_pidinfo + proc_listallpids) ---

#[cfg(target_os = "macos")]
fn macos_proc_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len() as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    let slice = &buf[..(ret as usize).min(buf.len())];
    let s = String::from_utf8_lossy(slice)
        .trim_end_matches('\0')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(target_os = "macos")]
fn query_single_process(pid: u32) -> Option<ProcessInfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<libc::c_void>(),
            size,
        )
    };
    if ret <= 0 {
        return None;
    }
    let parent_pid = info.pbi_ppid;
    let exe_path = macos_proc_path(pid);
    let comm_slice = if info.pbi_name[0] != 0 {
        &info.pbi_name[..]
    } else {
        &info.pbi_comm[..]
    };
    let comm_bytes: Vec<u8> = comm_slice
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let comm = String::from_utf8_lossy(&comm_bytes).to_string();
    let name = exe_path
        .as_deref()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or(comm);

    Some(ProcessInfo {
        pid,
        parent_pid,
        name,
        exe_path,
    })
}

#[cfg(target_os = "macos")]
fn take_os_process_snapshot() -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();
    let expected = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if expected <= 0 {
        return map;
    }
    let capacity = (expected as usize).saturating_add(64).max(128);
    let mut pids: Vec<libc::c_int> = vec![0; capacity];
    let filled = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast::<libc::c_void>(),
            (pids.len() * std::mem::size_of::<libc::c_int>()) as libc::c_int,
        )
    };
    if filled <= 0 {
        return map;
    }
    let count = (filled as usize).min(pids.len());
    for &raw_pid in &pids[..count] {
        if raw_pid <= 0 {
            continue;
        }
        let pid_u32 = raw_pid as u32;
        if let Some(info) = query_single_process(pid_u32) {
            map.insert(pid_u32, info);
        }
    }
    map
}

// --- Linux Process Implementation (/proc) ---

#[cfg(all(unix, not(target_os = "macos")))]
fn query_single_process(pid: u32) -> Option<ProcessInfo> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&stat_path).ok()?;
    let lparen = stat.find('(')?;
    let rparen = stat.rfind(')')?;
    let comm = stat[lparen + 1..rparen].to_string();
    let rest: Vec<&str> = stat[rparen + 2..].split_whitespace().collect();
    let parent_pid = rest.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let name = exe_path
        .as_deref()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or(comm);
    Some(ProcessInfo {
        pid,
        parent_pid,
        name,
        exe_path,
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn take_os_process_snapshot() -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if let Some(info) = query_single_process(pid) {
                    map.insert(pid, info);
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets::preset_to_rule;

    #[test]
    fn detects_macos_external_children_and_respects_ignore_list() {
        let mut cursor_rule = preset_to_rule("cursor", "follow", 10).unwrap();
        let tracker = MockProcessTracker::with_processes([
            ProcessInfo {
                pid: 100,
                parent_pid: 1,
                name: "Cursor".into(),
                exe_path: Some("/Applications/Cursor.app/Contents/MacOS/Cursor".into()),
            },
            ProcessInfo {
                pid: 101,
                parent_pid: 100,
                name: "Cursor Helper".into(),
                exe_path: Some(
                    "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper"
                        .into(),
                ),
            },
            ProcessInfo {
                pid: 102,
                parent_pid: 101,
                name: "node".into(),
                exe_path: Some("/opt/homebrew/bin/node".into()),
            },
            ProcessInfo {
                pid: 103,
                parent_pid: 101,
                name: "uv".into(),
                exe_path: Some("/Users/dev/.local/bin/uv".into()),
            },
            ProcessInfo {
                pid: 200,
                parent_pid: 1,
                name: "Safari".into(),
                exe_path: Some("/Applications/Safari.app/Contents/MacOS/Safari".into()),
            },
        ]);

        let alerts = detect_external_children(std::slice::from_ref(&cursor_rule), &tracker);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "preset-cursor");
        assert_eq!(alerts[0].children.len(), 2);

        // Ignoring node leaves only uv.
        cursor_rule
            .ignored_external_children
            .push("/opt/homebrew/bin/node".into());
        let alerts2 = detect_external_children(std::slice::from_ref(&cursor_rule), &tracker);
        assert_eq!(alerts2.len(), 1);
        assert_eq!(alerts2[0].children.len(), 1);
        assert_eq!(alerts2[0].children[0].name, "uv");
    }

    #[test]
    fn current_process_single_pid_lookup_succeeds() {
        let info = query_single_process(std::process::id()).expect("current process info");
        assert_eq!(info.pid, std::process::id());
        assert!(!info.name.is_empty());
    }
}
