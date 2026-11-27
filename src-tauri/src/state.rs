use bypax_appproxy::process::SnapshotProcessTracker;
use bypax_core::compiler::{
    build_app_proxy_target_bindings, CompileInput, CompilePlatform, SingBox114Compiler,
};
use bypax_core::control::ControlClient;
use bypax_core::core_manager::CoreManager;
use bypax_core::model::{
    AppProxyRule, AppSettings, CaptureMode, CompileOutput, ConnectionHistoryRecord, ConnectionItem,
    CoreInfo, PreflightReport,
};
use bypax_core::netguard::NetGuard;
use bypax_core::rule_cache::RuleCache;
use bypax_core::storage::{classify_platform, extract_host, DataPaths, Store};
use bypax_core::supervisor::{CoreSupervisor, LogRing, MAX_LOG_RING_ENTRIES};
use bypax_core::updater::{
    take_last_update_result, AppUpdateCheckReport, AppUpdateState, UpdateApplyResult,
};
use bypax_ipc::{
    default_svc_endpoint, generate_session_token, load_ipc_token, resolve_or_create_ipc_token,
    send_service_request, worker_svc_endpoint, AppProxyRuleWire, AppProxyStartConfig,
    AppProxyStatusDto, DriverProbeDto, FlowOriginDto, ServiceCommand, ServiceEnvelope,
    ServiceResponse,
};
use bypax_windivert::probe_windivert;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegedServiceStatus {
    pub platform: String,
    pub mode: String,
    pub installed: bool,
    pub running: bool,
    pub connected: bool,
    pub elevated: bool,
    pub state: String,
    pub service_pid: Option<u32>,
    pub app_proxy_running: bool,
    pub tun_running: bool,
    #[serde(default)]
    pub legacy_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_detail: Option<String>,
    pub error: Option<String>,
    pub error_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureModeResult {
    pub capture_mode: CaptureMode,
    pub core_info: CoreInfo,
    pub service_status: PrivilegedServiceStatus,
    pub app_proxy_status: Option<AppProxyStatusDto>,
    pub compiled: CompileOutput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CliIntegrationInfo {
    pub ready: bool,
    pub cli_path: Option<String>,
    pub mcp_config_json: String,
    pub cli_examples: Vec<String>,
}

pub struct TrafficCursor {
    pub last_up: u64,
    pub last_down: u64,
    pub last_at: Instant,
}

impl Default for TrafficCursor {
    fn default() -> Self {
        Self {
            last_up: 0,
            last_down: 0,
            last_at: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct ConnectionTracker {
    active: HashMap<String, ConnectionItem>,
}

impl ConnectionTracker {
    /// Updates active connection map from a live Clash API snapshot and returns
    /// records for connections that just closed so they can be persisted to SQLite.
    pub fn sync_snapshot(&mut self, live: &[ConnectionItem]) -> Vec<ConnectionHistoryRecord> {
        let mut live_ids: HashSet<&str> = HashSet::with_capacity(live.len());
        for item in live {
            if item.id.is_empty() || item.local_action.is_some() {
                continue;
            }
            live_ids.insert(item.id.as_str());
            self.active.insert(item.id.clone(), item.clone());
        }

        let closed_ids: Vec<String> = self
            .active
            .keys()
            .filter(|id| !live_ids.contains(id.as_str()))
            .cloned()
            .collect();

        let now = chrono::Utc::now().to_rfc3339();
        let mut closed = Vec::with_capacity(closed_ids.len());
        for id in closed_ids {
            if let Some(item) = self.active.remove(&id) {
                closed.push(to_history_record(item, &now));
            }
        }
        closed
    }

    pub fn drain_all(&mut self) -> Vec<ConnectionHistoryRecord> {
        let now = chrono::Utc::now().to_rfc3339();
        self.active
            .drain()
            .map(|(_, item)| to_history_record(item, &now))
            .collect()
    }

    pub fn snapshot_active(&self) -> Vec<ConnectionItem> {
        self.active.values().cloned().collect()
    }
}

fn to_history_record(item: ConnectionItem, closed_at: &str) -> ConnectionHistoryRecord {
    let host = extract_host(&item.destination);
    let platform = classify_platform(&host, &item.process);
    ConnectionHistoryRecord {
        id: item.id,
        process: item.process,
        destination: item.destination,
        host,
        platform,
        inbound: item.inbound,
        rule: item.rule,
        chain: item.chain,
        upload_bytes: item.upload_bytes,
        download_bytes: item.download_bytes,
        started_at: if item.start.is_empty() {
            closed_at.to_string()
        } else {
            item.start
        },
        closed_at: closed_at.to_string(),
    }
}

pub struct AppState {
    pub paths: DataPaths,
    pub updates_dir: PathBuf,
    pub update_result_file: PathBuf,
    pub store: Mutex<Store>,
    pub netguard: Mutex<NetGuard>,
    pub rule_cache: RuleCache,
    pub core_manager: CoreManager,
    pub supervisor: Mutex<CoreSupervisor>,
    pub logs: Arc<Mutex<LogRing>>,
    pub control_secret: String,
    pub ipc_token: Mutex<String>,
    pub service_endpoint: String,
    pub process_tracker: Arc<SnapshotProcessTracker>,
    pub core_via_service: AtomicBool,
    pub app_proxy_active: AtomicBool,
    pub tun_active: AtomicBool,
    pub recovered_from_crash: bool,
    pub traffic_cursor: Mutex<TrafficCursor>,
    pub conn_tracker: Mutex<ConnectionTracker>,
    pub app_update_report: Mutex<Option<AppUpdateCheckReport>>,
    pub app_update_state: Mutex<AppUpdateState>,
    pub app_update_cancel: Mutex<Option<Arc<AtomicBool>>>,
    pub last_update_result: Mutex<Option<UpdateApplyResult>>,
    pub last_service_error: Mutex<Option<(String, Option<String>)>>,
}

impl AppState {
    pub fn initialize() -> anyhow::Result<Self> {
        let paths = DataPaths::resolve()?;
        let updates_dir = paths.runtime_dir.join("updates");
        let update_result_file = paths.runtime_dir.join("last-update-result.json");
        let _ = std::fs::create_dir_all(&updates_dir);

        let store = Store::open(&paths.db_path)?;
        let netguard = NetGuard::new(&paths.runtime_dir);
        let recovered_from_crash = netguard.recover_if_dirty().unwrap_or(false);
        let last_update_result = take_last_update_result(&update_result_file);

        let logs = Arc::new(Mutex::new(LogRing::new(MAX_LOG_RING_ENTRIES)));
        if let Ok(mut guard) = logs.lock() {
            guard.push(
                "INFO",
                format!(
                    "bypax initialized (portable={}, data_dir={})",
                    paths.portable_mode,
                    paths.root_dir.display()
                ),
            );
            if recovered_from_crash {
                guard.push(
                    "WARN",
                    "netguard: detected unclean exit snapshot and restored OS proxy/DNS cleanly",
                );
            }
            if let Some(ref res) = last_update_result {
                if res.success {
                    guard.push(
                        "INFO",
                        format!(
                            "updater: upgraded Bypax v{} -> v{}",
                            res.from_version, res.to_version
                        ),
                    );
                } else {
                    guard.push(
                        "WARN",
                        format!(
                            "updater: update to {} rolled back ({})",
                            res.to_tag,
                            res.error.as_deref().unwrap_or("unknown error")
                        ),
                    );
                }
            }
        }

        let rule_cache = RuleCache::new(paths.rule_sets_dir.clone());
        let core_manager = CoreManager::new(paths.core_dir.clone());
        let supervisor = CoreSupervisor::new(paths.runtime_dir.clone(), Arc::clone(&logs));
        let control_secret = generate_session_token();
        let (ipc_token, service_endpoint) = if cfg!(target_os = "windows") {
            // Windows uses an ephemeral per-GUI-session named pipe + random token strictly
            // bound to this GUI PID (zero SCM registration, zero cross-account token split).
            let nonce = uuid::Uuid::new_v4().simple().to_string();
            let ep = worker_svc_endpoint(&paths.runtime_dir, std::process::id(), &nonce[..8]);
            (generate_session_token(), ep)
        } else {
            (
                resolve_or_create_ipc_token(Some(&paths.runtime_dir)),
                default_svc_endpoint(),
            )
        };
        let process_tracker = Arc::new(SnapshotProcessTracker::new(Duration::from_millis(800)));

        Ok(Self {
            paths,
            updates_dir,
            update_result_file,
            store: Mutex::new(store),
            netguard: Mutex::new(netguard),
            rule_cache,
            core_manager,
            supervisor: Mutex::new(supervisor),
            logs,
            control_secret,
            ipc_token: Mutex::new(ipc_token),
            service_endpoint,
            process_tracker,
            core_via_service: AtomicBool::new(false),
            app_proxy_active: AtomicBool::new(false),
            tun_active: AtomicBool::new(false),
            recovered_from_crash,
            traffic_cursor: Mutex::new(TrafficCursor::default()),
            conn_tracker: Mutex::new(ConnectionTracker::default()),
            app_update_report: Mutex::new(None),
            app_update_state: Mutex::new(AppUpdateState::default()),
            app_update_cancel: Mutex::new(None),
            last_update_result: Mutex::new(last_update_result),
            last_service_error: Mutex::new(None),
        })
    }

    pub fn platform_name(&self) -> &'static str {
        if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        }
    }

    pub fn push_log(&self, level: &str, msg: impl Into<String>) {
        if let Ok(mut guard) = self.logs.lock() {
            guard.push(level, msg);
        }
    }

    pub fn is_core_running(&self) -> bool {
        let local = self
            .supervisor
            .lock()
            .map(|mut s| s.is_running())
            .unwrap_or(false);
        local || self.core_via_service.load(Ordering::Relaxed)
    }

    pub fn current_capture_mode(&self) -> CaptureMode {
        if self.tun_active.load(Ordering::Relaxed) {
            CaptureMode::Tun
        } else if self.app_proxy_active.load(Ordering::Relaxed) {
            CaptureMode::Apps
        } else {
            CaptureMode::Off
        }
    }

    pub fn active_local_proxy_port(&self) -> Option<u16> {
        if !self.is_core_running() {
            return None;
        }
        self.store
            .lock()
            .ok()
            .and_then(|s| s.load_settings().ok())
            .map(|s| s.mixed_port)
    }

    pub fn record_connections_snapshot(&self, conns: &[ConnectionItem]) {
        let closed = if let Ok(mut tracker) = self.conn_tracker.lock() {
            tracker.sync_snapshot(conns)
        } else {
            Vec::new()
        };
        if !closed.is_empty() {
            if let Ok(mut store) = self.store.lock() {
                let _ = store.insert_connection_history(&closed);
            }
        }
    }

    pub fn flush_active_connections(&self) {
        let flushed = if let Ok(mut tracker) = self.conn_tracker.lock() {
            tracker.drain_all()
        } else {
            Vec::new()
        };
        if !flushed.is_empty() {
            if let Ok(mut store) = self.store.lock() {
                let _ = store.insert_connection_history(&flushed);
            }
        }
    }

    pub fn compile_current(&self) -> Result<CompileOutput, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let nodes = store.list_nodes().map_err(|e| e.to_string())?;
        let rules = store.list_rules().map_err(|e| e.to_string())?;
        let app_rules = store.list_app_proxy_rules().map_err(|e| e.to_string())?;
        let extra_ports = store.list_inbound_ports().map_err(|e| e.to_string())?;
        let settings = store.load_settings().map_err(|e| e.to_string())?;
        let cache_db = self.paths.runtime_dir.join("cache.db");

        SingBox114Compiler::compile(&CompileInput {
            nodes: &nodes,
            rules: &rules,
            app_rules: &app_rules,
            extra_ports: &extra_ports,
            settings: &settings,
            control_secret: &self.control_secret,
            cache_db_path: Some(&cache_db),
            rule_cache: Some(&self.rule_cache),
            platform: CompilePlatform::current(),
        })
        .map_err(|e| e.to_string())
    }

    pub fn build_core_info(&self) -> CoreInfo {
        let installed = self.core_manager.is_installed();
        let version = self.core_manager.detect_version();
        let sha256 = self.core_manager.sha256_of_binary().ok().flatten();
        let running = self.is_core_running();
        let netguard_armed = self
            .netguard
            .lock()
            .map(|g| g.is_armed())
            .unwrap_or(false);

        let bin_path = self
            .core_manager
            .resolve_binary_path()
            .unwrap_or_else(|| self.core_manager.binary_path());

        CoreInfo {
            installed,
            running,
            version,
            binary_path: bin_path.to_string_lossy().to_string(),
            sha256,
            portable_mode: self.paths.portable_mode,
            data_dir: self.paths.root_dir.to_string_lossy().to_string(),
            netguard_armed,
            netguard_recovered_from_crash: self.recovered_from_crash,
        }
    }

    /// Resolves an installed sing-box binary or returns a structured `CORE_NOT_INSTALLED` error
    /// immediately (never silently hanging on blocked GitHub networks during start or latency test).
    pub fn require_core_binary(&self) -> Result<PathBuf, String> {
        self.core_manager
            .resolve_binary_path()
            .ok_or_else(|| "CORE_NOT_INSTALLED".to_string())
    }

    pub fn find_sidecar_binary(&self, stem: &str) -> Option<PathBuf> {
        let file_name = if cfg!(windows) {
            format!("{}.exe", stem)
        } else {
            stem.to_string()
        };

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join(&file_name));
                candidates.push(dir.join("bin").join(&file_name));
            }
        }
        candidates.push(self.paths.root_dir.join(&file_name));
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("target").join("release").join(&file_name));
            candidates.push(cwd.join("target").join("debug").join(&file_name));
            candidates.push(cwd.join(&file_name));
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                candidates.push(dir.join(&file_name));
            }
        }

        candidates.into_iter().find(|p| p.is_file())
    }

    pub fn get_cli_integration_info(&self) -> CliIntegrationInfo {
        let cli_path = self
            .find_sidecar_binary("bypax-cli")
            .map(|p| p.to_string_lossy().to_string());
        let cmd_str = cli_path
            .clone()
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    "bypax-cli.exe".to_string()
                } else {
                    "bypax-cli".to_string()
                }
            });
        let mcp_json = serde_json::json!({
            "mcpServers": {
                "bypax": {
                    "command": cmd_str,
                    "args": ["mcp"]
                }
            }
        });
        let mcp_config_json =
            serde_json::to_string_pretty(&mcp_json).unwrap_or_else(|_| "{}".to_string());

        CliIntegrationInfo {
            ready: cli_path.is_some(),
            cli_path,
            mcp_config_json,
            cli_examples: vec![
                "bypax-cli status --json".to_string(),
                "bypax-cli nodes list --region US".to_string(),
                "bypax-cli app rules list".to_string(),
                "bypax-cli route test api.openai.com".to_string(),
                "bypax-cli doctor --json".to_string(),
            ],
        }
    }

    pub fn probe_windivert(&self, custom_dir: Option<&str>) -> DriverProbeDto {
        let fallback_dir = if custom_dir.is_none() {
            self.store
                .lock()
                .ok()
                .and_then(|s| s.load_settings().ok())
                .and_then(|s| s.app_proxy_windivert_dir)
        } else {
            None
        };
        let dir = custom_dir
            .filter(|s| !s.trim().is_empty())
            .or(fallback_dir.as_deref())
            .map(std::path::Path::new);
        normalize_gui_driver_probe(probe_windivert(dir).to_dto(), false)
    }

    pub async fn probe_windivert_with_service(
        &self,
        custom_dir: Option<&str>,
        service_connected: bool,
    ) -> DriverProbeDto {
        if service_connected {
            let fallback_dir = if custom_dir.is_none() {
                self.store
                    .lock()
                    .ok()
                    .and_then(|s| s.load_settings().ok())
                    .and_then(|s| s.app_proxy_windivert_dir)
            } else {
                None
            };
            let windivert_dir = custom_dir
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .or(fallback_dir);
            if let Ok(resp) = self
                .service_request(
                    ServiceCommand::ProbeDriver { windivert_dir },
                    Duration::from_millis(800),
                )
                .await
            {
                if let Some(driver) = resp.driver {
                    return normalize_gui_driver_probe(driver, true);
                }
            }
        }
        self.probe_windivert(custom_dir)
    }

    pub fn current_ipc_token(&self) -> String {
        if cfg!(target_os = "windows") {
            return self
                .ipc_token
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
        }
        if let Some(disk_token) = load_ipc_token(Some(&self.paths.runtime_dir)) {
            if let Ok(mut guard) = self.ipc_token.lock() {
                if *guard != disk_token {
                    *guard = disk_token.clone();
                }
            }
            return disk_token;
        }
        self.ipc_token
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    fn persist_service_mode(&self, mode: &str) {
        if let Ok(store) = self.store.lock() {
            if let Ok(mut settings) = store.load_settings() {
                if settings.service_mode != mode {
                    settings.service_mode = mode.to_string();
                    let _ = store.save_settings(&settings);
                }
            }
        }
    }

    pub async fn service_request(
        &self,
        cmd: ServiceCommand,
        timeout: Duration,
    ) -> Result<ServiceResponse, String> {
        let token = self.current_ipc_token();
        let env = ServiceEnvelope {
            id: uuid::Uuid::new_v4().simple().to_string(),
            session_token: token.clone(),
            command: cmd.clone(),
        };
        let resp = send_service_request(&self.service_endpoint, &env, timeout)
            .await
            .map_err(|e| e.to_string())?;
        if !cfg!(target_os = "windows")
            && !resp.ok
            && resp.message.to_ascii_lowercase().contains("unauthorized")
        {
            if let Some(fresh_token) = load_ipc_token(Some(&self.paths.runtime_dir)) {
                if fresh_token != token {
                    if let Ok(mut guard) = self.ipc_token.lock() {
                        *guard = fresh_token.clone();
                    }
                    let retry_env = ServiceEnvelope {
                        id: uuid::Uuid::new_v4().simple().to_string(),
                        session_token: fresh_token,
                        command: cmd,
                    };
                    return send_service_request(&self.service_endpoint, &retry_env, timeout)
                        .await
                        .map_err(|e| e.to_string());
                }
            }
        }
        Ok(resp)
    }

    /// Sends a heartbeat to the active privileged helper and returns `true` if the helper
    /// disconnected unexpectedly so callers can sync UI state immediately.
    pub async fn send_service_heartbeat(&self) -> bool {
        let active = self.core_via_service.load(Ordering::Relaxed)
            || self.app_proxy_active.load(Ordering::Relaxed)
            || self.tun_active.load(Ordering::Relaxed);
        if !active {
            return false;
        }
        let ok = matches!(
            self.service_request(
                ServiceCommand::Heartbeat {
                    gui_pid: std::process::id(),
                },
                Duration::from_millis(800),
            )
            .await,
            Ok(resp) if resp.ok
        );
        if ok {
            return false;
        }
        // Single quick retry before declaring helper lost.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let retry_ok = matches!(
            self.service_request(
                ServiceCommand::Heartbeat {
                    gui_pid: std::process::id(),
                },
                Duration::from_millis(800),
            )
            .await,
            Ok(resp) if resp.ok
        );
        if !retry_ok {
            self.core_via_service.store(false, Ordering::Relaxed);
            self.app_proxy_active.store(false, Ordering::Relaxed);
            self.tun_active.store(false, Ordering::Relaxed);
            self.push_log(
                "WARN",
                "helper: privileged helper disconnected; reset active capture state to off",
            );
            return true;
        }
        false
    }

    /// Inspects Windows SCM (read-only) for legacy persistent services (`BypaxService`,
    /// active/enabled `BypathService`) or an externally locked `WinDivert` kernel driver.
    pub fn detect_windows_conflicts(&self, own_app_proxy_running: bool) -> (Vec<String>, Option<String>) {
        #[cfg(target_os = "windows")]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
                QueryServiceStatus, QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SERVICE_DISABLED,
                SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
                SERVICE_STATUS, SERVICE_STOP_PENDING,
            };

            fn wide(s: &str) -> Vec<u16> {
                s.encode_utf16().chain(std::iter::once(0)).collect()
            }

            let mut legacy = Vec::new();
            let mut detail: Option<String> = None;

            unsafe {
                let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
                else {
                    return (legacy, detail);
                };

                for name in ["BypaxService", "BypathService"] {
                    let w = wide(name);
                    let Ok(svc) = OpenServiceW(
                        scm,
                        PCWSTR(w.as_ptr()),
                        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
                    ) else {
                        continue;
                    };
                    let mut st = SERVICE_STATUS::default();
                    let running = QueryServiceStatus(svc, &mut st).is_ok()
                        && (st.dwCurrentState == SERVICE_RUNNING
                            || st.dwCurrentState == SERVICE_START_PENDING);
                    let mut disabled = false;
                    let mut needed = 0u32;
                    let _ = QueryServiceConfigW(svc, None, 0, &mut needed);
                    if needed > 0 {
                        let mut buf = vec![0u8; needed as usize];
                        if QueryServiceConfigW(
                            svc,
                            Some(buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                            needed,
                            &mut needed,
                        )
                        .is_ok()
                        {
                            let cfg = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
                            disabled = cfg.dwStartType == SERVICE_DISABLED;
                        }
                    }
                    let _ = CloseServiceHandle(svc);

                    if name == "BypaxService" || running || !disabled {
                        legacy.push(name.to_string());
                    }
                }

                // Check if WinDivert kernel driver service is externally locked or stuck deleting.
                let wd_w = wide("WinDivert");
                if let Ok(wd_svc) = OpenServiceW(
                    scm,
                    PCWSTR(wd_w.as_ptr()),
                    SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
                ) {
                    let mut st = SERVICE_STATUS::default();
                    if QueryServiceStatus(wd_svc, &mut st).is_ok() {
                        if st.dwCurrentState == SERVICE_STOP_PENDING {
                            detail = Some(
                                "WinDivert kernel driver is pending unload from another process"
                                    .to_string(),
                            );
                        } else if !own_app_proxy_running
                            && (st.dwCurrentState == SERVICE_RUNNING
                                || st.dwCurrentState == SERVICE_START_PENDING)
                        {
                            detail = Some(
                                "WinDivert kernel driver is currently held by another service or process"
                                    .to_string(),
                            );
                        }
                    }
                    let _ = CloseServiceHandle(wd_svc);
                }

                let _ = CloseServiceHandle(scm);
            }

            if detail.is_none() && !legacy.is_empty() {
                detail = Some(format!(
                    "Legacy background proxy service detected: {}",
                    legacy.join(", ")
                ));
            }
            (legacy, detail)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = own_app_proxy_running;
            (Vec::new(), None)
        }
    }

    pub fn is_service_installed_on_os(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            // Windows uses the GUI-bound on-demand helper (`worker-run`), not an SCM service.
            false
        }
        #[cfg(target_os = "macos")]
        {
            std::path::Path::new("/Library/LaunchDaemons/com.bypax.service.plist").is_file()
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            std::path::Path::new("/etc/systemd/system/bypax-service.service").is_file()
        }
    }

    pub async fn query_service_status(&self) -> PrivilegedServiceStatus {
        let (mode, capture_requested) = self
            .store
            .lock()
            .ok()
            .and_then(|s| s.load_settings().ok())
            .map(|s| (s.service_mode, s.app_proxy_enabled || s.tun_enabled))
            .unwrap_or_else(|| ("off".to_string(), false));
        let installed = self.is_service_installed_on_os();

        let ping = self
            .service_request(ServiceCommand::Ping, Duration::from_millis(450))
            .await;
        match ping {
            Ok(resp) if resp.ok => {
                let service_pid = resp.service_pid;
                let elevated = resp.elevated.unwrap_or(false);
                let core_st = self
                    .service_request(ServiceCommand::CoreStatus, Duration::from_millis(450))
                    .await
                    .ok();
                let app_st = self
                    .service_request(ServiceCommand::AppProxyStatus, Duration::from_millis(450))
                    .await
                    .ok();

                let (svc_core_running, svc_tun_running) = core_st
                    .and_then(|r| r.core_status)
                    .map(|st| (st.running, st.tun_active && st.running))
                    .unwrap_or((false, false));
                let svc_app_running = app_st
                    .and_then(|r| r.app_proxy_status)
                    .map(|st| st.running)
                    .unwrap_or(false);

                self.core_via_service
                    .store(svc_core_running, Ordering::Relaxed);
                self.tun_active.store(svc_tun_running, Ordering::Relaxed);
                if cfg!(target_os = "windows") {
                    self.app_proxy_active
                        .store(svc_app_running, Ordering::Relaxed);
                } else {
                    let mac_apps = svc_core_running && !svc_tun_running;
                    self.app_proxy_active.store(mac_apps, Ordering::Relaxed);
                }

                let (legacy_services, conflict_detail) =
                    self.detect_windows_conflicts(svc_app_running);
                let has_legacy_conflict = !legacy_services.is_empty();

                if let Ok(mut err_g) = self.last_service_error.lock() {
                    if has_legacy_conflict {
                        *err_g = Some((
                            conflict_detail.clone().unwrap_or_default(),
                            Some("legacy_conflict".to_string()),
                        ));
                    } else {
                        *err_g = None;
                    }
                }

                let effective_mode = if cfg!(target_os = "windows") {
                    "elevated_worker".to_string()
                } else if installed && mode != "elevated_worker" {
                    "service".to_string()
                } else {
                    "elevated_worker".to_string()
                };

                PrivilegedServiceStatus {
                    platform: self.platform_name().to_string(),
                    mode: effective_mode,
                    installed,
                    running: true,
                    connected: true,
                    elevated,
                    state: "connected".to_string(),
                    service_pid,
                    app_proxy_running: self.app_proxy_active.load(Ordering::Relaxed),
                    tun_running: svc_tun_running,
                    legacy_services,
                    conflict_detail: conflict_detail.clone(),
                    error: if has_legacy_conflict {
                        conflict_detail
                    } else {
                        None
                    },
                    error_kind: if has_legacy_conflict {
                        Some("legacy_conflict".to_string())
                    } else {
                        None
                    },
                }
            }
            Ok(resp) => {
                let (legacy_services, conflict_detail) = self.detect_windows_conflicts(false);
                let kind = if !legacy_services.is_empty() || conflict_detail.is_some() {
                    Some("legacy_conflict".to_string())
                } else {
                    classify_service_error_kind(&resp.message, installed, capture_requested)
                };
                let err_msg = conflict_detail.clone().unwrap_or(resp.message);
                let has_fault = kind.is_some();
                if let Ok(mut err_g) = self.last_service_error.lock() {
                    if has_fault {
                        *err_g = Some((err_msg.clone(), kind.clone()));
                    } else {
                        *err_g = None;
                    }
                }
                PrivilegedServiceStatus {
                    platform: self.platform_name().to_string(),
                    mode: "off".to_string(),
                    installed,
                    running: false,
                    connected: false,
                    elevated: false,
                    state: if has_fault {
                        "error".to_string()
                    } else if installed {
                        "stopped".to_string()
                    } else {
                        "not_installed".to_string()
                    },
                    service_pid: None,
                    app_proxy_running: false,
                    tun_running: false,
                    legacy_services,
                    conflict_detail,
                    error: if has_fault { Some(err_msg) } else { None },
                    error_kind: kind,
                }
            }
            Err(_) => {
                self.core_via_service.store(false, Ordering::Relaxed);
                self.app_proxy_active.store(false, Ordering::Relaxed);
                self.tun_active.store(false, Ordering::Relaxed);

                let (legacy_services, conflict_detail) = self.detect_windows_conflicts(false);
                if !legacy_services.is_empty() || conflict_detail.is_some() {
                    let msg = conflict_detail.clone().unwrap_or_else(|| {
                        format!(
                            "Legacy background proxy service detected: {}",
                            legacy_services.join(", ")
                        )
                    });
                    let kind = Some("legacy_conflict".to_string());
                    if let Ok(mut err_g) = self.last_service_error.lock() {
                        *err_g = Some((msg.clone(), kind.clone()));
                    }
                    return PrivilegedServiceStatus {
                        platform: self.platform_name().to_string(),
                        mode: "off".to_string(),
                        installed,
                        running: false,
                        connected: false,
                        elevated: false,
                        state: "conflict".to_string(),
                        service_pid: None,
                        app_proxy_running: false,
                        tun_running: false,
                        legacy_services,
                        conflict_detail,
                        error: Some(msg),
                        error_kind: kind,
                    };
                }

                if !installed && !capture_requested {
                    if let Ok(mut err_g) = self.last_service_error.lock() {
                        *err_g = None;
                    }
                    return PrivilegedServiceStatus {
                        platform: self.platform_name().to_string(),
                        mode: "off".to_string(),
                        installed: false,
                        running: false,
                        connected: false,
                        elevated: false,
                        state: "stopped".to_string(),
                        service_pid: None,
                        app_proxy_running: false,
                        tun_running: false,
                        legacy_services: Vec::new(),
                        conflict_detail: None,
                        error: None,
                        error_kind: None,
                    };
                }

                let (error, error_kind) = if capture_requested {
                    self.last_service_error
                        .lock()
                        .ok()
                        .and_then(|g| g.clone())
                        .map(|(m, k)| (Some(m), k))
                        .unwrap_or((None, None))
                } else {
                    if let Ok(mut err_g) = self.last_service_error.lock() {
                        *err_g = None;
                    }
                    (None, None)
                };
                let effective_mode = if !cfg!(target_os = "windows") && mode == "service" {
                    "service".to_string()
                } else {
                    "off".to_string()
                };
                PrivilegedServiceStatus {
                    platform: self.platform_name().to_string(),
                    mode: effective_mode,
                    installed,
                    running: false,
                    connected: false,
                    elevated: false,
                    state: "stopped".to_string(),
                    service_pid: None,
                    app_proxy_running: false,
                    tun_running: false,
                    legacy_services: Vec::new(),
                    conflict_detail: None,
                    error,
                    error_kind,
                }
            }
        }
    }

    pub async fn query_app_proxy_status(&self) -> Option<AppProxyStatusDto> {
        if !self.app_proxy_active.load(Ordering::Relaxed)
            && !self.core_via_service.load(Ordering::Relaxed)
        {
            return None;
        }
        match self
            .service_request(ServiceCommand::AppProxyStatus, Duration::from_millis(450))
            .await
        {
            Ok(resp) if resp.ok => resp.app_proxy_status,
            _ => None,
        }
    }

    fn build_app_proxy_start_config(
        &self,
        settings: &AppSettings,
        app_rules: &[AppProxyRule],
        sing_box_pid: u32,
    ) -> Result<AppProxyStartConfig, String> {
        let nodes = {
            let store = self
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            store.list_nodes().map_err(|e| e.to_string())?
        };
        let bindings = build_app_proxy_target_bindings(app_rules, &nodes);
        let wire_rules: Vec<AppProxyRuleWire> =
            app_rules.iter().map(AppProxyRuleWire::from).collect();
        let mut exempt_pids = vec![std::process::id()];
        if sing_box_pid != 0 {
            exempt_pids.push(sing_box_pid);
        }
        Ok(AppProxyStartConfig {
            app_proxy_port: settings.app_proxy_port,
            control_secret: self.control_secret.clone(),
            bypass_lan: settings.app_proxy_bypass_lan,
            block_quic_when_needed: settings.app_proxy_block_quic_when_needed,
            windivert_dir: settings.app_proxy_windivert_dir.clone(),
            gui_pid: Some(std::process::id()),
            sing_box_pid: if sing_box_pid != 0 {
                Some(sing_box_pid)
            } else {
                None
            },
            exempt_pids,
            rules: wire_rules,
            target_bindings: bindings,
        })
    }

    async fn ensure_service_connected(&self) -> Result<(), String> {
        if matches!(
            self.service_request(ServiceCommand::Ping, Duration::from_millis(400))
                .await,
            Ok(r) if r.ok
        ) {
            return Ok(());
        }

        if cfg!(target_os = "windows") {
            // Windows strictly uses the GUI-bound on-demand elevated helper (zero SCM service).
            let status = self.perform_service_action("start_worker").await?;
            return if status.connected {
                Ok(())
            } else {
                Err(status.error.unwrap_or_else(|| {
                    "SERVICE_UNAVAILABLE: Unable to connect to Bypax elevated helper".to_string()
                }))
            };
        }

        let service_mode = self
            .store
            .lock()
            .ok()
            .and_then(|s| s.load_settings().ok())
            .map(|s| s.service_mode)
            .unwrap_or_else(|| "auto".to_string());

        if service_mode == "off" {
            return Err("SERVICE_DISABLED: Privileged service is disabled in settings".to_string());
        }

        let action = if self.is_service_installed_on_os() && service_mode != "elevated_worker" {
            "start"
        } else {
            "start_worker"
        };

        let status = self.perform_service_action(action).await?;
        if status.connected {
            Ok(())
        } else {
            Err(status.error.unwrap_or_else(|| {
                "SERVICE_UNAVAILABLE: Unable to connect to Bypax helper".to_string()
            }))
        }
    }

    /// Starts ONLY the local non-privileged `sing-box` proxy core (never spawns UAC / WinDivert).
    pub async fn start_local_core_only(&self) -> Result<(CoreInfo, PreflightReport), String> {
        let bin = self.require_core_binary()?;
        let settings = {
            let store = self
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            store.load_settings().map_err(|e| e.to_string())?
        };
        let compiled = self.compile_current()?;
        let report = {
            let mut sup = self
                .supervisor
                .lock()
                .map_err(|_| "supervisor lock poisoned".to_string())?;
            sup.apply_config(&bin, compiled.config)
                .map_err(|e| e.to_string())?
        };
        if !report.ok {
            return Ok((self.build_core_info(), report));
        }
        self.core_via_service.store(false, Ordering::Relaxed);
        self.tun_active.store(false, Ordering::Relaxed);
        self.sync_clash_control(&settings).await;
        Ok((self.build_core_info(), report))
    }

    pub async fn start_core_flow(&self) -> Result<(CoreInfo, PreflightReport), String> {
        let bin = self.require_core_binary()?;
        let (settings, app_rules) = {
            let store = self
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            (
                store.load_settings().map_err(|e| e.to_string())?,
                store.list_app_proxy_rules().map_err(|e| e.to_string())?,
            )
        };
        let compiled = self.compile_current()?;

        // Determine if sing-box itself must run inside privileged bypax-service (TUN or macOS App Proxy utun).
        let needs_privileged_core = settings.tun_enabled
            || (cfg!(target_os = "macos") && settings.app_proxy_enabled);

        if needs_privileged_core {
            let preflight = SingBox114Compiler::preflight_check(&bin, &compiled.config)
                .map_err(|e| e.to_string())?;
            if !preflight.ok {
                return Ok((self.build_core_info(), preflight));
            }
            self.ensure_service_connected().await?;
            if let Ok(mut sup) = self.supervisor.lock() {
                sup.stop();
            }
            let config_json = serde_json::to_string(&compiled.config).map_err(|e| e.to_string())?;
            let resp = self
                .service_request(
                    ServiceCommand::StartCore {
                        sing_box_path: bin.to_string_lossy().to_string(),
                        config_json,
                        tun_mode: settings.tun_enabled,
                        gui_pid: Some(std::process::id()),
                    },
                    Duration::from_secs(8),
                )
                .await?;
            if resp.ok && resp.core_running.unwrap_or(false) {
                self.core_via_service.store(true, Ordering::Relaxed);
                self.tun_active
                    .store(settings.tun_enabled, Ordering::Relaxed);
                self.app_proxy_active.store(
                    !settings.tun_enabled && settings.app_proxy_enabled,
                    Ordering::Relaxed,
                );
                self.send_service_heartbeat().await;
            } else {
                return Err(if resp.message.is_empty() {
                    "Privileged service failed to start sing-box".to_string()
                } else {
                    resp.message
                });
            }
            self.sync_clash_control(&settings).await;
            return Ok((self.build_core_info(), preflight));
        }

        // Non-privileged local sing-box startup (also serves Windows App Proxy via app-proxy-in).
        let report = {
            let mut sup = self
                .supervisor
                .lock()
                .map_err(|_| "supervisor lock poisoned".to_string())?;
            sup.apply_config(&bin, compiled.config)
                .map_err(|e| e.to_string())?
        };
        if !report.ok {
            return Ok((self.build_core_info(), report));
        }

        self.core_via_service.store(false, Ordering::Relaxed);
        self.tun_active.store(false, Ordering::Relaxed);
        self.sync_clash_control(&settings).await;

        // If Windows App Proxy is enabled in settings, attach WinDivert capture via bypax-service.
        if cfg!(target_os = "windows") && settings.app_proxy_enabled && !settings.tun_enabled {
            let sing_box_pid = self
                .supervisor
                .lock()
                .ok()
                .and_then(|mut s| s.require_running_pid().ok())
                .unwrap_or(0);
            match self.ensure_service_connected().await {
                Ok(()) => {
                    let cfg =
                        self.build_app_proxy_start_config(&settings, &app_rules, sing_box_pid)?;
                    match self
                        .service_request(
                            ServiceCommand::StartAppProxy { config: cfg },
                            Duration::from_secs(8),
                        )
                        .await
                    {
                        Ok(resp) if resp.ok => {
                            let running = resp
                                .app_proxy_status
                                .as_ref()
                                .map(|st| st.running)
                                .unwrap_or(true);
                            self.app_proxy_active.store(running, Ordering::Relaxed);
                            if running {
                                self.send_service_heartbeat().await;
                            }
                        }
                        Ok(resp) => {
                            self.push_log(
                                "WARN",
                                format!("app-proxy: auto-attach failed: {}", resp.message),
                            );
                        }
                        Err(err) => {
                            self.push_log(
                                "WARN",
                                format!("app-proxy: auto-attach IPC failed: {}", err),
                            );
                        }
                    }
                }
                Err(err) => {
                    self.push_log(
                        "WARN",
                        format!("app-proxy: service unavailable during core start: {}", err),
                    );
                }
            }
        }

        Ok((self.build_core_info(), report))
    }

    async fn sync_clash_control(&self, settings: &AppSettings) {
        if let Ok(client) = ControlClient::new(settings.control_port, &self.control_secret) {
            if client.wait_ready(2000).await {
                let _ = client.set_mode(settings.route_mode.as_str()).await;
                if let Some(ref main_id) = settings.main_node_id {
                    let _ = client.select_proxy("main-exit", main_id).await;
                }
            }
        }
    }

    pub async fn stop_core_flow(&self) -> CoreInfo {
        self.flush_active_connections();
        if self.app_proxy_active.swap(false, Ordering::Relaxed) {
            let _ = self
                .service_request(ServiceCommand::StopAppProxy, Duration::from_secs(3))
                .await;
        }
        if self.core_via_service.swap(false, Ordering::Relaxed) {
            let _ = self
                .service_request(ServiceCommand::StopCore, Duration::from_secs(3))
                .await;
        }
        self.tun_active.store(false, Ordering::Relaxed);
        if let Ok(mut sup) = self.supervisor.lock() {
            sup.stop();
        }
        self.build_core_info()
    }

    pub async fn apply_capture_mode(&self, mode: CaptureMode) -> Result<CaptureModeResult, String> {
        let prev_settings = {
            let store = self
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            store.load_settings().map_err(|e| e.to_string())?
        };
        let was_core_running = self.is_core_running();

        let (want_app, want_tun) = match mode {
            CaptureMode::Off => (false, false),
            CaptureMode::Apps => (true, false),
            CaptureMode::Tun => (false, true),
        };

        {
            let store = self
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            let mut updated = prev_settings.clone();
            updated.app_proxy_enabled = want_app;
            updated.tun_enabled = want_tun;
            store.save_settings(&updated).map_err(|e| e.to_string())?;
        }

        let res: Result<(), String> = async {
            match mode {
                CaptureMode::Off => {
                    if self.app_proxy_active.swap(false, Ordering::Relaxed) {
                        let _ = self
                            .service_request(ServiceCommand::StopAppProxy, Duration::from_secs(3))
                            .await;
                    }
                    let had_service_core = self.core_via_service.swap(false, Ordering::Relaxed);
                    self.tun_active.store(false, Ordering::Relaxed);
                    if had_service_core {
                        let _ = self
                            .service_request(ServiceCommand::StopCore, Duration::from_secs(3))
                            .await;
                    }
                    if was_core_running {
                        // Keep local proxy core running cleanly without capture.
                        let _ = self.start_core_flow().await?;
                    }
                    self.push_log("INFO", "capture: switched capture mode -> off");
                    Ok(())
                }
                CaptureMode::Apps => {
                    let bin = self.require_core_binary()?;
                    self.ensure_service_connected().await?;

                    if cfg!(target_os = "windows") {
                        // Stop privileged TUN core if active so local sing-box owns ports.
                        if self.core_via_service.swap(false, Ordering::Relaxed) {
                            let _ = self
                                .service_request(ServiceCommand::StopCore, Duration::from_secs(3))
                                .await;
                        }
                        self.tun_active.store(false, Ordering::Relaxed);

                        let (settings, app_rules) = {
                            let store = self
                                .store
                                .lock()
                                .map_err(|_| "store lock poisoned".to_string())?;
                            (
                                store.load_settings().map_err(|e| e.to_string())?,
                                store.list_app_proxy_rules().map_err(|e| e.to_string())?,
                            )
                        };
                        let compiled = self.compile_current()?;
                        let report = {
                            let mut sup = self
                                .supervisor
                                .lock()
                                .map_err(|_| "supervisor lock poisoned".to_string())?;
                            sup.apply_config(&bin, compiled.config)
                                .map_err(|e| e.to_string())?
                        };
                        if !report.ok {
                            return Err(format!(
                                "sing-box preflight failed (exit {}): {}",
                                report.exit_code, report.stderr
                            ));
                        }
                        self.sync_clash_control(&settings).await;
                        let sing_box_pid = self
                            .supervisor
                            .lock()
                            .ok()
                            .and_then(|mut s| s.require_running_pid().ok())
                            .unwrap_or(0);

                        let start_cfg =
                            self.build_app_proxy_start_config(&settings, &app_rules, sing_box_pid)?;
                        let resp = self
                            .service_request(
                                ServiceCommand::StartAppProxy { config: start_cfg },
                                Duration::from_secs(8),
                            )
                            .await?;
                        if resp.ok {
                            if let Some(st) = resp.app_proxy_status {
                                if st.running {
                                    self.app_proxy_active.store(true, Ordering::Relaxed);
                                    self.send_service_heartbeat().await;
                                    self.push_log(
                                        "INFO",
                                        format!(
                                            "capture: Windows App Proxy active (port={}, rules={})",
                                            settings.app_proxy_port, st.active_rules
                                        ),
                                    );
                                    Ok(())
                                } else {
                                    Err(st.last_error.unwrap_or_else(|| {
                                        "WinDivert App Proxy did not enter running state".to_string()
                                    }))
                                }
                            } else {
                                self.app_proxy_active.store(true, Ordering::Relaxed);
                                self.send_service_heartbeat().await;
                                Ok(())
                            }
                        } else {
                            Err(resp.message)
                        }
                    } else {
                        // macOS / Linux: run sing-box utun with .app process_path_regex inside bypax-service.
                        let (_info, report) = self.start_core_flow().await?;
                        if !report.ok {
                            return Err(format!(
                                "sing-box preflight failed (exit {}): {}",
                                report.exit_code, report.stderr
                            ));
                        }
                        self.push_log("INFO", "capture: macOS/Unix App Proxy utun mode active");
                        Ok(())
                    }
                }
                CaptureMode::Tun => {
                    let _bin = self.require_core_binary()?;
                    self.ensure_service_connected().await?;

                    // Mutual exclusion: stop WinDivert App Proxy before starting TUN.
                    if self.app_proxy_active.swap(false, Ordering::Relaxed) {
                        let _ = self
                            .service_request(ServiceCommand::StopAppProxy, Duration::from_secs(3))
                            .await;
                    }
                    let (_info, report) = self.start_core_flow().await?;
                    if !report.ok {
                        return Err(format!(
                            "sing-box TUN preflight failed (exit {}): {}",
                            report.exit_code, report.stderr
                        ));
                    }
                    self.push_log("INFO", "capture: Full TUN mode active via bypax-service");
                    Ok(())
                }
            }
        }
        .await;

        if let Err(err) = res {
            // Roll back persisted capture settings on failure (e.g., UAC cancelled or missing driver).
            if let Ok(store) = self.store.lock() {
                let _ = store.save_settings(&prev_settings);
            }
            if let Ok(mut err_g) = self.last_service_error.lock() {
                if err.contains("UAC_CANCELLED") {
                    // User intentionally dismissed UAC prompt: do not leave a sticky fault banner.
                    *err_g = None;
                } else {
                    let installed = self.is_service_installed_on_os();
                    let kind = classify_service_error_kind(&err, installed, true);
                    if kind.is_some() {
                        *err_g = Some((err.clone(), kind));
                    } else {
                        *err_g = None;
                    }
                }
            }
            return Err(err);
        }

        let service_status = self.query_service_status().await;
        let app_proxy_status = self.query_app_proxy_status().await;
        let compiled = self.compile_current()?;

        Ok(CaptureModeResult {
            capture_mode: self.current_capture_mode(),
            core_info: self.build_core_info(),
            service_status,
            app_proxy_status,
            compiled,
        })
    }

    pub async fn sync_app_proxy_if_running(&self) -> bool {
        if !self.app_proxy_active.load(Ordering::Relaxed) {
            return false;
        }
        if cfg!(target_os = "windows") {
            let (settings, app_rules) = match self.store.lock() {
                Ok(store) => match (store.load_settings(), store.list_app_proxy_rules()) {
                    (Ok(s), Ok(r)) => (s, r),
                    _ => return false,
                },
                Err(_) => return false,
            };
            // Reload local sing-box first so any new auth_user bindings exist before WinDivert dials them.
            let _ = self.reload_core_if_running();
            let sing_box_pid = self
                .supervisor
                .lock()
                .ok()
                .and_then(|mut s| s.require_running_pid().ok())
                .unwrap_or(0);
            let Ok(cfg) = self.build_app_proxy_start_config(&settings, &app_rules, sing_box_pid)
            else {
                return false;
            };
            matches!(
                self.service_request(
                    ServiceCommand::ReloadAppProxy { config: cfg },
                    Duration::from_secs(4),
                )
                .await,
                Ok(resp) if resp.ok && resp.app_proxy_status.as_ref().is_some_and(|st| st.running)
            )
        } else {
            self.reload_core_if_running_async().await.is_ok()
        }
    }

    pub fn reload_core_if_running(&self) -> Result<Option<PreflightReport>, String> {
        let running = self
            .supervisor
            .lock()
            .map(|mut s| s.is_running())
            .unwrap_or(false);
        let Some(bin_path) = self.core_manager.resolve_binary_path() else {
            return Ok(None);
        };
        if !running {
            return Ok(None);
        }
        let compiled = self.compile_current()?;
        let mut sup = self
            .supervisor
            .lock()
            .map_err(|_| "supervisor lock poisoned".to_string())?;
        let report = match sup.apply_config(&bin_path, compiled.config) {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("reload failed: {}", e);
                drop(sup);
                self.push_log("ERROR", &msg);
                return Err(msg);
            }
        };
        if !report.ok {
            drop(sup);
            self.push_log(
                "ERROR",
                format!("reload blocked by preflight (exit {})", report.exit_code),
            );
        }
        Ok(Some(report))
    }

    pub async fn reload_core_if_running_async(&self) -> Result<Option<PreflightReport>, String> {
        if self.core_via_service.load(Ordering::Relaxed) {
            let Some(bin_path) = self.core_manager.resolve_binary_path() else {
                return Ok(None);
            };
            let compiled = self.compile_current()?;
            let preflight = SingBox114Compiler::preflight_check(&bin_path, &compiled.config)
                .map_err(|e| e.to_string())?;
            if !preflight.ok {
                self.push_log(
                    "ERROR",
                    format!(
                        "service reload blocked by preflight (exit {})",
                        preflight.exit_code
                    ),
                );
                return Ok(Some(preflight));
            }
            let config_json = serde_json::to_string(&compiled.config).map_err(|e| e.to_string())?;
            let tun_mode = self.tun_active.load(Ordering::Relaxed);
            self.service_request(
                ServiceCommand::StartCore {
                    sing_box_path: bin_path.to_string_lossy().to_string(),
                    config_json,
                    tun_mode,
                    gui_pid: Some(std::process::id()),
                },
                Duration::from_secs(6),
            )
            .await?;
            return Ok(Some(preflight));
        }
        self.reload_core_if_running()
    }

    /// Queries Plane 1 `LookupAppProxyOrigins` and `AppProxyStatus` to attribute
    /// `app-proxy-in` connections to real ancestor -> process chains (never leaking
    /// `bypax-service.exe`) and appends `local_direct`/`local_reject` rows without
    /// double-counting proxied traffic.
    pub async fn enrich_connections_with_origins(
        &self,
        conns: &mut Vec<ConnectionItem>,
    ) -> (Option<AppProxyStatusDto>, u64, u64) {
        let app_ports: Vec<u16> = conns
            .iter()
            .filter(|c| c.source_kind == "app_proxy")
            .filter_map(|c| c.source_port)
            .collect();

        let app_running = self.app_proxy_active.load(Ordering::Relaxed);
        if !app_running && app_ports.is_empty() {
            return (None, 0, 0);
        }

        let origins: HashMap<u16, FlowOriginDto> = if !app_ports.is_empty() {
            match self
                .service_request(
                    ServiceCommand::LookupAppProxyOrigins {
                        local_ports: app_ports,
                    },
                    Duration::from_millis(350),
                )
                .await
            {
                Ok(resp) if resp.ok => resp
                    .origins
                    .unwrap_or_default()
                    .into_iter()
                    .map(|o| (o.local_port, o))
                    .collect(),
                _ => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        for conn in conns.iter_mut() {
            if conn.source_kind != "app_proxy" {
                continue;
            }
            if let Some(origin) = conn.source_port.and_then(|p| origins.get(&p)) {
                conn.process = origin.process_name.clone();
                conn.pid = Some(origin.pid);
                conn.ancestor_app = origin.ancestor_name.clone();
                conn.ancestor_chain = origin.ancestor_chain.clone();
                conn.app_rule_name = if origin.rule_name.is_empty() {
                    None
                } else {
                    Some(origin.rule_name.clone())
                };
                conn.origin_expired = origin.expired;
            } else {
                // Never leak bypax-service.exe into the UI when an origin entry expired.
                let lower = conn.process.to_ascii_lowercase();
                if lower.is_empty() || lower.contains("bypax-service") || lower.contains("service") {
                    conn.process = "App Proxy (origin expired)".to_string();
                }
                conn.origin_expired = true;
            }
        }

        let status = self.query_app_proxy_status().await;
        let mut local_direct_bytes = 0u64;
        let mut local_reject_count = 0u64;

        if let Some(ref st) = status {
            local_direct_bytes = st.stats.local_direct_bytes_tx + st.stats.local_direct_bytes_rx;
            local_reject_count = st.stats.local_reject_connections;
            for local in &st.stats.local_connections {
                conns.push(ConnectionItem {
                    id: local.id.clone(),
                    process: local.process_name.clone(),
                    destination: local.destination.clone(),
                    inbound: "App Proxy".to_string(),
                    rule: if local.rule_name.is_empty() {
                        local.local_action.clone()
                    } else {
                        local.rule_name.clone()
                    },
                    chain: vec![local.local_action.clone()],
                    upload_bytes: local.upload_bytes,
                    download_bytes: local.download_bytes,
                    start: local.started_at.clone(),
                    source_port: None,
                    source_kind: "app_proxy".to_string(),
                    ancestor_app: local.ancestor_app.clone(),
                    ancestor_chain: local.ancestor_chain.clone(),
                    pid: local.pid,
                    app_rule_name: if local.rule_name.is_empty() {
                        None
                    } else {
                        Some(local.rule_name.clone())
                    },
                    origin_expired: false,
                    local_action: Some(local.local_action.clone()),
                });
            }
        }

        (status, local_direct_bytes, local_reject_count)
    }

    pub async fn perform_service_action(
        &self,
        action: &str,
    ) -> Result<PrivilegedServiceStatus, String> {
        match action {
            "stop_worker" => {
                self.app_proxy_active.store(false, Ordering::Relaxed);
                self.tun_active.store(false, Ordering::Relaxed);
                self.core_via_service.store(false, Ordering::Relaxed);
                let _ = self
                    .service_request(ServiceCommand::Shutdown, Duration::from_secs(3))
                    .await;
                self.persist_service_mode("off");
                tokio::time::sleep(Duration::from_millis(250)).await;
                return Ok(self.query_service_status().await);
            }
            "install"
            | "uninstall"
            | "start"
            | "stop"
            | "restart"
            | "start_worker"
            | "cleanup_legacy" => {}
            other => {
                return Err(format!("Unknown service action: {}", other));
            }
        }

        let svc_bin = self
            .find_sidecar_binary("bypax-service")
            .ok_or_else(|| "SERVICE_BINARY_NOT_FOUND: bypax-service executable not found".to_string())?;

        #[cfg(target_os = "windows")]
        {
            match action {
                "install" => {
                    return Err(
                        "WINDOWS_SERVICE_REMOVED: Windows Bypax uses the GUI-bound on-demand \
                         elevated helper instead of registering a background system service."
                            .to_string(),
                    );
                }
                "uninstall" | "cleanup_legacy" => {
                    self.app_proxy_active.store(false, Ordering::Relaxed);
                    self.tun_active.store(false, Ordering::Relaxed);
                    self.core_via_service.store(false, Ordering::Relaxed);
                    let _ = self
                        .service_request(ServiceCommand::Shutdown, Duration::from_secs(2))
                        .await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    run_elevated_windows(&svc_bin, &["cleanup-legacy"], true)?;
                    if let Ok(mut err_g) = self.last_service_error.lock() {
                        *err_g = None;
                    }
                    self.persist_service_mode("off");
                }
                "stop" => {
                    self.app_proxy_active.store(false, Ordering::Relaxed);
                    self.tun_active.store(false, Ordering::Relaxed);
                    self.core_via_service.store(false, Ordering::Relaxed);
                    let _ = self
                        .service_request(ServiceCommand::Shutdown, Duration::from_secs(2))
                        .await;
                    self.persist_service_mode("off");
                }
                "start" | "restart" | "start_worker" => {
                    if action == "restart" {
                        self.app_proxy_active.store(false, Ordering::Relaxed);
                        self.tun_active.store(false, Ordering::Relaxed);
                        self.core_via_service.store(false, Ordering::Relaxed);
                        let _ = self
                            .service_request(ServiceCommand::Shutdown, Duration::from_secs(2))
                            .await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    let pid_str = std::process::id().to_string();
                    let token = self.current_ipc_token();
                    let token_file = self.paths.runtime_dir.join(format!(
                        "worker-{}-{}.token",
                        std::process::id(),
                        &uuid::Uuid::new_v4().simple().to_string()[..8]
                    ));
                    std::fs::create_dir_all(&self.paths.runtime_dir)
                        .map_err(|e| format!("Failed to prepare runtime directory: {e}"))?;
                    std::fs::write(&token_file, &token)
                        .map_err(|e| format!("Failed to write ephemeral helper token: {e}"))?;

                    let ep_str = self.service_endpoint.clone();
                    let tf_str = token_file.to_string_lossy().to_string();
                    let rt_str = self.paths.runtime_dir.to_string_lossy().to_string();
                    let launch_res = run_elevated_windows(
                        &svc_bin,
                        &[
                            "worker-run",
                            "--parent-pid",
                            &pid_str,
                            "--endpoint",
                            &ep_str,
                            "--token-file",
                            &tf_str,
                            "--runtime-dir",
                            &rt_str,
                        ],
                        false,
                    );
                    if let Err(err) = launch_res {
                        let _ = std::fs::remove_file(&token_file);
                        return Err(err);
                    }
                    self.persist_service_mode("elevated_worker");
                }
                _ => {}
            }
        }

        #[cfg(target_os = "macos")]
        {
            match action {
                "install" => {
                    run_elevated_macos(&svc_bin, &["install-launchd"])?;
                    self.persist_service_mode("service");
                }
                "uninstall" => {
                    self.app_proxy_active.store(false, Ordering::Relaxed);
                    self.tun_active.store(false, Ordering::Relaxed);
                    self.core_via_service.store(false, Ordering::Relaxed);
                    run_elevated_macos(&svc_bin, &["uninstall-launchd"])?;
                    self.persist_service_mode("off");
                }
                "start" | "restart" => {
                    run_elevated_macos(&svc_bin, &["install-launchd"])?;
                    self.persist_service_mode("service");
                }
                "stop" => {
                    self.app_proxy_active.store(false, Ordering::Relaxed);
                    self.tun_active.store(false, Ordering::Relaxed);
                    self.core_via_service.store(false, Ordering::Relaxed);
                    let _ = self
                        .service_request(ServiceCommand::Shutdown, Duration::from_secs(2))
                        .await;
                    self.persist_service_mode("off");
                }
                "start_worker" => {
                    let pid_str = std::process::id().to_string();
                    let token = self.current_ipc_token();
                    run_elevated_macos(
                        &svc_bin,
                        &[
                            "daemon-run",
                            "--parent-pid",
                            &pid_str,
                            "--token",
                            &token,
                        ],
                    )?;
                    self.persist_service_mode("elevated_worker");
                }
                _ => {}
            }
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let _ = svc_bin;
            Err(format!(
                "Privileged service action '{}' is not automated on this OS; run bypax-service daemon-run manually",
                action
            ))
        }

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            // Poll until connected for start / restart / start_worker / install.
            if matches!(action, "install" | "start" | "restart" | "start_worker") {
                for _ in 0..20 {
                    let st = self.query_service_status().await;
                    if st.connected {
                        return Ok(st);
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }

            Ok(self.query_service_status().await)
        }
    }

    pub fn shutdown_cleanly(&self) {
        self.flush_active_connections();

        let stop_app = self.app_proxy_active.swap(false, Ordering::Relaxed);
        let stop_svc_core = self.core_via_service.swap(false, Ordering::Relaxed);
        self.tun_active.store(false, Ordering::Relaxed);

        if cfg!(target_os = "windows") || stop_app || stop_svc_core {
            let endpoint = self.service_endpoint.clone();
            let token = self.current_ipc_token();
            let _ = std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        if cfg!(target_os = "windows") {
                            // Gracefully terminate the GUI-bound elevated helper (also releases
                            // WinDivert handles and any privileged TUN core atomically).
                            let env = ServiceEnvelope {
                                id: "shutdown-worker".to_string(),
                                session_token: token,
                                command: ServiceCommand::Shutdown,
                            };
                            let _ = send_service_request(
                                &endpoint,
                                &env,
                                Duration::from_millis(1200),
                            )
                            .await;
                            return;
                        }
                        if stop_app {
                            let env = ServiceEnvelope {
                                id: "shutdown-app".to_string(),
                                session_token: token.clone(),
                                command: ServiceCommand::StopAppProxy,
                            };
                            let _ = send_service_request(
                                &endpoint,
                                &env,
                                Duration::from_millis(1200),
                            )
                            .await;
                        }
                        if stop_svc_core {
                            let env = ServiceEnvelope {
                                id: "shutdown-core".to_string(),
                                session_token: token,
                                command: ServiceCommand::StopCore,
                            };
                            let _ = send_service_request(
                                &endpoint,
                                &env,
                                Duration::from_millis(1200),
                            )
                            .await;
                        }
                    });
                }
            })
            .join();
        }

        if let Ok(mut sup) = self.supervisor.lock() {
            sup.stop();
        }
        if let Ok(guard) = self.netguard.lock() {
            if guard.is_armed() {
                let _ = guard.disable_system_proxy();
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn run_elevated_windows(exe: &std::path::Path, args: &[&str], wait: bool) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows::Win32::System::Threading::WaitForSingleObject;
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = format!("{}\0", exe.display()).encode_utf16().collect();
    let joined_args = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{}\"", a)
            } else {
                (*a).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let params: Vec<u16> = format!("{}\0", joined_args).encode_utf16().collect();

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    unsafe {
        if ShellExecuteExW(&mut info).is_err() {
            let err = GetLastError();
            if err == ERROR_CANCELLED {
                return Err("UAC_CANCELLED".to_string());
            }
            return Err(format!("Windows elevation failed (error {})", err.0));
        }
        if !info.hProcess.is_invalid() {
            if wait {
                let _ = WaitForSingleObject(info.hProcess, 15_000);
            }
            let _ = CloseHandle(info.hProcess);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_elevated_macos(exe: &std::path::Path, args: &[&str]) -> Result<(), String> {
    let mut cmd_parts = vec![shell_escape_single(&exe.to_string_lossy())];
    for a in args {
        cmd_parts.push(shell_escape_single(a));
    }
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        cmd_parts.join(" ").replace('\\', "\\\\").replace('"', "\\\"")
    );
    let output = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("-128") || stderr.to_ascii_lowercase().contains("user canceled") {
            return Err("UAC_CANCELLED".to_string());
        }
        return Err(format!("macOS elevation failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn shell_escape_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Normalizes a driver probe DTO to the canonical frontend recovery vocabulary
/// (`driver_missing` | `hvci_blocked` | `signature_failed` | `pipe_timeout`),
/// treating non-elevated `access_denied` in standby GUI mode as healthy (no error).
pub fn normalize_gui_driver_probe(
    mut dto: DriverProbeDto,
    service_connected: bool,
) -> DriverProbeDto {
    let canonical = match dto.error_kind.as_deref() {
        Some("driver_missing" | "missing_dll" | "missing_sys") => {
            Some("driver_missing".to_string())
        }
        Some("hvci_blocked" | "blocked_by_security") => Some("hvci_blocked".to_string()),
        Some("signature_failed" | "invalid_signature") => Some("signature_failed".to_string()),
        Some("legacy_conflict") => Some("legacy_conflict".to_string()),
        Some("pipe_timeout") => Some("pipe_timeout".to_string()),
        Some("access_denied") => {
            if !dto.elevated && !service_connected {
                dto.error = None;
            }
            None
        }
        _ => None,
    };
    dto.error_kind = canonical;
    dto
}

/// Classifies a privileged service / capture error message into the canonical UI
/// recovery vocabulary, reporting `pipe_timeout` only when the OS service is installed
/// or the user actively requested capture.
pub fn classify_service_error_kind(
    msg: &str,
    service_installed: bool,
    capture_requested: bool,
) -> Option<String> {
    if msg.contains("UAC_CANCELLED") {
        return None;
    }
    let lower = msg.to_ascii_lowercase();
    if lower.contains("hvci")
        || lower.contains("antivirus")
        || lower.contains("os error 1275")
        || lower.contains("blocked_by_security")
        || lower.contains("hvci_blocked")
    {
        return Some("hvci_blocked".to_string());
    }
    if lower.contains("signature")
        || lower.contains("os error 577")
        || lower.contains("invalid_signature")
        || lower.contains("signature_failed")
    {
        return Some("signature_failed".to_string());
    }
    if lower.contains("driver_missing")
        || lower.contains("missing_dll")
        || lower.contains("missing_sys")
        || lower.contains("windivert.dll not found")
        || lower.contains("windivert64.sys")
    {
        return Some("driver_missing".to_string());
    }
    if lower.contains("legacy_conflict")
        || lower.contains("os error 87")
        || lower.contains("os error 1072")
        || lower.contains("marked for deletion")
        || lower.contains("conflicting windivert")
        || lower.contains("same layer/priority")
        || lower.contains("legacy background proxy service")
    {
        return Some("legacy_conflict".to_string());
    }
    if (service_installed || capture_requested)
        && (lower.contains("pipe")
            || lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("service_unavailable")
            || lower.contains("unable to connect")
            || lower.contains("unauthorized")
            || lower.contains("session token"))
    {
        return Some("pipe_timeout".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_driver_dto(elevated: bool, dll_loaded: bool, kind: Option<&str>) -> DriverProbeDto {
        DriverProbeDto {
            platform: "windows".to_string(),
            elevated,
            dll_loaded,
            dll_path: if dll_loaded {
                Some(r"C:\Bypax\runtime\windivert\WinDivert.dll".to_string())
            } else {
                None
            },
            driver_opened: false,
            driver_version: None,
            error: kind.map(|k| format!("sample error ({k})")),
            error_kind: kind.map(str::to_string),
        }
    }

    #[test]
    fn non_elevated_access_denied_is_healthy_standby() {
        let dto = sample_driver_dto(false, true, Some("access_denied"));
        let norm = normalize_gui_driver_probe(dto, false);
        assert!(norm.dll_loaded);
        assert_eq!(norm.error_kind, None);
        assert_eq!(norm.error, None);
    }

    #[test]
    fn maps_driver_error_kinds_to_canonical_frontend_vocabulary() {
        assert_eq!(
            normalize_gui_driver_probe(sample_driver_dto(false, false, Some("missing_dll")), false)
                .error_kind
                .as_deref(),
            Some("driver_missing")
        );
        assert_eq!(
            normalize_gui_driver_probe(sample_driver_dto(true, true, Some("missing_sys")), true)
                .error_kind
                .as_deref(),
            Some("driver_missing")
        );
        assert_eq!(
            normalize_gui_driver_probe(
                sample_driver_dto(true, true, Some("blocked_by_security")),
                true
            )
            .error_kind
            .as_deref(),
            Some("hvci_blocked")
        );
        assert_eq!(
            normalize_gui_driver_probe(
                sample_driver_dto(true, true, Some("invalid_signature")),
                true
            )
            .error_kind
            .as_deref(),
            Some("signature_failed")
        );
        assert_eq!(
            normalize_gui_driver_probe(sample_driver_dto(false, true, Some("other")), false)
                .error_kind,
            None
        );
    }

    #[test]
    fn service_error_classification_respects_standby_vs_capture() {
        assert_eq!(
            classify_service_error_kind("IPC pipe timed out", false, false),
            None
        );
        assert_eq!(
            classify_service_error_kind("IPC pipe timed out", true, false).as_deref(),
            Some("pipe_timeout")
        );
        assert_eq!(
            classify_service_error_kind("SERVICE_UNAVAILABLE: pipe busy", false, true).as_deref(),
            Some("pipe_timeout")
        );
        assert_eq!(classify_service_error_kind("UAC_CANCELLED", true, true), None);
        assert_eq!(
            classify_service_error_kind("WinDivertOpen failed (os error 1275 HVCI)", true, true)
                .as_deref(),
            Some("hvci_blocked")
        );
        assert_eq!(
            classify_service_error_kind("os error 577 signature error", true, true).as_deref(),
            Some("signature_failed")
        );
        assert_eq!(
            classify_service_error_kind("WinDivert.dll not found", false, true).as_deref(),
            Some("driver_missing")
        );
        assert_eq!(
            classify_service_error_kind("Unauthorized session token", true, false).as_deref(),
            Some("pipe_timeout")
        );
    }
}
