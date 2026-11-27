use crate::platform_svc;
#[cfg(windows)]
use bypax_appproxy::engine::AppProxyEngine;
use bypax_appproxy::engine::AppProxyHandle;
use bypax_appproxy::process::{ProcessTracker, SnapshotProcessTracker};
use bypax_appproxy::rules::RuleEngine;
use bypax_core::netguard::NetGuard;
use bypax_core::storage::DataPaths;
use bypax_core::supervisor::{CoreSupervisor, LogRing, MAX_LOG_RING_ENTRIES};
use bypax_ipc::{
    AppProxyStartConfig, AppProxyStatusDto, CoreStatusDto, ProcessInfoDto, ServiceCommand,
    ServiceEnvelope, ServiceHandler, ServiceResponse, HEARTBEAT_TIMEOUT_SECS,
};
#[cfg(windows)]
use bypax_windivert::WinDivertCaptureEngine;
use bypax_windivert::{is_elevated, probe_windivert};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{info, warn};

#[cfg_attr(not(windows), allow(dead_code))]
struct RunningAppProxy {
    handle: AppProxyHandle,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    last_config: AppProxyStartConfig,
    sing_box_pid: Option<u32>,
    dead_core_ticks: u8,
}

struct InnerState {
    expected_token: String,
    supervisor: CoreSupervisor,
    tun_active: bool,
    netguard: NetGuard,
    last_heartbeat: Option<Instant>,
    gui_pid: Option<u32>,
    app_proxy: Option<RunningAppProxy>,
    last_app_proxy_error: Option<String>,
    last_app_proxy_error_kind: Option<String>,
}

/// Core privileged helper controller shared by Windows GUI-bound on-demand worker (`worker-run`),
/// macOS `launchd` LaunchDaemon (`daemon-run`), and integration tests. Enforces a strict GUI
/// lease boundary so no proxy capture or TUN can run while the desktop GUI is closed.
pub struct ServiceController {
    inner: Mutex<InnerState>,
    capture_mutex: tokio::sync::Mutex<()>,
    tracker: Arc<SnapshotProcessTracker>,
}

impl ServiceController {
    pub fn new(paths: &DataPaths, expected_token: String) -> Arc<Self> {
        Self::new_with_runtime_dir(paths.runtime_dir.clone(), expected_token)
    }

    pub fn new_with_runtime_dir(runtime_dir: PathBuf, expected_token: String) -> Arc<Self> {
        let logs = Arc::new(Mutex::new(LogRing::new(MAX_LOG_RING_ENTRIES)));
        let tracker = Arc::new(SnapshotProcessTracker::default());
        Arc::new(Self {
            inner: Mutex::new(InnerState {
                expected_token,
                supervisor: CoreSupervisor::new(runtime_dir.clone(), logs),
                tun_active: false,
                netguard: NetGuard::new(&runtime_dir),
                last_heartbeat: None,
                gui_pid: None,
                app_proxy: None,
                last_app_proxy_error: None,
                last_app_proxy_error_kind: None,
            }),
            capture_mutex: tokio::sync::Mutex::new(()),
            tracker,
        })
    }

    /// Binds this controller to a specific parent GUI PID before IPC starts.
    pub fn set_gui_pid(&self, gui_pid: u32) {
        if let Ok(mut st) = self.inner.lock() {
            st.gui_pid = Some(gui_pid);
            st.last_heartbeat = Some(Instant::now());
        }
    }

    /// Validates that a live desktop GUI process holds the lease before activating capture.
    fn require_live_gui_lease(&self, incoming_gui_pid: Option<u32>) -> Result<u32, String> {
        let candidate = {
            let Ok(st) = self.inner.lock() else {
                return Err("State lock poisoned".to_string());
            };
            incoming_gui_pid.filter(|&p| p > 0).or(st.gui_pid)
        };
        let Some(pid) = candidate else {
            return Err(
                "GUI_LEASE_REQUIRED: Launch Bypax GUI to activate App Proxy or TUN capture"
                    .to_string(),
            );
        };
        if !platform_svc::is_parent_alive(pid) {
            return Err(format!(
                "GUI_LEASE_REQUIRED: Bound Bypax GUI process (pid {pid}) is no longer running"
            ));
        }
        if let Ok(mut st) = self.inner.lock() {
            st.gui_pid = Some(pid);
            st.last_heartbeat = Some(Instant::now());
        }
        Ok(pid)
    }

    /// Stops all active data planes (App Proxy + Core Supervisor) and restores NetGuard if dirty.
    pub async fn stop_all_and_restore(&self) {
        let _guard = self.capture_mutex.lock().await;
        self.stop_app_proxy_locked().await;
        if let Ok(mut st) = self.inner.lock() {
            st.supervisor.stop();
            st.tun_active = false;
            let _ = st.netguard.recover_if_dirty();
            st.last_heartbeat = None;
        }
    }

    /// Executes one watchdog tick; returns `true` if a dead GUI lease, heartbeat timeout, or
    /// unexpected local proxy core exit triggered automatic fail-safe teardown.
    pub async fn check_heartbeat_timeout(&self, timeout: Duration) -> bool {
        let (should_stop_all, reason, pause_app_proxy_only) = {
            let Ok(mut st) = self.inner.lock() else {
                return false;
            };
            let active = st.supervisor.is_running() || st.app_proxy.is_some();
            if !active {
                (false, "", false)
            } else if st
                .gui_pid
                .is_some_and(|pid| !platform_svc::is_parent_alive(pid))
            {
                (true, "bound GUI process exited", false)
            } else if st
                .last_heartbeat
                .is_some_and(|last| last.elapsed() > timeout)
            {
                (true, "GUI heartbeat timed out", false)
            } else if let Some(ref mut running) = st.app_proxy {
                if let Some(sb_pid) = running.sing_box_pid.filter(|&p| p > 4) {
                    if !platform_svc::is_parent_alive(sb_pid) {
                        running.dead_core_ticks = running.dead_core_ticks.saturating_add(1);
                        if running.dead_core_ticks == 1 {
                            running
                                .handle
                                .reset_proxied_sessions("local proxy core process exited");
                        }
                        if running.dead_core_ticks >= 2 {
                            (false, "local proxy core exited unexpectedly", true)
                        } else {
                            (false, "", false)
                        }
                    } else {
                        running.dead_core_ticks = 0;
                        (false, "", false)
                    }
                } else {
                    (false, "", false)
                }
            } else {
                (false, "", false)
            }
        };

        if should_stop_all {
            warn!(
                reason,
                timeout_secs = timeout.as_secs(),
                "GUI lease lost; stopping App Proxy & Core and restoring NetGuard"
            );
            self.stop_all_and_restore().await;
            return true;
        }

        if pause_app_proxy_only {
            warn!(
                reason,
                "local proxy core disappeared; pausing WinDivert App Proxy (fail-open)"
            );
            let _guard = self.capture_mutex.lock().await;
            self.stop_app_proxy_locked().await;
            if let Ok(mut st) = self.inner.lock() {
                st.last_app_proxy_error = Some(
                    "Proxy core exited unexpectedly; App Proxy paused to prevent traffic blackhole"
                        .to_string(),
                );
                st.last_app_proxy_error_kind = Some("core_exited".to_string());
                if !st.supervisor.is_running() {
                    st.last_heartbeat = None;
                }
            }
            return true;
        }
        false
    }

    pub fn spawn_watchdog(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let ctrl = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            let timeout = Duration::from_secs(HEARTBEAT_TIMEOUT_SECS);
            loop {
                interval.tick().await;
                let _ = ctrl.check_heartbeat_timeout(timeout).await;
            }
        })
    }

    async fn stop_app_proxy_locked(&self) {
        let taken = {
            let Ok(mut st) = self.inner.lock() else {
                return;
            };
            st.app_proxy.take()
        };
        if let Some(mut running) = taken {
            if let Some(tx) = running.shutdown_tx.take() {
                let _ = tx.send(());
            }
            let _ = tokio::time::timeout(Duration::from_secs(3), running.task).await;
            info!("bypax-service: stopped App Proxy engine");
        }
    }

    async fn start_app_proxy(&self, id: String, mut cfg: AppProxyStartConfig) -> ServiceResponse {
        let _lock = self.capture_mutex.lock().await;

        let leased_gui_pid = match self.require_live_gui_lease(cfg.gui_pid) {
            Ok(pid) => pid,
            Err(msg) => {
                let mut resp = ServiceResponse::error(id, msg);
                resp.app_proxy_status = Some(self.build_app_proxy_status());
                return resp;
            }
        };

        // Kernel-level mutual exclusion: stop TUN core if currently active before starting WinDivert.
        {
            if let Ok(mut st) = self.inner.lock() {
                if st.tun_active && st.supervisor.is_running() {
                    info!("bypax-service: stopping privileged TUN core before starting App Proxy");
                    st.supervisor.stop();
                    st.tun_active = false;
                }
            }
        }
        if !cfg.exempt_pids.contains(&leased_gui_pid) {
            cfg.exempt_pids.push(leased_gui_pid);
        }
        let self_pid = std::process::id();
        if !cfg.exempt_pids.contains(&self_pid) {
            cfg.exempt_pids.push(self_pid);
        }
        let sing_box_pid = cfg.sing_box_pid;

        // Stop any previous App Proxy engine cleanly first.
        self.stop_app_proxy_locked().await;

        #[cfg(not(windows))]
        {
            let _ = sing_box_pid;
            // On macOS/Linux, App Proxy runs via `sing-box` `utun` path routing (StartCore).
            let mut resp = ServiceResponse::success(
                id,
                "Non-Windows platforms use sing-box utun path routing via StartCore",
            );
            resp.app_proxy_status = Some(self.build_app_proxy_status());
            resp
        }

        #[cfg(windows)]
        {
            let preferred = cfg.windivert_dir.as_deref().map(Path::new);
            let capture = match WinDivertCaptureEngine::with_process_tracker(
                preferred,
                Some(Arc::clone(&self.tracker) as Arc<dyn ProcessTracker>),
            ) {
                Ok(c) => Arc::new(c),
                Err(err) => {
                    let msg = err.to_string();
                    let kind = bypax_windivert::windows_engine::classify_windivert_error(false, &msg);
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = Some(msg.clone());
                        st.last_app_proxy_error_kind = Some(kind);
                    }
                    let mut resp = ServiceResponse::error(id, msg);
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    return resp;
                }
            };

            let engine = match AppProxyEngine::new(
                &cfg,
                capture,
                Arc::clone(&self.tracker) as Arc<dyn ProcessTracker>,
            ) {
                Ok(e) => e,
                Err(err) => {
                    let msg = format!("Failed to compile App Proxy rules: {err}");
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = Some(msg.clone());
                        st.last_app_proxy_error_kind = Some("other".to_string());
                    }
                    return ServiceResponse::error(id, msg);
                }
            };

            let handle = engine.handle();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let (started_tx, started_rx) = oneshot::channel::<Result<(), String>>();

            let task = tokio::spawn(async move {
                let _ = engine.run_with_ready(shutdown_rx, Some(started_tx)).await;
            });

            // Await deterministic capture startup (WinDivertOpen across SOCKET/FLOW/NETWORK)
            // instead of a fixed sleep that can miss slow driver loads or report dead tasks as running.
            match tokio::time::timeout(Duration::from_secs(5), started_rx).await {
                Ok(Ok(Ok(()))) => {
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = None;
                        st.last_app_proxy_error_kind = None;
                        st.last_heartbeat = Some(Instant::now());
                        st.app_proxy = Some(RunningAppProxy {
                            handle,
                            shutdown_tx: Some(shutdown_tx),
                            task,
                            last_config: cfg,
                            sing_box_pid,
                            dead_core_ticks: 0,
                        });
                    }
                    let mut resp = ServiceResponse::success(id, "App Proxy started");
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    resp
                }
                Ok(Ok(Err(err_msg))) => {
                    let kind =
                        bypax_windivert::windows_engine::classify_windivert_error(true, &err_msg);
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = Some(err_msg.clone());
                        st.last_app_proxy_error_kind = Some(kind);
                    }
                    let mut resp = ServiceResponse::error(id, err_msg);
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    resp
                }
                Ok(Err(_)) => {
                    let err_msg = "App Proxy engine task exited before signaling readiness".to_string();
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = Some(err_msg.clone());
                        st.last_app_proxy_error_kind = Some("other".to_string());
                    }
                    let mut resp = ServiceResponse::error(id, err_msg);
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    resp
                }
                Err(_) => {
                    let _ = shutdown_tx.send(());
                    let err_msg = "Timed out waiting for WinDivert App Proxy startup".to_string();
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_app_proxy_error = Some(err_msg.clone());
                        st.last_app_proxy_error_kind = Some("other".to_string());
                    }
                    let mut resp = ServiceResponse::error(id, err_msg);
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    resp
                }
            }
        }
    }

    async fn reload_app_proxy(&self, id: String, mut cfg: AppProxyStartConfig) -> ServiceResponse {
        let _lock = self.capture_mutex.lock().await;
        let self_pid = std::process::id();
        if !cfg.exempt_pids.contains(&self_pid) {
            cfg.exempt_pids.push(self_pid);
        }
        let next_sb_pid = cfg.sing_box_pid;
        let res = {
            let Ok(mut st) = self.inner.lock() else {
                return ServiceResponse::error(id, "State lock poisoned");
            };
            if let Some(gui_pid) = st.gui_pid {
                if !cfg.exempt_pids.contains(&gui_pid) {
                    cfg.exempt_pids.push(gui_pid);
                }
            }
            if let Some(ref mut running) = st.app_proxy {
                let prev_sb_pid = running.sing_box_pid;
                let prev_port = running.last_config.app_proxy_port;
                let next_port = cfg.app_proxy_port;
                let r = running.handle.reload_config(&cfg);
                if r.is_ok() {
                    let sb_restarted = prev_sb_pid.is_some()
                        && next_sb_pid.filter(|&p| p > 0).is_some()
                        && prev_sb_pid != next_sb_pid;
                    let port_changed = prev_port != next_port;
                    if sb_restarted || port_changed {
                        running
                            .handle
                            .reset_proxied_sessions("sing-box restarted or app-proxy port changed");
                    }
                    running.last_config = cfg;
                    if let Some(pid) = next_sb_pid.filter(|&p| p > 0) {
                        running.sing_box_pid = Some(pid);
                        running.dead_core_ticks = 0;
                    }
                }
                Some(r)
            } else {
                None
            }
        };

        match res {
            Some(Ok(())) => {
                let mut resp = ServiceResponse::success(id, "App Proxy reloaded");
                resp.app_proxy_status = Some(self.build_app_proxy_status());
                resp
            }
            Some(Err(e)) => ServiceResponse::error(id, format!("Reload failed: {e}")),
            None => ServiceResponse::error(id, "App Proxy is not running"),
        }
    }

    fn build_core_status(&self) -> CoreStatusDto {
        let Ok(mut st) = self.inner.lock() else {
            return CoreStatusDto::default();
        };
        let running = st.supervisor.is_running();
        let pid = if running {
            st.supervisor.require_running_pid().ok()
        } else {
            None
        };
        let app_running = st
            .app_proxy
            .as_ref()
            .is_some_and(|r| !r.task.is_finished());
        let capture_mode = if running && st.tun_active {
            "tun"
        } else if app_running {
            "apps"
        } else {
            "off"
        };
        CoreStatusDto {
            running,
            pid,
            tun_active: running && st.tun_active,
            capture_mode: capture_mode.to_string(),
        }
    }

    fn build_app_proxy_status(&self) -> AppProxyStatusDto {
        let Ok(st) = self.inner.lock() else {
            return AppProxyStatusDto::default();
        };
        if let Some(ref running) = st.app_proxy {
            if !running.task.is_finished() {
                return AppProxyStatusDto {
                    running: true,
                    mode: "windivert_zero_tun".to_string(),
                    active_rules: running.handle.active_rule_count(),
                    exempt_pids: running.handle.exempt_pids(),
                    last_error: st.last_app_proxy_error.clone(),
                    error_kind: st.last_app_proxy_error_kind.clone(),
                    stats: running.handle.stats_snapshot(),
                };
            }
        }
        AppProxyStatusDto {
            running: false,
            mode: "inactive".to_string(),
            active_rules: 0,
            exempt_pids: Vec::new(),
            last_error: st.last_app_proxy_error.clone(),
            error_kind: st.last_app_proxy_error_kind.clone(),
            stats: Default::default(),
        }
    }

    fn list_processes(&self, filter: Option<&str>) -> Vec<ProcessInfoDto> {
        let needle = filter
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());

        let rule_engine: Option<RuleEngine> = self.inner.lock().ok().and_then(|st| {
            st.app_proxy.as_ref().and_then(|r| {
                RuleEngine::from_wire(
                    &r.last_config.rules,
                    &r.last_config.target_bindings,
                    r.last_config.bypass_lan,
                    &r.last_config.exempt_pids,
                )
                .ok()
            })
        });

        let procs = self.tracker.list_processes();
        let mut out = Vec::new();
        for p in procs {
            if let Some(ref q) = needle {
                let name_hit = p.name.to_ascii_lowercase().contains(q);
                let path_hit = p
                    .exe_path
                    .as_deref()
                    .is_some_and(|e| e.to_ascii_lowercase().contains(q));
                if !name_hit && !path_hit {
                    continue;
                }
            }
            let chain: Vec<String> = self
                .tracker
                .ancestor_chain(p.pid)
                .into_iter()
                .map(|a| a.name)
                .collect();
            let (matched_rule_id, matched_rule_name) = rule_engine
                .as_ref()
                .and_then(|re| re.match_process_rule(p.pid, self.tracker.as_ref()))
                .map(|(id, name)| (Some(id), Some(name)))
                .unwrap_or((None, None));
            out.push(ProcessInfoDto {
                pid: p.pid,
                parent_pid: p.parent_pid,
                name: p.name,
                exe_path: p.exe_path,
                ancestor_chain: chain,
                matched_rule_id,
                matched_rule_name,
            });
        }
        out
    }
}

impl ServiceHandler for ServiceController {
    fn handle(
        &self,
        env: ServiceEnvelope,
    ) -> Pin<Box<dyn Future<Output = (ServiceResponse, bool)> + Send + '_>> {
        Box::pin(async move {
            {
                let Ok(st) = self.inner.lock() else {
                    return (ServiceResponse::error(env.id, "State lock poisoned"), false);
                };
                if env.session_token != st.expected_token {
                    return (
                        ServiceResponse::error(env.id, "Unauthorized session token"),
                        false,
                    );
                }
            }

            match env.command {
                ServiceCommand::Ping => {
                    let mut resp = ServiceResponse::success(env.id, "pong");
                    resp.version = Some(env!("CARGO_PKG_VERSION").to_string());
                    resp.service_pid = Some(std::process::id());
                    resp.elevated = Some(is_elevated());
                    (resp, false)
                }
                ServiceCommand::Heartbeat { gui_pid } => {
                    if let Ok(mut st) = self.inner.lock() {
                        st.last_heartbeat = Some(Instant::now());
                        st.gui_pid = Some(gui_pid);
                    }
                    let mut resp =
                        ServiceResponse::success(env.id, format!("heartbeat ok (pid {gui_pid})"));
                    resp.service_pid = Some(std::process::id());
                    (resp, false)
                }
                ServiceCommand::StartCore {
                    sing_box_path,
                    config_json,
                    tun_mode,
                    gui_pid,
                } => {
                    let _lock = self.capture_mutex.lock().await;
                    if let Err(msg) = self.require_live_gui_lease(gui_pid) {
                        return (ServiceResponse::error(env.id, msg), false);
                    }
                    if tun_mode {
                        // Kernel-level mutual exclusion: stop App Proxy before starting TUN.
                        self.stop_app_proxy_locked().await;
                    }
                    let parsed: serde_json::Value = match serde_json::from_str(&config_json) {
                        Ok(v) => v,
                        Err(e) => {
                            return (
                                ServiceResponse::error(env.id, format!("Invalid JSON: {e}")),
                                false,
                            )
                        }
                    };
                    let mut st = match self.inner.lock() {
                        Ok(g) => g,
                        Err(_) => {
                            return (ServiceResponse::error(env.id, "State lock poisoned"), false)
                        }
                    };
                    match st
                        .supervisor
                        .apply_config(&PathBuf::from(sing_box_path), parsed)
                    {
                        Ok(rep) if rep.ok => {
                            st.tun_active = tun_mode;
                            st.last_heartbeat = Some(Instant::now());
                            let pid = st.supervisor.require_running_pid().ok();
                            drop(st);
                            let mut resp = ServiceResponse::success(env.id, "Core started");
                            resp.core_running = Some(true);
                            resp.core_pid = pid;
                            resp.core_status = Some(self.build_core_status());
                            (resp, false)
                        }
                        Ok(rep) => (
                            ServiceResponse::error(
                                env.id,
                                format!("Preflight failed: {}", rep.stderr),
                            ),
                            false,
                        ),
                        Err(e) => (
                            ServiceResponse::error(env.id, format!("Start error: {e}")),
                            false,
                        ),
                    }
                }
                ServiceCommand::StopCore => {
                    let _lock = self.capture_mutex.lock().await;
                    if let Ok(mut st) = self.inner.lock() {
                        st.supervisor.stop();
                        st.tun_active = false;
                        if st.app_proxy.is_none() {
                            st.last_heartbeat = None;
                        }
                    }
                    let mut resp = ServiceResponse::success(env.id, "Core stopped");
                    resp.core_running = Some(false);
                    resp.core_status = Some(self.build_core_status());
                    (resp, false)
                }
                ServiceCommand::CoreStatus => {
                    let cs = self.build_core_status();
                    let mut resp = ServiceResponse::success(env.id, "ok");
                    resp.core_running = Some(cs.running);
                    resp.core_pid = cs.pid;
                    resp.core_status = Some(cs);
                    resp.service_pid = Some(std::process::id());
                    resp.elevated = Some(is_elevated());
                    (resp, false)
                }
                ServiceCommand::StartAppProxy { config } => {
                    (self.start_app_proxy(env.id, config).await, false)
                }
                ServiceCommand::StopAppProxy => {
                    let _lock = self.capture_mutex.lock().await;
                    self.stop_app_proxy_locked().await;
                    if let Ok(mut st) = self.inner.lock() {
                        if !st.supervisor.is_running() {
                            st.last_heartbeat = None;
                        }
                    }
                    let mut resp = ServiceResponse::success(env.id, "App Proxy stopped");
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    (resp, false)
                }
                ServiceCommand::ReloadAppProxy { config } => {
                    (self.reload_app_proxy(env.id, config).await, false)
                }
                ServiceCommand::AppProxyStatus => {
                    let mut resp = ServiceResponse::success(env.id, "ok");
                    resp.app_proxy_status = Some(self.build_app_proxy_status());
                    (resp, false)
                }
                ServiceCommand::LookupAppProxyOrigins { local_ports } => {
                    let origins = self
                        .inner
                        .lock()
                        .ok()
                        .and_then(|st| {
                            st.app_proxy
                                .as_ref()
                                .map(|r| r.handle.lookup_origins(&local_ports))
                        })
                        .unwrap_or_default();
                    let mut resp = ServiceResponse::success(env.id, "ok");
                    resp.origins = Some(origins);
                    (resp, false)
                }
                ServiceCommand::ProbeDriver { windivert_dir } => {
                    let dir = windivert_dir.as_deref().map(Path::new);
                    let report = probe_windivert(dir);
                    let mut resp = ServiceResponse::success(env.id, "ok");
                    resp.driver = Some(report.to_dto());
                    (resp, false)
                }
                ServiceCommand::ListProcesses { filter } => {
                    let list = self.list_processes(filter.as_deref());
                    let mut resp = ServiceResponse::success(env.id, "ok");
                    resp.processes = Some(list);
                    (resp, false)
                }
                ServiceCommand::RestoreNetwork => {
                    let res = self
                        .inner
                        .lock()
                        .map_err(|_| anyhow::anyhow!("State lock poisoned"))
                        .and_then(|st| st.netguard.disable_system_proxy());
                    match res {
                        Ok(_) => (ServiceResponse::success(env.id, "Network restored"), false),
                        Err(e) => (
                            ServiceResponse::error(env.id, format!("Restore failed: {e}")),
                            false,
                        ),
                    }
                }
                ServiceCommand::Shutdown => {
                    self.stop_all_and_restore().await;
                    (ServiceResponse::success(env.id, "Shutting down"), true)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bypax_ipc::{
        generate_session_token, send_service_request, PipeAclMode, ServiceIpcServer,
    };

    #[tokio::test]
    async fn service_controller_ipc_roundtrip_and_heartbeat_watchdog() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = DataPaths::from_root(tmp.path().to_path_buf(), true).unwrap();
        let token = generate_session_token();
        let ctrl = ServiceController::new(&paths, token.clone());

        #[cfg(windows)]
        let ep = format!(r"\\.\pipe\bypax-svc-unit-{}", std::process::id());
        #[cfg(unix)]
        let ep = tmp.path().join("svc.sock").to_string_lossy().to_string();

        let server = ServiceIpcServer::new(ep.clone(), PipeAclMode::PrivilegedService, ctrl.clone());
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(server.run(rx));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ping = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "p1".into(),
                session_token: token.clone(),
                command: ServiceCommand::Ping,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(ping.ok);
        assert_eq!(ping.message, "pong");

        // Strict GUI lease: StartCore MUST be rejected when no live GUI PID holds a lease.
        let denied_start = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "sc-denied".into(),
                session_token: token.clone(),
                command: ServiceCommand::StartCore {
                    sing_box_path: "nonexistent".into(),
                    config_json: "{}".into(),
                    tun_mode: true,
                    gui_pid: None,
                },
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(!denied_start.ok);
        assert!(denied_start.message.contains("GUI_LEASE_REQUIRED"));

        // Dead GUI PID MUST also be rejected.
        let denied_dead = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "sc-dead".into(),
                session_token: token.clone(),
                command: ServiceCommand::StartCore {
                    sing_box_path: "nonexistent".into(),
                    config_json: "{}".into(),
                    tun_mode: true,
                    gui_pid: Some(1),
                },
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(!denied_dead.ok);
        assert!(denied_dead.message.contains("GUI_LEASE_REQUIRED"));

        let hb = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "h1".into(),
                session_token: token.clone(),
                command: ServiceCommand::Heartbeat {
                    gui_pid: std::process::id(),
                },
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(hb.ok);

        let procs = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "ps1".into(),
                session_token: token.clone(),
                command: ServiceCommand::ListProcesses { filter: None },
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(procs.ok);
        assert!(!procs.processes.unwrap_or_default().is_empty());

        // Verify watchdog triggers when heartbeat is stale and no active crash occurs.
        assert!(!ctrl.check_heartbeat_timeout(Duration::from_secs(15)).await);

        // Stopping App Proxy when no core is active must clear the recorded heartbeat so
        // a later start is never killed immediately by a stale timestamp.
        let stop_app = send_service_request(
            &ep,
            &ServiceEnvelope {
                id: "sa1".into(),
                session_token: token.clone(),
                command: ServiceCommand::StopAppProxy,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(stop_app.ok);
        assert!(ctrl.inner.lock().unwrap().last_heartbeat.is_none());

        let _ = tx.send(());
        let _ = task.await;
    }
}
