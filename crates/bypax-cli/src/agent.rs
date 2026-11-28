use crate::service_cmd::query_os_service_status;
use anyhow::{anyhow, bail, Result};
use bypax_appproxy::{AppRuleTestQuery, ProcessTracker, RuleEngine, SnapshotProcessTracker};
use bypax_core::compiler::build_app_proxy_target_bindings;
use bypax_core::core_manager::CoreManager;
use bypax_core::model::{AppProxyRule, CaptureMode, NodeIR, RouteMode};
use bypax_core::netguard::NetGuard;
use bypax_core::parser::parse_payload;
use bypax_core::route_eval::evaluate_route_target;
use bypax_core::rule_cache::RuleCache;
use bypax_core::storage::{DataPaths, Store};
use bypax_core::tester::batch_real_delay_with_progress;
use bypax_core::updater::fetch_text_via_channels;
use bypax_ipc::{
    default_ctl_endpoint, default_svc_endpoint, load_ipc_token, send_ctl_request,
    send_service_request, AppProxyRuleWire, CtlEnvelope, CtlRequest, CtlResponse, DriverProbeDto,
    ProcessInfoDto, ServiceCommand, ServiceEnvelope, ServiceResponse,
};
use bypax_windivert::probe_windivert;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const CTL_NORMAL_TIMEOUT: Duration = Duration::from_secs(6);
const CTL_LONG_TIMEOUT: Duration = Duration::from_secs(60);
const SVC_TIMEOUT: Duration = Duration::from_secs(3);

/// Unified control client shared by `bypax-cli ctl`, `bypax-cli mcp`, `doctor`, and `ps`.
///
/// - **Live Mode**: communicates with the running non-elevated Bypax GUI over Plane 2
///   (`\\.\pipe\bypax-ctl-v1` / `<runtime_dir>/bypax-ctl.sock`), guaranteeing 0ms hot-switches
///   and immediate `bypax-state-sync` UI refreshes.
/// - **Offline Fallback**: when Plane 2 is unreachable (GUI closed), transparently reads/writes
///   SQLite WAL (`bypax.db` with `busy_timeout = 5000`) and talks directly to Plane 1
///   `bypax-service` IPC where available.
pub struct AgentClient {
    ctl_endpoint: String,
    svc_endpoint: String,
    paths: DataPaths,
}

impl AgentClient {
    pub fn new(
        ctl_endpoint: Option<String>,
        svc_endpoint: Option<String>,
        data_dir_override: Option<PathBuf>,
    ) -> Result<Self> {
        let paths = match data_dir_override {
            Some(dir) => DataPaths::from_root(dir, true)?,
            None => DataPaths::resolve()?,
        };
        let ctl_ep = ctl_endpoint.unwrap_or_else(|| default_ctl_endpoint(&paths.runtime_dir));
        let svc_ep = svc_endpoint.unwrap_or_else(default_svc_endpoint);
        Ok(Self {
            ctl_endpoint: ctl_ep,
            svc_endpoint: svc_ep,
            paths,
        })
    }

    fn open_store(&self) -> Result<Store> {
        Store::open(&self.paths.db_path)
    }

    async fn try_ctl(&self, req: &CtlRequest) -> Option<CtlResponse> {
        let timeout = match req {
            CtlRequest::TestLatency { .. } | CtlRequest::RefreshSubscriptions { .. } => {
                CTL_LONG_TIMEOUT
            }
            _ => CTL_NORMAL_TIMEOUT,
        };
        let env = CtlEnvelope {
            id: format!("cli-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
            request: req.clone(),
        };
        send_ctl_request(&self.ctl_endpoint, &env, timeout)
            .await
            .ok()
    }

    async fn try_service(&self, cmd: ServiceCommand) -> Option<ServiceResponse> {
        let token = load_ipc_token(Some(&self.paths.runtime_dir)).unwrap_or_default();
        let env = ServiceEnvelope {
            id: format!("cli-svc-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
            session_token: token,
            command: cmd,
        };
        send_service_request(&self.svc_endpoint, &env, SVC_TIMEOUT)
            .await
            .ok()
    }

    /// Dispatches a `CtlRequest` via Plane 2 (Live Mode) first, falling back cleanly
    /// to SQLite WAL + Plane 1 `bypax-service` (Offline Mode) if the GUI is closed.
    pub async fn execute(&self, req: CtlRequest) -> Result<Value> {
        if let Some(resp) = self.try_ctl(&req).await {
            if resp.ok {
                return Ok(resp
                    .data
                    .unwrap_or_else(|| json!({ "ok": true, "message": resp.message })));
            }
            bail!("{}", resp.message);
        }

        self.execute_offline(req).await
    }

    async fn execute_offline(&self, req: CtlRequest) -> Result<Value> {
        match req {
            CtlRequest::Status => self.offline_status().await,
            CtlRequest::ToggleCore { enabled } => self.offline_toggle_core(enabled).await,
            CtlRequest::SetMode { mode } => self.offline_set_mode(&mode),
            CtlRequest::ToggleSystemProxy { enabled } => self.offline_toggle_system_proxy(enabled),
            CtlRequest::ToggleTun { enabled } => self.offline_toggle_tun(enabled).await,
            CtlRequest::SetCaptureMode { mode } => self.offline_set_capture_mode(&mode).await,
            CtlRequest::ListNodes {
                group,
                region,
                query,
            } => self.offline_list_nodes(group, region, query),
            CtlRequest::SelectNode { node_id } => self.offline_select_node(&node_id),
            CtlRequest::TestLatency { node_ids, kind } => {
                self.offline_test_latency(node_ids, &kind).await
            }
            CtlRequest::RefreshSubscriptions { subscription_id } => {
                self.offline_refresh_subscriptions(subscription_id).await
            }
            CtlRequest::ListRouteRules => self.offline_list_route_rules(),
            CtlRequest::TestRoute {
                input,
                process_name,
            } => self.offline_test_route(&input, process_name),
            CtlRequest::ListConnections { source, query } => {
                self.offline_list_connections(source, query).await
            }
            CtlRequest::GetLogs { level, limit } => self.offline_get_logs(level, limit),
            CtlRequest::Doctor => self.offline_doctor().await,
            CtlRequest::AppToggle { enabled } => self.offline_app_toggle(enabled).await,
            CtlRequest::AppListRules => self.offline_app_list_rules(),
            CtlRequest::AppUpsertRule { rule } => self.offline_app_upsert_rule(rule),
            CtlRequest::AppDeleteRule { id } => self.offline_app_delete_rule(&id),
            CtlRequest::AppTestRule {
                process_name,
                exe_path,
                host,
                dst_ip,
                dst_port,
                protocol,
            } => self.offline_app_test_rule(
                process_name,
                exe_path,
                host,
                dst_ip,
                dst_port,
                protocol,
            ),
            CtlRequest::ListProcesses { filter } => self.offline_list_processes(filter).await,
        }
    }

    async fn offline_status(&self) -> Result<Value> {
        let store = self.open_store()?;
        let settings = store.load_settings()?;
        let nodes = store.list_nodes()?;
        let rules = store.list_rules()?;
        let app_rules = store.list_app_proxy_rules()?;

        let core_mgr = CoreManager::new(self.paths.core_dir.clone());
        let netguard = NetGuard::new(&self.paths.runtime_dir);
        let os_service = query_os_service_status();

        let svc_ping = self.try_service(ServiceCommand::Ping).await;
        let svc_connected = svc_ping.as_ref().map(|r| r.ok).unwrap_or(false);
        let core_status = if svc_connected {
            self.try_service(ServiceCommand::CoreStatus)
                .await
                .and_then(|r| r.core_status)
        } else {
            None
        };
        let app_status = if svc_connected {
            self.try_service(ServiceCommand::AppProxyStatus)
                .await
                .and_then(|r| r.app_proxy_status)
        } else {
            None
        };

        let capture_mode = if settings.tun_enabled {
            "tun"
        } else if settings.app_proxy_enabled {
            "apps"
        } else {
            "off"
        };

        Ok(json!({
            "controlMode": "offline",
            "appVersion": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "portableMode": self.paths.portable_mode,
            "dataDir": self.paths.root_dir.to_string_lossy(),
            "routeMode": settings.route_mode.as_str(),
            "captureMode": capture_mode,
            "mainNodeId": settings.main_node_id,
            "mixedPort": settings.mixed_port,
            "controlPort": settings.control_port,
            "systemProxyEnabled": settings.system_proxy_enabled,
            "netguardArmed": netguard.is_armed(),
            "appProxyEnabled": settings.app_proxy_enabled,
            "tunEnabled": settings.tun_enabled,
            "coreInstalled": core_mgr.is_installed(),
            "coreVersion": core_mgr.detect_version(),
            "coreRunning": core_status.as_ref().map(|c| c.running).unwrap_or(false),
            "appProxyRunning": app_status.as_ref().map(|a| a.running).unwrap_or(false),
            "serviceMode": settings.service_mode,
            "serviceInstalled": os_service.installed,
            "serviceRunning": os_service.running,
            "serviceConnected": svc_connected,
            "nodeCount": nodes.len(),
            "routeRuleCount": rules.len(),
            "appRuleCount": app_rules.len(),
            "enabledAppRuleCount": app_rules.iter().filter(|r| r.enabled).count(),
        }))
    }

    async fn offline_toggle_core(&self, enabled: bool) -> Result<Value> {
        if !enabled {
            if let Some(resp) = self.try_service(ServiceCommand::StopCore).await {
                if resp.ok {
                    return Ok(json!({
                        "ok": true,
                        "controlMode": "offline",
                        "coreRunning": false,
                        "message": resp.message
                    }));
                }
            }
            return Ok(json!({
                "ok": true,
                "controlMode": "offline",
                "coreRunning": false,
                "message": "GUI is closed and no proxy core was running"
            }));
        }

        bail!(
            "GUI_NOT_RUNNING: Bypax GUI must be open to start the proxy core. \
             Launch Bypax first so proxy lifecycle stays bound to the GUI."
        );
    }

    fn offline_set_mode(&self, mode_raw: &str) -> Result<Value> {
        let mode = parse_route_mode(mode_raw)?;
        let store = self.open_store()?;
        let mut settings = store.load_settings()?;
        settings.route_mode = mode;
        store.save_settings(&settings)?;
        Ok(json!({
            "ok": true,
            "controlMode": "offline",
            "routeMode": mode.as_str(),
            "persisted": true
        }))
    }

    fn offline_toggle_system_proxy(&self, enabled: bool) -> Result<Value> {
        if enabled {
            bail!(
                "GUI_NOT_RUNNING: Refusing to enable OS system proxy while Bypax GUI is closed \
                 because the local proxy core is not running. Launch Bypax first."
            );
        }
        let store = self.open_store()?;
        let mut settings = store.load_settings()?;
        settings.system_proxy_enabled = false;
        store.save_settings(&settings)?;
        let guard = NetGuard::new(&self.paths.runtime_dir);
        guard.disable_system_proxy()?;
        Ok(json!({
            "ok": true,
            "controlMode": "offline",
            "systemProxyEnabled": false,
            "mixedPort": settings.mixed_port,
            "netguardArmed": guard.is_armed()
        }))
    }

    async fn offline_toggle_tun(&self, enabled: bool) -> Result<Value> {
        let target_mode = if enabled { "tun" } else { "off" };
        self.offline_set_capture_mode(target_mode).await
    }

    async fn offline_app_toggle(&self, enabled: bool) -> Result<Value> {
        let target_mode = if enabled { "apps" } else { "off" };
        self.offline_set_capture_mode(target_mode).await
    }

    async fn offline_set_capture_mode(&self, raw: &str) -> Result<Value> {
        let mode = CaptureMode::parse(raw)
            .ok_or_else(|| anyhow!("Invalid capture mode '{raw}': expected off, apps, or tun"))?;
        if mode != CaptureMode::Off {
            bail!(
                "GUI_NOT_RUNNING: Launch Bypax GUI to activate {} capture. \
                 Live proxy and per-app capture are strictly bound to the GUI lifecycle.",
                mode.as_str()
            );
        }
        let store = self.open_store()?;
        let mut settings = store.load_settings()?;
        settings.app_proxy_enabled = false;
        settings.tun_enabled = false;
        store.save_settings(&settings)?;

        let mut service_synced = false;
        if let Some(r) = self.try_service(ServiceCommand::StopAppProxy).await {
            service_synced |= r.ok;
        }
        if let Some(r) = self.try_service(ServiceCommand::StopCore).await {
            service_synced |= r.ok;
        }

        Ok(json!({
            "ok": true,
            "controlMode": "offline",
            "captureMode": "off",
            "appProxyEnabled": false,
            "tunEnabled": false,
            "serviceSynced": service_synced
        }))
    }

    fn offline_list_nodes(
        &self,
        group: Option<String>,
        region: Option<String>,
        query: Option<String>,
    ) -> Result<Value> {
        let store = self.open_store()?;
        let settings = store.load_settings()?;
        let group_f = group.map(|s| s.trim().to_ascii_lowercase());
        let region_f = region.map(|s| s.trim().to_ascii_uppercase());
        let query_f = query.map(|s| s.trim().to_ascii_lowercase());

        let nodes: Vec<NodeIR> = store
            .list_nodes()?
            .into_iter()
            .filter(|n| {
                if let Some(ref g) = group_f {
                    if !g.is_empty() && !n.group.to_ascii_lowercase().contains(g) {
                        return false;
                    }
                }
                if let Some(ref r) = region_f {
                    if !r.is_empty() && !n.region.eq_ignore_ascii_case(r) {
                        return false;
                    }
                }
                if let Some(ref q) = query_f {
                    if !q.is_empty()
                        && !n.remark.to_ascii_lowercase().contains(q)
                        && !n.server.to_ascii_lowercase().contains(q)
                        && !n.id.to_ascii_lowercase().contains(q)
                    {
                        return false;
                    }
                }
                true
            })
            .collect();

        Ok(json!({
            "controlMode": "offline",
            "mainNodeId": settings.main_node_id,
            "total": nodes.len(),
            "nodes": nodes
        }))
    }

    fn offline_select_node(&self, node_id: &str) -> Result<Value> {
        let store = self.open_store()?;
        let remark = if let Some(cid) = node_id.strip_prefix("chain:") {
            let chains = store.list_proxy_chains()?;
            let matched = chains
                .iter()
                .find(|c| c.id == cid)
                .ok_or_else(|| anyhow!("Proxy chain '{}' not found", cid))?;
            matched.name.clone()
        } else {
            let nodes = store.list_nodes()?;
            let matched = nodes
                .iter()
                .find(|n| n.id == node_id)
                .ok_or_else(|| anyhow!("Node '{}' not found", node_id))?;
            matched.remark.clone()
        };
        let mut settings = store.load_settings()?;
        settings.main_node_id = Some(node_id.to_string());
        store.save_settings(&settings)?;
        Ok(json!({
            "ok": true,
            "controlMode": "offline",
            "hotSwitched": false,
            "mainNodeId": node_id,
            "remark": remark
        }))
    }

    async fn offline_test_latency(&self, node_ids: Vec<String>, _kind: &str) -> Result<Value> {
        let store = self.open_store()?;
        let settings = store.load_settings()?;
        let all = store.list_nodes()?;
        let targets: Vec<NodeIR> = if node_ids.is_empty() {
            all.clone()
        } else {
            all.iter()
                .filter(|n| node_ids.contains(&n.id))
                .cloned()
                .collect()
        };

        let core_mgr = CoreManager::new(self.paths.core_dir.clone());
        let bin = core_mgr
            .resolve_binary_path()
            .ok_or_else(|| anyhow!("CORE_NOT_INSTALLED"))?;
        let results = batch_real_delay_with_progress(
            &bin,
            &targets,
            &all,
            &settings.latency_test_url,
            4500,
            12,
            Some(&settings.dns_local_server),
            settings.latency_strip_handshake,
            |_| {},
        )
        .await?;

        for r in &results {
            let _ = store.record_latency_result(r);
        }

        Ok(json!({
            "controlMode": "offline",
            "kind": "real_delay",
            "total": results.len(),
            "results": results
        }))
    }

    async fn offline_refresh_subscriptions(&self, subscription_id: Option<String>) -> Result<Value> {
        let mut store = self.open_store()?;
        let subs = store.list_subscriptions()?;
        let targets: Vec<_> = match subscription_id {
            Some(ref id) if !id.trim().is_empty() => subs
                .into_iter()
                .filter(|s| s.id == id.trim() || s.name.eq_ignore_ascii_case(id.trim()))
                .collect(),
            _ => subs,
        };

        let mut updated_list = Vec::new();
        let mut errors = Vec::new();

        for sub in targets {
            match fetch_text_via_channels(
                &sub.url,
                None,
                Some(&format!("Bypax/{}", env!("CARGO_PKG_VERSION"))),
                None,
                20,
            )
            .await
            {
                Ok((body, via)) => match parse_payload(&body, &sub.name) {
                    Ok(summary) => {
                        let mut next = sub.clone();
                        next.last_updated = Some(chrono::Utc::now().to_rfc3339());
                        next.node_count = summary.nodes.len();
                        store.replace_group_nodes(&next.name, &summary.nodes)?;
                        store.upsert_subscription(&next)?;
                        updated_list.push(json!({
                            "id": next.id,
                            "name": next.name,
                            "nodeCount": next.node_count,
                            "via": via
                        }));
                    }
                    Err(e) => errors.push(format!("{}: {}", sub.name, e)),
                },
                Err(e) => errors.push(format!("{}: {}", sub.name, e)),
            }
        }

        Ok(json!({
            "controlMode": "offline",
            "refreshed": updated_list,
            "errors": errors
        }))
    }

    fn offline_list_route_rules(&self) -> Result<Value> {
        let store = self.open_store()?;
        let rules = store.list_rules()?;
        Ok(json!({
            "controlMode": "offline",
            "total": rules.len(),
            "rules": rules
        }))
    }

    fn offline_test_route(&self, input: &str, process_name: Option<String>) -> Result<Value> {
        let store = self.open_store()?;
        let settings = store.load_settings()?;
        let rules = store.list_rules()?;
        let nodes = store.list_nodes()?;
        let chains = store.list_proxy_chains()?;
        let rule_cache = RuleCache::new(self.paths.rule_sets_dir.clone());
        let core_mgr = CoreManager::new(self.paths.core_dir.clone());
        let bin = core_mgr.resolve_binary_path();
        let res = evaluate_route_target(
            input,
            process_name.as_deref(),
            &settings,
            &rules,
            &nodes,
            &chains,
            Some(&rule_cache),
            bin.as_deref(),
        );
        Ok(serde_json::to_value(res)?)
    }

    async fn offline_list_connections(
        &self,
        source: Option<String>,
        query: Option<String>,
    ) -> Result<Value> {
        let mut connections = Vec::new();
        if let Some(resp) = self.try_service(ServiceCommand::AppProxyStatus).await {
            if let Some(status) = resp.app_proxy_status {
                let src_f = source.as_deref().map(|s| s.trim().to_ascii_lowercase());
                let q_f = query.as_deref().map(|s| s.trim().to_ascii_lowercase());
                for conn in status.stats.local_connections {
                    if let Some(ref sf) = src_f {
                        if !sf.is_empty() && sf != "app_proxy" && sf != "all" {
                            continue;
                        }
                    }
                    if let Some(ref qf) = q_f {
                        if !qf.is_empty()
                            && !conn.process_name.to_ascii_lowercase().contains(qf)
                            && !conn.destination.to_ascii_lowercase().contains(qf)
                            && !conn.rule_name.to_ascii_lowercase().contains(qf)
                        {
                            continue;
                        }
                    }
                    connections.push(conn);
                }
            }
        }
        Ok(json!({
            "controlMode": "offline",
            "coreRunning": false,
            "total": connections.len(),
            "connections": connections
        }))
    }

    fn offline_get_logs(&self, _level: Option<String>, _limit: Option<usize>) -> Result<Value> {
        Ok(json!({
            "controlMode": "offline",
            "logs": [],
            "note": "Bypax GUI is closed; live log ring buffer is hosted in the GUI process"
        }))
    }

    async fn offline_doctor(&self) -> Result<Value> {
        let store = self.open_store()?;
        let settings = store.load_settings()?;
        let nodes = store.list_nodes()?;
        let subs = store.list_subscriptions()?;
        let rules = store.list_rules()?;
        let app_rules = store.list_app_proxy_rules()?;

        let core_mgr = CoreManager::new(self.paths.core_dir.clone());
        let netguard = NetGuard::new(&self.paths.runtime_dir);
        let os_svc = query_os_service_status();

        let svc_ping = self.try_service(ServiceCommand::Ping).await;
        let svc_connected = svc_ping.as_ref().map(|r| r.ok).unwrap_or(false);
        let wd_override = settings
            .app_proxy_windivert_dir
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(std::path::Path::new);
        let driver: DriverProbeDto = if svc_connected {
            self.try_service(ServiceCommand::ProbeDriver {
                windivert_dir: settings.app_proxy_windivert_dir.clone(),
            })
            .await
            .and_then(|r| r.driver)
            .unwrap_or_else(|| probe_windivert(wd_override).to_dto())
        } else {
            probe_windivert(wd_override).to_dto()
        };

        Ok(json!({
            "controlMode": "offline",
            "platform": std::env::consts::OS,
            "appVersion": env!("CARGO_PKG_VERSION"),
            "guiConnected": false,
            "ctlEndpoint": self.ctl_endpoint,
            "svcEndpoint": self.svc_endpoint,
            "storage": {
                "portableMode": self.paths.portable_mode,
                "dataDir": self.paths.root_dir.to_string_lossy(),
                "dbPath": self.paths.db_path.to_string_lossy(),
                "walEnabled": true
            },
            "core": {
                "installed": core_mgr.is_installed(),
                "version": core_mgr.detect_version(),
                "binaryPath": core_mgr
                    .resolve_binary_path()
                    .unwrap_or_else(|| core_mgr.binary_path())
                    .to_string_lossy()
            },
            "service": {
                "name": os_svc.service_name,
                "mode": settings.service_mode,
                "installed": os_svc.installed,
                "running": os_svc.running,
                "state": os_svc.state,
                "legacyServices": os_svc.legacy_services,
                "plane1Connected": svc_connected,
                "servicePid": svc_ping.as_ref().and_then(|r| r.service_pid),
                "elevated": svc_ping.as_ref().and_then(|r| r.elevated).unwrap_or(false)
            },
            "driver": driver,
            "netguard": {
                "armed": netguard.is_armed(),
                "snapshotPath": netguard.snapshot_path().to_string_lossy()
            },
            "counts": {
                "nodes": nodes.len(),
                "subscriptions": subs.len(),
                "routeRules": rules.len(),
                "appRules": app_rules.len()
            }
        }))
    }

    fn offline_app_list_rules(&self) -> Result<Value> {
        let store = self.open_store()?;
        let rules = store.list_app_proxy_rules()?;
        Ok(json!({
            "controlMode": "offline",
            "total": rules.len(),
            "rules": rules
        }))
    }

    fn offline_app_upsert_rule(&self, wire: AppProxyRuleWire) -> Result<Value> {
        let store = self.open_store()?;
        let mut rule: AppProxyRule = wire.into();
        if rule.name.trim().is_empty() {
            bail!("App proxy rule name cannot be empty");
        }
        let existing = store.list_app_proxy_rules()?;
        if rule.id.trim().is_empty() {
            if let Some(found) = existing
                .iter()
                .find(|r| r.name.eq_ignore_ascii_case(rule.name.trim()))
            {
                rule.id = found.id.clone();
            } else {
                rule.id = format!(
                    "app-{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..8]
                );
            }
        }
        if rule.priority == 0 {
            let max_prio = existing.iter().map(|r| r.priority).max().unwrap_or(0);
            rule.priority = max_prio + 10;
        }
        if rule.target.trim().is_empty() {
            rule.target = "follow".to_string();
        }
        store.upsert_app_proxy_rule(&rule)?;
        let all = store.list_app_proxy_rules()?;
        Ok(json!({
            "ok": true,
            "controlMode": "offline",
            "rule": rule,
            "totalRules": all.len()
        }))
    }

    fn offline_app_delete_rule(&self, selector: &str) -> Result<Value> {
        let store = self.open_store()?;
        let trimmed = selector.trim();
        let rules = store.list_app_proxy_rules()?;
        let target_id = if rules.iter().any(|r| r.id == trimmed) {
            trimmed.to_string()
        } else if let Some(found) = rules.iter().find(|r| r.name.eq_ignore_ascii_case(trimmed)) {
            found.id.clone()
        } else {
            bail!("App proxy rule '{}' not found", trimmed);
        };
        let deleted = store.delete_app_proxy_rule(&target_id)?;
        let remaining = store.list_app_proxy_rules()?.len();
        Ok(json!({
            "ok": deleted,
            "controlMode": "offline",
            "deletedId": target_id,
            "remainingRules": remaining
        }))
    }

    fn offline_app_test_rule(
        &self,
        process_name: Option<String>,
        exe_path: Option<String>,
        host: Option<String>,
        dst_ip: Option<String>,
        dst_port: u16,
        protocol: String,
    ) -> Result<Value> {
        let store = self.open_store()?;
        let rules = store.list_app_proxy_rules()?;
        let settings = store.load_settings()?;
        let nodes = store.list_nodes()?;
        let chains = store.list_proxy_chains()?;
        let query = AppRuleTestQuery {
            process_name,
            exe_path,
            ancestor_name: None,
            ancestor_path: None,
            host,
            dst_ip,
            dst_port,
            protocol,
        };
        let trace = RuleEngine::dry_run_trace(
            &rules,
            &query,
            &nodes,
            &chains,
            settings.main_node_id.as_deref(),
            settings.app_proxy_bypass_lan,
        );
        Ok(serde_json::to_value(trace)?)
    }

    async fn offline_list_processes(&self, filter: Option<String>) -> Result<Value> {
        if let Some(resp) = self
            .try_service(ServiceCommand::ListProcesses {
                filter: filter.clone(),
            })
            .await
        {
            if resp.ok {
                let procs = resp.processes.unwrap_or_default();
                return Ok(json!({
                    "controlMode": "offline",
                    "source": "bypax-service",
                    "total": procs.len(),
                    "processes": procs
                }));
            }
        }

        let (rules, nodes, chains, bypass_lan) = self
            .open_store()
            .and_then(|s| {
                let st = s.load_settings()?;
                Ok((
                    s.list_app_proxy_rules()?,
                    s.list_nodes()?,
                    s.list_proxy_chains()?,
                    st.app_proxy_bypass_lan,
                ))
            })
            .unwrap_or_else(|_| (Vec::new(), Vec::new(), Vec::new(), true));

        let bindings = build_app_proxy_target_bindings(&rules, &nodes, &chains);
        let engine = RuleEngine::from_rules(&rules, &bindings, bypass_lan, &[]).ok();
        let tracker = SnapshotProcessTracker::new(Duration::from_millis(500));

        let needle = filter
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());

        let mut procs = Vec::new();
        for p in tracker.list_processes() {
            if let Some(ref q) = needle {
                let name_hit = p.name.to_ascii_lowercase().contains(q);
                let path_hit = p
                    .exe_path
                    .as_deref()
                    .map(|s| s.to_ascii_lowercase().contains(q))
                    .unwrap_or(false);
                if !name_hit && !path_hit {
                    continue;
                }
            }
            let chain: Vec<String> = tracker
                .ancestor_chain(p.pid)
                .into_iter()
                .skip(1)
                .map(|a| a.name)
                .collect();
            let matched = engine
                .as_ref()
                .and_then(|e| e.match_process_rule(p.pid, &tracker));
            procs.push(ProcessInfoDto {
                pid: p.pid,
                parent_pid: p.parent_pid,
                name: p.name,
                exe_path: p.exe_path,
                ancestor_chain: chain,
                matched_rule_id: matched.as_ref().map(|(id, _)| id.clone()),
                matched_rule_name: matched.map(|(_, name)| name),
            });
        }
        procs.sort_by_key(|p| p.pid);

        Ok(json!({
            "controlMode": "offline",
            "source": "local",
            "total": procs.len(),
            "processes": procs
        }))
    }
}

pub fn parse_route_mode(raw: &str) -> Result<RouteMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "rule" => Ok(RouteMode::Rule),
        "global" => Ok(RouteMode::Global),
        "direct" => Ok(RouteMode::Direct),
        other => bail!("Invalid route mode '{other}': expected rule, global, or direct"),
    }
}

/// Machine-readable capability manifest and schema for AI Agents (`bypax-cli ctl schema`).
pub fn capability_schema() -> Value {
    json!({
        "name": "bypax-cli",
        "version": env!("CARGO_PKG_VERSION"),
        "mcpProtocolVersion": "2024-11-05",
        "mcpServerName": "bypax-mcp",
        "ipc": {
            "plane1Service": bypax_ipc::default_svc_endpoint(),
            "plane2Control": {
                "windows": bypax_ipc::WINDOWS_CTL_PIPE_NAME,
                "unixSocketName": bypax_ipc::UNIX_CTL_SOCKET_NAME
            }
        },
        "interfaces": {
            "cliJson": "bypax-cli ctl --json <subcommand>",
            "mcpStdio": "bypax-cli mcp"
        },
        "cliCommands": [
            "ctl --json status",
            "ctl --json core start|stop",
            "ctl --json mode rule|global|direct",
            "ctl --json sys-proxy on|off",
            "ctl --json tun on|off",
            "ctl --json capture off|apps|tun",
            "ctl --json node list [--group <g>] [--region <r>] [--query <q>]",
            "ctl --json node select <node_id>",
            "ctl --json node test [--kind real] [--node-id <id>...]",
            "ctl --json sub refresh [--id <subscription_id>]",
            "ctl --json route list",
            "ctl --json route test --target <host_or_url> [--process <name>]",
            "ctl --json connections [--source <kind>] [--query <text>]",
            "ctl --json logs [--level INFO|WARN|ERROR] [--limit <n>]",
            "ctl --json doctor",
            "ctl --json app toggle on|off",
            "ctl --json app list-rules",
            "ctl --json app upsert-rule --name <name> [--target <target>] ...",
            "ctl --json app delete-rule <id_or_name>",
            "ctl --json app test [--process <name>] [--path <exe>] [--host <host>] [--port 443]",
            "ctl --json ps [--filter <text>]",
            "ctl schema",
            "mcp",
            "doctor [--json]",
            "ps [--filter <text>] [--json]",
            "service install|uninstall|cleanup|start|stop|status [--json]"
        ],
        "mcpTools": [
            "bypax_status",
            "bypax_toggle_core",
            "bypax_set_mode",
            "bypax_toggle_system_proxy",
            "bypax_toggle_tun",
            "bypax_list_nodes",
            "bypax_select_node",
            "bypax_test_latency",
            "bypax_refresh_subscriptions",
            "bypax_list_route_rules",
            "bypax_test_route",
            "bypax_list_connections",
            "bypax_get_logs",
            "bypax_doctor",
            "bypax_app_toggle",
            "bypax_app_list_rules",
            "bypax_app_upsert_rule",
            "bypax_app_delete_rule",
            "bypax_app_test_rule",
            "bypax_list_processes"
        ]
    })
}
