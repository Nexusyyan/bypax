use crate::state::AppState;
use crate::tray;
use bypax_appproxy::{AppRuleTestQuery, ProcessTracker, RuleEngine};
use bypax_core::control::ControlClient;
use bypax_core::model::{AppProxyRule, CaptureMode, NodeIR, RouteMode};
use bypax_core::parser::parse_payload;
use bypax_core::route_eval::evaluate_route_target;
use bypax_core::tester::{batch_real_delay_with_progress, batch_tcping_with_progress};
use bypax_core::updater::{fetch_text_via_channels, CURRENT_APP_VERSION};
use bypax_ipc::{
    default_ctl_endpoint, CtlEnvelope, CtlHandler, CtlIpcServer, CtlRequest, CtlResponse,
    ProcessInfoDto,
};
use serde_json::{json, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::oneshot;

struct GuiCtlHandler {
    app: AppHandle,
}

fn emit_state_sync(app: &AppHandle) {
    let _ = app.emit("bypax-state-sync", ());
}

fn refresh_tray_status(app: &AppHandle, state: &AppState) {
    let sys_proxy = state
        .netguard
        .lock()
        .map(|g| g.is_armed())
        .unwrap_or(false);
    let capture = state.current_capture_mode();
    let active = sys_proxy || capture != CaptureMode::Off;
    let warn = state
        .last_service_error
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|_| true))
        .unwrap_or(false);
    tray::update_tray_icon_state(app, active, warn);
}

fn parse_route_mode(raw: &str) -> Result<RouteMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "rule" => Ok(RouteMode::Rule),
        "global" => Ok(RouteMode::Global),
        "direct" => Ok(RouteMode::Direct),
        other => Err(format!(
            "Invalid route mode '{}': expected rule, global, or direct",
            other
        )),
    }
}

fn log_level_rank(level: &str) -> u8 {
    match level.trim().to_ascii_uppercase().as_str() {
        "ERROR" => 3,
        "WARN" | "WARNING" => 2,
        "INFO" => 1,
        _ => 0,
    }
}

impl CtlHandler for GuiCtlHandler {
    fn handle(
        &self,
        envelope: CtlEnvelope,
    ) -> Pin<Box<dyn Future<Output = CtlResponse> + Send + '_>> {
        Box::pin(async move {
            let id = envelope.id;
            let Some(state) = self.app.try_state::<AppState>() else {
                return CtlResponse::error(id, "Bypax GUI state is not initialized");
            };

            match dispatch_ctl_request(&self.app, &state, envelope.request).await {
                Ok((data, mutated)) => {
                    if mutated {
                        refresh_tray_status(&self.app, &state);
                        emit_state_sync(&self.app);
                    }
                    CtlResponse::success(id, "ok", Some(data))
                }
                Err(err) => CtlResponse::error(id, err),
            }
        })
    }
}

async fn dispatch_ctl_request(
    app: &AppHandle,
    state: &AppState,
    req: CtlRequest,
) -> Result<(Value, bool), String> {
    match req {
        CtlRequest::Status => {
            let (settings, node_count, rule_count, app_rules) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                (
                    store.load_settings().map_err(|e| e.to_string())?,
                    store.list_nodes().map_err(|e| e.to_string())?.len(),
                    store.list_rules().map_err(|e| e.to_string())?.len(),
                    store.list_app_proxy_rules().map_err(|e| e.to_string())?,
                )
            };
            let core_info = state.build_core_info();
            let service_status = state.query_service_status().await;
            let app_proxy_status = state.query_app_proxy_status().await;
            let capture_mode = state.current_capture_mode();

            Ok((
                json!({
                    "controlMode": "live",
                    "appVersion": CURRENT_APP_VERSION,
                    "platform": state.platform_name(),
                    "portableMode": state.paths.portable_mode,
                    "dataDir": state.paths.root_dir.to_string_lossy(),
                    "routeMode": settings.route_mode.as_str(),
                    "captureMode": capture_mode.as_str(),
                    "mainNodeId": settings.main_node_id,
                    "mixedPort": settings.mixed_port,
                    "controlPort": settings.control_port,
                    "systemProxyEnabled": settings.system_proxy_enabled,
                    "netguardArmed": core_info.netguard_armed,
                    "appProxyEnabled": settings.app_proxy_enabled,
                    "tunEnabled": settings.tun_enabled,
                    "coreInstalled": core_info.installed,
                    "coreVersion": core_info.version,
                    "coreRunning": core_info.running,
                    "appProxyRunning": app_proxy_status.as_ref().map(|s| s.running).unwrap_or(false),
                    "serviceStatus": service_status,
                    "nodeCount": node_count,
                    "routeRuleCount": rule_count,
                    "appRuleCount": app_rules.len(),
                    "enabledAppRuleCount": app_rules.iter().filter(|r| r.enabled).count(),
                }),
                false,
            ))
        }

        CtlRequest::ToggleCore { enabled } => {
            if enabled {
                let (core_info, report) = state.start_core_flow().await?;
                Ok((
                    json!({
                        "controlMode": "live",
                        "ok": report.ok,
                        "coreInfo": core_info,
                        "preflight": report
                    }),
                    true,
                ))
            } else {
                let core_info = state.stop_core_flow().await;
                Ok((
                    json!({
                        "controlMode": "live",
                        "ok": true,
                        "coreInfo": core_info
                    }),
                    true,
                ))
            }
        }

        CtlRequest::SetMode { mode } => {
            let parsed = parse_route_mode(&mode)?;
            let control_port = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let mut settings = store.load_settings().map_err(|e| e.to_string())?;
                settings.route_mode = parsed;
                store.save_settings(&settings).map_err(|e| e.to_string())?;
                settings.control_port
            };

            let mut hot_switched = false;
            if state.is_core_running() {
                if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
                    if client.set_mode(parsed.as_str()).await.is_ok() {
                        hot_switched = true;
                        let _ = client.close_all_connections().await;
                    }
                }
                if !hot_switched {
                    let _ = state.reload_core_if_running_async().await?;
                }
            }
            state.push_log(
                "INFO",
                format!(
                    "ctl: route mode switched -> {} (hot={})",
                    parsed.as_str(),
                    hot_switched
                ),
            );
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "routeMode": parsed.as_str(),
                    "hotSwitched": hot_switched
                }),
                true,
            ))
        }

        CtlRequest::ToggleSystemProxy { enabled } => {
            let mixed_port = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let mut settings = store.load_settings().map_err(|e| e.to_string())?;
                settings.system_proxy_enabled = enabled;
                store.save_settings(&settings).map_err(|e| e.to_string())?;
                settings.mixed_port
            };
            {
                let guard = state
                    .netguard
                    .lock()
                    .map_err(|_| "netguard lock poisoned".to_string())?;
                if enabled {
                    guard
                        .enable_system_proxy("127.0.0.1", mixed_port)
                        .map_err(|e| e.to_string())?;
                } else {
                    guard.disable_system_proxy().map_err(|e| e.to_string())?;
                }
            }
            state.push_log(
                "INFO",
                format!("ctl: system proxy -> {}", if enabled { "ON" } else { "OFF" }),
            );
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "systemProxyEnabled": enabled,
                    "coreInfo": state.build_core_info()
                }),
                true,
            ))
        }

        CtlRequest::ToggleTun { enabled } => {
            let target = if enabled {
                CaptureMode::Tun
            } else {
                CaptureMode::Off
            };
            let res = state.apply_capture_mode(target).await?;
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "captureMode": res.capture_mode,
                    "coreInfo": res.core_info,
                    "serviceStatus": res.service_status
                }),
                true,
            ))
        }

        CtlRequest::SetCaptureMode { mode } => {
            let parsed = CaptureMode::parse(&mode).ok_or_else(|| {
                format!("Invalid capture mode '{}': expected off, apps, or tun", mode)
            })?;
            let res = state.apply_capture_mode(parsed).await?;
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "captureMode": res.capture_mode,
                    "coreInfo": res.core_info,
                    "serviceStatus": res.service_status,
                    "appProxyStatus": res.app_proxy_status
                }),
                true,
            ))
        }

        CtlRequest::ListNodes {
            group,
            region,
            query,
        } => {
            let (main_id, all_nodes) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let s = store.load_settings().map_err(|e| e.to_string())?;
                let n = store.list_nodes().map_err(|e| e.to_string())?;
                (s.main_node_id, n)
            };
            let group_f = group.map(|s| s.trim().to_ascii_lowercase());
            let region_f = region.map(|s| s.trim().to_ascii_uppercase());
            let query_f = query.map(|s| s.trim().to_ascii_lowercase());

            let nodes: Vec<NodeIR> = all_nodes
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

            Ok((
                json!({
                    "controlMode": "live",
                    "mainNodeId": main_id,
                    "total": nodes.len(),
                    "nodes": nodes
                }),
                false,
            ))
        }

        CtlRequest::SelectNode { node_id } => {
            let (control_port, remark) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let nodes = store.list_nodes().map_err(|e| e.to_string())?;
                let found = nodes
                    .iter()
                    .find(|n| n.id == node_id)
                    .ok_or_else(|| format!("Node '{}' not found", node_id))?;
                let remark = found.remark.clone();
                let mut settings = store.load_settings().map_err(|e| e.to_string())?;
                settings.main_node_id = Some(node_id.clone());
                store.save_settings(&settings).map_err(|e| e.to_string())?;
                (settings.control_port, remark)
            };

            let mut hot_switched = false;
            if state.is_core_running() {
                if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
                    if client.select_proxy("main-exit", &node_id).await.is_ok() {
                        hot_switched = true;
                    }
                }
                if !hot_switched {
                    let _ = state.reload_core_if_running_async().await;
                }
            }
            state.push_log(
                "INFO",
                format!(
                    "ctl: selected main-exit -> {} ({}, hot={})",
                    node_id, remark, hot_switched
                ),
            );
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "hotSwitched": hot_switched,
                    "mainNodeId": node_id,
                    "remark": remark
                }),
                true,
            ))
        }

        CtlRequest::TestLatency { node_ids, kind } => {
            let (targets, test_url, local_dns, strip_handshake) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let settings = store.load_settings().map_err(|e| e.to_string())?;
                let all = store.list_nodes().map_err(|e| e.to_string())?;
                let list = if node_ids.is_empty() {
                    all
                } else {
                    all.into_iter()
                        .filter(|n| node_ids.contains(&n.id))
                        .collect()
                };
                (
                    list,
                    settings.latency_test_url,
                    settings.dns_local_server,
                    settings.latency_strip_handshake,
                )
            };

            let norm_kind = kind.trim().to_ascii_lowercase();
            let is_real = norm_kind == "real" || norm_kind == "real_delay";
            let emit_handle = app.clone();
            let results = if is_real {
                let bin = state.require_core_binary()?;
                batch_real_delay_with_progress(
                    &bin,
                    &targets,
                    &test_url,
                    4500,
                    12,
                    Some(&local_dns),
                    strip_handshake,
                    move |ev| {
                        let _ = emit_handle.emit("bypax-latency-progress", ev);
                    },
                )
                .await
                .map_err(|e| e.to_string())?
            } else {
                batch_tcping_with_progress(&targets, 2500, 16, move |ev| {
                    let _ = emit_handle.emit("bypax-latency-progress", ev);
                })
                .await
            };

            if let Ok(store) = state.store.lock() {
                for r in &results {
                    if is_real {
                        let _ = store.update_node_latency(&r.node_id, None, r.delay_ms);
                    } else {
                        let _ = store.update_node_latency(&r.node_id, r.delay_ms, None);
                    }
                }
            }

            Ok((
                json!({
                    "controlMode": "live",
                    "kind": if is_real { "real_delay" } else { "tcping" },
                    "total": results.len(),
                    "results": results
                }),
                true,
            ))
        }

        CtlRequest::RefreshSubscriptions { subscription_id } => {
            let subs = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                store.list_subscriptions().map_err(|e| e.to_string())?
            };
            let targets: Vec<_> = match subscription_id {
                Some(ref id) if !id.trim().is_empty() => subs
                    .into_iter()
                    .filter(|s| s.id == id.trim() || s.name.eq_ignore_ascii_case(id.trim()))
                    .collect(),
                _ => subs,
            };

            let proxy_port = state.active_local_proxy_port();
            let mut refreshed = Vec::new();
            let mut errors = Vec::new();
            for sub in targets {
                match fetch_text_via_channels(
                    &sub.url,
                    proxy_port,
                    Some(&format!("Bypax/{}", CURRENT_APP_VERSION)),
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
                            if let Ok(mut store) = state.store.lock() {
                                if store
                                    .replace_group_nodes(&next.name, &summary.nodes)
                                    .is_ok()
                                    && store.upsert_subscription(&next).is_ok()
                                {
                                    refreshed.push(json!({
                                        "id": next.id,
                                        "name": next.name,
                                        "nodeCount": next.node_count,
                                        "via": via
                                    }));
                                }
                            }
                        }
                        Err(e) => errors.push(format!("{}: {}", sub.name, e)),
                    },
                    Err(e) => errors.push(format!("{}: {}", sub.name, e)),
                }
            }
            let mutated = !refreshed.is_empty();
            if mutated {
                let _ = state.reload_core_if_running_async().await;
            }
            Ok((
                json!({
                    "controlMode": "live",
                    "refreshed": refreshed,
                    "errors": errors
                }),
                mutated,
            ))
        }

        CtlRequest::ListRouteRules => {
            let store = state
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            let rules = store.list_rules().map_err(|e| e.to_string())?;
            Ok((
                json!({
                    "controlMode": "live",
                    "total": rules.len(),
                    "rules": rules
                }),
                false,
            ))
        }

        CtlRequest::TestRoute {
            input,
            process_name,
        } => {
            let (settings, rules, nodes) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                (
                    store.load_settings().map_err(|e| e.to_string())?,
                    store.list_rules().map_err(|e| e.to_string())?,
                    store.list_nodes().map_err(|e| e.to_string())?,
                )
            };
            let sb = state.core_manager.resolve_binary_path();
            let res = evaluate_route_target(
                &input,
                process_name.as_deref(),
                &settings,
                &rules,
                &nodes,
                Some(&state.rule_cache),
                sb.as_deref(),
            );
            Ok((
                serde_json::to_value(res).map_err(|e| e.to_string())?,
                false,
            ))
        }

        CtlRequest::ListConnections { source, query } => {
            let running = state.is_core_running();
            let control_port = state
                .store
                .lock()
                .ok()
                .and_then(|s| s.load_settings().ok())
                .map(|s| s.control_port)
                .unwrap_or(9090);

            let mut conns = Vec::new();
            if running {
                if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
                    if let Ok((live, _, _, _)) = client.get_connections().await {
                        conns = live;
                    }
                }
            }
            let (_app_st, local_direct_bytes, local_reject_count) =
                state.enrich_connections_with_origins(&mut conns).await;

            let src_f = source.as_deref().map(|s| s.trim().to_ascii_lowercase());
            let q_f = query.as_deref().map(|s| s.trim().to_ascii_lowercase());
            conns.retain(|c| {
                if let Some(ref sf) = src_f {
                    if !sf.is_empty() && sf != "all" && !c.source_kind.eq_ignore_ascii_case(sf) {
                        return false;
                    }
                }
                if let Some(ref qf) = q_f {
                    if !qf.is_empty() {
                        let hit = c.process.to_ascii_lowercase().contains(qf)
                            || c.destination.to_ascii_lowercase().contains(qf)
                            || c.rule.to_ascii_lowercase().contains(qf)
                            || c.ancestor_app
                                .as_deref()
                                .map(|a| a.to_ascii_lowercase().contains(qf))
                                .unwrap_or(false);
                        if !hit {
                            return false;
                        }
                    }
                }
                true
            });

            Ok((
                json!({
                    "controlMode": "live",
                    "coreRunning": running,
                    "total": conns.len(),
                    "localDirectBytes": local_direct_bytes,
                    "localRejectCount": local_reject_count,
                    "connections": conns
                }),
                false,
            ))
        }

        CtlRequest::GetLogs { level, limit } => {
            let min_rank = level.as_deref().map(log_level_rank).unwrap_or(0);
            let max_items = limit.unwrap_or(100).min(1000);
            let mut entries = state
                .logs
                .lock()
                .map(|l| l.snapshot())
                .unwrap_or_default();
            if min_rank > 0 {
                entries.retain(|e| log_level_rank(&e.level) >= min_rank);
            }
            if entries.len() > max_items {
                let start = entries.len() - max_items;
                entries = entries.split_off(start);
            }
            Ok((
                json!({
                    "controlMode": "live",
                    "total": entries.len(),
                    "logs": entries
                }),
                false,
            ))
        }

        CtlRequest::Doctor => {
            let (nodes, subs, route_rules, app_rules) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                (
                    store.list_nodes().map_err(|e| e.to_string())?.len(),
                    store.list_subscriptions().map_err(|e| e.to_string())?.len(),
                    store.list_rules().map_err(|e| e.to_string())?.len(),
                    store
                        .list_app_proxy_rules()
                        .map_err(|e| e.to_string())?
                        .len(),
                )
            };
            let core_info = state.build_core_info();
            let service_status = state.query_service_status().await;
            let driver = state
                .probe_windivert_with_service(None, service_status.connected)
                .await;
            let ctl_ep = default_ctl_endpoint(&state.paths.runtime_dir);

            Ok((
                json!({
                    "controlMode": "live",
                    "platform": state.platform_name(),
                    "appVersion": CURRENT_APP_VERSION,
                    "guiConnected": true,
                    "ctlEndpoint": ctl_ep,
                    "svcEndpoint": state.service_endpoint,
                    "storage": {
                        "portableMode": state.paths.portable_mode,
                        "dataDir": state.paths.root_dir.to_string_lossy(),
                        "dbPath": state.paths.db_path.to_string_lossy(),
                        "logsDir": state.paths.logs_dir.to_string_lossy(),
                        "walEnabled": true
                    },
                    "core": core_info,
                    "service": service_status,
                    "driver": driver,
                    "netguard": {
                        "armed": core_info.netguard_armed
                    },
                    "counts": {
                        "nodes": nodes,
                        "subscriptions": subs,
                        "routeRules": route_rules,
                        "appRules": app_rules
                    }
                }),
                false,
            ))
        }

        CtlRequest::AppToggle { enabled } => {
            let target = if enabled {
                CaptureMode::Apps
            } else {
                CaptureMode::Off
            };
            let res = state.apply_capture_mode(target).await?;
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "captureMode": res.capture_mode,
                    "appProxyEnabled": enabled,
                    "serviceStatus": res.service_status,
                    "appProxyStatus": res.app_proxy_status
                }),
                true,
            ))
        }

        CtlRequest::AppListRules => {
            let store = state
                .store
                .lock()
                .map_err(|_| "store lock poisoned".to_string())?;
            let rules = store.list_app_proxy_rules().map_err(|e| e.to_string())?;
            Ok((
                json!({
                    "controlMode": "live",
                    "total": rules.len(),
                    "rules": rules
                }),
                false,
            ))
        }

        CtlRequest::AppUpsertRule { rule: wire } => {
            let mut rule: AppProxyRule = wire.into();
            if rule.name.trim().is_empty() {
                return Err("App proxy rule name cannot be empty".to_string());
            }
            let total = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let existing = store.list_app_proxy_rules().map_err(|e| e.to_string())?;
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
                store
                    .upsert_app_proxy_rule(&rule)
                    .map_err(|e| e.to_string())?;
                store.list_app_proxy_rules().map_err(|e| e.to_string())?.len()
            };
            let reloaded = state.sync_app_proxy_if_running().await;
            state.push_log(
                "INFO",
                format!("ctl: upserted app rule [{}] (reloaded={})", rule.name, reloaded),
            );
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "rule": rule,
                    "totalRules": total,
                    "reloaded": reloaded
                }),
                true,
            ))
        }

        CtlRequest::AppDeleteRule { id } => {
            let trimmed = id.trim();
            let (deleted_id, remaining) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let rules = store.list_app_proxy_rules().map_err(|e| e.to_string())?;
                let target_id = if rules.iter().any(|r| r.id == trimmed) {
                    trimmed.to_string()
                } else if let Some(found) = rules
                    .iter()
                    .find(|r| r.name.eq_ignore_ascii_case(trimmed))
                {
                    found.id.clone()
                } else {
                    return Err(format!("App proxy rule '{}' not found", trimmed));
                };
                store
                    .delete_app_proxy_rule(&target_id)
                    .map_err(|e| e.to_string())?;
                let left = store.list_app_proxy_rules().map_err(|e| e.to_string())?.len();
                (target_id, left)
            };
            let reloaded = state.sync_app_proxy_if_running().await;
            state.push_log(
                "INFO",
                format!("ctl: deleted app rule [{}] (reloaded={})", deleted_id, reloaded),
            );
            Ok((
                json!({
                    "controlMode": "live",
                    "ok": true,
                    "deletedId": deleted_id,
                    "remainingRules": remaining,
                    "reloaded": reloaded
                }),
                true,
            ))
        }

        CtlRequest::AppTestRule {
            process_name,
            exe_path,
            host,
            dst_ip,
            dst_port,
            protocol,
        } => {
            let (app_rules, nodes, settings) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                (
                    store.list_app_proxy_rules().map_err(|e| e.to_string())?,
                    store.list_nodes().map_err(|e| e.to_string())?,
                    store.load_settings().map_err(|e| e.to_string())?,
                )
            };
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
                &app_rules,
                &query,
                &nodes,
                settings.main_node_id.as_deref(),
                settings.app_proxy_bypass_lan,
            );
            Ok((
                serde_json::to_value(trace).map_err(|e| e.to_string())?,
                false,
            ))
        }

        CtlRequest::ListProcesses { filter } => {
            let (app_rules, nodes, bypass_lan) = {
                let store = state
                    .store
                    .lock()
                    .map_err(|_| "store lock poisoned".to_string())?;
                let s = store.load_settings().map_err(|e| e.to_string())?;
                (
                    store.list_app_proxy_rules().map_err(|e| e.to_string())?,
                    store.list_nodes().map_err(|e| e.to_string())?,
                    s.app_proxy_bypass_lan,
                )
            };
            let bindings =
                bypax_core::compiler::build_app_proxy_target_bindings(&app_rules, &nodes);
            let engine = RuleEngine::from_rules(&app_rules, &bindings, bypass_lan, &[]).ok();

            let needle = filter
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());

            let procs = state.process_tracker.list_processes();
            let mut out = Vec::with_capacity(procs.len());
            for p in procs {
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
                let chain_names: Vec<String> = state
                    .process_tracker
                    .ancestor_chain(p.pid)
                    .into_iter()
                    .skip(1)
                    .map(|a| a.name)
                    .collect();
                let matched = engine
                    .as_ref()
                    .and_then(|e| e.match_process_rule(p.pid, state.process_tracker.as_ref()));
                out.push(ProcessInfoDto {
                    pid: p.pid,
                    parent_pid: p.parent_pid,
                    name: p.name,
                    exe_path: p.exe_path,
                    ancestor_chain: chain_names,
                    matched_rule_id: matched.as_ref().map(|(id, _)| id.clone()),
                    matched_rule_name: matched.map(|(_, name)| name),
                });
            }

            Ok((
                json!({
                    "controlMode": "live",
                    "source": "gui",
                    "total": out.len(),
                    "processes": out
                }),
                false,
            ))
        }
    }
}

/// Spawns the Plane 2 Control IPC server (`bypax-ctl-v1` / `bypax-ctl.sock` `0600`)
/// and returns a oneshot shutdown trigger for clean exit teardown.
pub fn spawn_ctl_server(app: AppHandle) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let runtime_dir = app
        .try_state::<AppState>()
        .map(|s| s.paths.runtime_dir.clone())
        .unwrap_or_else(std::env::temp_dir);
    let endpoint = default_ctl_endpoint(&runtime_dir);

    tauri::async_runtime::spawn(async move {
        let handler = Arc::new(GuiCtlHandler { app: app.clone() });
        let server = CtlIpcServer::new(endpoint.clone(), handler);
        if let Err(err) = server.run(shutdown_rx).await {
            if let Some(st) = app.try_state::<AppState>() {
                st.push_log(
                    "WARN",
                    format!("ctl-server: Plane 2 IPC listener stopped ({}): {}", endpoint, err),
                );
            }
        }
    });

    shutdown_tx
}
