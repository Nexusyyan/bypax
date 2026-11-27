use crate::state::{AppState, CaptureModeResult, CliIntegrationInfo, PrivilegedServiceStatus};
use crate::tray;
use bypax_appproxy::{
    detect_external_children as detect_ext_children_impl, detect_preset_statuses,
    list_installed_apps as list_installed_apps_impl, preset_to_rule, AppPresetStatus,
    AppRuleTestQuery, AppRuleTestTrace, ExternalChildAlert, InstalledAppItem, ProcessTracker,
    RuleEngine,
};
use bypax_core::compiler::SingBox114Compiler;
use bypax_core::control::ControlClient;
use bypax_core::core_manager::{CoreDownloadProgressEvent, CoreUpdateCheckReport};
use bypax_core::model::{
    AppProxyRule, AppSettings, CaptureMode, CompileOutput, ConnectionHistoryRecord, ConnectionItem,
    CoreInfo, InboundPort, LatencyResult, LogEntry, NodeIR, PlatformTrafficStat, PreflightReport,
    RouteMode, RouteTestResult, RulePresetSpec, SimpleRoutingRule, SubscriptionGroup,
    TrafficSample,
};
use bypax_core::parser::{parse_payload, ImportSummary};
use bypax_core::route_eval::evaluate_route_target;
use bypax_core::rule_cache::RuleSetStatus;
use bypax_core::storage::{classify_platform, extract_host, rule_preset_catalog};
use bypax_core::tester::{batch_real_delay_with_progress, batch_tcping_with_progress};
use bypax_core::updater::{
    check_for_app_update, download_and_stage_update, fetch_text_via_channels, is_safe_release_url,
    spawn_detached_update_helper, AppUpdateCheckReport, AppUpdateStage, AppUpdateState,
    UpdateApplyResult, UpdatePlan, CURRENT_APP_VERSION,
};
use bypax_ipc::{AppProxyStatusDto, DriverProbeDto, ProcessInfoDto};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapPayload {
    pub app_version: String,
    pub platform: String,
    pub capture_mode: CaptureMode,
    pub core_info: CoreInfo,
    pub settings: AppSettings,
    pub nodes: Vec<NodeIR>,
    pub subscriptions: Vec<SubscriptionGroup>,
    pub rules: Vec<SimpleRoutingRule>,
    pub app_rules: Vec<AppProxyRule>,
    pub app_presets: Vec<AppPresetStatus>,
    pub extra_ports: Vec<InboundPort>,
    pub rule_sets: Vec<RuleSetStatus>,
    pub compiled: CompileOutput,
    pub logs: Vec<LogEntry>,
    pub app_update_state: AppUpdateState,
    pub last_update_result: Option<UpdateApplyResult>,
    pub service_status: PrivilegedServiceStatus,
    pub driver_status: DriverProbeDto,
    pub app_proxy_status: Option<AppProxyStatusDto>,
    pub external_children: Vec<ExternalChildAlert>,
    pub cli_info: CliIntegrationInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveMonitorPayload {
    pub core_running: bool,
    pub connections: Vec<ConnectionItem>,
    pub traffic: TrafficSample,
    pub logs: Vec<LogEntry>,
    pub app_proxy_status: Option<AppProxyStatusDto>,
    pub local_direct_bytes: u64,
    pub local_reject_count: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRulesMutationResult {
    pub rules: Vec<AppProxyRule>,
    pub compiled: CompileOutput,
    pub reloaded: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectNodeResult {
    pub hot_switched: bool,
    pub main_node_id: String,
    pub compiled: CompileOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRuleSetsResult {
    pub statuses: Vec<RuleSetStatus>,
    pub compiled: CompileOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyStrategyResult {
    pub rules: Vec<SimpleRoutingRule>,
    pub rule_sets: Vec<RuleSetStatus>,
    pub compiled: CompileOutput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionHistoryPage {
    pub items: Vec<ConnectionHistoryRecord>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformTrafficPayload {
    pub items: Vec<PlatformTrafficStat>,
    pub total_upload: u64,
    pub total_download: u64,
    pub total_connections: u64,
}

fn notify_sync(app: &AppHandle) {
    let _ = app.emit("bypax-state-sync", ());
}

#[tauri::command]
pub async fn get_bootstrap_state(state: State<'_, AppState>) -> Result<BootstrapPayload, String> {
    let (mut settings, nodes, subscriptions, rules, app_rules, extra_ports) = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        (
            store.load_settings().map_err(|e| e.to_string())?,
            store.list_nodes().map_err(|e| e.to_string())?,
            store.list_subscriptions().map_err(|e| e.to_string())?,
            store.list_rules().map_err(|e| e.to_string())?,
            store.list_app_proxy_rules().map_err(|e| e.to_string())?,
            store.list_inbound_ports().map_err(|e| e.to_string())?,
        )
    };
    // Reconcile stored launch_at_login flag with actual OS startup registration.
    let os_autostart = bypax_core::autostart::is_autostart_enabled();
    if settings.launch_at_login != os_autostart {
        settings.launch_at_login = os_autostart;
        if let Ok(store) = state.store.lock() {
            let _ = store.save_settings(&settings);
        }
    }
    let rule_sets = state.rule_cache.list_cached();
    let compiled = state.compile_current()?;
    let logs = state
        .logs
        .lock()
        .map(|l| l.snapshot())
        .unwrap_or_default();

    let app_update_state = state
        .app_update_state
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default();
    let last_update_result = state
        .last_update_result
        .lock()
        .ok()
        .and_then(|r| r.clone());

    let app_presets = detect_preset_statuses(&app_rules, state.process_tracker.as_ref());
    let external_children = detect_ext_children_impl(&app_rules, state.process_tracker.as_ref());
    let service_status = state.query_service_status().await;
    let driver_status = state
        .probe_windivert_with_service(None, service_status.connected)
        .await;
    let app_proxy_status = state.query_app_proxy_status().await;
    let cli_info = state.get_cli_integration_info();

    Ok(BootstrapPayload {
        app_version: CURRENT_APP_VERSION.to_string(),
        platform: state.platform_name().to_string(),
        capture_mode: state.current_capture_mode(),
        core_info: state.build_core_info(),
        settings,
        nodes,
        subscriptions,
        rules,
        app_rules,
        app_presets,
        extra_ports,
        rule_sets,
        compiled,
        logs,
        app_update_state,
        last_update_result,
        service_status,
        driver_status,
        app_proxy_status,
        external_children,
        cli_info,
    })
}

#[tauri::command]
pub fn import_nodes(
    app: AppHandle,
    state: State<'_, AppState>,
    payload: String,
    group_name: Option<String>,
) -> Result<ImportSummary, String> {
    let group = group_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Imported".to_string());
    let summary = parse_payload(&payload, &group).map_err(|e| e.to_string())?;
    if !summary.nodes.is_empty() {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .upsert_nodes(&summary.nodes)
            .map_err(|e| e.to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        if settings.main_node_id.is_none() {
            settings.main_node_id = Some(summary.nodes[0].id.clone());
            store.save_settings(&settings).map_err(|e| e.to_string())?;
        }
    }
    state.push_log(
        "INFO",
        format!(
            "import: added {} node(s) into group [{}], skipped {}",
            summary.nodes.len(),
            group,
            summary.skipped
        ),
    );
    notify_sync(&app);
    Ok(summary)
}

#[tauri::command]
pub async fn import_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    url: String,
) -> Result<SubscriptionGroup, String> {
    let clean_url = url.trim().to_string();
    let clean_name = if name.trim().is_empty() {
        "Subscription".to_string()
    } else {
        name.trim().to_string()
    };

    let proxy_port = state.active_local_proxy_port();
    let (body, via) = fetch_text_via_channels(
        &clean_url,
        proxy_port,
        Some("Bypax/0.1 sing-box"),
        None,
        20,
    )
    .await
    .map_err(|e| e.to_string())?;

    let summary = parse_payload(&body, &clean_name).map_err(|e| e.to_string())?;
    let sub = SubscriptionGroup {
        id: format!("sub-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
        name: clean_name.clone(),
        url: clean_url,
        auto_update_hours: 24,
        last_updated: Some(chrono::Utc::now().to_rfc3339()),
        node_count: summary.nodes.len(),
    };

    {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .replace_group_nodes(&clean_name, &summary.nodes)
            .map_err(|e| e.to_string())?;
        store
            .upsert_subscription(&sub)
            .map_err(|e| e.to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        if settings.main_node_id.is_none() {
            if let Some(first) = summary.nodes.first() {
                settings.main_node_id = Some(first.id.clone());
                store.save_settings(&settings).map_err(|e| e.to_string())?;
            }
        }
    }

    state.push_log(
        "INFO",
        format!(
            "subscription: synced [{}] ({} nodes via {})",
            clean_name,
            summary.nodes.len(),
            via
        ),
    );
    let _ = state.reload_core_if_running_async().await;
    notify_sync(&app);
    Ok(sub)
}

#[tauri::command]
pub async fn refresh_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<SubscriptionGroup, String> {
    let existing = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .list_subscriptions()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| "Subscription not found".to_string())?
    };

    let proxy_port = state.active_local_proxy_port();
    let (body, via) = fetch_text_via_channels(
        &existing.url,
        proxy_port,
        Some("Bypax/0.1 sing-box"),
        None,
        20,
    )
    .await
    .map_err(|e| e.to_string())?;

    let summary = parse_payload(&body, &existing.name).map_err(|e| e.to_string())?;
    let updated = SubscriptionGroup {
        last_updated: Some(chrono::Utc::now().to_rfc3339()),
        node_count: summary.nodes.len(),
        ..existing
    };

    {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .replace_group_nodes(&updated.name, &summary.nodes)
            .map_err(|e| e.to_string())?;
        store
            .upsert_subscription(&updated)
            .map_err(|e| e.to_string())?;
    }

    state.push_log(
        "INFO",
        format!(
            "subscription: refreshed [{}] ({} nodes via {})",
            updated.name, updated.node_count, via,
        ),
    );
    let _ = state.reload_core_if_running_async().await;
    notify_sync(&app);
    Ok(updated)
}

#[tauri::command]
pub fn delete_subscription(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let store = state
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    store.delete_subscription(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_node(app: AppHandle, state: State<'_, AppState>, node: NodeIR) -> Result<(), String> {
    {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.upsert_nodes(&[node]).map_err(|e| e.to_string())?;
    }
    let _ = state.reload_core_if_running_async().await;
    notify_sync(&app);
    Ok(())
}

#[tauri::command]
pub async fn delete_node(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<bool, String> {
    let deleted = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let ok = store.delete_node(&id).map_err(|e| e.to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        if settings.main_node_id.as_deref() == Some(id.as_str()) {
            settings.main_node_id = store
                .list_nodes()
                .ok()
                .and_then(|list| list.first().map(|n| n.id.clone()));
            store.save_settings(&settings).map_err(|e| e.to_string())?;
        }
        ok
    };
    let _ = state.reload_core_if_running_async().await;
    notify_sync(&app);
    Ok(deleted)
}

#[tauri::command]
pub async fn select_main_node(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<SelectNodeResult, String> {
    let control_port = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        settings.main_node_id = Some(id.clone());
        store.save_settings(&settings).map_err(|e| e.to_string())?;
        settings.control_port
    };

    let running = state.is_core_running();
    let mut hot_switched = false;
    if running {
        if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
            if client.select_proxy("main-exit", &id).await.is_ok() {
                hot_switched = true;
                state.push_log(
                    "INFO",
                    format!("hot-switch: main-exit -> {} (0ms, no core restart)", id),
                );
            }
        }
        if !hot_switched {
            let _ = state.reload_core_if_running_async().await;
            state.push_log(
                "INFO",
                format!("reload: switched main-exit -> {} via preflight reload", id),
            );
        }
    } else {
        state.push_log("INFO", format!("main-exit selected -> {}", id));
    }

    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(SelectNodeResult {
        hot_switched,
        main_node_id: id,
        compiled,
    })
}

#[tauri::command]
pub async fn set_route_mode(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: RouteMode,
) -> Result<CompileOutput, String> {
    let control_port = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        settings.route_mode = mode;
        store.save_settings(&settings).map_err(|e| e.to_string())?;
        settings.control_port
    };

    let running = state.is_core_running();
    if running {
        let mut live_switched = false;
        if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
            if client.set_mode(mode.as_str()).await.is_ok() {
                live_switched = true;
                let _ = client.close_all_connections().await;
                state.push_log(
                    "INFO",
                    format!("route mode switched -> {} (clash_mode)", mode.as_str()),
                );
            }
        }
        if !live_switched {
            state.reload_core_if_running_async().await?;
            state.push_log(
                "INFO",
                format!("route mode switched -> {} (core reload)", mode.as_str()),
            );
        }
    } else {
        state.push_log("INFO", format!("route mode changed -> {}", mode.as_str()));
    }

    notify_sync(&app);
    state.compile_current()
}

#[tauri::command]
pub fn toggle_system_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<CoreInfo, String> {
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

    let guard = state
        .netguard
        .lock()
        .map_err(|_| "netguard lock poisoned".to_string())?;
    if enabled {
        guard
            .enable_system_proxy("127.0.0.1", mixed_port)
            .map_err(|e| e.to_string())?;
        state.push_log(
            "INFO",
            format!("netguard: enabled system proxy 127.0.0.1:{}", mixed_port),
        );
    } else {
        guard.disable_system_proxy().map_err(|e| e.to_string())?;
        state.push_log(
            "INFO",
            "netguard: disabled system proxy & restored snapshot",
        );
    }
    drop(guard);

    notify_sync(&app);
    Ok(state.build_core_info())
}

#[tauri::command]
pub async fn toggle_tun(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<CompileOutput, String> {
    let target_mode = if enabled {
        CaptureMode::Tun
    } else {
        CaptureMode::Off
    };
    let result = state.apply_capture_mode(target_mode).await?;
    tray::update_tray_icon_state(&app, state.is_core_running(), false);
    notify_sync(&app);
    Ok(result.compiled)
}

#[tauri::command]
pub async fn set_capture_mode(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: CaptureMode,
) -> Result<CaptureModeResult, String> {
    let result = state.apply_capture_mode(mode).await?;
    tray::update_tray_icon_state(&app, state.is_core_running(), false);
    notify_sync(&app);
    Ok(result)
}

#[tauri::command]
pub fn list_app_proxy_rules(state: State<'_, AppState>) -> Result<Vec<AppProxyRule>, String> {
    let store = state
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    store.list_app_proxy_rules().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_app_proxy_rule(
    app: AppHandle,
    state: State<'_, AppState>,
    rule: AppProxyRule,
) -> Result<AppRulesMutationResult, String> {
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .upsert_app_proxy_rule(&rule)
            .map_err(|e| e.to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };
    state.push_log(
        "INFO",
        format!(
            "app-proxy: saved rule [{}] (target={})",
            rule.name, rule.target
        ),
    );
    let reloaded = state.sync_app_proxy_if_running().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded,
    })
}

#[tauri::command]
pub async fn delete_app_proxy_rule(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<AppRulesMutationResult, String> {
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .delete_app_proxy_rule(&id)
            .map_err(|e| e.to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };
    state.push_log("INFO", format!("app-proxy: deleted rule [{}]", id));
    let reloaded = state.sync_app_proxy_if_running().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded,
    })
}

#[tauri::command]
pub async fn reorder_app_proxy_rules(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<String>,
) -> Result<AppRulesMutationResult, String> {
    let rules = {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .reorder_app_proxy_rules(&ids)
            .map_err(|e| e.to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };
    state.push_log(
        "INFO",
        format!("app-proxy: reordered {} rule(s)", ids.len()),
    );
    let reloaded = state.sync_app_proxy_if_running().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded,
    })
}

#[tauri::command]
pub fn list_app_presets(state: State<'_, AppState>) -> Result<Vec<AppPresetStatus>, String> {
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };
    Ok(detect_preset_statuses(
        &rules,
        state.process_tracker.as_ref(),
    ))
}

#[tauri::command]
pub async fn toggle_app_preset(
    app: AppHandle,
    state: State<'_, AppState>,
    preset_id: String,
    enabled: bool,
    target: Option<String>,
) -> Result<AppRulesMutationResult, String> {
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let existing = store.list_app_proxy_rules().map_err(|e| e.to_string())?;
        if let Some(mut found) = existing
            .iter()
            .find(|r| r.preset_id.as_deref() == Some(preset_id.as_str()))
            .cloned()
        {
            found.enabled = enabled;
            if let Some(t) = target.filter(|s| !s.trim().is_empty()) {
                found.target = t;
            }
            store
                .upsert_app_proxy_rule(&found)
                .map_err(|e| e.to_string())?;
        } else if enabled {
            let next_prio = existing
                .iter()
                .map(|r| r.priority)
                .max()
                .unwrap_or(0)
                + 10;
            let chosen_target = target
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "follow".to_string());
            let rule = preset_to_rule(&preset_id, &chosen_target, next_prio)
                .map_err(|e| e.to_string())?;
            store
                .upsert_app_proxy_rule(&rule)
                .map_err(|e| e.to_string())?;
        }
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };

    state.push_log(
        "INFO",
        format!("app-proxy: preset [{}] enabled={}", preset_id, enabled),
    );
    let reloaded = state.sync_app_proxy_if_running().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded,
    })
}

#[tauri::command]
pub fn test_app_proxy_rule(
    state: State<'_, AppState>,
    query: AppRuleTestQuery,
) -> Result<AppRuleTestTrace, String> {
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
    Ok(RuleEngine::dry_run_trace(
        &app_rules,
        &query,
        &nodes,
        settings.main_node_id.as_deref(),
        settings.app_proxy_bypass_lan,
    ))
}

#[tauri::command]
pub fn list_running_processes(
    state: State<'_, AppState>,
    filter: Option<String>,
) -> Result<Vec<ProcessInfoDto>, String> {
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
    let bindings = bypax_core::compiler::build_app_proxy_target_bindings(&app_rules, &nodes);
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
        let matched = engine
            .as_ref()
            .and_then(|e| e.match_process_rule(p.pid, state.process_tracker.as_ref()));
        let chain: Vec<String> = state
            .process_tracker
            .ancestor_chain(p.pid)
            .into_iter()
            .map(|a| a.name)
            .collect();
        out.push(ProcessInfoDto {
            pid: p.pid,
            parent_pid: p.parent_pid,
            name: p.name,
            exe_path: p.exe_path,
            ancestor_chain: chain,
            matched_rule_id: matched.as_ref().map(|(id, _)| id.clone()),
            matched_rule_name: matched.map(|(_, name)| name),
        });
    }
    Ok(out)
}

#[tauri::command]
pub fn list_installed_apps() -> Vec<InstalledAppItem> {
    list_installed_apps_impl()
}

#[tauri::command]
pub fn detect_external_children(
    state: State<'_, AppState>,
) -> Result<Vec<ExternalChildAlert>, String> {
    let app_rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };
    Ok(detect_ext_children_impl(
        &app_rules,
        state.process_tracker.as_ref(),
    ))
}

#[tauri::command]
pub async fn include_external_child(
    app: AppHandle,
    state: State<'_, AppState>,
    rule_id: String,
    child_path: String,
) -> Result<AppRulesMutationResult, String> {
    let clean_path = child_path.trim().to_string();
    if clean_path.is_empty() {
        return Err("Child executable path cannot be empty".to_string());
    }
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let mut rule = store
            .list_app_proxy_rules()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|r| r.id == rule_id)
            .ok_or_else(|| format!("App Proxy rule '{}' not found", rule_id))?;
        if !rule
            .path_prefixes
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&clean_path))
        {
            rule.path_prefixes.push(clean_path.clone());
        }
        rule.ignored_external_children
            .retain(|p| !p.eq_ignore_ascii_case(&clean_path));
        store
            .upsert_app_proxy_rule(&rule)
            .map_err(|e| e.to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };

    state.push_log(
        "INFO",
        format!(
            "app-proxy: included external child [{}] into rule [{}]",
            clean_path, rule_id
        ),
    );
    let reloaded = state.sync_app_proxy_if_running().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded,
    })
}

#[tauri::command]
pub async fn ignore_external_child(
    app: AppHandle,
    state: State<'_, AppState>,
    rule_id: String,
    child_path: String,
) -> Result<AppRulesMutationResult, String> {
    let clean_path = child_path.trim().to_string();
    if clean_path.is_empty() {
        return Err("Child executable path cannot be empty".to_string());
    }
    let rules = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let mut rule = store
            .list_app_proxy_rules()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|r| r.id == rule_id)
            .ok_or_else(|| format!("App Proxy rule '{}' not found", rule_id))?;
        if !rule
            .ignored_external_children
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&clean_path))
        {
            rule.ignored_external_children.push(clean_path.clone());
        }
        store
            .upsert_app_proxy_rule(&rule)
            .map_err(|e| e.to_string())?;
        store.list_app_proxy_rules().map_err(|e| e.to_string())?
    };

    state.push_log(
        "INFO",
        format!(
            "app-proxy: ignored external child [{}] for rule [{}]",
            clean_path, rule_id
        ),
    );
    let compiled = state.compile_current()?;
    notify_sync(&app);
    Ok(AppRulesMutationResult {
        rules,
        compiled,
        reloaded: false,
    })
}

#[tauri::command]
pub async fn get_service_status(
    state: State<'_, AppState>,
) -> Result<PrivilegedServiceStatus, String> {
    Ok(state.query_service_status().await)
}

#[tauri::command]
pub async fn probe_windivert_driver(
    state: State<'_, AppState>,
    custom_dir: Option<String>,
) -> Result<DriverProbeDto, String> {
    let svc = state.query_service_status().await;
    Ok(state
        .probe_windivert_with_service(custom_dir.as_deref(), svc.connected)
        .await)
}

#[tauri::command]
pub async fn set_windivert_dir(
    app: AppHandle,
    state: State<'_, AppState>,
    dir: String,
) -> Result<DriverProbeDto, String> {
    let trimmed = dir.trim().to_string();
    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let mut settings = store.load_settings().map_err(|e| e.to_string())?;
        settings.app_proxy_windivert_dir = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.clone())
        };
        store.save_settings(&settings).map_err(|e| e.to_string())?;
    }
    let svc = state.query_service_status().await;
    let probe = state
        .probe_windivert_with_service(
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.as_str())
            },
            svc.connected,
        )
        .await;
    state.push_log(
        "INFO",
        format!(
            "windivert: configured custom directory [{}] (dll_loaded={}, driver_opened={})",
            trimmed, probe.dll_loaded, probe.driver_opened
        ),
    );
    notify_sync(&app);
    Ok(probe)
}

#[tauri::command]
pub async fn service_action(
    app: AppHandle,
    state: State<'_, AppState>,
    action: String,
) -> Result<PrivilegedServiceStatus, String> {
    let status = state.perform_service_action(&action).await?;
    state.push_log(
        "INFO",
        format!(
            "service: action '{}' completed (state={}, connected={})",
            action, status.state, status.connected
        ),
    );
    notify_sync(&app);
    Ok(status)
}

#[tauri::command]
pub fn open_windows_security() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("cmd")
            .args(["/C", "start", "", "windowsdefender://threatsettings"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("Windows Security is only available on Windows".to_string())
    }
}

#[tauri::command]
pub fn get_cli_integration_info(state: State<'_, AppState>) -> Result<CliIntegrationInfo, String> {
    Ok(state.get_cli_integration_info())
}

#[tauri::command]
pub async fn save_rule(
    state: State<'_, AppState>,
    rule: SimpleRoutingRule,
) -> Result<CompileOutput, String> {
    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.upsert_rule(&rule).map_err(|e| e.to_string())?;
    }
    state.push_log("INFO", format!("routing: updated rule [{}]", rule.title_en));
    let _ = state.reload_core_if_running_async().await;
    state.compile_current()
}

#[tauri::command]
pub async fn delete_rule(state: State<'_, AppState>, id: String) -> Result<CompileOutput, String> {
    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.delete_rule(&id).map_err(|e| e.to_string())?;
    }
    state.push_log("INFO", format!("routing: deleted rule [{}]", id));
    let _ = state.reload_core_if_running_async().await;
    state.compile_current()
}

#[tauri::command]
pub fn list_rule_presets() -> Vec<RulePresetSpec> {
    rule_preset_catalog()
}

#[tauri::command]
pub fn list_rule_sets(state: State<'_, AppState>) -> Vec<RuleSetStatus> {
    state.rule_cache.list_cached()
}

#[tauri::command]
pub async fn apply_routing_strategy(
    app: AppHandle,
    state: State<'_, AppState>,
    strategy_id: String,
) -> Result<ApplyStrategyResult, String> {
    let (rules, tags_to_sync, proxy_port) = {
        let mut store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let rules = store
            .apply_routing_strategy(&strategy_id)
            .map_err(|e| e.to_string())?;
        let settings = store.load_settings().map_err(|e| e.to_string())?;
        let running = state.is_core_running();
        let mut missing: Vec<String> = Vec::new();
        for r in rules.iter().filter(|r| r.enabled) {
            if let Some(ref tag) = r.rule_set {
                let clean = tag.trim();
                if !clean.is_empty()
                    && state.rule_cache.local_srs_path(clean).is_none()
                    && !missing.iter().any(|x| x == clean)
                {
                    missing.push(clean.to_string());
                }
            }
        }
        (
            rules,
            missing,
            if running {
                Some(settings.mixed_port)
            } else {
                None
            },
        )
    };

    for tag in &tags_to_sync {
        let _ = state
            .rule_cache
            .refresh_rule_set_auto(tag, proxy_port)
            .await;
    }

    state.push_log(
        "INFO",
        format!(
            "routing: applied classic strategy [{}] ({} rules)",
            strategy_id,
            rules.len()
        ),
    );
    let _ = state.reload_core_if_running_async().await;
    let compiled = state.compile_current()?;
    notify_sync(&app);

    Ok(ApplyStrategyResult {
        rules,
        rule_sets: state.rule_cache.list_cached(),
        compiled,
    })
}

#[tauri::command]
pub async fn sync_rule_sets(
    state: State<'_, AppState>,
    tags: Vec<String>,
) -> Result<SyncRuleSetsResult, String> {
    let (target_tags, proxy_port) = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let settings = store.load_settings().map_err(|e| e.to_string())?;
        let rules = store.list_rules().map_err(|e| e.to_string())?;
        let running = state.is_core_running();

        let mut set: HashSet<String> = HashSet::new();
        if tags.is_empty() {
            for r in rules.iter().filter(|r| r.enabled) {
                if let Some(ref tag) = r.rule_set {
                    let clean = tag.trim();
                    if !clean.is_empty() {
                        set.insert(clean.to_string());
                    }
                }
            }
            for cr in settings.dns_custom_rules.iter().filter(|r| r.enabled) {
                if let Some(ref tag) = cr.rule_set {
                    let clean = tag.trim();
                    if !clean.is_empty() {
                        set.insert(clean.to_string());
                    }
                }
            }
            if set.contains("geosite-cn") {
                set.insert("geoip-cn".to_string());
            }
        } else {
            for t in tags {
                let clean = t.trim();
                if !clean.is_empty() {
                    set.insert(clean.to_string());
                }
            }
        }
        let mut sorted: Vec<String> = set.into_iter().collect();
        sorted.sort();
        (
            sorted,
            if running {
                Some(settings.mixed_port)
            } else {
                None
            },
        )
    };

    let mut statuses = Vec::with_capacity(target_tags.len());
    for tag in &target_tags {
        let st = state
            .rule_cache
            .refresh_rule_set_auto(tag, proxy_port)
            .await;
        statuses.push(st);
    }

    let ok_count = statuses
        .iter()
        .filter(|s| s.cached_locally && !s.fallback_mode)
        .count();
    state.push_log(
        "INFO",
        format!(
            "rule-sets: synced {}/{} .srs files",
            ok_count,
            target_tags.len()
        ),
    );

    let _ = state.reload_core_if_running_async().await;
    let compiled = state.compile_current()?;
    Ok(SyncRuleSetsResult {
        statuses: state.rule_cache.list_cached(),
        compiled,
    })
}

#[tauri::command]
pub fn test_route_target(
    state: State<'_, AppState>,
    input: String,
    process_name: Option<String>,
) -> Result<RouteTestResult, String> {
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
    Ok(evaluate_route_target(
        &input,
        process_name.as_deref(),
        &settings,
        &rules,
        &nodes,
        Some(&state.rule_cache),
        sb.as_deref(),
    ))
}

#[tauri::command]
pub async fn save_inbound_port(
    state: State<'_, AppState>,
    port: InboundPort,
) -> Result<CompileOutput, String> {
    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .upsert_inbound_port(&port)
            .map_err(|e| e.to_string())?;
    }
    state.push_log(
        "INFO",
        format!(
            "inbound: configured dedicated port :{} -> {}",
            port.port, port.target
        ),
    );
    let _ = state.reload_core_if_running_async().await;
    state.compile_current()
}

#[tauri::command]
pub async fn delete_inbound_port(
    state: State<'_, AppState>,
    id: String,
) -> Result<CompileOutput, String> {
    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .delete_inbound_port(&id)
            .map_err(|e| e.to_string())?;
    }
    state.push_log("INFO", format!("inbound: removed port [{}]", id));
    let _ = state.reload_core_if_running_async().await;
    state.compile_current()
}

#[tauri::command]
pub async fn update_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: AppSettings,
) -> Result<CompileOutput, String> {
    let prev_settings = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.load_settings().ok()
    };

    let prev_port = prev_settings.as_ref().map(|s| s.mixed_port);
    let prev_autostart = prev_settings.as_ref().map(|s| s.launch_at_login);
    let prev_theme = prev_settings.as_ref().map(|s| s.theme.clone());
    let needs_core_reload = prev_settings
        .as_ref()
        .map(|old| old.affects_core_config(&settings))
        .unwrap_or(true);
    let needs_app_proxy_sync = prev_settings
        .as_ref()
        .map(|old| old.affects_app_proxy_engine(&settings))
        .unwrap_or(false);

    if prev_autostart != Some(settings.launch_at_login) {
        bypax_core::autostart::set_autostart_enabled(settings.launch_at_login)
            .map_err(|e| e.to_string())?;
        state.push_log(
            "INFO",
            format!(
                "autostart: {} launch at OS login",
                if settings.launch_at_login {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        );
    }

    {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store.save_settings(&settings).map_err(|e| e.to_string())?;
    }

    if prev_theme.as_deref() != Some(settings.theme.as_str()) {
        tray::sync_window_background_colors(&app, &settings.theme);
    }

    if prev_port != Some(settings.mixed_port) {
        if let Ok(guard) = state.netguard.lock() {
            if guard.is_armed() {
                let _ = guard.enable_system_proxy("127.0.0.1", settings.mixed_port);
            }
        }
    }

    if needs_core_reload {
        let _ = state.reload_core_if_running_async().await;
    } else if needs_app_proxy_sync && state.app_proxy_active.load(Ordering::Relaxed) {
        let _ = state.sync_app_proxy_with_helper("settings update").await;
    }

    notify_sync(&app);
    state.compile_current()
}

#[tauri::command]
pub fn compile_preview(state: State<'_, AppState>) -> Result<CompileOutput, String> {
    state.compile_current()
}

#[tauri::command]
pub fn run_preflight_check(
    state: State<'_, AppState>,
    simulate_bad: bool,
) -> Result<PreflightReport, String> {
    let mut compiled = state.compile_current()?;
    if simulate_bad {
        compiled.config["outbounds"] =
            serde_json::json!([{ "type": "invalid_protocol_test", "tag": "broken-test" }]);
    }
    let bin = match state.core_manager.resolve_binary_path() {
        Some(p) => p,
        None if simulate_bad => {
            return Ok(PreflightReport {
                ok: false,
                exit_code: 1,
                stdout: String::new(),
                stderr: "Simulated bad config rejected before core swap".to_string(),
                deprecated_warnings: Vec::new(),
            });
        }
        None => return Err("CORE_NOT_INSTALLED".to_string()),
    };
    let report = SingBox114Compiler::preflight_check(&bin, &compiled.config)
        .map_err(|e| e.to_string())?;
    state.push_log(
        if report.ok { "INFO" } else { "ERROR" },
        format!(
            "preflight check -c -> exit {} (warnings={})",
            report.exit_code,
            report.deprecated_warnings.len()
        ),
    );
    Ok(report)
}

#[tauri::command]
pub async fn start_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(CoreInfo, PreflightReport), String> {
    let (info, report) = state.start_core_flow().await?;
    tray::update_tray_icon_state(&app, info.running, !report.ok);
    notify_sync(&app);
    Ok((info, report))
}

#[tauri::command]
pub async fn stop_core(app: AppHandle, state: State<'_, AppState>) -> Result<CoreInfo, String> {
    let info = state.stop_core_flow().await;
    tray::update_tray_icon_state(&app, false, false);
    notify_sync(&app);
    Ok(info)
}

async fn commit_core_and_resume_if_running(
    app: &AppHandle,
    state: &AppState,
    staged_candidate: &PathBuf,
    emit_progress: bool,
) -> Result<(String, String, bool), String> {
    let was_running = state.is_core_running();

    if was_running {
        if emit_progress {
            let _ = app.emit(
                "bypax-core-download-progress",
                CoreDownloadProgressEvent {
                    phase: "restarting".to_string(),
                    downloaded_bytes: 0,
                    total_bytes: None,
                    percent: Some(100),
                    via: None,
                    target_version: None,
                },
            );
        }
        let _ = state.stop_core_flow().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    let (ver, sha) = match state.core_manager.commit_staged_binary(staged_candidate) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = std::fs::remove_file(staged_candidate);
            if was_running {
                let _ = state.start_core_flow().await;
            }
            return Err(e.to_string());
        }
    };

    if was_running {
        let restart_ok = state
            .start_core_flow()
            .await
            .map(|(_, r)| r.ok)
            .unwrap_or(false);

        if !restart_ok {
            let rolled_back = state.core_manager.rollback_binary().unwrap_or(false);
            if rolled_back {
                let _ = state.start_core_flow().await;
            }
            return Err(format!(
                "New sing-box {} failed preflight/startup and was rolled back to the previous working binary",
                ver
            ));
        }
    }

    if emit_progress {
        let _ = app.emit(
            "bypax-core-download-progress",
            CoreDownloadProgressEvent {
                phase: "done".to_string(),
                downloaded_bytes: 0,
                total_bytes: None,
                percent: Some(100),
                via: None,
                target_version: Some(ver.clone()),
            },
        );
    }

    Ok((ver, sha, was_running))
}

#[tauri::command]
pub async fn check_core_update(
    state: State<'_, AppState>,
) -> Result<CoreUpdateCheckReport, String> {
    let proxy_port = state.active_local_proxy_port();
    let report = state
        .core_manager
        .check_for_core_update(proxy_port)
        .await
        .map_err(|e| e.to_string())?;
    state.push_log(
        "INFO",
        format!(
            "core-manager: checked latest sing-box -> {} (installed={}, via {})",
            report.latest_tag,
            report.installed_version.as_deref().unwrap_or("none"),
            report.checked_via
        ),
    );
    Ok(report)
}

#[tauri::command]
pub async fn download_official_core(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreInfo, String> {
    state.push_log(
        "INFO",
        "core-manager: downloading official sing-box release...",
    );
    let proxy_port = state.active_local_proxy_port();
    let emit_handle = app.clone();
    let (candidate, _staged_ver, via) = state
        .core_manager
        .stage_official_core(proxy_port, None, move |ev| {
            let _ = emit_handle.emit("bypax-core-download-progress", ev);
        })
        .await
        .map_err(|e| e.to_string())?;

    let (ver, sha, restarted) =
        commit_core_and_resume_if_running(&app, &state, &candidate, true).await?;
    state.push_log(
        "INFO",
        format!(
            "core-manager: installed {} via {} (sha256: {}..., restarted={})",
            ver,
            via,
            &sha[..12.min(sha.len())],
            restarted
        ),
    );
    notify_sync(&app);
    Ok(state.build_core_info())
}

#[tauri::command]
pub async fn import_core_binary(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<CoreInfo, String> {
    let (candidate, _staged_ver) = state
        .core_manager
        .stage_local_binary(&PathBuf::from(&path), None)
        .map_err(|e| e.to_string())?;
    let (ver, _sha, restarted) =
        commit_core_and_resume_if_running(&app, &state, &candidate, false).await?;
    state.push_log(
        "INFO",
        format!(
            "core-manager: imported local binary {} (restarted={})",
            ver, restarted
        ),
    );
    notify_sync(&app);
    Ok(state.build_core_info())
}

#[tauri::command]
pub async fn check_app_update(
    state: State<'_, AppState>,
) -> Result<AppUpdateCheckReport, String> {
    let proxy_port = state.active_local_proxy_port();
    let portable_mode = state.paths.portable_mode;
    let core_installed = state.core_manager.is_installed();
    let report = check_for_app_update(proxy_port, portable_mode, core_installed)
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.app_update_report.lock() {
        *guard = Some(report.clone());
    }
    state.push_log(
        "INFO",
        format!(
            "updater: checked Bypax release -> latest={} available={} via {}",
            report.latest_tag, report.update_available, report.checked_via
        ),
    );
    Ok(report)
}

#[tauri::command]
pub async fn download_app_update(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppUpdateState, String> {
    let report = {
        let cached = state
            .app_update_report
            .lock()
            .ok()
            .and_then(|g| g.clone());
        match cached {
            Some(r) => r,
            None => {
                let proxy_port = state.active_local_proxy_port();
                let fresh = check_for_app_update(
                    proxy_port,
                    state.paths.portable_mode,
                    state.core_manager.is_installed(),
                )
                .await
                .map_err(|e| e.to_string())?;
                if let Ok(mut guard) = state.app_update_report.lock() {
                    *guard = Some(fresh.clone());
                }
                fresh
            }
        }
    };

    if !report.update_available {
        return Err("Bypax is already up to date".to_string());
    }

    if let Ok(cur) = state.app_update_state.lock() {
        if matches!(
            cur.stage,
            AppUpdateStage::Downloading | AppUpdateStage::Verifying | AppUpdateStage::Extracting
        ) {
            return Ok(cur.clone());
        }
        if cur.stage == AppUpdateStage::ReadyToRestart
            && cur.target_tag.as_deref() == Some(report.latest_tag.as_str())
            && cur
                .staged_exe_path
                .as_deref()
                .map(|p| PathBuf::from(p).is_file())
                .unwrap_or(false)
        {
            return Ok(cur.clone());
        }
    }

    let cancel_flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut c) = state.app_update_cancel.lock() {
        *c = Some(Arc::clone(&cancel_flag));
    }

    let proxy_port = state.active_local_proxy_port();
    let updates_dir = state.updates_dir.clone();
    let emit_handle = app.clone();

    let result = download_and_stage_update(
        &report,
        &updates_dir,
        proxy_port,
        cancel_flag,
        move |next_state| {
            if let Some(st) = emit_handle.try_state::<AppState>() {
                if let Ok(mut guard) = st.app_update_state.lock() {
                    *guard = next_state.clone();
                }
            }
            let _ = emit_handle.emit("bypax-update-progress", &next_state);
        },
    )
    .await;

    if let Ok(mut c) = state.app_update_cancel.lock() {
        *c = None;
    }

    match result {
        Ok(ready_state) => {
            if let Ok(mut guard) = state.app_update_state.lock() {
                *guard = ready_state.clone();
            }
            state.push_log(
                "INFO",
                format!(
                    "updater: staged Bypax {} (sha256 verified, ready to restart)",
                    report.latest_tag
                ),
            );
            let _ = app.emit("bypax-update-progress", &ready_state);
            Ok(ready_state)
        }
        Err(e) => {
            let msg = e.to_string();
            let final_state = if msg.contains("UPDATE_CANCELLED") {
                state.push_log("INFO", "updater: update download cancelled by user");
                AppUpdateState::default()
            } else {
                state.push_log("ERROR", format!("updater: download failed: {}", msg));
                AppUpdateState {
                    stage: AppUpdateStage::Failed,
                    target_version: Some(report.latest_version.clone()),
                    target_tag: Some(report.latest_tag.clone()),
                    error: Some(msg.clone()),
                    ..AppUpdateState::default()
                }
            };
            if let Ok(mut guard) = state.app_update_state.lock() {
                *guard = final_state.clone();
            }
            let _ = app.emit("bypax-update-progress", &final_state);
            if msg.contains("UPDATE_CANCELLED") {
                Ok(final_state)
            } else {
                Err(msg)
            }
        }
    }
}

#[tauri::command]
pub fn cancel_app_update(state: State<'_, AppState>) -> Result<(), String> {
    if let Ok(guard) = state.app_update_cancel.lock() {
        if let Some(ref flag) = *guard {
            flag.store(true, Ordering::Relaxed);
        }
    }
    Ok(())
}

#[tauri::command]
pub fn get_app_update_state(state: State<'_, AppState>) -> Result<AppUpdateState, String> {
    let guard = state
        .app_update_state
        .lock()
        .map_err(|_| "update state lock poisoned".to_string())?;
    Ok(guard.clone())
}

#[tauri::command]
pub fn consume_update_result(
    state: State<'_, AppState>,
) -> Result<Option<UpdateApplyResult>, String> {
    let mut guard = state
        .last_update_result
        .lock()
        .map_err(|_| "update result lock poisoned".to_string())?;
    Ok(guard.take())
}

#[tauri::command]
pub fn restart_to_update(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let staged = state
        .app_update_state
        .lock()
        .map_err(|_| "update state lock poisoned".to_string())?
        .clone();

    if staged.stage != AppUpdateStage::ReadyToRestart {
        return Err("No verified update is ready to install".to_string());
    }
    let staged_exe = staged
        .staged_exe_path
        .as_deref()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .ok_or_else(|| "Staged update binary is missing; please download again".to_string())?;
    let staged_dir = staged
        .staged_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            staged_exe
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| state.updates_dir.clone())
        });

    let target_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let target_dir = target_exe
        .parent()
        .ok_or_else(|| "Unable to determine Bypax install directory".to_string())?
        .to_path_buf();

    let resume_core = state.is_core_running();
    let resume_sys_proxy = state
        .netguard
        .lock()
        .map(|g| g.is_armed())
        .unwrap_or(false);
    let resume_app_proxy = state.app_proxy_active.load(Ordering::Relaxed);
    let resume_tun = state.tun_active.load(Ordering::Relaxed);

    let plan = UpdatePlan::from_staged(
        &staged,
        std::process::id(),
        target_exe,
        target_dir,
        state.paths.portable_mode,
        staged_dir,
        staged_exe,
        resume_core,
        resume_sys_proxy,
        resume_app_proxy,
        resume_tun,
        state.update_result_file.clone(),
    );

    spawn_detached_update_helper(&plan).map_err(|e| e.to_string())?;

    let mut restarting = staged;
    restarting.stage = AppUpdateStage::Restarting;
    if let Ok(mut guard) = state.app_update_state.lock() {
        *guard = restarting.clone();
    }
    let _ = app.emit("bypax-update-progress", &restarting);
    state.push_log(
        "INFO",
        format!(
            "updater: launching detached updater helper for {} (resume_core={}, resume_proxy={}, resume_app_proxy={}, resume_tun={})",
            plan.to_tag, plan.resume_core, plan.resume_sys_proxy, plan.resume_app_proxy, plan.resume_tun
        ),
    );

    let exit_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        if let Some(st) = exit_handle.try_state::<AppState>() {
            st.shutdown_cleanly();
        }
        exit_handle.exit(0);
    });

    Ok(())
}

#[tauri::command]
pub fn open_external_url(url: String) -> Result<(), String> {
    let trimmed = url.trim();
    if !is_safe_release_url(trimmed) {
        return Err("Refusing to open untrusted external URL".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("cmd")
            .args(["/C", "start", "", trimmed])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(trimmed)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(trimmed)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn run_batch_tcping(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
) -> Result<Vec<LatencyResult>, String> {
    let targets = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        let all = store.list_nodes().map_err(|e| e.to_string())?;
        if node_ids.is_empty() {
            all
        } else {
            all.into_iter()
                .filter(|n| node_ids.contains(&n.id))
                .collect()
        }
    };
    let emit_handle = app.clone();
    let results = batch_tcping_with_progress(&targets, 2500, 16, move |ev| {
        let _ = emit_handle.emit("bypax-latency-progress", ev);
    })
    .await;

    if let Ok(store) = state.store.lock() {
        for r in &results {
            let _ = store.update_node_latency(&r.node_id, r.delay_ms, None);
        }
    }
    state.push_log(
        "INFO",
        format!("tester: TCPing finished ({} nodes)", results.len()),
    );
    Ok(results)
}

#[tauri::command]
pub async fn run_batch_real_delay(
    app: AppHandle,
    state: State<'_, AppState>,
    node_ids: Vec<String>,
) -> Result<Vec<LatencyResult>, String> {
    let bin = state.require_core_binary()?;
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
    let emit_handle = app.clone();
    let results = batch_real_delay_with_progress(
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
    .map_err(|e| e.to_string())?;

    if let Ok(store) = state.store.lock() {
        for r in &results {
            let _ = store.update_node_latency(&r.node_id, None, r.delay_ms);
        }
    }
    state.push_log(
        "INFO",
        format!(
            "tester: real-delay finished ({} nodes, strip_handshake={})",
            results.len(),
            strip_handshake
        ),
    );
    Ok(results)
}

#[tauri::command]
pub async fn get_live_monitor(state: State<'_, AppState>) -> Result<LiveMonitorPayload, String> {
    let running = state.is_core_running();
    let control_port = state
        .store
        .lock()
        .ok()
        .and_then(|s| s.load_settings().ok())
        .map(|s| s.control_port)
        .unwrap_or(9090);

    let mut connections = Vec::new();
    let mut up_bps = 0u64;
    let mut down_bps = 0u64;
    let mut memory_bytes = 0u64;

    if running {
        if let Ok(client) = ControlClient::new(control_port, &state.control_secret) {
            if let Ok((mut conns, up_total, down_total, mem)) = client.get_connections().await {
                let (app_proxy_status, local_direct_bytes, local_reject_count) =
                    state.enrich_connections_with_origins(&mut conns).await;
                state.record_connections_snapshot(&conns);
                connections = conns;
                memory_bytes = mem;
                if let Ok(mut cursor) = state.traffic_cursor.lock() {
                    let elapsed = cursor.last_at.elapsed().as_secs_f64().max(0.2);
                    if up_total >= cursor.last_up && down_total >= cursor.last_down {
                        up_bps = ((up_total - cursor.last_up) as f64 / elapsed) as u64;
                        down_bps = ((down_total - cursor.last_down) as f64 / elapsed) as u64;
                    }
                    cursor.last_up = up_total;
                    cursor.last_down = down_total;
                    cursor.last_at = Instant::now();
                }

                let logs = state
                    .logs
                    .lock()
                    .map(|l| l.snapshot())
                    .unwrap_or_default();

                return Ok(LiveMonitorPayload {
                    core_running: running,
                    traffic: TrafficSample {
                        up_bytes_per_sec: up_bps,
                        down_bytes_per_sec: down_bps,
                        memory_bytes,
                        active_connections: connections.len(),
                    },
                    connections,
                    logs,
                    app_proxy_status,
                    local_direct_bytes,
                    local_reject_count,
                });
            }
        }
    }

    let (app_proxy_status, local_direct_bytes, local_reject_count) =
        state.enrich_connections_with_origins(&mut connections).await;

    let logs = state
        .logs
        .lock()
        .map(|l| l.snapshot())
        .unwrap_or_default();

    Ok(LiveMonitorPayload {
        core_running: running,
        traffic: TrafficSample {
            up_bytes_per_sec: up_bps,
            down_bytes_per_sec: down_bps,
            memory_bytes,
            active_connections: connections.len(),
        },
        connections,
        logs,
        app_proxy_status,
        local_direct_bytes,
        local_reject_count,
    })
}

#[tauri::command]
pub fn get_connection_history(
    state: State<'_, AppState>,
    query: String,
    page: usize,
    page_size: usize,
) -> Result<ConnectionHistoryPage, String> {
    let store = state
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    let safe_page = page.max(1);
    let safe_size = page_size.clamp(10, 200);
    let (items, total) = store
        .query_connection_history(&query, safe_page, safe_size)
        .map_err(|e| e.to_string())?;
    Ok(ConnectionHistoryPage {
        items,
        total,
        page: safe_page,
        page_size: safe_size,
    })
}

#[tauri::command]
pub fn get_platform_traffic(
    state: State<'_, AppState>,
    range: String,
) -> Result<PlatformTrafficPayload, String> {
    let since_iso: Option<String> = match range.as_str() {
        "today" => {
            let now_local = chrono::Local::now();
            now_local
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .and_then(|dt| dt.and_local_timezone(chrono::Local).single())
                .map(|dt| dt.with_timezone(&chrono::Utc).to_rfc3339())
        }
        "7d" => Some((chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339()),
        "30d" => Some((chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339()),
        _ => None,
    };

    let stored = {
        let store = state
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        store
            .query_platform_traffic(since_iso.as_deref())
            .map_err(|e| e.to_string())?
    };

    let active_conns = state
        .conn_tracker
        .lock()
        .map(|t| t.snapshot_active())
        .unwrap_or_default();

    let mut merged: HashMap<String, PlatformTrafficStat> = stored
        .into_iter()
        .map(|s| (s.platform.clone(), s))
        .collect();

    for conn in active_conns {
        let host = extract_host(&conn.destination);
        let platform = classify_platform(&host, &conn.process);
        let entry = merged
            .entry(platform.clone())
            .or_insert_with(|| PlatformTrafficStat {
                platform,
                upload_bytes: 0,
                download_bytes: 0,
                total_bytes: 0,
                connection_count: 0,
                active_count: 0,
                top_domains: Vec::new(),
            });
        entry.upload_bytes += conn.upload_bytes;
        entry.download_bytes += conn.download_bytes;
        entry.total_bytes += conn.upload_bytes + conn.download_bytes;
        entry.connection_count += 1;
        entry.active_count += 1;
        if !host.is_empty() && entry.top_domains.len() < 3 && !entry.top_domains.contains(&host) {
            entry.top_domains.push(host);
        }
    }

    let mut items: Vec<PlatformTrafficStat> = merged.into_values().collect();
    items.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| b.connection_count.cmp(&a.connection_count))
            .then_with(|| a.platform.cmp(&b.platform))
    });

    let total_upload = items.iter().map(|i| i.upload_bytes).sum();
    let total_download = items.iter().map(|i| i.download_bytes).sum();
    let total_connections = items.iter().map(|i| i.connection_count).sum();

    Ok(PlatformTrafficPayload {
        items,
        total_upload,
        total_download,
        total_connections,
    })
}

#[tauri::command]
pub fn clear_connection_history(state: State<'_, AppState>) -> Result<(), String> {
    let store = state
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())?;
    store
        .clear_connection_history()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_connection(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let control_port = state
        .store
        .lock()
        .ok()
        .and_then(|s| s.load_settings().ok())
        .map(|s| s.control_port)
        .unwrap_or(9090);
    let client =
        ControlClient::new(control_port, &state.control_secret).map_err(|e| e.to_string())?;
    client.close_connection(&id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn close_all_connections(state: State<'_, AppState>) -> Result<(), String> {
    let control_port = state
        .store
        .lock()
        .ok()
        .and_then(|s| s.load_settings().ok())
        .map(|s| s.control_port)
        .unwrap_or(9090);
    let client =
        ControlClient::new(control_port, &state.control_secret).map_err(|e| e.to_string())?;
    client
        .close_all_connections()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn open_logs_dir(state: State<'_, AppState>) -> Result<String, String> {
    let dir = state.paths.logs_dir.clone();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dir_str = dir.to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("explorer")
            .arg(&dir)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&dir)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(&dir)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(dir_str)
}

#[tauri::command]
pub fn clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    if let Ok(mut guard) = state.logs.lock() {
        guard.clear();
    }
    Ok(())
}

#[tauri::command]
pub async fn restore_netguard_now(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreInfo, String> {
    if state.current_capture_mode() != CaptureMode::Off {
        let _ = state.apply_capture_mode(CaptureMode::Off).await;
    }
    if let Ok(guard) = state.netguard.lock() {
        guard.disable_system_proxy().map_err(|e| e.to_string())?;
    }
    if let Ok(store) = state.store.lock() {
        if let Ok(mut settings) = store.load_settings() {
            settings.system_proxy_enabled = false;
            settings.app_proxy_enabled = false;
            settings.tun_enabled = false;
            let _ = store.save_settings(&settings);
        }
    }
    tray::update_tray_icon_state(&app, false, false);
    state.push_log(
        "INFO",
        "netguard: manual network recovery disabled system proxy and active capture",
    );
    notify_sync(&app);
    Ok(state.build_core_info())
}

#[tauri::command]
pub fn hide_to_tray(window: tauri::WebviewWindow) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn show_main_window(app: AppHandle) -> Result<(), String> {
    tray::show_main_window(&app);
    Ok(())
}

#[tauri::command]
pub fn hide_tray_popup(app: AppHandle) -> Result<(), String> {
    tray::hide_tray_popup(&app);
    Ok(())
}

#[tauri::command]
pub fn quit_app(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.shutdown_cleanly();
    app.exit(0);
    Ok(())
}
