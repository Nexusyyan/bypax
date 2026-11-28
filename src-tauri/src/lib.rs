mod commands;
mod ctl_server;
mod state;
mod tray;

use bypax_core::control::ControlClient;
use bypax_core::model::CaptureMode;
use bypax_core::parser::parse_payload;
use bypax_core::updater::{
    cleanup_post_update_artifacts, fetch_text_via_channels, CURRENT_APP_VERSION,
    RESUME_AFTER_UPDATE_ARG, RESUME_APP_PROXY_ARG, RESUME_CORE_ARG, RESUME_SYS_PROXY_ARG,
    RESUME_TUN_ARG,
};
use state::AppState;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::oneshot;

struct CtlServerGuard(Mutex<Option<oneshot::Sender<()>>>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::initialize().expect("Failed to initialize Bypax state");

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Some(ref sink) = app_state.app_log_file {
        let writer_sink = std::sync::Arc::clone(sink);
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_target(true)
            .with_writer(move || writer_sink.writer())
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .try_init();
    }

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
            if let Ok(running_exe) = std::env::current_exe() {
                if let Some(payload) = detect_instance_path_conflict(&running_exe, &args, &cwd) {
                    if let Some(state) = app.try_state::<AppState>() {
                        state.push_log(
                            "WARN",
                            format!(
                                "single-instance: launch attempted from [{}] while active instance runs from [{}]",
                                payload.attempted_cwd, payload.running_path
                            ),
                        );
                    }
                    let _ = app.emit("bypax-instance-conflict", payload);
                }
            }
        }))
        .manage(app_state)
        .manage(CtlServerGuard(Mutex::new(None)))
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    let minimize_to_tray = window
                        .app_handle()
                        .try_state::<AppState>()
                        .and_then(|st| st.store.lock().ok().and_then(|s| s.load_settings().ok()))
                        .map(|s| s.minimize_to_tray)
                        .unwrap_or(true);
                    if minimize_to_tray {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
            }
        })
        .setup(|app| {
            // Apply saved Light/Dark/System native window background color immediately (R1 anti-white-flash).
            let saved_theme = app
                .try_state::<AppState>()
                .and_then(|st| st.store.lock().ok().and_then(|s| s.load_settings().ok()))
                .map(|s| s.theme)
                .unwrap_or_else(|| "system".to_string());
            tray::sync_window_background_colors(app.handle(), &saved_theme);

            let _ = tray::setup_tray(app.handle());

            // Start Plane 2 Control IPC server (`bypax-ctl-v1` / `bypax-ctl.sock` 0600) for bypax-cli & MCP.
            let ctl_shutdown = ctl_server::spawn_ctl_server(app.handle().clone());
            if let Some(guard) = app.try_state::<CtlServerGuard>() {
                if let Ok(mut slot) = guard.0.lock() {
                    *slot = Some(ctl_shutdown);
                }
            }

            let cli_args: Vec<String> = std::env::args().skip(1).collect();

            // Clean up any leftover updater helper binary, .prev backups, and old staging dirs.
            if let Some(state) = app.try_state::<AppState>() {
                let updates_dir = state.updates_dir.clone();
                let cleanup_args = cli_args.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(500));
                    cleanup_post_update_artifacts(&cleanup_args, &updates_dir);
                });
            }

            // 5-second heartbeat task feeding the elevated helper's GUI lease watchdog.
            let hb_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if let Some(st) = hb_handle.try_state::<AppState>() {
                        if st.send_service_heartbeat().await {
                            let _ = hb_handle.emit("bypax-state-sync", ());
                        }
                    }
                }
            });

            // Handle post-update relaunch (`--resume-after-update`) restoring core, system proxy,
            // app proxy, or TUN seamlessly.
            let resumed_after_update = cli_args.iter().any(|a| a == RESUME_AFTER_UPDATE_ARG);
            let resume_core_flag = cli_args.iter().any(|a| a == RESUME_CORE_ARG);
            let resume_sys_proxy_flag = cli_args.iter().any(|a| a == RESUME_SYS_PROXY_ARG);
            let resume_app_proxy_flag = cli_args.iter().any(|a| a == RESUME_APP_PROXY_ARG);
            let resume_tun_flag = cli_args.iter().any(|a| a == RESUME_TUN_ARG);

            // Handle OS login autostart (`--autostart`).
            let launched_via_autostart = cli_args
                .iter()
                .any(|a| a == bypax_core::autostart::AUTOSTART_ARG);

            if resumed_after_update
                && (resume_core_flag
                    || resume_sys_proxy_flag
                    || resume_app_proxy_flag
                    || resume_tun_flag)
            {
                let resume_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let Some(st) = resume_handle.try_state::<AppState>() else {
                        return;
                    };
                    let startup_cfg = st.store.lock().ok().and_then(|s| {
                        let settings = s.load_settings().ok()?;
                        let has_nodes = !s.list_nodes().unwrap_or_default().is_empty();
                        Some((settings, has_nodes))
                    });
                    let Some((settings, has_nodes)) = startup_cfg else {
                        return;
                    };
                    if !has_nodes || !st.core_manager.is_installed() {
                        return;
                    }

                    let mut restored_ok = false;
                    if resume_tun_flag {
                        restored_ok = st.apply_capture_mode(CaptureMode::Tun).await.is_ok();
                        if !restored_ok {
                            clear_persisted_capture_flags(&st);
                            if resume_sys_proxy_flag || resume_core_flag {
                                restored_ok = st
                                    .start_local_core_only()
                                    .await
                                    .map(|(_, rep)| rep.ok)
                                    .unwrap_or(false);
                            }
                        }
                    } else if resume_app_proxy_flag {
                        let local_ok = st
                            .start_local_core_only()
                            .await
                            .map(|(_, rep)| rep.ok)
                            .unwrap_or(false);
                        if local_ok && resume_sys_proxy_flag {
                            if let Ok(guard) = st.netguard.lock() {
                                let _ = guard.enable_system_proxy("127.0.0.1", settings.mixed_port);
                            }
                        }
                        if st.apply_capture_mode(CaptureMode::Apps).await.is_ok() {
                            restored_ok = true;
                        } else {
                            clear_persisted_capture_flags(&st);
                            restored_ok = local_ok;
                        }
                    } else if resume_core_flag {
                        restored_ok = st
                            .start_local_core_only()
                            .await
                            .map(|(_, rep)| rep.ok)
                            .unwrap_or(false);
                    }

                    if resume_sys_proxy_flag && restored_ok {
                        if let Ok(guard) = st.netguard.lock() {
                            let _ = guard.enable_system_proxy("127.0.0.1", settings.mixed_port);
                        }
                    }

                    if restored_ok || resume_sys_proxy_flag {
                        st.push_log(
                            "INFO",
                            format!(
                                "updater: resumed state cleanly after update (core={}, sys_proxy={}, app_proxy={}, tun={})",
                                resume_core_flag,
                                resume_sys_proxy_flag,
                                st.app_proxy_active.load(std::sync::atomic::Ordering::Relaxed),
                                st.tun_active.load(std::sync::atomic::Ordering::Relaxed)
                            ),
                        );
                        let active = st.netguard.lock().map(|g| g.is_armed()).unwrap_or(false)
                            || st.current_capture_mode() != CaptureMode::Off;
                        tray::update_tray_icon_state(&resume_handle, active, false);
                        let _ = resume_handle.emit("bypax-state-sync", ());
                    }
                });
            } else {
                // Both `--autostart` and normal manual GUI launch obey the GUI-bound boundary:
                // proxy and capture activate ONLY after GUI opens, restoring saved preferences
                // cleanly (falling back capture to Off if UAC elevation is cancelled).
                if let Some(state) = app.try_state::<AppState>() {
                    let startup_cfg = state.store.lock().ok().and_then(|s| {
                        let settings = s.load_settings().ok()?;
                        let has_nodes = !s.list_nodes().unwrap_or_default().is_empty();
                        Some((settings, has_nodes))
                    });
                    if let Some((settings, has_nodes)) = startup_cfg {
                        if launched_via_autostart && settings.minimize_to_tray {
                            if let Some(win) = app.get_webview_window("main") {
                                let _ = win.hide();
                            }
                        }
                        let should_restore = settings.auto_start_core
                            || settings.system_proxy_enabled
                            || settings.app_proxy_enabled
                            || settings.tun_enabled;
                        if should_restore && has_nodes && state.core_manager.is_installed() {
                            let start_handle = app.handle().clone();
                            tauri::async_runtime::spawn(async move {
                                let Some(st) = start_handle.try_state::<AppState>() else {
                                    return;
                                };
                                let mut core_ready = false;

                                match select_startup_restore_plan(&settings) {
                                    StartupRestorePlan::Tun => {
                                        match st.apply_capture_mode(CaptureMode::Tun).await {
                                            Ok(_) => {
                                                core_ready = true;
                                            }
                                            Err(err) => {
                                                clear_persisted_capture_flags(&st);
                                                log_startup_capture_fallback(&st, "TUN", &err);
                                                if settings.system_proxy_enabled
                                                    || settings.auto_start_core
                                                {
                                                    core_ready = st
                                                        .start_local_core_only()
                                                        .await
                                                        .map(|(_, rep)| rep.ok)
                                                        .unwrap_or(false);
                                                }
                                            }
                                        }
                                    }
                                    StartupRestorePlan::AppProxy => {
                                        match st.apply_capture_mode(CaptureMode::Apps).await {
                                            Ok(_) => {
                                                core_ready = true;
                                            }
                                            Err(err) => {
                                                clear_persisted_capture_flags(&st);
                                                log_startup_capture_fallback(
                                                    &st,
                                                    "App Proxy",
                                                    &err,
                                                );
                                                if settings.auto_start_core
                                                    || settings.system_proxy_enabled
                                                {
                                                    core_ready = st
                                                        .start_local_core_only()
                                                        .await
                                                        .map(|(_, rep)| rep.ok)
                                                        .unwrap_or(false);
                                                }
                                            }
                                        }
                                    }
                                    StartupRestorePlan::LocalCoreOnly => {
                                        core_ready = st
                                            .start_local_core_only()
                                            .await
                                            .map(|(_, rep)| rep.ok)
                                            .unwrap_or(false);
                                    }
                                    StartupRestorePlan::None => {}
                                }

                                if core_ready && settings.system_proxy_enabled {
                                    if let Ok(guard) = st.netguard.lock() {
                                        if !guard.is_armed() {
                                            let _ = guard.enable_system_proxy(
                                                "127.0.0.1",
                                                settings.mixed_port,
                                            );
                                        }
                                    }
                                }

                                if core_ready {
                                    st.push_log(
                                        "INFO",
                                        if launched_via_autostart {
                                            "startup: auto-started GUI proxy session silently in background"
                                        } else {
                                            "startup: restored saved proxy preferences for GUI session"
                                        },
                                    );
                                }
                                let active =
                                    st.netguard.lock().map(|g| g.is_armed()).unwrap_or(false)
                                        || st.current_capture_mode() != CaptureMode::Off;
                                tray::update_tray_icon_state(&start_handle, active, false);
                                let _ = start_handle.emit("bypax-state-sync", ());
                            });
                        }
                    }
                }
            }

            // Auto-sync missing classic .srs binary rule-sets in the background on startup.
            let srs_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let Some(state) = srs_handle.try_state::<AppState>() else {
                    return;
                };
                let (missing_tags, proxy_port) = {
                    let Ok(store) = state.store.lock() else {
                        return;
                    };
                    let rules = store.list_rules().unwrap_or_default();
                    let settings = store.load_settings().unwrap_or_default();
                    let running = state.is_core_running();
                    let mut tags: Vec<String> = Vec::new();
                    for r in rules.iter().filter(|r| r.enabled) {
                        if let Some(ref tag) = r.rule_set {
                            let clean = tag.trim();
                            if !clean.is_empty()
                                && state.rule_cache.local_srs_path(clean).is_none()
                                && !tags.iter().any(|x| x == clean)
                            {
                                tags.push(clean.to_string());
                            }
                        }
                    }
                    (tags, if running { Some(settings.mixed_port) } else { None })
                };
                if missing_tags.is_empty() {
                    return;
                }
                let statuses = futures::future::join_all(
                    missing_tags
                        .iter()
                        .map(|tag| state.rule_cache.refresh_rule_set_auto(tag, proxy_port)),
                )
                .await;
                let synced = statuses
                    .iter()
                    .filter(|st| st.cached_locally && !st.fallback_mode)
                    .count();
                if synced > 0 {
                    state.push_log(
                        "INFO",
                        format!(
                            "rule-sets: auto-synced {}/{} .srs files",
                            synced,
                            missing_tags.len()
                        ),
                    );
                    let _ = state.reload_core_if_running_async().await;
                    let _ = srs_handle.emit("bypax-state-sync", ());
                }
            });

            // Background subscription auto-refresh scheduler honoring each group's `auto_update_hours`.
            let sub_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(25)).await;
                let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
                loop {
                    interval.tick().await;
                    let Some(state) = sub_handle.try_state::<AppState>() else {
                        continue;
                    };
                    let subs = match state.store.lock() {
                        Ok(s) => s.list_subscriptions().unwrap_or_default(),
                        Err(_) => continue,
                    };
                    let now = chrono::Utc::now();
                    let mut refreshed_any = false;
                    for sub in subs {
                        if sub.auto_update_hours == 0 {
                            continue;
                        }
                        let due = match sub
                            .last_updated
                            .as_deref()
                            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
                        {
                            Some(last) => {
                                let elapsed =
                                    now.signed_duration_since(last.with_timezone(&chrono::Utc));
                                elapsed >= chrono::Duration::hours(sub.auto_update_hours as i64)
                            }
                            None => true,
                        };
                        if !due {
                            continue;
                        }
                        let proxy_port = state.active_local_proxy_port();
                        let ua = format!("Bypax/{}", CURRENT_APP_VERSION);
                        let Ok((body, via)) =
                            fetch_text_via_channels(&sub.url, proxy_port, Some(&ua), None, 20)
                                .await
                        else {
                            continue;
                        };
                        let Ok(summary) = parse_payload(&body, &sub.name) else {
                            continue;
                        };
                        if summary.nodes.is_empty() {
                            continue;
                        }
                        let mut updated = sub.clone();
                        updated.last_updated = Some(chrono::Utc::now().to_rfc3339());
                        updated.node_count = summary.nodes.len();
                        if let Ok(mut store) = state.store.lock() {
                            if store
                                .replace_group_nodes(&updated.name, &summary.nodes)
                                .is_ok()
                                && store.upsert_subscription(&updated).is_ok()
                            {
                                state.push_log(
                                    "INFO",
                                    format!(
                                        "subscription: auto-refreshed [{}] ({} nodes via {})",
                                        updated.name, updated.node_count, via
                                    ),
                                );
                                refreshed_any = true;
                            }
                        }
                    }
                    if refreshed_any {
                        let _ = state.reload_core_if_running_async().await;
                        let _ = sub_handle.emit("bypax-state-sync", ());
                    }
                }
            });

            // Lightweight background collector: persists closed connections, keeps tray tooltip
            // and active/warn tray icon state updated even while minimized to tray.
            let bg_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                loop {
                    interval.tick().await;
                    let Some(state) = bg_handle.try_state::<AppState>() else {
                        continue;
                    };
                    let running = state.is_core_running();
                    // Fail-open guard: on Windows, if local sing-box dies unexpectedly while
                    // WinDivert App Proxy is capturing, immediately stop capture to prevent a blackhole.
                    if cfg!(target_os = "windows")
                        && state
                            .app_proxy_active
                            .load(std::sync::atomic::Ordering::Relaxed)
                        && !running
                    {
                        state
                            .app_proxy_active
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        let _ = state
                            .service_request(
                                bypax_ipc::ServiceCommand::StopAppProxy,
                                Duration::from_secs(2),
                            )
                            .await;
                        state.push_log(
                            "WARN",
                            "app-proxy: paused capture because local proxy core stopped unexpectedly",
                        );
                        let _ = bg_handle.emit("bypax-state-sync", ());
                    }

                    let capture = state.current_capture_mode();
                    let has_warn = state
                        .last_service_error
                        .lock()
                        .ok()
                        .and_then(|g| g.as_ref().map(|_| true))
                        .unwrap_or(false);
                    let (control_port, sys_proxy, main_node_name) = state
                        .store
                        .lock()
                        .ok()
                        .and_then(|store| {
                            let settings = store.load_settings().ok()?;
                            let nodes = store.list_nodes().ok().unwrap_or_default();
                            let chains = store.list_proxy_chains().ok().unwrap_or_default();
                            let active = settings
                                .main_node_id
                                .as_deref()
                                .and_then(|id| {
                                    if let Some(cid) = id.strip_prefix("chain:") {
                                        chains
                                            .iter()
                                            .find(|c| c.id == cid)
                                            .map(|c| c.name.clone())
                                    } else {
                                        nodes.iter().find(|n| n.id == id).map(|n| n.remark.clone())
                                    }
                                })
                                .or_else(|| nodes.first().map(|n| n.remark.clone()))
                                .unwrap_or_default();
                            Some((settings.control_port, settings.system_proxy_enabled, active))
                        })
                        .unwrap_or((9090, false, String::new()));

                    let takeover_active = sys_proxy || capture != CaptureMode::Off;
                    tray::update_tray_icon_state(&bg_handle, takeover_active, has_warn);

                    if running {
                        if let Ok(client) = ControlClient::new(control_port, &state.control_secret)
                        {
                            if let Ok((mut conns, _, _, _)) = client.get_connections().await {
                                let _ = state.enrich_connections_with_origins(&mut conns).await;
                                state.record_connections_snapshot(&conns);
                            }
                        }
                        let capture_suffix = match capture {
                            CaptureMode::Tun => " [TUN]",
                            CaptureMode::Apps => " [Apps]",
                            CaptureMode::Off => {
                                if sys_proxy {
                                    " [Proxy ON]"
                                } else {
                                    ""
                                }
                            }
                        };
                        let tip = if main_node_name.is_empty() {
                            format!("Bypax - Running{}", capture_suffix)
                        } else {
                            format!("Bypax - {}{}", main_node_name, capture_suffix)
                        };
                        tray::update_tray_tooltip(&bg_handle, &tip);
                    } else {
                        tray::update_tray_tooltip(&bg_handle, "Bypax - Stopped");
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_bootstrap_state,
            commands::import_nodes,
            commands::import_subscription,
            commands::refresh_subscription,
            commands::delete_subscription,
            commands::save_node,
            commands::delete_node,
            commands::select_main_node,
            commands::set_route_mode,
            commands::toggle_system_proxy,
            commands::toggle_tun,
            commands::set_capture_mode,
            commands::list_app_proxy_rules,
            commands::save_app_proxy_rule,
            commands::delete_app_proxy_rule,
            commands::reorder_app_proxy_rules,
            commands::list_app_presets,
            commands::toggle_app_preset,
            commands::test_app_proxy_rule,
            commands::list_running_processes,
            commands::list_installed_apps,
            commands::detect_external_children,
            commands::include_external_child,
            commands::ignore_external_child,
            commands::get_service_status,
            commands::probe_windivert_driver,
            commands::set_windivert_dir,
            commands::service_action,
            commands::open_windows_security,
            commands::get_cli_integration_info,
            commands::save_rule,
            commands::delete_rule,
            commands::list_rule_presets,
            commands::list_rule_sets,
            commands::apply_routing_strategy,
            commands::sync_rule_sets,
            commands::test_route_target,
            commands::save_inbound_port,
            commands::delete_inbound_port,
            commands::update_settings,
            commands::compile_preview,
            commands::run_preflight_check,
            commands::start_core,
            commands::stop_core,
            commands::check_core_update,
            commands::download_official_core,
            commands::import_core_binary,
            commands::check_app_update,
            commands::download_app_update,
            commands::cancel_app_update,
            commands::get_app_update_state,
            commands::consume_update_result,
            commands::restart_to_update,
            commands::open_external_url,
            commands::save_proxy_chain,
            commands::delete_proxy_chain,
            commands::test_proxy_chain_delay,
            commands::run_batch_real_delay,
            commands::get_live_monitor,
            commands::get_connection_history,
            commands::get_platform_traffic,
            commands::clear_connection_history,
            commands::close_connection,
            commands::close_all_connections,
            commands::open_logs_dir,
            commands::clear_logs,
            commands::restore_netguard_now,
            commands::hide_to_tray,
            commands::show_main_window,
            commands::hide_tray_popup,
            commands::quit_app,
        ])
        .build(tauri::generate_context!())
        .expect("Failed to build Bypax desktop application");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(guard) = app_handle.try_state::<CtlServerGuard>() {
                if let Ok(mut slot) = guard.0.lock() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(());
                    }
                }
            }
            if let Some(state) = app_handle.try_state::<AppState>() {
                state.shutdown_cleanly();
            }
        }
    });
}

fn clear_persisted_capture_flags(st: &AppState) {
    if let Ok(store) = st.store.lock() {
        if let Ok(mut updated) = store.load_settings() {
            if updated.app_proxy_enabled || updated.tun_enabled {
                updated.app_proxy_enabled = false;
                updated.tun_enabled = false;
                let _ = store.save_settings(&updated);
            }
        }
    }
}

fn log_startup_capture_fallback(st: &AppState, label: &str, err: &str) {
    if err.contains("UAC_CANCELLED") {
        st.push_log(
            "INFO",
            format!("startup: {label} elevation cancelled; fell back to capture off"),
        );
    } else {
        st.push_log(
            "WARN",
            format!("startup: {label} auto-restore failed ({err}); fell back to capture off"),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupRestorePlan {
    Tun,
    AppProxy,
    LocalCoreOnly,
    None,
}

fn select_startup_restore_plan(settings: &bypax_core::model::AppSettings) -> StartupRestorePlan {
    if settings.tun_enabled {
        StartupRestorePlan::Tun
    } else if settings.app_proxy_enabled {
        StartupRestorePlan::AppProxy
    } else if settings.auto_start_core || settings.system_proxy_enabled {
        StartupRestorePlan::LocalCoreOnly
    } else {
        StartupRestorePlan::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceConflictPayload {
    running_path: String,
    attempted_cwd: String,
}

fn clean_display_path(path: &std::path::Path) -> String {
    let raw = path.to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            return stripped.to_string();
        }
    }
    raw
}

fn normalize_dir_for_compare(path: &std::path::Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut s = resolved.to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    {
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            s = stripped.to_string();
        }
        s = s.replace('/', "\\");
        while s.len() > 3 && s.ends_with('\\') {
            s.pop();
        }
        s.to_ascii_lowercase()
    }
    #[cfg(not(target_os = "windows"))]
    {
        while s.len() > 1 && s.ends_with('/') {
            s.pop();
        }
        s
    }
}

fn is_generic_system_cwd(norm_dir: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        matches!(
            norm_dir,
            "c:\\windows\\system32" | "c:\\windows\\syswow64" | "c:\\windows"
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        norm_dir == "/"
    }
}

fn resolve_attempted_exe_dir(
    args: &[String],
    cwd: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let raw = args.first()?.trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = std::path::Path::new(raw);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else if candidate.components().count() > 1 {
        cwd.join(candidate)
    } else {
        let in_cwd = cwd.join(candidate);
        if in_cwd.is_file() {
            in_cwd
        } else {
            return None;
        }
    };
    resolved.parent().map(|p| p.to_path_buf())
}

fn detect_instance_path_conflict(
    running_exe: &std::path::Path,
    args: &[String],
    cwd: &str,
) -> Option<InstanceConflictPayload> {
    let running_dir = running_exe.parent()?;
    let norm_running = normalize_dir_for_compare(running_dir);
    let cwd_trimmed = cwd.trim();
    let cwd_path = std::path::Path::new(cwd_trimmed);

    if let Some(attempted_dir) = resolve_attempted_exe_dir(args, cwd_path) {
        let norm_attempted = normalize_dir_for_compare(&attempted_dir);
        if norm_attempted == norm_running {
            return None;
        }
        let reported_cwd = if cwd_trimmed.is_empty() {
            clean_display_path(&attempted_dir)
        } else {
            cwd_trimmed.to_string()
        };
        return Some(InstanceConflictPayload {
            running_path: clean_display_path(running_exe),
            attempted_cwd: reported_cwd,
        });
    }

    if cwd_trimmed.is_empty() {
        return None;
    }

    let norm_cwd = normalize_dir_for_compare(cwd_path);
    if norm_cwd == norm_running {
        return None;
    }

    let exe_name = if cfg!(target_os = "windows") {
        "bypax.exe"
    } else {
        "bypax"
    };
    let cwd_contains_exe = cwd_path.join(exe_name).is_file();
    if !cwd_contains_exe && is_generic_system_cwd(&norm_cwd) {
        return None;
    }

    Some(InstanceConflictPayload {
        running_path: clean_display_path(running_exe),
        attempted_cwd: cwd_trimmed.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bypax_core::model::AppSettings;
    use std::path::PathBuf;

    #[test]
    fn startup_restore_plan_eliminates_double_start_for_app_proxy() {
        let mut s = AppSettings {
            tun_enabled: false,
            app_proxy_enabled: true,
            auto_start_core: true,
            system_proxy_enabled: true,
            ..AppSettings::default()
        };
        assert_eq!(select_startup_restore_plan(&s), StartupRestorePlan::AppProxy);

        s.tun_enabled = true;
        assert_eq!(select_startup_restore_plan(&s), StartupRestorePlan::Tun);

        s.tun_enabled = false;
        s.app_proxy_enabled = false;
        assert_eq!(
            select_startup_restore_plan(&s),
            StartupRestorePlan::LocalCoreOnly
        );

        s.auto_start_core = false;
        s.system_proxy_enabled = false;
        assert_eq!(select_startup_restore_plan(&s), StartupRestorePlan::None);
    }

    #[test]
    fn single_instance_conflict_ignores_same_dir_and_same_binary() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_a = tmp.path().join("BypaxA");
        let dir_b = tmp.path().join("BypaxB");
        std::fs::create_dir_all(&dir_a).expect("mkdir a");
        std::fs::create_dir_all(&dir_b).expect("mkdir b");
        let exe_name = if cfg!(target_os = "windows") {
            "bypax.exe"
        } else {
            "bypax"
        };
        let exe_a = dir_a.join(exe_name);
        std::fs::write(&exe_a, b"stub").expect("write exe a");

        // Same directory -> no conflict.
        assert_eq!(
            detect_instance_path_conflict(&exe_a, &[], &dir_a.to_string_lossy()),
            None
        );

        // Trailing separator (and case variation on Windows) -> no conflict.
        let mut same_variant = dir_a.to_string_lossy().to_string();
        if cfg!(target_os = "windows") {
            same_variant = format!("{}\\", same_variant.to_ascii_lowercase());
        } else {
            same_variant = format!("{}/", same_variant);
        }
        assert_eq!(detect_instance_path_conflict(&exe_a, &[], &same_variant), None);

        // Same executable launched from another working directory -> no conflict.
        let args_same = vec![exe_a.to_string_lossy().to_string()];
        assert_eq!(
            detect_instance_path_conflict(&exe_a, &args_same, &dir_b.to_string_lossy()),
            None
        );

        // Empty cwd and empty args -> no conflict.
        assert_eq!(detect_instance_path_conflict(&exe_a, &[], "   "), None);
    }

    #[test]
    fn single_instance_conflict_detects_different_folder_and_serializes_payload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir_a = tmp.path().join("BypaxMain");
        let dir_b = tmp.path().join("BypaxPortable");
        std::fs::create_dir_all(&dir_a).expect("mkdir a");
        std::fs::create_dir_all(&dir_b).expect("mkdir b");
        let exe_name = if cfg!(target_os = "windows") {
            "bypax.exe"
        } else {
            "bypax"
        };
        let exe_a = dir_a.join(exe_name);
        let exe_b = dir_b.join(exe_name);
        std::fs::write(&exe_a, b"stub-a").expect("write exe a");
        std::fs::write(&exe_b, b"stub-b").expect("write exe b");

        let conflict = detect_instance_path_conflict(&exe_a, &[], &dir_b.to_string_lossy())
            .expect("expected conflict for distinct portable dir");
        assert_eq!(conflict.running_path, clean_display_path(&exe_a));
        assert_eq!(conflict.attempted_cwd, dir_b.to_string_lossy());

        let json_val = serde_json::to_value(&conflict).expect("serialize payload");
        assert_eq!(json_val["runningPath"], clean_display_path(&exe_a));
        assert_eq!(json_val["attemptedCwd"], dir_b.to_string_lossy().as_ref());

        // Distinct binary passed in args[0] even from a third cwd -> conflict.
        let dir_c = tmp.path().join("NeutralCwd");
        std::fs::create_dir_all(&dir_c).expect("mkdir c");
        let args_b = vec![exe_b.to_string_lossy().to_string()];
        let conflict_args =
            detect_instance_path_conflict(&exe_a, &args_b, &dir_c.to_string_lossy())
                .expect("expected conflict when args[0] points to another binary");
        assert_eq!(conflict_args.attempted_cwd, dir_c.to_string_lossy());
    }

    #[test]
    fn single_instance_conflict_ignores_generic_system_cwd_without_binary() {
        let running = if cfg!(target_os = "windows") {
            PathBuf::from(r"D:\Bypax\bypax.exe")
        } else {
            PathBuf::from("/opt/bypax/bypax")
        };
        let generic_cwd = if cfg!(target_os = "windows") {
            r"C:\Windows\System32"
        } else {
            "/"
        };
        assert_eq!(
            detect_instance_path_conflict(&running, &[], generic_cwd),
            None
        );
    }
}
