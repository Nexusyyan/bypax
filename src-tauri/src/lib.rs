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
    tracing_subscriber::fmt::init();

    let app_state = AppState::initialize().expect("Failed to initialize Bypax state");

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.unminimize();
                let _ = win.set_focus();
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

            // 5-second heartbeat task feeding bypax-service's 15-second GUI watchdog.
            let hb_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    if let Some(st) = hb_handle.try_state::<AppState>() {
                        st.send_service_heartbeat().await;
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
                    } else if resume_app_proxy_flag {
                        restored_ok = st.apply_capture_mode(CaptureMode::Apps).await.is_ok();
                    } else if resume_core_flag {
                        restored_ok = st
                            .start_core_flow()
                            .await
                            .map(|(_, rep)| rep.ok)
                            .unwrap_or(false);
                    }

                    if resume_sys_proxy_flag {
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
                                resume_app_proxy_flag,
                                resume_tun_flag
                            ),
                        );
                        tray::update_tray_icon_state(
                            &resume_handle,
                            resume_sys_proxy_flag || resume_app_proxy_flag || resume_tun_flag,
                            false,
                        );
                        let _ = resume_handle.emit("bypax-state-sync", ());
                    }
                });
            } else if launched_via_autostart {
                if let Some(state) = app.try_state::<AppState>() {
                    let startup_cfg = state.store.lock().ok().and_then(|s| {
                        let settings = s.load_settings().ok()?;
                        let has_nodes = !s.list_nodes().unwrap_or_default().is_empty();
                        Some((settings, has_nodes))
                    });
                    if let Some((settings, has_nodes)) = startup_cfg {
                        if settings.minimize_to_tray {
                            if let Some(win) = app.get_webview_window("main") {
                                let _ = win.hide();
                            }
                        }
                        if settings.auto_start_core
                            && has_nodes
                            && state.core_manager.is_installed()
                        {
                            let start_handle = app.handle().clone();
                            tauri::async_runtime::spawn(async move {
                                let Some(st) = start_handle.try_state::<AppState>() else {
                                    return;
                                };
                                let started_ok = if settings.tun_enabled {
                                    st.apply_capture_mode(CaptureMode::Tun).await.is_ok()
                                } else if settings.app_proxy_enabled {
                                    st.apply_capture_mode(CaptureMode::Apps).await.is_ok()
                                } else {
                                    st.start_core_flow()
                                        .await
                                        .map(|(_, rep)| rep.ok)
                                        .unwrap_or(false)
                                };
                                if started_ok {
                                    if settings.system_proxy_enabled {
                                        if let Ok(guard) = st.netguard.lock() {
                                            let _ = guard.enable_system_proxy(
                                                "127.0.0.1",
                                                settings.mixed_port,
                                            );
                                        }
                                    }
                                    st.push_log(
                                        "INFO",
                                        "autostart: core started silently in background",
                                    );
                                    let active = settings.system_proxy_enabled
                                        || st.current_capture_mode() != CaptureMode::Off;
                                    tray::update_tray_icon_state(&start_handle, active, false);
                                    let _ = start_handle.emit("bypax-state-sync", ());
                                }
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
                let mut synced = 0usize;
                for tag in &missing_tags {
                    let st = state.rule_cache.refresh_rule_set_auto(tag, proxy_port).await;
                    if st.cached_locally && !st.fallback_mode {
                        synced += 1;
                    }
                }
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
                            let active = settings
                                .main_node_id
                                .as_deref()
                                .and_then(|id| nodes.iter().find(|n| n.id == id))
                                .or_else(|| nodes.first())
                                .map(|n| n.remark.clone())
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
            commands::run_batch_tcping,
            commands::run_batch_real_delay,
            commands::get_live_monitor,
            commands::get_connection_history,
            commands::get_platform_traffic,
            commands::clear_connection_history,
            commands::close_connection,
            commands::close_all_connections,
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
