use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const WINDOWS_SERVICE_NAME: &str = "BypaxService";
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = "Bypax Privileged Proxy Service";
pub const WINDOWS_SERVICE_DESCRIPTION: &str =
    "Privileged WinDivert per-app proxy and TUN supervisor for Bypax.";

pub const MACOS_LAUNCHD_LABEL: &str = "com.bypax.service";
pub const MACOS_LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.bypax.service.plist";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformServiceStatus {
    pub platform: String,
    pub installed: bool,
    pub running: bool,
    pub state: String,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::controller::ServiceController;
    use anyhow::{anyhow, Context};
    use bypax_core::storage::DataPaths;
    use bypax_ipc::{
        default_svc_endpoint, resolve_or_create_ipc_token, PipeAclMode, ServiceIpcServer,
    };
    use std::ffi::OsString;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tracing::{error, info};
    use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    pub fn is_parent_alive(pid: u32) -> bool {
        if pid <= 4 {
            return false;
        }
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                return false;
            };
            let mut exit_code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut exit_code).is_ok();
            let _ = CloseHandle(handle);
            ok && exit_code == STILL_ACTIVE.0 as u32
        }
    }

    pub fn query_status() -> PlatformServiceStatus {
        let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        else {
            return PlatformServiceStatus {
                platform: "windows".into(),
                installed: false,
                running: false,
                state: "unknown".into(),
            };
        };
        let Ok(service) = manager.open_service(WINDOWS_SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        else {
            return PlatformServiceStatus {
                platform: "windows".into(),
                installed: false,
                running: false,
                state: "not_installed".into(),
            };
        };
        match service.query_status() {
            Ok(st) => {
                let (running, state) = match st.current_state {
                    ServiceState::Running => (true, "running"),
                    ServiceState::StartPending => (false, "start_pending"),
                    ServiceState::StopPending => (false, "stop_pending"),
                    ServiceState::Stopped => (false, "stopped"),
                    ServiceState::Paused => (false, "paused"),
                    ServiceState::PausePending => (false, "pause_pending"),
                    ServiceState::ContinuePending => (false, "continue_pending"),
                };
                PlatformServiceStatus {
                    platform: "windows".into(),
                    installed: true,
                    running,
                    state: state.into(),
                }
            }
            Err(_) => PlatformServiceStatus {
                platform: "windows".into(),
                installed: true,
                running: false,
                state: "unknown".into(),
            },
        }
    }

    pub fn install(service_exe: &Path, autostart: bool) -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("failed to open Windows SCM (Administrator privileges required)")?;

        let start_type = if autostart {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::OnDemand
        };

        let info = ServiceInfo {
            name: OsString::from(WINDOWS_SERVICE_NAME),
            display_name: OsString::from(WINDOWS_SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type,
            error_control: ServiceErrorControl::Normal,
            executable_path: service_exe.to_path_buf(),
            launch_arguments: vec![OsString::from("service-run")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        // If already installed, update config cleanly; otherwise create fresh service.
        if let Ok(existing) = manager.open_service(
            WINDOWS_SERVICE_NAME,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        ) {
            existing
                .change_config(&info)
                .context("failed to update existing BypaxService configuration")?;
            let _ = existing.set_description(WINDOWS_SERVICE_DESCRIPTION);
            return Ok(());
        }

        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("failed to create BypaxService")?;
        let _ = service.set_description(WINDOWS_SERVICE_DESCRIPTION);
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("failed to open Windows SCM (Administrator privileges required)")?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
            )
            .context("BypaxService is not installed or access was denied")?;

        if let Ok(st) = service.query_status() {
            if st.current_state != ServiceState::Stopped {
                let _ = service.stop();
                for _ in 0..20 {
                    std::thread::sleep(Duration::from_millis(250));
                    if let Ok(s) = service.query_status() {
                        if s.current_state == ServiceState::Stopped {
                            break;
                        }
                    }
                }
            }
        }
        service.delete().context("failed to delete BypaxService")?;
        Ok(())
    }

    pub fn start() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("failed to open Windows SCM (Administrator privileges required)")?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .context("BypaxService is not installed or access was denied")?;
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Running {
                return Ok(());
            }
        }
        service
            .start::<&str>(&[])
            .context("failed to start BypaxService")?;
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("failed to open Windows SCM (Administrator privileges required)")?;
        let service = manager
            .open_service(
                WINDOWS_SERVICE_NAME,
                ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
            )
            .context("BypaxService is not installed or access was denied")?;
        if let Ok(st) = service.query_status() {
            if st.current_state == ServiceState::Stopped {
                return Ok(());
            }
        }
        service.stop().context("failed to stop BypaxService")?;
        Ok(())
    }

    pub fn run_windows_service() -> Result<()> {
        service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
            .map_err(|err| anyhow!("Windows Service dispatcher failed: {err}"))
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service_inner() {
            error!(error = %err, "BypaxService terminated with error");
        }
    }

    fn run_service_inner() -> Result<()> {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let stop_slot = Mutex::new(Some(stop_tx));

        let status_handle =
            service_control_handler::register(WINDOWS_SERVICE_NAME, move |control_event| {
                match control_event {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        if let Ok(mut guard) = stop_slot.lock() {
                            if let Some(tx) = guard.take() {
                                let _ = tx.send(());
                            }
                        }
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async {
            let paths = DataPaths::resolve()?;
            let token = resolve_or_create_ipc_token(Some(&paths.runtime_dir));
            let controller = ServiceController::new(&paths, token);
            let _watchdog = controller.spawn_watchdog();

            let (ipc_tx, ipc_rx) = oneshot::channel();
            let server = ServiceIpcServer::new(
                default_svc_endpoint(),
                PipeAclMode::PrivilegedService,
                controller.clone(),
            );
            let ipc_task = tokio::spawn(async move {
                if let Err(err) = server.run(ipc_rx).await {
                    error!(error = %err, "BypaxService IPC server exited with error");
                }
            });

            status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            info!("BypaxService is running");

            let _ = stop_rx.await;

            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StopPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            });

            controller.stop_all_and_restore().await;
            let _ = ipc_tx.send(());
            let _ = ipc_task.await;
            Ok::<(), anyhow::Error>(())
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    pub fn install_launchd(_service_exe: &Path) -> Result<()> {
        anyhow::bail!("launchd installation is only available on macOS")
    }

    pub fn uninstall_launchd() -> Result<()> {
        anyhow::bail!("launchd uninstallation is only available on macOS")
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use anyhow::Context;
    use std::process::Command;

    pub fn is_parent_alive(pid: u32) -> bool {
        if pid <= 1 {
            return false;
        }
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    pub fn query_status() -> PlatformServiceStatus {
        let installed = Path::new(MACOS_LAUNCHD_PLIST_PATH).exists();
        let running = Command::new("launchctl")
            .args(["print", &format!("system/{MACOS_LAUNCHD_LABEL}")])
            .output()
            .map(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout).contains("state = running")
            })
            .unwrap_or(false);
        let state = if running {
            "running"
        } else if installed {
            "stopped"
        } else {
            "not_installed"
        };
        PlatformServiceStatus {
            platform: "macos".into(),
            installed,
            running,
            state: state.into(),
        }
    }

    pub fn install_launchd(service_exe: &Path) -> Result<()> {
        let escaped = service_exe
            .to_string_lossy()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>{MACOS_LAUNCHD_LABEL}</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
    <string>{escaped}</string>\n\
    <string>daemon-run</string>\n\
  </array>\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
</dict>\n\
</plist>\n"
        );
        std::fs::write(MACOS_LAUNCHD_PLIST_PATH, plist)
            .context("failed to write LaunchDaemon plist (root privileges required)")?;
        let _ = Command::new("chown")
            .args(["root:wheel", MACOS_LAUNCHD_PLIST_PATH])
            .status();
        let _ = Command::new("chmod")
            .args(["644", MACOS_LAUNCHD_PLIST_PATH])
            .status();
        let _ = Command::new("launchctl")
            .args(["bootout", "system", MACOS_LAUNCHD_PLIST_PATH])
            .status();
        let status = Command::new("launchctl")
            .args(["bootstrap", "system", MACOS_LAUNCHD_PLIST_PATH])
            .status()
            .context("failed to bootstrap macOS LaunchDaemon")?;
        if !status.success() {
            anyhow::bail!("launchctl bootstrap failed with status {status}");
        }
        Ok(())
    }

    pub fn uninstall_launchd() -> Result<()> {
        let _ = Command::new("launchctl")
            .args(["bootout", "system", MACOS_LAUNCHD_PLIST_PATH])
            .status();
        if Path::new(MACOS_LAUNCHD_PLIST_PATH).exists() {
            std::fs::remove_file(MACOS_LAUNCHD_PLIST_PATH)
                .context("failed to remove LaunchDaemon plist")?;
        }
        Ok(())
    }

    pub fn install(service_exe: &Path, _autostart: bool) -> Result<()> {
        install_launchd(service_exe)
    }

    pub fn uninstall() -> Result<()> {
        uninstall_launchd()
    }

    pub fn start() -> Result<()> {
        let status = Command::new("launchctl")
            .args(["kickstart", "-k", &format!("system/{MACOS_LAUNCHD_LABEL}")])
            .status()
            .context("failed to kickstart LaunchDaemon")?;
        if !status.success() {
            anyhow::bail!("launchctl kickstart failed with status {status}");
        }
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let _ = Command::new("launchctl")
            .args(["bootout", "system", MACOS_LAUNCHD_PLIST_PATH])
            .status();
        Ok(())
    }

    pub fn run_windows_service() -> Result<()> {
        anyhow::bail!("service-run is only available on Windows; use daemon-run on macOS")
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;

    pub fn is_parent_alive(pid: u32) -> bool {
        if pid <= 1 {
            return false;
        }
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    pub fn query_status() -> PlatformServiceStatus {
        PlatformServiceStatus {
            platform: std::env::consts::OS.into(),
            installed: false,
            running: false,
            state: "manual".into(),
        }
    }

    pub fn install(_: &Path, _: bool) -> Result<()> {
        anyhow::bail!("use daemon-run or systemd unit on Linux")
    }
    pub fn uninstall() -> Result<()> {
        anyhow::bail!("use systemd on Linux")
    }
    pub fn start() -> Result<()> {
        anyhow::bail!("use daemon-run or systemd on Linux")
    }
    pub fn stop() -> Result<()> {
        anyhow::bail!("use systemd on Linux")
    }
    pub fn run_windows_service() -> Result<()> {
        anyhow::bail!("service-run is only available on Windows")
    }
    pub fn install_launchd(_: &Path) -> Result<()> {
        anyhow::bail!("launchd is only available on macOS")
    }
    pub fn uninstall_launchd() -> Result<()> {
        anyhow::bail!("launchd is only available on macOS")
    }
}

pub use platform::{
    install, install_launchd, is_parent_alive, query_status, run_windows_service, start, stop,
    uninstall, uninstall_launchd,
};
