use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_NAME: &str = "BypaxService";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatusReport {
    pub platform: String,
    pub service_name: String,
    pub installed: bool,
    pub running: bool,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
}

/// Resolves the sibling `bypax-service` binary next to `bypax-cli`.
pub fn resolve_service_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        bail!("Specified service binary does not exist: {}", p.display());
    }

    let bin_name = if cfg!(windows) {
        "bypax-service.exe"
    } else {
        "bypax-service"
    };

    if let Ok(cur) = std::env::current_exe() {
        if let Some(parent) = cur.parent() {
            let sibling = parent.join(bin_name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }

    let cwd_cand = PathBuf::from(bin_name);
    if cwd_cand.is_file() {
        return Ok(cwd_cand);
    }

    Err(anyhow!(
        "Could not locate '{}' next to bypax-cli; pass --service-exe <path>",
        bin_name
    ))
}

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
pub fn query_os_service_status() -> ServiceStatusReport {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_PAUSE_PENDING, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
        SERVICE_STOP_PENDING,
    };

    let binary_path = resolve_service_binary(None)
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let svc_wide = to_wide_null(SERVICE_NAME);
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) else {
            return ServiceStatusReport {
                platform: "windows".to_string(),
                service_name: SERVICE_NAME.to_string(),
                installed: false,
                running: false,
                state: "unknown".to_string(),
                binary_path,
            };
        };
        let Ok(svc) = OpenServiceW(scm, PCWSTR(svc_wide.as_ptr()), SERVICE_QUERY_STATUS) else {
            let _ = CloseServiceHandle(scm);
            return ServiceStatusReport {
                platform: "windows".to_string(),
                service_name: SERVICE_NAME.to_string(),
                installed: false,
                running: false,
                state: "not_installed".to_string(),
                binary_path,
            };
        };
        let mut status = SERVICE_STATUS::default();
        let report = if QueryServiceStatus(svc, &mut status).is_ok() {
            let (running, state) = match status.dwCurrentState {
                SERVICE_RUNNING => (true, "running"),
                SERVICE_START_PENDING => (false, "start_pending"),
                SERVICE_STOP_PENDING => (false, "stop_pending"),
                SERVICE_STOPPED => (false, "stopped"),
                SERVICE_PAUSED => (false, "paused"),
                SERVICE_PAUSE_PENDING => (false, "pause_pending"),
                SERVICE_CONTINUE_PENDING => (false, "continue_pending"),
                _ => (false, "unknown"),
            };
            ServiceStatusReport {
                platform: "windows".to_string(),
                service_name: SERVICE_NAME.to_string(),
                installed: true,
                running,
                state: state.to_string(),
                binary_path,
            }
        } else {
            ServiceStatusReport {
                platform: "windows".to_string(),
                service_name: SERVICE_NAME.to_string(),
                installed: true,
                running: false,
                state: "unknown".to_string(),
                binary_path,
            }
        };
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        report
    }
}

#[cfg(target_os = "macos")]
pub fn query_os_service_status() -> ServiceStatusReport {
    let plist = Path::new("/Library/LaunchDaemons/com.bypax.service.plist");
    let installed = plist.is_file();
    let running = if installed {
        Command::new("launchctl")
            .args(["print", "system/com.bypax.service"])
            .output()
            .map(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout).contains("state = running")
            })
            .unwrap_or(false)
    } else {
        false
    };
    let state = if !installed {
        "not_installed"
    } else if running {
        "running"
    } else {
        "stopped"
    };
    ServiceStatusReport {
        platform: "macos".to_string(),
        service_name: "com.bypax.service".to_string(),
        installed,
        running,
        state: state.to_string(),
        binary_path: resolve_service_binary(None)
            .ok()
            .map(|p| p.to_string_lossy().to_string()),
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
pub fn query_os_service_status() -> ServiceStatusReport {
    ServiceStatusReport {
        platform: std::env::consts::OS.to_string(),
        service_name: "bypax-service".to_string(),
        installed: false,
        running: false,
        state: "unsupported".to_string(),
        binary_path: resolve_service_binary(None)
            .ok()
            .map(|p| p.to_string_lossy().to_string()),
    }
}

/// Delegates `install` / `uninstall` / `start` / `stop` to the sibling `bypax-service` binary.
pub fn run_service_subcommand(
    action: &str,
    service_exe_override: Option<&Path>,
) -> Result<String> {
    let svc_bin = resolve_service_binary(service_exe_override)?;
    let mapped_arg = if cfg!(target_os = "macos") {
        match action {
            "install" => "install-launchd",
            "uninstall" => "uninstall-launchd",
            other => other,
        }
    } else {
        action
    };

    let output = Command::new(&svc_bin)
        .arg(mapped_arg)
        .output()
        .with_context(|| format!("Failed to invoke {} {}", svc_bin.display(), mapped_arg))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit code {:?}", output.status.code())
        };
        bail!(
            "bypax-service {} failed (Administrator/root privileges may be required): {}",
            mapped_arg,
            detail
        );
    }

    if !stdout.is_empty() {
        Ok(stdout)
    } else {
        Ok(format!(
            "Service command '{}' completed successfully",
            mapped_arg
        ))
    }
}
