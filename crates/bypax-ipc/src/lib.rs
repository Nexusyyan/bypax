pub mod ctl_proto;
pub mod service_proto;
pub mod transport;

use rand::RngCore;
use std::path::{Path, PathBuf};

/// Plane 1 Windows Named Pipe endpoint protected by local-interactive SDDL ACL.
pub const WINDOWS_SVC_PIPE_NAME: &str = r"\\.\pipe\bypax-svc-v1";

/// Plane 1 Unix Domain Socket endpoint for macOS/Linux privileged daemon.
pub const UNIX_SVC_SOCKET_PATH: &str = "/var/run/bypax-svc.sock";

/// Plane 2 Windows Named Pipe endpoint hosted by the non-elevated desktop GUI for CLI/MCP control.
pub const WINDOWS_CTL_PIPE_NAME: &str = r"\\.\pipe\bypax-ctl-v1";

/// Plane 2 Unix Domain Socket filename inside the user's runtime directory (`0600`).
pub const UNIX_CTL_SOCKET_NAME: &str = "bypax-ctl.sock";

/// Environment variable overriding the shared 64-hex Plane 1 IPC session token.
pub const IPC_TOKEN_ENV: &str = "BYPAX_IPC_TOKEN";

/// Explicit SDDL granting Full Control to LocalSystem (SY) and Builtin Administrators (BA),
/// and Read/Write only to local Interactive Users (IU), rejecting remote callers.
pub const WINDOWS_PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Default GUI heartbeat watchdog timeout (seconds) before the service stops core/app-proxy
/// and triggers NetGuard rollback.
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 15;

pub use ctl_proto::{CtlEnvelope, CtlRequest, CtlResponse};
pub use service_proto::{
    AppProxyLocalConnectionDto, AppProxyLocalStatsDto, AppProxyRuleWire, AppProxyStartConfig,
    AppProxyStatusDto, AppProxyTargetBinding, CoreStatusDto, DomainOverrideWire, DriverProbeDto,
    FlowOriginDto, IpcEnvelope, IpcResponse, ProcessInfoDto, ServiceCommand, ServiceEnvelope,
    ServiceResponse,
};
pub use transport::{
    send_ctl_request, send_service_request, CtlHandler, CtlIpcServer, PipeAclMode, ServiceHandler,
    ServiceIpcServer,
};

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn default_svc_endpoint() -> String {
    #[cfg(windows)]
    {
        WINDOWS_SVC_PIPE_NAME.to_string()
    }
    #[cfg(not(windows))]
    {
        UNIX_SVC_SOCKET_PATH.to_string()
    }
}

pub fn default_ctl_endpoint(runtime_dir: &Path) -> String {
    #[cfg(windows)]
    {
        let _ = runtime_dir;
        WINDOWS_CTL_PIPE_NAME.to_string()
    }
    #[cfg(not(windows))]
    {
        runtime_dir
            .join(UNIX_CTL_SOCKET_NAME)
            .to_string_lossy()
            .to_string()
    }
}

/// Returns candidate paths for the persisted Plane 1 shared IPC token file.
pub fn ipc_token_candidates(runtime_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = runtime_dir {
        out.push(dir.join("ipc.token"));
    }
    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("ProgramData") {
            out.push(PathBuf::from(program_data).join("Bypax").join("ipc.token"));
        }
    }
    #[cfg(not(windows))]
    {
        out.push(PathBuf::from("/var/run/bypax-svc.token"));
        if let Ok(home) = std::env::var("HOME") {
            out.push(
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("Bypax")
                    .join("runtime")
                    .join("ipc.token"),
            );
        }
    }
    out
}

/// Loads the Plane 1 session token from `BYPAX_IPC_TOKEN` or a shared token file.
pub fn load_ipc_token(runtime_dir: Option<&Path>) -> Option<String> {
    if let Ok(env_val) = std::env::var(IPC_TOKEN_ENV) {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    for cand in ipc_token_candidates(runtime_dir) {
        if let Ok(raw) = std::fs::read_to_string(&cand) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Loads or creates a persistent Plane 1 session token file.
pub fn resolve_or_create_ipc_token(runtime_dir: Option<&Path>) -> String {
    if let Some(existing) = load_ipc_token(runtime_dir) {
        return existing;
    }
    let token = generate_session_token();
    for cand in ipc_token_candidates(runtime_dir) {
        if let Some(parent) = cand.parent() {
            if std::fs::create_dir_all(parent).is_ok() && std::fs::write(&cand, &token).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&cand, std::fs::Permissions::from_mode(0o644));
                }
                break;
            }
        }
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_service_and_ctl_envelopes() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        assert!(WINDOWS_PIPE_SDDL.contains("SY") && WINDOWS_PIPE_SDDL.contains("IU"));

        let env = ServiceEnvelope {
            id: "req-1".to_string(),
            session_token: t1,
            command: ServiceCommand::Heartbeat { gui_pid: 4242 },
        };
        let encoded = serde_json::to_string(&env).expect("serialize service envelope");
        let parsed: ServiceEnvelope =
            serde_json::from_str(&encoded).expect("deserialize service envelope");
        assert_eq!(parsed, env);

        let ctl = CtlEnvelope {
            id: "ctl-1".to_string(),
            request: CtlRequest::SetCaptureMode {
                mode: "apps".to_string(),
            },
        };
        let enc_ctl = serde_json::to_string(&ctl).expect("serialize ctl envelope");
        let dec_ctl: CtlEnvelope =
            serde_json::from_str(&enc_ctl).expect("deserialize ctl envelope");
        assert_eq!(dec_ctl, ctl);
    }
}
