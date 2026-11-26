use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_follow() -> String {
    "follow".to_string()
}

fn default_proxy_action() -> String {
    "proxy".to_string()
}

/// Wire representation of a per-domain L7 override attached to an application rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainOverrideWire {
    pub pattern: String,
    #[serde(default = "default_proxy_action")]
    pub action: String, // "proxy" | "direct" | "reject"
}

/// Wire representation of an application proxy rule synchronized to `bypax-service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyRuleWire {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub path_contains: Vec<String>,
    #[serde(default)]
    pub mac_bundle_paths: Vec<String>,
    #[serde(default)]
    pub ignored_external_children: Vec<String>,
    #[serde(default = "default_true")]
    pub include_children: bool,
    #[serde(default)]
    pub domains: Vec<DomainOverrideWire>,
    #[serde(default)]
    pub dst_cidrs: Vec<String>,
    #[serde(default)]
    pub dst_ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default = "default_follow")]
    pub target: String,
}

/// Maps a logical rule target (for example `"follow"`, `"main"`, `"auto:US"`, `"node:n-1"`)
/// to its compiled loopback SOCKS5 `auth_user` username (or local `"direct"` / `"reject"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyTargetBinding {
    pub target: String,
    pub auth_user: String,
    pub local_action: Option<String>, // None => proxy via auth_user; Some("direct" | "reject")
}

/// Full runtime configuration pushed from GUI/CLI to `bypax-service` to start or reload App Proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyStartConfig {
    pub app_proxy_port: u16,
    pub control_secret: String,
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    #[serde(default = "default_true")]
    pub block_quic_when_needed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windivert_dir: Option<String>,
    #[serde(default)]
    pub exempt_pids: Vec<u32>,
    #[serde(default)]
    pub rules: Vec<AppProxyRuleWire>,
    #[serde(default)]
    pub target_bindings: Vec<AppProxyTargetBinding>,
}

/// Real process & rule origin registered for an ephemeral local port dialing `app-proxy-in`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowOriginDto {
    pub local_port: u16,
    pub pid: u32,
    pub process_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancestor_name: Option<String>,
    #[serde(default)]
    pub ancestor_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub target: String,
    pub auth_user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffed_host: Option<String>,
    pub action: String, // "proxy" | "direct" | "reject"
    #[serde(default)]
    pub expired: bool,
}

/// Non-proxied connection handled locally by `bypax-appproxy` (local direct or local reject),
/// reported separately from `sing-box` connections for zero double-counting telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyLocalConnectionDto {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub process_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancestor_app: Option<String>,
    #[serde(default)]
    pub ancestor_chain: Vec<String>,
    pub destination: String,
    pub rule_name: String,
    pub local_action: String, // "local_direct" | "local_reject"
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub started_at: String,
    pub active: bool,
}

/// De-duplicated statistics reported by `bypax-appproxy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyLocalStatsDto {
    pub local_direct_bytes_tx: u64,
    pub local_direct_bytes_rx: u64,
    pub local_direct_connections: u64,
    pub local_reject_connections: u64,
    pub proxied_connections: u64,
    pub active_proxied_connections: u64,
    #[serde(default)]
    pub local_connections: Vec<AppProxyLocalConnectionDto>,
}

/// Driver / platform backend probe report returned by `ProbeDriver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverProbeDto {
    pub platform: String,
    pub elevated: bool,
    pub dll_loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll_path: Option<String>,
    pub driver_opened: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
}

/// Running OS process snapshot with ancestor lineage for GUI Process Picker & CLI `ps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfoDto {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub ancestor_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_name: Option<String>,
}

/// Status of the privileged `sing-box` supervisor hosted inside `bypax-service`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatusDto {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub tun_active: bool,
    pub capture_mode: String, // "off" | "apps" | "tun"
}

/// Live status of the WinDivert / App Proxy engine inside `bypax-service`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProxyStatusDto {
    pub running: bool,
    pub mode: String, // "windivert_zero_tun" | "macos_utun_path" | "inactive"
    pub active_rules: usize,
    #[serde(default)]
    pub exempt_pids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(default)]
    pub stats: AppProxyLocalStatsDto,
}

/// Plane 1 authenticated RPC envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEnvelope {
    pub id: String,
    pub session_token: String,
    pub command: ServiceCommand,
}

pub type IpcEnvelope = ServiceEnvelope;

/// Plane 1 command set handled by `bypax-service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum ServiceCommand {
    Ping,
    Heartbeat {
        gui_pid: u32,
    },
    StartCore {
        sing_box_path: String,
        config_json: String,
        #[serde(default)]
        tun_mode: bool,
    },
    StopCore,
    CoreStatus,
    StartAppProxy {
        config: AppProxyStartConfig,
    },
    StopAppProxy,
    ReloadAppProxy {
        config: AppProxyStartConfig,
    },
    AppProxyStatus,
    LookupAppProxyOrigins {
        local_ports: Vec<u16>,
    },
    ProbeDriver {
        #[serde(default)]
        windivert_dir: Option<String>,
    },
    ListProcesses {
        #[serde(default)]
        filter: Option<String>,
    },
    RestoreNetwork,
    Shutdown,
}

/// Plane 1 response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResponse {
    pub id: String,
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_status: Option<CoreStatusDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_proxy_status: Option<AppProxyStatusDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<FlowOriginDto>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<DriverProbeDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessInfoDto>>,
}

pub type IpcResponse = ServiceResponse;

impl ServiceResponse {
    pub fn success(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: true,
            message: message.into(),
            version: None,
            service_pid: None,
            elevated: None,
            core_running: None,
            core_pid: None,
            core_status: None,
            app_proxy_status: None,
            origins: None,
            driver: None,
            processes: None,
        }
    }

    pub fn error(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: false,
            message: message.into(),
            version: None,
            service_pid: None,
            elevated: None,
            core_running: None,
            core_pid: None,
            core_status: None,
            app_proxy_status: None,
            origins: None,
            driver: None,
            processes: None,
        }
    }
}
