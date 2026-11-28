use crate::service_proto::AppProxyRuleWire;
use serde::{Deserialize, Serialize};

fn default_test_port() -> u16 {
    443
}

fn default_test_protocol() -> String {
    "tcp".to_string()
}

/// Plane 2 user-space control RPC envelope between `bypax-cli` / MCP and the running GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtlEnvelope {
    pub id: String,
    pub request: CtlRequest,
}

/// Full typed control surface covering all 20 CLI / Stdio MCP operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum CtlRequest {
    // Core & Nodes (9+1)
    Status,
    ToggleCore {
        enabled: bool,
    },
    SetMode {
        mode: String, // "rule" | "global" | "direct"
    },
    ToggleSystemProxy {
        enabled: bool,
    },
    ToggleTun {
        enabled: bool,
    },
    SetCaptureMode {
        mode: String, // "off" | "apps" | "tun"
    },
    ListNodes {
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        query: Option<String>,
    },
    SelectNode {
        node_id: String,
    },
    TestLatency {
        #[serde(default)]
        node_ids: Vec<String>,
        #[serde(default = "default_latency_kind")]
        kind: String, // "real"
    },
    RefreshSubscriptions {
        #[serde(default)]
        subscription_id: Option<String>,
    },

    // Routing & Monitor (5)
    ListRouteRules,
    TestRoute {
        input: String,
        #[serde(default)]
        process_name: Option<String>,
    },
    ListConnections {
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        query: Option<String>,
    },
    GetLogs {
        #[serde(default)]
        level: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
    },
    Doctor,

    // App Proxy (6)
    AppToggle {
        enabled: bool,
    },
    AppListRules,
    AppUpsertRule {
        rule: AppProxyRuleWire,
    },
    AppDeleteRule {
        id: String,
    },
    AppTestRule {
        #[serde(default)]
        process_name: Option<String>,
        #[serde(default)]
        exe_path: Option<String>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        dst_ip: Option<String>,
        #[serde(default = "default_test_port")]
        dst_port: u16,
        #[serde(default = "default_test_protocol")]
        protocol: String,
    },
    ListProcesses {
        #[serde(default)]
        filter: Option<String>,
    },
}

fn default_latency_kind() -> String {
    "real".to_string()
}

/// Plane 2 response envelope carrying structured JSON output for CLI `--json` and MCP tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtlResponse {
    pub id: String,
    pub ok: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CtlResponse {
    pub fn success(
        id: impl Into<String>,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: id.into(),
            ok: true,
            message: message.into(),
            data,
        }
    }

    pub fn error(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: false,
            message: message.into(),
            data: None,
        }
    }
}
