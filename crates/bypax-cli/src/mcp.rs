use crate::agent::AgentClient;
use anyhow::{anyhow, Result};
use bypax_ipc::{AppProxyRuleWire, CtlRequest, DomainOverrideWire};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
pub const MCP_SERVER_NAME: &str = "bypax-mcp";

/// Runs the zero-external-SDK Stdio JSON-RPC 2.0 MCP server backed by `AgentClient`.
///
/// Caller MUST ensure all tracing/logging is routed exclusively to `stderr` so `stdout`
/// emits ONLY valid newline-delimited JSON-RPC 2.0 responses.
pub async fn run_mcp_stdio(client: AgentClient) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(resp) = handle_jsonrpc_line(&client, trimmed).await {
            let mut out = serde_json::to_string(&resp)?;
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Processes one JSON-RPC 2.0 line and returns an optional response payload
/// (`None` for notifications with no `id`).
pub async fn handle_jsonrpc_line(client: &AgentClient, raw: &str) -> Option<Value> {
    let req: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(err) => {
            return Some(jsonrpc_error(
                Value::Null,
                -32700,
                &format!("parse error: {err}"),
            ));
        }
    };

    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

    // JSON-RPC 2.0 notifications have no `id` and expect no reply.
    let id = id?;

    let response = match method {
        "initialize" => jsonrpc_result(
            id,
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": MCP_SERVER_NAME,
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),
        "ping" => jsonrpc_result(id, json!({})),
        "tools/list" => jsonrpc_result(id, json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match execute_tool(client, name, &args).await {
                Ok(payload) => jsonrpc_result(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&payload)
                                .unwrap_or_else(|_| payload.to_string())
                        }],
                        "isError": false
                    }),
                ),
                Err(err) => jsonrpc_result(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": err.to_string()
                        }],
                        "isError": true
                    }),
                ),
            }
        }
        other => jsonrpc_error(id, -32601, &format!("method not found: {other}")),
    };

    Some(response)
}

async fn execute_tool(client: &AgentClient, name: &str, args: &Value) -> Result<Value> {
    let ctl_req = match name {
        // Core & Nodes (9)
        "bypax_status" => CtlRequest::Status,
        "bypax_toggle_core" => {
            let enabled = parse_bool_or_action(args, "enabled", "action")?;
            CtlRequest::ToggleCore { enabled }
        }
        "bypax_set_mode" => {
            let mode = req_str(args, "mode")?.to_string();
            CtlRequest::SetMode { mode }
        }
        "bypax_toggle_system_proxy" => {
            let enabled = parse_bool_or_action(args, "enabled", "action")?;
            CtlRequest::ToggleSystemProxy { enabled }
        }
        "bypax_toggle_tun" => {
            let enabled = parse_bool_or_action(args, "enabled", "action")?;
            CtlRequest::ToggleTun { enabled }
        }
        "bypax_list_nodes" => CtlRequest::ListNodes {
            group: opt_str(args, "group"),
            region: opt_str(args, "region"),
            query: opt_str(args, "query"),
        },
        "bypax_select_node" => {
            let node_id = req_str(args, "node_id")?.to_string();
            CtlRequest::SelectNode { node_id }
        }
        "bypax_test_latency" => {
            let kind_raw = opt_str(args, "kind").unwrap_or_else(|| "tcping".to_string());
            let kind = if kind_raw.eq_ignore_ascii_case("real_delay") {
                "real".to_string()
            } else {
                kind_raw
            };
            CtlRequest::TestLatency {
                node_ids: str_vec(args, "node_ids"),
                kind,
            }
        }
        "bypax_refresh_subscriptions" => CtlRequest::RefreshSubscriptions {
            subscription_id: opt_str(args, "subscription_id"),
        },

        // Routing & Monitor (5)
        "bypax_list_route_rules" => CtlRequest::ListRouteRules,
        "bypax_test_route" => {
            let input = opt_str(args, "target")
                .or_else(|| opt_str(args, "input"))
                .ok_or_else(|| anyhow!("missing required string argument 'target'"))?;
            CtlRequest::TestRoute {
                input,
                process_name: opt_str(args, "process_name"),
            }
        }
        "bypax_list_connections" => CtlRequest::ListConnections {
            source: opt_str(args, "source"),
            query: opt_str(args, "query").or_else(|| opt_str(args, "process")),
        },
        "bypax_get_logs" => CtlRequest::GetLogs {
            level: opt_str(args, "min_level").or_else(|| opt_str(args, "level")),
            limit: args
                .get("limit")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
        },
        "bypax_doctor" => CtlRequest::Doctor,

        // App Proxy (6)
        "bypax_app_toggle" => {
            let enabled = parse_bool_or_action(args, "enabled", "action")?;
            CtlRequest::AppToggle { enabled }
        }
        "bypax_app_list_rules" => CtlRequest::AppListRules,
        "bypax_app_upsert_rule" => {
            let rule = parse_app_rule_wire(args)?;
            CtlRequest::AppUpsertRule { rule }
        }
        "bypax_app_delete_rule" => {
            let id = opt_str(args, "id")
                .or_else(|| opt_str(args, "selector"))
                .or_else(|| opt_str(args, "name"))
                .ok_or_else(|| anyhow!("missing required string argument 'id'"))?;
            CtlRequest::AppDeleteRule { id }
        }
        "bypax_app_test_rule" => CtlRequest::AppTestRule {
            process_name: opt_str(args, "process_name"),
            exe_path: opt_str(args, "exe_path"),
            host: opt_str(args, "host"),
            dst_ip: opt_str(args, "dst_ip"),
            dst_port: args.get("dst_port").and_then(Value::as_u64).unwrap_or(443) as u16,
            protocol: opt_str(args, "protocol").unwrap_or_else(|| "tcp".to_string()),
        },
        "bypax_list_processes" => CtlRequest::ListProcesses {
            filter: opt_str(args, "filter"),
        },
        other => return Err(anyhow!("unknown tool '{other}'")),
    };

    client.execute(ctl_req).await
}

fn parse_bool_or_action(args: &Value, bool_key: &str, action_key: &str) -> Result<bool> {
    if let Some(b) = args.get(bool_key).and_then(Value::as_bool) {
        return Ok(b);
    }
    if let Some(s) = args.get(action_key).and_then(Value::as_str) {
        match s.trim().to_ascii_lowercase().as_str() {
            "start" | "on" | "enable" | "true" => return Ok(true),
            "stop" | "off" | "disable" | "false" => return Ok(false),
            other => {
                return Err(anyhow!(
                    "invalid '{action_key}' value '{other}': expected start/stop or boolean '{bool_key}'"
                ))
            }
        }
    }
    Err(anyhow!("missing required boolean argument '{bool_key}'"))
}

fn parse_app_rule_wire(args: &Value) -> Result<AppProxyRuleWire> {
    let name = req_str(args, "name")?.to_string();
    let id = opt_str(args, "id").unwrap_or_default();
    let enabled = args.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let priority = args.get("priority").and_then(Value::as_i64).unwrap_or(0) as i32;
    let include_children = args
        .get("include_children")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let target = opt_str(args, "target").unwrap_or_else(|| "follow".to_string());

    let domains = parse_domain_overrides(args.get("domains"));

    Ok(AppProxyRuleWire {
        id,
        name,
        enabled,
        priority,
        preset_id: opt_str(args, "preset_id"),
        process_names: str_vec(args, "process_names"),
        path_prefixes: str_vec(args, "path_prefixes"),
        path_contains: str_vec(args, "path_contains"),
        mac_bundle_paths: str_vec(args, "mac_bundle_paths"),
        ignored_external_children: str_vec(args, "ignored_external_children"),
        include_children,
        domains,
        dst_cidrs: str_vec(args, "dst_cidrs"),
        dst_ports: u16_vec(args, "dst_ports"),
        protocols: str_vec(args, "protocols"),
        target,
    })
}

fn parse_domain_overrides(raw: Option<&Value>) -> Vec<DomainOverrideWire> {
    let Some(arr) = raw.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((prefix, pat)) = trimmed.split_once(':') {
                let p_low = prefix.trim().to_ascii_lowercase();
                if matches!(p_low.as_str(), "proxy" | "direct" | "reject" | "block") {
                    let act = if p_low == "block" {
                        "reject".to_string()
                    } else {
                        p_low
                    };
                    out.push(DomainOverrideWire {
                        pattern: pat.trim().to_string(),
                        action: act,
                    });
                    continue;
                }
            }
            out.push(DomainOverrideWire {
                pattern: trimmed.to_string(),
                action: "proxy".to_string(),
            });
        } else if let Some(obj) = item.as_object() {
            if let Some(pat) = obj
                .get("pattern")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let act = obj
                    .get("action")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or("proxy");
                let norm = if act.eq_ignore_ascii_case("block") {
                    "reject".to_string()
                } else {
                    act.to_ascii_lowercase()
                };
                out.push(DomainOverrideWire {
                    pattern: pat.to_string(),
                    action: norm,
                });
            }
        }
    }
    out
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing required string argument '{key}'"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn str_vec(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn u16_vec(args: &Value, key: &str) -> Vec<u16> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_u64)
                .filter_map(|v| u16::try_from(v).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// Complete JSON Schema definitions for all 20 Bypax MCP tools.
pub fn tool_definitions() -> Value {
    Value::Array(vec![
        // Core & Nodes (9)
        json!({
            "name": "bypax_status",
            "description": "Returns live or offline Bypax status: core state, route mode, takeover mode (system proxy, app proxy, TUN), privileged service status, and node/rule counts.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "bypax_toggle_core",
            "description": "Starts or stops the Bypax proxy core with preflight validation.",
            "inputSchema": {
                "type": "object",
                "required": ["enabled"],
                "properties": {
                    "enabled": { "type": "boolean", "description": "true to start core, false to stop core" }
                }
            }
        }),
        json!({
            "name": "bypax_set_mode",
            "description": "Switches the active routing mode (rule, global, or direct) without restarting the core when live.",
            "inputSchema": {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": { "type": "string", "enum": ["rule", "global", "direct"] }
                }
            }
        }),
        json!({
            "name": "bypax_toggle_system_proxy",
            "description": "Enables or disables the OS system proxy safely with NetGuard snapshot rollback protection.",
            "inputSchema": {
                "type": "object",
                "required": ["enabled"],
                "properties": {
                    "enabled": { "type": "boolean" }
                }
            }
        }),
        json!({
            "name": "bypax_toggle_tun",
            "description": "Enables or disables Global TUN capture (mutually exclusive with App Proxy; preserves all saved app rules).",
            "inputSchema": {
                "type": "object",
                "required": ["enabled"],
                "properties": {
                    "enabled": { "type": "boolean" }
                }
            }
        }),
        json!({
            "name": "bypax_list_nodes",
            "description": "Lists configured proxy nodes with optional group, region, and search query filters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group": { "type": "string", "description": "Optional subscription/group filter" },
                    "region": { "type": "string", "description": "Optional region code filter (e.g. US, JP, SG, HK)" },
                    "query": { "type": "string", "description": "Optional substring filter on remark, server, or ID" }
                }
            }
        }),
        json!({
            "name": "bypax_select_node",
            "description": "Selects the active main exit node by ID (0ms hot-switch when GUI is running).",
            "inputSchema": {
                "type": "object",
                "required": ["node_id"],
                "properties": {
                    "node_id": { "type": "string" }
                }
            }
        }),
        json!({
            "name": "bypax_test_latency",
            "description": "Runs concurrent TCPing or isolated real-delay latency tests across selected or all nodes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": ["tcping", "real", "real_delay"], "default": "tcping" },
                    "node_ids": { "type": "array", "items": { "type": "string" }, "description": "Optional list of node IDs; omit to test all nodes" }
                }
            }
        }),
        json!({
            "name": "bypax_refresh_subscriptions",
            "description": "Refreshes one subscription by ID or all configured subscriptions and reloads core if running.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "subscription_id": { "type": "string", "description": "Optional subscription ID; omit to refresh all" }
                }
            }
        }),
        // Routing & Monitor (5)
        json!({
            "name": "bypax_list_route_rules",
            "description": "Lists configured traffic routing rules in priority order.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "bypax_test_route",
            "description": "Dry-runs domain or IP routing evaluation and returns the matched rule, resolved exit, and DNS server.",
            "inputSchema": {
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": { "type": "string", "description": "Domain, URL, or IP address to evaluate" },
                    "process_name": { "type": "string", "description": "Optional process name context" }
                }
            }
        }),
        json!({
            "name": "bypax_list_connections",
            "description": "Lists live active connections with attributed ancestor/process names and capture source.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string", "enum": ["sys_proxy", "app_proxy", "tun", "dedicated_port"] },
                    "query": { "type": "string", "description": "Optional substring filter on process, host, or rule" }
                }
            }
        }),
        json!({
            "name": "bypax_get_logs",
            "description": "Retrieves recent structured diagnostic logs from Bypax.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "min_level": { "type": "string", "enum": ["INFO", "WARN", "ERROR"] },
                    "limit": { "type": "integer", "default": 100 }
                }
            }
        }),
        json!({
            "name": "bypax_doctor",
            "description": "Runs full environment diagnostics covering core binary, SQLite WAL storage, Plane 1 service, WinDivert/launchd status, and NetGuard.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        // App Proxy (6)
        json!({
            "name": "bypax_app_toggle",
            "description": "Enables or disables per-application capture (mutually exclusive with Global TUN).",
            "inputSchema": {
                "type": "object",
                "required": ["enabled"],
                "properties": {
                    "enabled": { "type": "boolean" }
                }
            }
        }),
        json!({
            "name": "bypax_app_list_rules",
            "description": "Lists all per-application capture rules in top-to-bottom priority order.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "bypax_app_upsert_rule",
            "description": "Creates or updates a per-application capture rule (process tree, paths, macOS .app bundles, L7 domain overrides, target) and hot-reloads.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "id": { "type": "string", "description": "Optional existing rule ID to update in place" },
                    "name": { "type": "string" },
                    "enabled": { "type": "boolean", "default": true },
                    "priority": { "type": "integer", "description": "Lower numbers evaluate first" },
                    "preset_id": { "type": "string" },
                    "process_names": { "type": "array", "items": { "type": "string" } },
                    "path_prefixes": { "type": "array", "items": { "type": "string" } },
                    "path_contains": { "type": "array", "items": { "type": "string" } },
                    "mac_bundle_paths": { "type": "array", "items": { "type": "string" } },
                    "include_children": { "type": "boolean", "default": true },
                    "domains": {
                        "type": "array",
                        "description": "L7 domain overrides: objects {pattern, action: proxy|direct|reject} or strings",
                        "items": {
                            "type": "object",
                            "properties": {
                                "pattern": { "type": "string" },
                                "action": { "type": "string", "enum": ["proxy", "direct", "reject"] }
                            }
                        }
                    },
                    "dst_cidrs": { "type": "array", "items": { "type": "string" } },
                    "dst_ports": { "type": "array", "items": { "type": "integer" } },
                    "protocols": { "type": "array", "items": { "type": "string", "enum": ["tcp", "udp"] } },
                    "target": { "type": "string", "default": "follow", "description": "follow | main | auto:<region> | node:<id> | direct | reject" }
                }
            }
        }),
        json!({
            "name": "bypax_app_delete_rule",
            "description": "Deletes a per-application capture rule by ID or exact rule name.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "description": "Rule ID or exact rule name" }
                }
            }
        }),
        json!({
            "name": "bypax_app_test_rule",
            "description": "Dry-runs the 3-step per-application rule evaluator (L4 process/path -> L7 domain override -> final exit target).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "process_name": { "type": "string" },
                    "exe_path": { "type": "string" },
                    "host": { "type": "string", "description": "Target hostname or TLS SNI" },
                    "dst_ip": { "type": "string" },
                    "dst_port": { "type": "integer", "default": 443 },
                    "protocol": { "type": "string", "enum": ["tcp", "udp"], "default": "tcp" }
                }
            }
        }),
        json!({
            "name": "bypax_list_processes",
            "description": "Lists running OS processes with PID, PPID, executable path, ancestor lineage, and matched Bypax app rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": { "type": "string", "description": "Optional case-insensitive filter on process name or path" }
                }
            }
        }),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn mcp_exposes_all_20_tools_and_offline_rule_lifecycle() {
        let dir = tempdir().unwrap();
        let fake_ep = if cfg!(windows) {
            format!(r"\\.\pipe\bypax-nonexistent-mcp-{}", std::process::id())
        } else {
            dir.path()
                .join("nonexistent.sock")
                .to_string_lossy()
                .to_string()
        };
        let client = AgentClient::new(
            Some(fake_ep.clone()),
            Some(fake_ep),
            Some(dir.path().to_path_buf()),
        )
        .unwrap();

        // 1. initialize
        let init = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(init["result"]["serverInfo"]["name"], MCP_SERVER_NAME);

        // 2. notification produces no response
        assert!(handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#
        )
        .await
        .is_none());

        // 3. tools/list has exact 20 tools
        let list = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )
        .await
        .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 20);
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        for expected in [
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
            "bypax_list_processes",
        ] {
            assert!(names.contains(&expected), "missing MCP tool: {expected}");
        }

        // 4. upsert rule + dry-run test + delete in offline WAL fallback
        let upsert = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bypax_app_upsert_rule","arguments":{"name":"Cursor IDE","process_names":["Cursor.exe"],"domains":[{"pattern":"*.corp.internal","action":"direct"}],"target":"main"}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(upsert["result"]["isError"], false);

        let dry_proxy = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bypax_app_test_rule","arguments":{"process_name":"Cursor.exe","host":"api.openai.com","dst_port":443}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(dry_proxy["result"]["isError"], false);
        let body_proxy: Value =
            serde_json::from_str(dry_proxy["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(body_proxy["finalTarget"], "main");
        assert_eq!(body_proxy["bypassedToRouting"], false);

        let dry_direct = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bypax_app_test_rule","arguments":{"process_name":"Cursor.exe","host":"git.corp.internal","dst_port":443}}}"#,
        )
        .await
        .unwrap();
        let body_direct: Value =
            serde_json::from_str(dry_direct["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(body_direct["finalAction"], "direct");

        let del = handle_jsonrpc_line(
            &client,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"bypax_app_delete_rule","arguments":{"id":"Cursor IDE"}}}"#,
        )
        .await
        .unwrap();
        assert_eq!(del["result"]["isError"], false);
    }
}
