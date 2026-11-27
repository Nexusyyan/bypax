use bypax_ipc::{CtlEnvelope, CtlHandler, CtlIpcServer, CtlRequest, CtlResponse};
use serde_json::{json, Value};
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::oneshot;

struct MockLiveGuiCtl {
    seen_methods: Arc<Mutex<Vec<String>>>,
}

impl CtlHandler for MockLiveGuiCtl {
    fn handle(
        &self,
        env: CtlEnvelope,
    ) -> Pin<Box<dyn Future<Output = CtlResponse> + Send + '_>> {
        Box::pin(async move {
            let tag = match &env.request {
                CtlRequest::Status => "status",
                CtlRequest::SelectNode { .. } => "select_node",
                CtlRequest::AppToggle { .. } => "app_toggle",
                CtlRequest::ListConnections { .. } => "list_connections",
                _ => "other",
            };
            self.seen_methods.lock().unwrap().push(tag.to_string());

            match env.request {
                CtlRequest::Status => CtlResponse::success(
                    env.id,
                    "ok",
                    Some(json!({
                        "controlMode": "live",
                        "coreRunning": true,
                        "routeMode": "rule",
                        "captureMode": "apps"
                    })),
                ),
                CtlRequest::SelectNode { node_id } => CtlResponse::success(
                    env.id,
                    "hot-switched",
                    Some(json!({
                        "controlMode": "live",
                        "hotSwitched": true,
                        "mainNodeId": node_id
                    })),
                ),
                CtlRequest::AppToggle { enabled } => CtlResponse::success(
                    env.id,
                    "ok",
                    Some(json!({
                        "controlMode": "live",
                        "appProxyEnabled": enabled,
                        "stateSynced": true
                    })),
                ),
                CtlRequest::ListConnections { .. } => CtlResponse::success(
                    env.id,
                    "ok",
                    Some(json!({
                        "controlMode": "live",
                        "connections": [{
                            "id": "c-live-1",
                            "process": "node.exe",
                            "ancestorApp": "Antigravity",
                            "sourceKind": "app_proxy"
                        }]
                    })),
                ),
                _ => CtlResponse::success(env.id, "ok", Some(json!({ "controlMode": "live" }))),
            }
        })
    }
}

fn spawn_mcp_exchange(
    data_dir: &std::path::Path,
    ctl_endpoint: &str,
    svc_endpoint: &str,
    input_lines: &[&str],
) -> (Vec<Value>, String) {
    let bin = env!("CARGO_BIN_EXE_bypax-cli");
    let mut child = Command::new(bin)
        .args([
            "--log-level",
            "debug",
            "--data-dir",
            &data_dir.to_string_lossy(),
            "--ctl-endpoint",
            ctl_endpoint,
            "--svc-endpoint",
            svc_endpoint,
            "mcp",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bypax-cli mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in input_lines {
            writeln!(stdin, "{line}").expect("write jsonrpc line");
        }
        stdin.flush().expect("flush stdin");
    }
    // Close stdin so the MCP server exits cleanly after processing all frames.
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait bypax-cli mcp");
    assert!(
        output.status.success(),
        "bypax-cli mcp exited with {:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8(output.stdout).expect("valid utf8 stdout");
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    // STRICT STDOUT PURITY CHECK: every non-empty line MUST parse as JSON-RPC 2.0!
    let mut frames = Vec::new();
    for raw_line in stdout_str.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: Value = serde_json::from_str(trimmed).unwrap_or_else(|e| {
            panic!("STDOUT POLLUTION DETECTED ({e}): non-JSON line on stdout: {trimmed:?}")
        });
        assert_eq!(
            parsed["jsonrpc"], "2.0",
            "non-JSON-RPC 2.0 frame on stdout: {parsed}"
        );
        frames.push(parsed);
    }

    (frames, stderr_str)
}

#[test]
fn stdio_mcp_e2e_offline_all_20_tools_and_zero_stdout_pollution() {
    let dir = tempdir().unwrap();
    let dead_ep = if cfg!(windows) {
        format!(r"\\.\pipe\bypax-e2e-dead-{}", std::process::id())
    } else {
        dir.path().join("d.sock").to_string_lossy().to_string()
    };

    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bypax_status","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bypax_set_mode","arguments":{"mode":"global"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"bypax_app_upsert_rule","arguments":{"name":"Antigravity IDE","process_names":["Antigravity.exe"],"include_children":true,"domains":[{"pattern":"*.corp.local","action":"direct"}],"target":"main"}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"bypax_app_list_rules","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"bypax_app_test_rule","arguments":{"process_name":"Antigravity.exe","host":"aicode.googleapis.com","dst_port":443}}}"#,
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"bypax_test_route","arguments":{"target":"https://www.baidu.com"}}}"#,
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"bypax_set_mode","arguments":{"mode":"rule"}}}"#,
        r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"bypax_test_route","arguments":{"target":"https://www.baidu.com"}}}"#,
        r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"bypax_doctor","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"bypax_app_delete_rule","arguments":{"id":"Antigravity IDE"}}}"#,
        r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"bypax_toggle_core","arguments":{"action":"start"}}}"#,
        r#"{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"bypax_toggle_system_proxy","arguments":{"enabled":true}}}"#,
        r#"{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"bypax_app_toggle","arguments":{"enabled":true}}}"#,
        r#"{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"bypax_app_toggle","arguments":{"enabled":false}}}"#,
    ];

    let (frames, _stderr) = spawn_mcp_exchange(dir.path(), &dead_ep, &dead_ep, &requests);
    // 17 responses (notification produces 0 responses).
    assert_eq!(frames.len(), 17);

    // initialize
    assert_eq!(frames[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(frames[0]["result"]["serverInfo"]["name"], "bypax-mcp");

    // tools/list -> exact 20 tools
    let tools = frames[2]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 20);

    // bypax_status -> offline mode
    assert_eq!(frames[3]["result"]["isError"], false);
    let st: Value =
        serde_json::from_str(frames[3]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(st["controlMode"], "offline");

    // bypax_set_mode -> persisted global
    assert_eq!(frames[4]["result"]["isError"], false);
    let mode_res: Value =
        serde_json::from_str(frames[4]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(mode_res["routeMode"], "global");

    // bypax_app_list_rules -> contains our new rule
    assert_eq!(frames[6]["result"]["isError"], false);
    let rules_res: Value =
        serde_json::from_str(frames[6]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(rules_res["total"], 1);

    // bypax_app_test_rule -> matches Antigravity IDE -> main
    let test_res: Value =
        serde_json::from_str(frames[7]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(test_res["matchedRuleName"], "Antigravity IDE");
    assert_eq!(test_res["finalTarget"], "main");

    // bypax_test_route in global mode -> routes via main
    let route_global: Value =
        serde_json::from_str(frames[8]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(route_global["target"], "main");

    // bypax_test_route after switching back to rule mode -> CN domain direct
    let route_rule: Value =
        serde_json::from_str(frames[10]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(route_rule["target"], "direct");

    // bypax_doctor -> succeeds offline
    assert_eq!(frames[11]["result"]["isError"], false);

    // bypax_app_delete_rule -> 0 remaining
    let del_res: Value =
        serde_json::from_str(frames[12]["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(del_res["remainingRules"], 0);

    // Offline GUI-only boundary: enabling core / system proxy / app capture MUST be refused.
    for idx in [13usize, 14, 15] {
        assert_eq!(frames[idx]["result"]["isError"], true);
        let msg = frames[idx]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            msg.contains("GUI_NOT_RUNNING"),
            "expected GUI_NOT_RUNNING for offline frame {idx}, got: {msg}"
        );
    }

    // Disabling capture offline MUST remain allowed for safe recovery.
    assert_eq!(frames[16]["result"]["isError"], false);
}

#[tokio::test]
async fn stdio_mcp_e2e_live_plane2_mode_routes_through_gui_server() {
    let dir = tempdir().unwrap();
    let live_ep = if cfg!(windows) {
        format!(
            r"\\.\pipe\bypax-ctl-e2e-live-{}-{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        )
    } else {
        dir.path().join("c.sock").to_string_lossy().to_string()
    };
    let dead_svc = if cfg!(windows) {
        format!(r"\\.\pipe\bypax-svc-dead-{}", std::process::id())
    } else {
        dir.path().join("s.sock").to_string_lossy().to_string()
    };

    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = CtlIpcServer::new(
        live_ep.clone(),
        Arc::new(MockLiveGuiCtl {
            seen_methods: Arc::clone(&seen),
        }),
    );
    let (tx, rx) = oneshot::channel();
    let srv_task = tokio::spawn(server.run(rx));
    if cfg!(windows) {
        tokio::time::sleep(Duration::from_millis(60)).await;
    } else {
        for _ in 0..40 {
            if std::path::Path::new(&live_ep).exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    let data_dir = dir.path().to_path_buf();
    let live_ep_for_child = live_ep.clone();
    let (frames, _stderr) = tokio::task::spawn_blocking(move || {
        let requests = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bypax_status","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bypax_select_node","arguments":{"node_id":"node-jp-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bypax_app_toggle","arguments":{"enabled":true}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bypax_list_connections","arguments":{}}}"#,
        ];
        spawn_mcp_exchange(&data_dir, &live_ep_for_child, &dead_svc, &requests)
    })
    .await
    .unwrap();

    let _ = tx.send(());
    let _ = srv_task.await;

    assert_eq!(frames.len(), 5);
    let status_val: Value =
        serde_json::from_str(frames[1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(status_val["controlMode"], "live");
    assert_eq!(status_val["coreRunning"], true);

    let sel_val: Value =
        serde_json::from_str(frames[2]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(sel_val["hotSwitched"], true);
    assert_eq!(sel_val["mainNodeId"], "node-jp-1");

    let app_val: Value =
        serde_json::from_str(frames[3]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(app_val["appProxyEnabled"], true);

    let conn_val: Value =
        serde_json::from_str(frames[4]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(conn_val["connections"][0]["ancestorApp"], "Antigravity");

    let recorded = seen.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["status", "select_node", "app_toggle", "list_connections"]
    );
}

#[test]
fn cli_ctl_json_schema_and_offline_commands_emit_clean_json() {
    let dir = tempdir().unwrap();
    let dead_ep = if cfg!(windows) {
        format!(r"\\.\pipe\bypax-cli-dead-{}", std::process::id())
    } else {
        dir.path().join("d.sock").to_string_lossy().to_string()
    };
    let bin = env!("CARGO_BIN_EXE_bypax-cli");

    let out_schema = Command::new(bin)
        .args(["ctl", "schema"])
        .output()
        .expect("run ctl schema");
    assert!(out_schema.status.success());
    let schema: Value = serde_json::from_slice(&out_schema.stdout).expect("valid schema json");
    assert_eq!(schema["mcpServerName"], "bypax-mcp");
    assert_eq!(schema["mcpTools"].as_array().unwrap().len(), 20);

    let out_rules = Command::new(bin)
        .args([
            "--data-dir",
            &dir.path().to_string_lossy(),
            "--ctl-endpoint",
            &dead_ep,
            "--svc-endpoint",
            &dead_ep,
            "ctl",
            "--json",
            "app",
            "list-rules",
        ])
        .output()
        .expect("run ctl app list-rules");
    assert!(out_rules.status.success());
    let rules_json: Value = serde_json::from_slice(&out_rules.stdout).expect("valid rules json");
    assert_eq!(rules_json["controlMode"], "offline");
    assert_eq!(rules_json["total"], 0);
}
