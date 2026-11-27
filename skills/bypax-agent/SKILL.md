---
name: bypax-agent
description: Operate and automate Bypax cross-platform proxy routing, per-application capture rules, node selection, latency tests, live traffic monitoring, and diagnostics via the built-in 20-tool Stdio MCP Server (`bypax-cli mcp`) or structured JSON CLI (`bypax-cli ctl --json`).
---

# Bypax Agent Automation Skill

Use this skill when the user asks you to inspect or control Bypax, switch proxy modes or exit nodes, run latency tests, configure per-application proxy rules (Windows WinDivert Zero-TUN or macOS launchd + utun path routing), dry-run routing or app rules, inspect live connections/logs, or diagnose service and driver issues.

## 1. Quick Setup (Antigravity / Claude Code / Cursor)

### Stdio MCP Server (Preferred)

Register `bypax-cli` as a local Stdio MCP server (`protocolVersion: "2024-11-05"`, `serverInfo.name: "bypax-mcp"`). All tracing logs are routed strictly to `stderr` so `stdout` carries only valid JSON-RPC 2.0 lines.

Windows example (`mcp_config.json` / `.mcp.json`):

```json
{
  "mcpServers": {
    "bypax": {
      "command": "C:\\path\\to\\bypax\\bypax-cli.exe",
      "args": ["mcp"]
    }
  }
}
```

macOS / Linux example:

```json
{
  "mcpServers": {
    "bypax": {
      "command": "/Applications/Bypax.app/Contents/MacOS/bypax-cli",
      "args": ["mcp"]
    }
  }
}
```

Tip: Open **Settings -> Advanced -> AI Agent Integration** inside Bypax to copy a ready-to-paste snippet with the exact detected executable path.

### Structured JSON CLI (Zero-Setup Terminal Fallback)

Every control capability is also exposed via `bypax-cli ctl --json`:

```powershell
bypax-cli ctl --json status
bypax-cli ctl --json core start
bypax-cli ctl --json mode rule
bypax-cli ctl --json node list
bypax-cli ctl --json node select <node_id>
bypax-cli ctl --json node test --kind tcping
bypax-cli ctl --json app list-rules
bypax-cli ctl --json app test --process Cursor.exe --host api.openai.com --port 443
bypax-cli ctl --json route test --target https://github.com
bypax-cli ctl --json connections --limit 50
bypax-cli ctl --json logs --level WARN --limit 50
bypax-cli ctl schema
bypax-cli doctor
bypax-cli ps --filter code
bypax-cli service status
```

## 2. Live Mode vs. Automatic Offline Fallback

- **Live Mode (GUI open)**: `bypax-cli` connects to the non-elevated Bypax GUI over Plane 2 Control IPC (`\\.\pipe\bypax-ctl-v1` on Windows, `<runtime_dir>/bypax-ctl.sock` with mode `0600` on macOS/Linux). Node switches are 0ms hot-switches, and every mutation emits `bypax-state-sync` so the desktop UI refreshes immediately.
- **Offline Fallback (GUI closed)**: If Plane 2 is unavailable, `bypax-cli` automatically falls back to SQLite WAL (`bypax.db` with `busy_timeout = 5000`) for persistent settings, nodes, and rules. **No-GUI, No-Active-Proxy boundary**: offline mode can inspect state, edit nodes/rules, and run stop/disable/cleanup operations, but enabling active core, OS system proxy, App Proxy, or TUN returns `GUI_NOT_RUNNING` until Bypax GUI is open.

## 3. Complete 20-Tool MCP Catalog

### Core & Nodes (9 tools)

| Tool | Purpose |
| :--- | :--- |
| `bypax_status` | Returns runtime mode (`live` / `offline`), core status, route mode, takeover state (system proxy / app proxy / TUN), privileged service status, and counts. |
| `bypax_toggle_core` | Starts or stops the proxy core (`action: "start" \| "stop"`). |
| `bypax_set_mode` | Switches routing mode (`mode: "rule" \| "global" \| "direct"`). |
| `bypax_toggle_system_proxy` | Enables or disables the OS system proxy via NetGuard (`enabled: boolean`). |
| `bypax_toggle_tun` | Enables or disables Global TUN capture (`enabled: boolean`); mutually exclusive with App Proxy. |
| `bypax_list_nodes` | Lists proxy nodes with optional `group`, `region`, and `query` filters. |
| `bypax_select_node` | Selects the active main exit node (`node_id`), hot-switching in 0ms when live. |
| `bypax_test_latency` | Runs batch TCPing or real-delay latency tests (`kind: "tcping" \| "real_delay"`, optional `node_ids`). |
| `bypax_refresh_subscriptions` | Refreshes one subscription (`subscription_id`) or all subscriptions and reloads if running. |

### Routing & Monitor (5 tools)

| Tool | Purpose |
| :--- | :--- |
| `bypax_list_route_rules` | Lists configured routing rules in priority order. |
| `bypax_test_route` | Dry-runs domain/IP routing evaluation (`target`, optional `process_name`) and explains matched rule + DNS server. |
| `bypax_list_connections` | Lists live active connections with attributed ancestor/process names, source (`System Proxy` / `App Proxy` / `TUN`), and optional `process` / `source` / `limit` filters. |
| `bypax_get_logs` | Retrieves recent diagnostic log entries (`min_level: "INFO" \| "WARN" \| "ERROR"`, `limit`). |
| `bypax_doctor` | Runs full environment diagnostics: core binary, database/WAL, Plane 1 service, WinDivert driver (Windows) or launchd daemon (macOS), and NetGuard state. |

### App Proxy (6 tools)

| Tool | Purpose |
| :--- | :--- |
| `bypax_app_toggle` | Enables or disables per-application capture (`enabled: boolean`); atomically pauses Global TUN if active. |
| `bypax_app_list_rules` | Lists per-application capture rules in priority order. |
| `bypax_app_upsert_rule` | Creates or updates a per-application rule (process names, path prefixes/substrings, macOS `.app` bundle paths, `include_children`, L7 domain overrides, CIDRs, ports, protocols, outbound `target`). |
| `bypax_app_delete_rule` | Deletes a per-application rule by `id` or exact `name`. |
| `bypax_app_test_rule` | Runs the 3-step dry-run trace (L4 process/tree match -> L7 SNI/Host override -> final exit target). |
| `bypax_list_processes` | Lists running OS processes with PID, PPID, executable path, and currently matched app rule (`filter`). |

## 4. Per-App Rule Recipes

### Valid Outbound Targets (`target`)

- `follow` (recommended): Follow Bypax routing rules (direct for local/CN, proxy for global).
- `main`: Always route through the active main exit node.
- `auto:<region>`: Auto-select lowest latency node in a region (e.g. `auto:US`, `auto:JP`, `auto:SG`).
- `node:<id>`: Pin to a specific node ID from `bypax_list_nodes`.
- `direct`: Bypass proxy locally (zero proxy core hop on Windows).
- `reject`: Block matching traffic immediately.

### Recipe A: Proxy an AI IDE Process Tree While Keeping Intranet Direct

1. Discover exact process names and paths:
   - Call `bypax_list_processes` with `filter: "cursor"` (or `"antigravity"`, `"code"`).
2. Create or update the app rule with process-tree inheritance:
   - Call `bypax_app_upsert_rule`:
     ```json
     {
       "name": "Cursor IDE",
       "enabled": true,
       "process_names": ["Cursor.exe"],
       "path_contains": ["\\Programs\\cursor\\"],
       "mac_bundle_paths": ["/Applications/Cursor.app"],
       "include_children": true,
       "target": "main"
     }
     ```
3. Add a higher-priority L7 domain bypass rule if corporate domains must stay direct:
   - Call `bypax_app_upsert_rule` with lower `priority` (evaluated first), `domains: ["*.corp.internal"]`, `target: "direct"`.
4. Always dry-run verify both cases before enabling:
   - Call `bypax_app_test_rule` with `process_name: "Cursor.exe"`, `host: "api.openai.com"`, `dst_port: 443` (expect `main`).
   - Call `bypax_app_test_rule` with `process_name: "Cursor.exe"`, `host: "git.corp.internal"`, `dst_port: 443` (expect `direct`).
5. Enable App Proxy capture:
   - Call `bypax_app_toggle` with `enabled: true`.

### Recipe B: Pin a Single App to a Regional Exit

1. Verify region nodes exist via `bypax_list_nodes` (`region: "JP"`).
2. Upsert rule with `target: "auto:JP"` and verify via `bypax_app_test_rule`.

### Recipe C: Switch Between App Proxy and Global TUN Safely

- App Proxy (`bypax_app_toggle`) and Global TUN (`bypax_toggle_tun`) are mutually exclusive.
- Enabling one atomically pauses the other while preserving all saved app rules.
- System Proxy (`bypax_toggle_system_proxy`) is orthogonal and may stay enabled alongside either capture mode.

## 5. Troubleshooting SOP

1. **Always start with `bypax_doctor` and `bypax_status`**:
   - Confirm `mode` (`live` vs `offline`), core installation/running state, and privileged service readiness.
2. **Windows WinDivert blocked by Memory Integrity (HVCI)**:
   - If `bypax_doctor` reports `WinDivert64.sys` blocked by Windows Security / HVCI, inform the user and offer the immediate fallback: switch to Global TUN via `bypax_toggle_tun(enabled: true)`.
3. **Missing WinDivert files (`-nodriver` package)**:
   - Instruct the user to run `.\scripts\fetch-windivert.ps1` or place verified `WinDivert.dll` and `WinDivert64.sys` into `runtime/windivert/`.
4. **Unexpected routing or bypassed child processes**:
   - Inspect live attribution via `bypax_list_connections` (filter by `process`) and recent warnings via `bypax_get_logs(min_level: "WARN")`.
   - Run `bypax_app_test_rule` and `bypax_test_route` to detect higher-priority rule shadowing.
   - On macOS, child processes spawned outside `.app` bundles (such as `/opt/homebrew/bin/node`) can be included by adding their path prefix to `path_prefixes` or `process_names`.
5. **Service & legacy driver cleanup from terminal**:
   - On Windows, Bypax uses a GUI-bound on-demand UAC helper (`worker-run`, stops immediately on GUI exit/crash) with zero background Windows SCM service. Run `bypax-cli service cleanup` (or `bypax-cli doctor`) to detect and remove any legacy background services or stale WinDivert locks.
   - On macOS, use `bypax-cli service status`, `bypax-cli service install`, `bypax-cli service start`, `bypax-cli service stop`, or `bypax-cli service uninstall`.
