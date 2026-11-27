mod agent;
mod mcp;
mod service_cmd;

use crate::agent::{capability_schema, AgentClient};
use crate::service_cmd::{query_os_service_status, run_service_subcommand, ServiceStatusReport};
use anyhow::{bail, Result};
use bypax_ipc::{AppProxyRuleWire, CtlRequest, DomainOverrideWire};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "bypax-cli",
    version,
    about = "Bypax cross-platform proxy control CLI and 20-tool Stdio MCP server"
)]
struct Cli {
    /// Override log level (trace, debug, info, warn, error)
    #[arg(long, global = true)]
    log_level: Option<String>,

    /// Optional Bypax data directory override (for portable or test isolation)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Optional Plane 2 GUI control IPC endpoint override
    #[arg(long, global = true)]
    ctl_endpoint: Option<String>,

    /// Optional Plane 1 privileged service IPC endpoint override
    #[arg(long, global = true)]
    svc_endpoint: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Control Bypax via Plane 2 GUI IPC with automatic SQLite WAL + Plane 1 offline fallback
    Ctl {
        /// Emit structured machine-readable JSON output
        #[arg(long, global = true)]
        json: bool,

        #[command(subcommand)]
        action: Box<CtlAction>,
    },

    /// Run the zero-external-SDK Stdio JSON-RPC 2.0 MCP server (20 tools)
    Mcp,

    /// Run full environment, core, storage, service, and driver diagnostics
    Doctor {
        /// Emit structured machine-readable JSON output
        #[arg(long)]
        json: bool,
    },

    /// List running OS processes (PID, PPID, name, path, matched rule)
    Ps {
        /// Case-insensitive substring filter applied to process name and path
        #[arg(long, short)]
        filter: Option<String>,

        /// Emit structured machine-readable JSON output
        #[arg(long)]
        json: bool,
    },

    /// Manage the Bypax privileged service (Windows legacy cleanup / macOS launchd)
    Service {
        /// Emit structured machine-readable JSON output
        #[arg(long, global = true)]
        json: bool,

        /// Explicit path to bypax-service executable
        #[arg(long, global = true)]
        service_exe: Option<PathBuf>,

        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Install the privileged Bypax helper (macOS launchd only; Windows uses GUI-bound helper)
    Install,
    /// Uninstall any legacy Windows Service or macOS LaunchDaemon
    Uninstall,
    /// Clean up legacy Windows services (BypaxService/BypathService) and stale driver locks
    Cleanup,
    /// Start the installed service (macOS)
    Start,
    /// Stop the installed service
    Stop,
    /// Query privileged service installation and runtime status
    Status,
}

#[derive(Subcommand, Debug)]
enum CtlAction {
    /// Show live or offline Bypax status
    Status,
    /// Start or stop the proxy core
    Core {
        /// Action: start or stop
        action: String,
    },
    /// Set routing mode (rule | global | direct)
    Mode {
        /// Routing mode: rule, global, or direct
        mode: String,
    },
    /// Toggle OS system proxy (on | off)
    SysProxy {
        /// State: on or off
        state: String,
    },
    /// Toggle Global TUN capture (on | off)
    Tun {
        /// State: on or off
        state: String,
    },
    /// Set capture mode (off | apps | tun)
    Capture {
        /// Capture mode: off, apps, or tun
        mode: String,
    },
    /// Manage proxy nodes (list, select, test)
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Manage subscription groups
    Sub {
        #[command(subcommand)]
        action: SubAction,
    },
    /// Inspect and dry-run traffic routing rules
    Route {
        #[command(subcommand)]
        action: RouteAction,
    },
    /// List active connections
    Connections {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        query: Option<String>,
    },
    /// Fetch recent diagnostic logs
    Logs {
        #[arg(long)]
        level: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Run full environment diagnostics
    Doctor,
    /// Manage per-application proxy capture and rules
    App {
        #[command(subcommand)]
        action: Box<AppAction>,
    },
    /// List running OS processes with matched app rules
    Ps {
        #[arg(long, short)]
        filter: Option<String>,
    },
    /// Print machine-readable CLI and MCP capability schema
    Schema,
}

#[derive(Subcommand, Debug)]
enum NodeAction {
    /// List configured proxy nodes
    List {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        query: Option<String>,
    },
    /// Select active main exit node by ID
    Select { node_id: String },
    /// Run batch latency test across selected or all nodes
    Test {
        #[arg(long, default_value = "tcping")]
        kind: String,
        #[arg(long = "node-id")]
        node_ids: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SubAction {
    /// Refresh one subscription or all subscriptions
    Refresh {
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum RouteAction {
    /// List configured routing rules
    List,
    /// Dry-run route evaluation for a domain, URL, or IP
    Test {
        #[arg(long)]
        target: String,
        #[arg(long)]
        process: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AppAction {
    /// Toggle per-application capture (on | off)
    Toggle { state: String },
    /// List per-application capture rules
    ListRules,
    /// Create or update a per-application capture rule
    UpsertRule {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "follow")]
        target: String,
        #[arg(long)]
        priority: Option<i32>,
        #[arg(long)]
        preset_id: Option<String>,
        #[arg(long = "process")]
        process_names: Vec<String>,
        #[arg(long = "path-prefix")]
        path_prefixes: Vec<String>,
        #[arg(long = "path-contains")]
        path_contains: Vec<String>,
        #[arg(long = "mac-bundle")]
        mac_bundle_paths: Vec<String>,
        #[arg(long = "domain")]
        domains: Vec<String>,
        #[arg(long = "cidr")]
        dst_cidrs: Vec<String>,
        #[arg(long = "port")]
        dst_ports: Vec<u16>,
        #[arg(long = "proto")]
        protocols: Vec<String>,
        #[arg(long)]
        no_children: bool,
        #[arg(long)]
        disabled: bool,
    },
    /// Delete a per-application capture rule by ID or exact name
    DeleteRule { id: String },
    /// Dry-run 3-step per-application rule evaluation
    Test {
        #[arg(long)]
        process: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long, default_value = "tcp")]
        proto: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let default_level = cli.log_level.as_deref().unwrap_or("warn");

    match cli.command {
        Commands::Mcp => {
            // CRITICAL: Route ALL tracing strictly to stderr so stdout carries ONLY JSON-RPC 2.0 lines.
            init_tracing(default_level, true);
            let client = AgentClient::new(cli.ctl_endpoint, cli.svc_endpoint, cli.data_dir)?;
            mcp::run_mcp_stdio(client).await
        }
        Commands::Doctor { json: as_json } => {
            init_tracing(default_level, as_json);
            let client = AgentClient::new(cli.ctl_endpoint, cli.svc_endpoint, cli.data_dir)?;
            let data = client.execute(CtlRequest::Doctor).await?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                print_doctor_human(&data);
            }
            Ok(())
        }
        Commands::Ps {
            filter,
            json: as_json,
        } => {
            init_tracing(default_level, as_json);
            let client = AgentClient::new(cli.ctl_endpoint, cli.svc_endpoint, cli.data_dir)?;
            let data = client.execute(CtlRequest::ListProcesses { filter }).await?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                print_processes_human(&data);
            }
            Ok(())
        }
        Commands::Service {
            json: as_json,
            service_exe,
            action,
        } => {
            init_tracing(default_level, as_json);
            handle_service_command(action, service_exe.as_deref(), as_json)
        }
        Commands::Ctl {
            json: as_json,
            action,
        } => {
            init_tracing(default_level, as_json);
            if matches!(*action, CtlAction::Schema) {
                println!("{}", serde_json::to_string_pretty(&capability_schema())?);
                return Ok(());
            }
            let client = AgentClient::new(cli.ctl_endpoint, cli.svc_endpoint, cli.data_dir)?;
            let req = ctl_action_to_request(*action)?;
            let is_doctor = matches!(req, CtlRequest::Doctor);
            let is_ps = matches!(req, CtlRequest::ListProcesses { .. });
            let data = client.execute(req).await?;
            if !as_json && is_doctor {
                print_doctor_human(&data);
            } else if !as_json && is_ps {
                print_processes_human(&data);
            } else {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
            Ok(())
        }
    }
}

fn init_tracing(level: &str, to_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "bypax_cli={level},bypax_core={level},bypax_ipc={level},bypax_appproxy={level},{level}"
        ))
    });
    if to_stderr {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_target(false)
            .compact()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
    }
}

fn parse_toggle_arg(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "on" | "start" | "enable" | "true" | "1" => Ok(true),
        "off" | "stop" | "disable" | "false" | "0" => Ok(false),
        other => bail!("Invalid toggle value '{other}': expected on|off or start|stop"),
    }
}

fn parse_cli_domain_override(raw: &str) -> DomainOverrideWire {
    let trimmed = raw.trim();
    if let Some((prefix, pat)) = trimmed.split_once(':') {
        let low = prefix.trim().to_ascii_lowercase();
        if matches!(low.as_str(), "proxy" | "direct" | "reject" | "block") {
            return DomainOverrideWire {
                pattern: pat.trim().to_string(),
                action: if low == "block" {
                    "reject".to_string()
                } else {
                    low
                },
            };
        }
    }
    DomainOverrideWire {
        pattern: trimmed.to_string(),
        action: "proxy".to_string(),
    }
}

fn ctl_action_to_request(action: CtlAction) -> Result<CtlRequest> {
    Ok(match action {
        CtlAction::Status => CtlRequest::Status,
        CtlAction::Core { action } => CtlRequest::ToggleCore {
            enabled: parse_toggle_arg(&action)?,
        },
        CtlAction::Mode { mode } => CtlRequest::SetMode { mode },
        CtlAction::SysProxy { state } => CtlRequest::ToggleSystemProxy {
            enabled: parse_toggle_arg(&state)?,
        },
        CtlAction::Tun { state } => CtlRequest::ToggleTun {
            enabled: parse_toggle_arg(&state)?,
        },
        CtlAction::Capture { mode } => CtlRequest::SetCaptureMode { mode },
        CtlAction::Node { action } => match action {
            NodeAction::List {
                group,
                region,
                query,
            } => CtlRequest::ListNodes {
                group,
                region,
                query,
            },
            NodeAction::Select { node_id } => CtlRequest::SelectNode { node_id },
            NodeAction::Test { kind, node_ids } => CtlRequest::TestLatency { node_ids, kind },
        },
        CtlAction::Sub { action } => match action {
            SubAction::Refresh { id } => CtlRequest::RefreshSubscriptions {
                subscription_id: id,
            },
        },
        CtlAction::Route { action } => match action {
            RouteAction::List => CtlRequest::ListRouteRules,
            RouteAction::Test { target, process } => CtlRequest::TestRoute {
                input: target,
                process_name: process,
            },
        },
        CtlAction::Connections { source, query } => CtlRequest::ListConnections { source, query },
        CtlAction::Logs { level, limit } => CtlRequest::GetLogs {
            level,
            limit: Some(limit),
        },
        CtlAction::Doctor => CtlRequest::Doctor,
        CtlAction::App { action } => match *action {
            AppAction::Toggle { state } => CtlRequest::AppToggle {
                enabled: parse_toggle_arg(&state)?,
            },
            AppAction::ListRules => CtlRequest::AppListRules,
            AppAction::UpsertRule {
                id,
                name,
                target,
                priority,
                preset_id,
                process_names,
                path_prefixes,
                path_contains,
                mac_bundle_paths,
                domains,
                dst_cidrs,
                dst_ports,
                protocols,
                no_children,
                disabled,
            } => CtlRequest::AppUpsertRule {
                rule: AppProxyRuleWire {
                    id: id.unwrap_or_default(),
                    name,
                    enabled: !disabled,
                    priority: priority.unwrap_or(0),
                    preset_id,
                    process_names,
                    path_prefixes,
                    path_contains,
                    mac_bundle_paths,
                    ignored_external_children: Vec::new(),
                    include_children: !no_children,
                    domains: domains
                        .iter()
                        .map(|d| parse_cli_domain_override(d))
                        .collect(),
                    dst_cidrs,
                    dst_ports,
                    protocols,
                    target,
                },
            },
            AppAction::DeleteRule { id } => CtlRequest::AppDeleteRule { id },
            AppAction::Test {
                process,
                path,
                host,
                ip,
                port,
                proto,
            } => CtlRequest::AppTestRule {
                process_name: process,
                exe_path: path,
                host,
                dst_ip: ip,
                dst_port: port,
                protocol: proto,
            },
        },
        CtlAction::Ps { filter } => CtlRequest::ListProcesses { filter },
        CtlAction::Schema => unreachable!(),
    })
}

fn handle_service_command(
    action: ServiceAction,
    service_exe: Option<&std::path::Path>,
    as_json: bool,
) -> Result<()> {
    match action {
        ServiceAction::Status => {
            let report = query_os_service_status();
            if as_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", format_service_status_human(&report));
            }
            Ok(())
        }
        ServiceAction::Install => {
            let msg = run_service_subcommand("install", service_exe)?;
            emit_service_result("install", &msg, as_json)
        }
        ServiceAction::Uninstall => {
            let msg = run_service_subcommand("uninstall", service_exe)?;
            emit_service_result("uninstall", &msg, as_json)
        }
        ServiceAction::Cleanup => {
            let msg = run_service_subcommand("cleanup", service_exe)?;
            emit_service_result("cleanup", &msg, as_json)
        }
        ServiceAction::Start => {
            let msg = run_service_subcommand("start", service_exe)?;
            emit_service_result("start", &msg, as_json)
        }
        ServiceAction::Stop => {
            let msg = run_service_subcommand("stop", service_exe)?;
            emit_service_result("stop", &msg, as_json)
        }
    }
}

fn emit_service_result(action: &str, message: &str, as_json: bool) -> Result<()> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "action": action,
                "message": message,
                "status": query_os_service_status()
            }))?
        );
    } else {
        println!("{message}");
    }
    Ok(())
}

fn format_service_status_human(report: &ServiceStatusReport) -> String {
    if report.platform.eq_ignore_ascii_case("windows") {
        if !report.legacy_services.is_empty() {
            return format!(
                "Service (windows): mode=gui_bound_worker legacy=[{}] (run 'bypax-cli service cleanup')",
                report.legacy_services.join(", ")
            );
        }
        return "Service (windows): mode=gui_bound_worker running=false (starts on demand when GUI enables App Proxy/TUN)".to_string();
    }
    format!(
        "Service '{}' ({}): installed={} running={} state={}",
        report.service_name,
        report.platform,
        report.installed,
        report.running,
        report.state
    )
}

fn contains_os_error_code(lower: &str, code: &str) -> bool {
    let needle = format!("os error {code}");
    for (idx, _) in lower.match_indices(&needle) {
        let after = idx + needle.len();
        let next_is_digit = lower[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit());
        if !next_is_digit {
            return true;
        }
    }
    false
}

fn format_doctor_human(data: &Value) -> String {
    let mut lines = Vec::new();
    let platform = data
        .get("platform")
        .and_then(Value::as_str)
        .unwrap_or(std::env::consts::OS);
    let is_windows = platform.eq_ignore_ascii_case("windows");

    lines.push("=== Bypax Doctor ===".to_string());
    lines.push(format!(
        "Control Mode : {}",
        data.get("controlMode")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    ));
    lines.push(format!("Platform     : {}", platform));

    if let Some(core) = data.get("core") {
        lines.push(format!(
            "Core Binary  : installed={} version={} path={}",
            core.get("installed")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            core.get("version")
                .and_then(Value::as_str)
                .unwrap_or("-"),
            core.get("binaryPath")
                .and_then(Value::as_str)
                .unwrap_or("-")
        ));
    }

    if let Some(svc) = data.get("service") {
        let plane1 = svc
            .get("plane1Connected")
            .or_else(|| svc.get("connected"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let running = svc
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let legacy_names: Vec<&str> = svc
            .get("legacyServices")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        if is_windows {
            let worker_active = plane1 || (running && legacy_names.is_empty());
            if worker_active {
                let mode = svc
                    .get("mode")
                    .and_then(Value::as_str)
                    .filter(|m| !m.is_empty() && *m != "off")
                    .unwrap_or("elevated_worker");
                lines.push(format!(
                    "Service      : mode={} running=true plane1={}",
                    mode, plane1
                ));
            } else {
                lines.push(
                    "Service      : mode=gui_bound_worker running=false (starts on demand when GUI enables App Proxy/TUN)"
                        .to_string(),
                );
            }
        } else {
            let default_name = if platform.eq_ignore_ascii_case("macos") {
                "com.bypax.service"
            } else {
                "bypax-service"
            };
            lines.push(format!(
                "Service      : name={} installed={} running={} plane1={}",
                svc.get("name").and_then(Value::as_str).unwrap_or(default_name),
                svc.get("installed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                running,
                plane1
            ));
        }

        if !legacy_names.is_empty() {
            lines.push(format!(
                "Legacy Svcs  : {} (run 'bypax-cli service cleanup')",
                legacy_names.join(", ")
            ));
        }
    }

    if let Some(drv) = data.get("driver") {
        let dll_loaded = drv
            .get("dllLoaded")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let driver_opened = drv
            .get("driverOpened")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let elevated = drv
            .get("elevated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let error_kind = drv.get("errorKind").and_then(Value::as_str);
        let error_msg = drv.get("error").and_then(Value::as_str);

        let is_access_denied = match error_kind {
            Some("access_denied") => true,
            Some(other) if other != "other" => false,
            _ => error_msg.is_some_and(|e| {
                let lower = e.to_ascii_lowercase();
                lower.contains("access denied")
                    || lower.contains("access is denied")
                    || contains_os_error_code(&lower, "5")
            }),
        };

        if dll_loaded && !driver_opened && !elevated && is_access_denied {
            lines.push(
                "Driver       : loaded=true opened=standby (non-elevated terminal; opens via elevated worker when GUI enables App Proxy)"
                    .to_string(),
            );
        } else {
            lines.push(format!(
                "Driver       : loaded={} opened={} version={} error={}",
                dll_loaded,
                driver_opened,
                drv.get("driverVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("-"),
                error_msg.unwrap_or("none")
            ));
        }
    }

    if let Some(ng) = data.get("netguard") {
        lines.push(format!(
            "NetGuard     : armed={}",
            ng.get("armed").and_then(Value::as_bool).unwrap_or(false)
        ));
    }

    lines.join("\n")
}

fn print_doctor_human(data: &Value) {
    println!("{}", format_doctor_human(data));
}

fn print_processes_human(data: &Value) {
    let procs = data
        .get("processes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    println!("{:<8} {:<8} {:<28} {:<20} PATH", "PID", "PPID", "NAME", "RULE");
    println!("{}", "-".repeat(104));
    for p in &procs {
        let pid = p.get("pid").and_then(Value::as_u64).unwrap_or(0);
        let ppid = p.get("parentPid").and_then(Value::as_u64).unwrap_or(0);
        let name = p.get("name").and_then(Value::as_str).unwrap_or("-");
        let rule = p
            .get("matchedRuleName")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let path = p.get("exePath").and_then(Value::as_str).unwrap_or("-");
        println!("{:<8} {:<8} {:<28} {:<20} {}", pid, ppid, name, rule, path);
    }
    println!("\nTotal matched processes: {}", procs.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn doctor_human_windows_standby_non_elevated_is_calm_and_accurate() {
        let payload = json!({
            "controlMode": "offline",
            "platform": "windows",
            "core": {
                "installed": true,
                "version": "1.14.0",
                "binaryPath": r"C:\Bypax\core\sing-box.exe"
            },
            "service": {
                "name": "BypaxService",
                "mode": "off",
                "installed": false,
                "running": false,
                "plane1Connected": false,
                "legacyServices": []
            },
            "driver": {
                "platform": "windows",
                "elevated": false,
                "dllLoaded": true,
                "driverOpened": false,
                "driverVersion": null,
                "error": "WinDivertOpen failed (Access Denied: Administrator privileges or BypaxService required): os error 5",
                "errorKind": "access_denied"
            },
            "netguard": {
                "armed": false
            }
        });

        let rendered = format_doctor_human(&payload);
        assert!(rendered.contains(
            "Service      : mode=gui_bound_worker running=false (starts on demand when GUI enables App Proxy/TUN)"
        ));
        assert!(rendered.contains(
            "Driver       : loaded=true opened=standby (non-elevated terminal; opens via elevated worker when GUI enables App Proxy)"
        ));
        assert!(!rendered.contains("BypaxService"));
        assert!(!rendered.contains("Legacy Svcs"));
        assert!(!rendered.contains("Access Denied"));
    }

    #[test]
    fn doctor_human_windows_driver_fallback_distinguishes_access_denied_from_signature_error() {
        let denied_no_kind = json!({
            "controlMode": "offline",
            "platform": "windows",
            "driver": {
                "elevated": false,
                "dllLoaded": true,
                "driverOpened": false,
                "error": "Access Denied (os error 5)"
            }
        });
        let rendered_denied = format_doctor_human(&denied_no_kind);
        assert!(rendered_denied.contains("loaded=true opened=standby"));

        let sig_err = json!({
            "controlMode": "offline",
            "platform": "windows",
            "driver": {
                "elevated": false,
                "dllLoaded": true,
                "driverOpened": false,
                "error": "Driver signature verification failed: os error 577",
                "errorKind": "signature_failed"
            }
        });
        let rendered_sig = format_doctor_human(&sig_err);
        assert!(rendered_sig.contains("loaded=true opened=false version=- error=Driver signature verification failed: os error 577"));
        assert!(!rendered_sig.contains("opened=standby"));
    }

    #[test]
    fn doctor_human_windows_live_elevated_shows_active_worker_and_driver() {
        let payload = json!({
            "controlMode": "live",
            "platform": "windows",
            "core": {
                "installed": true,
                "version": "1.14.0",
                "binaryPath": r"C:\Bypax\core\sing-box.exe"
            },
            "service": {
                "mode": "elevated_worker",
                "installed": false,
                "running": true,
                "connected": true,
                "elevated": true,
                "legacyServices": []
            },
            "driver": {
                "platform": "windows",
                "elevated": true,
                "dllLoaded": true,
                "driverOpened": true,
                "driverVersion": "2.2",
                "error": null,
                "errorKind": null
            },
            "netguard": {
                "armed": true
            }
        });

        let rendered = format_doctor_human(&payload);
        assert!(rendered.contains("Service      : mode=elevated_worker running=true plane1=true"));
        assert!(rendered.contains("Driver       : loaded=true opened=true version=2.2 error=none"));
        assert!(rendered.contains("NetGuard     : armed=true"));
        assert!(!rendered.contains("BypaxService"));
        assert!(!rendered.contains("Legacy Svcs"));
    }

    #[test]
    fn doctor_human_windows_highlights_legacy_services_only_when_non_empty() {
        let payload = json!({
            "controlMode": "offline",
            "platform": "windows",
            "service": {
                "name": "BypaxService",
                "installed": true,
                "running": true,
                "plane1Connected": false,
                "legacyServices": ["BypaxService", "BypathService"]
            }
        });

        let rendered = format_doctor_human(&payload);
        assert!(rendered.contains(
            "Service      : mode=gui_bound_worker running=false (starts on demand when GUI enables App Proxy/TUN)"
        ));
        assert!(rendered.contains(
            "Legacy Svcs  : BypaxService, BypathService (run 'bypax-cli service cleanup')"
        ));
    }

    #[test]
    fn doctor_human_macos_uses_launchd_service_format() {
        let payload = json!({
            "controlMode": "live",
            "platform": "macos",
            "core": {
                "installed": true,
                "version": "1.14.0",
                "binaryPath": "/Users/test/Library/Application Support/Bypax/core/sing-box"
            },
            "service": {
                "installed": true,
                "running": true,
                "connected": true
            },
            "driver": {
                "platform": "macos",
                "elevated": false,
                "dllLoaded": false,
                "driverOpened": false,
                "driverVersion": null,
                "error": "WinDivert is only used on Windows; macOS uses zero-cert launchd + utun path routing"
            },
            "netguard": {
                "armed": false
            }
        });

        let rendered = format_doctor_human(&payload);
        assert!(rendered.contains("Service      : name=com.bypax.service installed=true running=true plane1=true"));
        assert!(rendered.contains("Driver       : loaded=false opened=false version=- error=WinDivert is only used on Windows; macOS uses zero-cert launchd + utun path routing"));
        assert!(!rendered.contains("gui_bound_worker"));
    }

    #[test]
    fn service_subcommand_help_reflects_windows_legacy_cleanup_and_macos_launchd() {
        let cmd = Cli::command();
        let svc = cmd
            .find_subcommand("service")
            .expect("service subcommand exists");
        let about = svc
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        assert!(
            about.contains("(Windows legacy cleanup / macOS launchd)"),
            "unexpected service about text: {about}"
        );
        assert!(!about.contains("Windows BypaxService"));
    }

    #[test]
    fn service_status_human_formats_windows_and_macos_accurately() {
        let win_clean = ServiceStatusReport {
            platform: "windows".to_string(),
            service_name: "BypaxService".to_string(),
            installed: false,
            running: false,
            state: "not_installed".to_string(),
            legacy_services: Vec::new(),
            binary_path: None,
        };
        let win_out = format_service_status_human(&win_clean);
        assert!(win_out.contains("mode=gui_bound_worker"));
        assert!(!win_out.contains("BypaxService"));

        let win_legacy = ServiceStatusReport {
            legacy_services: vec!["BypaxService".to_string()],
            ..win_clean
        };
        let win_legacy_out = format_service_status_human(&win_legacy);
        assert!(win_legacy_out.contains("legacy=[BypaxService]"));
        assert!(win_legacy_out.contains("bypax-cli service cleanup"));

        let mac = ServiceStatusReport {
            platform: "macos".to_string(),
            service_name: "com.bypax.service".to_string(),
            installed: true,
            running: true,
            state: "running".to_string(),
            legacy_services: Vec::new(),
            binary_path: None,
        };
        assert_eq!(
            format_service_status_human(&mac),
            "Service 'com.bypax.service' (macos): installed=true running=true state=running"
        );
    }
}
