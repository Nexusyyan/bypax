use anyhow::Result;
use bypax_core::logging::{logs_dir_from_runtime_dir, RotatingLogFile, DEFAULT_MAX_LOG_BYTES};
use bypax_core::netguard::NetGuard;
use bypax_core::storage::DataPaths;
use bypax_ipc::{
    default_svc_endpoint, resolve_or_create_ipc_token, PipeAclMode, ServiceIpcServer,
};
use bypax_service::controller::ServiceController;
use bypax_service::platform_svc;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "bypax-service", about = "Bypax privileged proxy & app-routing helper")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Legacy Windows Service Control Manager entry point (`BypaxService`).
    ServiceRun,
    /// On-demand elevated worker strictly bound to a parent GUI PID (exits in 0ms when GUI terminates).
    WorkerRun {
        #[arg(long)]
        parent_pid: u32,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Foreground / macOS launchd LaunchDaemon run loop.
    DaemonRun {
        #[arg(long)]
        parent_pid: Option<u32>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Cleans up legacy persistent Windows services (`BypaxService`/`BypathService`), stale
    /// WinDivert driver locks, and optionally restores NetGuard system proxy state.
    CleanupLegacy {
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
    },
    /// Installs the macOS LaunchDaemon (`com.bypax.service`). Disabled on Windows.
    Install {
        #[arg(long)]
        autostart: bool,
        #[arg(long)]
        start: bool,
    },
    /// Uninstalls any legacy Windows Service or macOS LaunchDaemon.
    Uninstall,
    /// Starts the installed service (macOS).
    Start,
    /// Stops the installed service.
    Stop,
    /// macOS explicit LaunchDaemon install (`com.bypax.service`).
    InstallLaunchd,
    /// macOS explicit LaunchDaemon uninstall.
    UninstallLaunchd,
    /// Prints service installation and runtime status.
    Status {
        #[arg(long)]
        json: bool,
    },
}

fn init_service_logging(runtime_dir_hint: Option<&Path>) -> Option<PathBuf> {
    let logs_dir = runtime_dir_hint
        .map(logs_dir_from_runtime_dir)
        .or_else(|| DataPaths::resolve().ok().map(|p| p.logs_dir));

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if let Some(dir) = logs_dir {
        let log_path = dir.join("bypax-service.log");
        if let Ok(log_file) = RotatingLogFile::open(log_path.clone(), DEFAULT_MAX_LOG_BYTES) {
            let writer_file = log_file.clone();
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_target(true)
                .with_writer(move || writer_file.writer())
                .try_init();
            return Some(log_path);
        }
    }

    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    None
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let runtime_hint = match &cli.command {
        Some(Commands::WorkerRun { runtime_dir, .. })
        | Some(Commands::DaemonRun { runtime_dir, .. })
        | Some(Commands::CleanupLegacy { runtime_dir }) => runtime_dir.as_deref(),
        _ => None,
    };
    let log_path = init_service_logging(runtime_hint);
    info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        log_file = ?log_path,
        "bypax-service starting"
    );

    match cli.command.unwrap_or(Commands::DaemonRun {
        parent_pid: None,
        endpoint: None,
        token: None,
        token_file: None,
        runtime_dir: None,
    }) {
        Commands::ServiceRun => platform_svc::run_windows_service(),
        Commands::WorkerRun {
            parent_pid,
            endpoint,
            token,
            token_file,
            runtime_dir,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_daemon_loop(
                endpoint,
                Some(parent_pid),
                token,
                token_file,
                runtime_dir,
            ))
        }
        Commands::DaemonRun {
            parent_pid,
            endpoint,
            token,
            token_file,
            runtime_dir,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_daemon_loop(
                endpoint,
                parent_pid,
                token,
                token_file,
                runtime_dir,
            ))
        }
        Commands::CleanupLegacy { runtime_dir } => {
            let mut actions = platform_svc::cleanup_legacy_services_and_driver()?;
            if let Some(rt_dir) = runtime_dir {
                let guard = NetGuard::new(&rt_dir);
                if guard.disable_system_proxy().is_ok() {
                    actions.push("restored:netguard".to_string());
                }
            }
            if actions.is_empty() {
                println!("No legacy services or stale driver locks found");
            } else {
                println!("Cleaned up legacy state: {}", actions.join(", "));
            }
            Ok(())
        }
        Commands::Install { autostart, start } => {
            let exe = std::env::current_exe()?;
            platform_svc::install(&exe, autostart)?;
            if start {
                platform_svc::start()?;
            }
            println!("Installed Bypax privileged service");
            Ok(())
        }
        Commands::Uninstall => {
            platform_svc::uninstall()?;
            println!("Uninstalled Bypax privileged service");
            Ok(())
        }
        Commands::Start => {
            platform_svc::start()?;
            println!("Started Bypax privileged service");
            Ok(())
        }
        Commands::Stop => {
            platform_svc::stop()?;
            println!("Stopped Bypax privileged service");
            Ok(())
        }
        Commands::InstallLaunchd => {
            let exe = std::env::current_exe()?;
            platform_svc::install_launchd(&exe)?;
            println!("Installed macOS LaunchDaemon com.bypax.service");
            Ok(())
        }
        Commands::UninstallLaunchd => {
            platform_svc::uninstall_launchd()?;
            println!("Uninstalled macOS LaunchDaemon com.bypax.service");
            Ok(())
        }
        Commands::Status { json } => {
            let status = platform_svc::query_status();
            if json {
                println!("{}", serde_json::to_string(&status)?);
            } else {
                println!(
                    "platform={} installed={} running={} state={}",
                    status.platform, status.installed, status.running, status.state
                );
            }
            Ok(())
        }
    }
}

async fn run_daemon_loop(
    endpoint_override: Option<String>,
    parent_pid: Option<u32>,
    token_override: Option<String>,
    token_file: Option<PathBuf>,
    runtime_dir_override: Option<PathBuf>,
) -> Result<()> {
    let runtime_dir = match runtime_dir_override {
        Some(dir) => {
            let _ = std::fs::create_dir_all(&dir);
            dir
        }
        None => DataPaths::resolve()?.runtime_dir,
    };

    let file_token = token_file.and_then(|tf| {
        let raw = std::fs::read_to_string(&tf).ok();
        // Immediately delete ephemeral one-shot token file once loaded into memory.
        let _ = std::fs::remove_file(&tf);
        raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    });

    let token = file_token
        .or_else(|| token_override.filter(|t| !t.trim().is_empty()))
        .unwrap_or_else(|| resolve_or_create_ipc_token(Some(&runtime_dir)));

    let controller = ServiceController::new_with_runtime_dir(runtime_dir, token);
    if let Some(ppid) = parent_pid {
        controller.set_gui_pid(ppid);
    }
    let _watchdog = controller.spawn_watchdog();

    let endpoint = endpoint_override.unwrap_or_else(default_svc_endpoint);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // If running as an on-demand elevated worker, pin a kernel handle on the parent GUI PID
    // so GUI exit or crash triggers 0ms cleanup of WinDivert, TUN, and user NetGuard proxy.
    if let Some(ppid) = parent_pid {
        let (exit_tx, exit_rx) = oneshot::channel::<()>();
        std::thread::Builder::new()
            .name("bypax-parent-watch".into())
            .spawn(move || {
                platform_svc::wait_for_process_exit(ppid);
                let _ = exit_tx.send(());
            })?;

        let ctrl_watch = controller.clone();
        tokio::spawn(async move {
            let _ = exit_rx.await;
            info!(
                parent_pid = ppid,
                "parent GUI process exited; tearing down capture and restoring network"
            );
            ctrl_watch.stop_all_and_restore().await;
            let _ = shutdown_tx.send(());
        });

        let server = ServiceIpcServer::new(endpoint, PipeAclMode::PrivilegedService, controller.clone());
        server.run(shutdown_rx).await?;
        controller.stop_all_and_restore().await;
        return Ok(());
    }

    // Standard foreground / launchd daemon mode: exit cleanly on Ctrl+C / SIGTERM.
    let ctrl_sig = controller.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl_sig.stop_all_and_restore().await;
        let _ = shutdown_tx.send(());
    });

    let server = ServiceIpcServer::new(endpoint, PipeAclMode::PrivilegedService, controller.clone());
    server.run(shutdown_rx).await?;
    controller.stop_all_and_restore().await;
    Ok(())
}
