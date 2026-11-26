use anyhow::Result;
use bypax_core::storage::DataPaths;
use bypax_ipc::{
    default_svc_endpoint, resolve_or_create_ipc_token, PipeAclMode, ServiceIpcServer,
};
use bypax_service::controller::ServiceController;
use bypax_service::platform_svc;
use clap::{Parser, Subcommand};
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "bypax-service", about = "Bypax privileged proxy & app-routing daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Windows Service Control Manager entry point (`BypaxService`).
    ServiceRun,
    /// On-demand elevated worker bound to a parent GUI PID (exits when parent terminates).
    WorkerRun {
        #[arg(long)]
        parent_pid: u32,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Foreground / macOS launchd LaunchDaemon run loop.
    DaemonRun {
        #[arg(long)]
        parent_pid: Option<u32>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Installs the Windows Service (`BypaxService`) or macOS LaunchDaemon.
    Install {
        #[arg(long)]
        autostart: bool,
    },
    /// Uninstalls the Windows Service or macOS LaunchDaemon.
    Uninstall,
    /// Starts the installed service.
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

fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::DaemonRun {
        parent_pid: None,
        endpoint: None,
        token: None,
    }) {
        Commands::ServiceRun => platform_svc::run_windows_service(),
        Commands::WorkerRun {
            parent_pid,
            endpoint,
            token,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_daemon_loop(endpoint, Some(parent_pid), token))
        }
        Commands::DaemonRun {
            parent_pid,
            endpoint,
            token,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run_daemon_loop(endpoint, parent_pid, token))
        }
        Commands::Install { autostart } => {
            let exe = std::env::current_exe()?;
            platform_svc::install(&exe, autostart)?;
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
) -> Result<()> {
    let paths = DataPaths::resolve()?;
    let token = token_override
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| resolve_or_create_ipc_token(Some(&paths.runtime_dir)));
    let controller = ServiceController::new(&paths, token);
    let _watchdog = controller.spawn_watchdog();

    let endpoint = endpoint_override.unwrap_or_else(default_svc_endpoint);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // If running as an on-demand elevated worker, watch the parent GUI PID and tear down
    // cleanly the moment the GUI exits or crashes.
    if let Some(ppid) = parent_pid {
        let ctrl_watch = controller.clone();
        let tx_slot = std::sync::Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));
        let tx_watch = tx_slot.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                if !platform_svc::is_parent_alive(ppid) {
                    info!(parent_pid = ppid, "parent GUI process exited; shutting down worker");
                    ctrl_watch.stop_all_and_restore().await;
                    if let Ok(mut g) = tx_watch.lock() {
                        if let Some(tx) = g.take() {
                            let _ = tx.send(());
                        }
                    }
                    break;
                }
            }
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
