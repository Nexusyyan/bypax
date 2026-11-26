use crate::ctl_proto::{CtlEnvelope, CtlResponse};
use crate::service_proto::{ServiceEnvelope, ServiceResponse};
use crate::WINDOWS_PIPE_SDDL;
use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Access-control policy applied to a local IPC listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeAclMode {
    /// Plane 1 (`bypax-svc-v1`): LocalSystem + Administrators + local Interactive Users (SDDL),
    /// rejecting remote network clients; Unix socket mode `0666` gated by `BYPAX_IPC_TOKEN`.
    PrivilegedService,
    /// Plane 2 (`bypax-ctl-v1`): Current interactive user only, rejecting remote callers;
    /// Unix socket mode `0600`.
    CurrentUserControl,
}

/// Async handler trait for Plane 1 (`bypax-service`) requests.
/// Returns `(ServiceResponse, should_shutdown)`.
pub trait ServiceHandler: Send + Sync + 'static {
    fn handle(
        &self,
        envelope: ServiceEnvelope,
    ) -> Pin<Box<dyn Future<Output = (ServiceResponse, bool)> + Send + '_>>;
}

/// Async handler trait for Plane 2 (`bypax` GUI control server) requests.
pub trait CtlHandler: Send + Sync + 'static {
    fn handle(
        &self,
        envelope: CtlEnvelope,
    ) -> Pin<Box<dyn Future<Output = CtlResponse> + Send + '_>>;
}

/// Sends a single Plane 1 authenticated RPC request with timeout and `PIPE_BUSY` retry.
pub async fn send_service_request(
    endpoint: &str,
    envelope: &ServiceEnvelope,
    timeout: Duration,
) -> Result<ServiceResponse> {
    tokio::time::timeout(timeout, send_json_line(endpoint, envelope))
        .await
        .map_err(|_| anyhow!("IPC_TIMEOUT: timed out waiting for service at '{endpoint}'"))?
}

/// Sends a single Plane 2 GUI control RPC request with timeout and `PIPE_BUSY` retry.
pub async fn send_ctl_request(
    endpoint: &str,
    envelope: &CtlEnvelope,
    timeout: Duration,
) -> Result<CtlResponse> {
    tokio::time::timeout(timeout, send_json_line(endpoint, envelope))
        .await
        .map_err(|_| anyhow!("CTL_TIMEOUT: timed out waiting for GUI control at '{endpoint}'"))?
}

async fn send_json_line<Req, Resp>(endpoint: &str, req: &Req) -> Result<Resp>
where
    Req: serde::Serialize,
    Resp: serde::de::DeserializeOwned,
{
    let mut payload = serde_json::to_string(req)?;
    payload.push('\n');

    #[cfg(windows)]
    {
        let mut pipe = connect_windows_pipe(endpoint).await?;
        pipe.write_all(payload.as_bytes()).await?;
        pipe.flush().await?;

        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("IPC pipe '{endpoint}' closed before response"));
        }
        let resp: Resp =
            serde_json::from_str(line.trim()).context("failed to decode IPC response JSON")?;
        Ok(resp)
    }

    #[cfg(unix)]
    {
        let mut stream = tokio::net::UnixStream::connect(endpoint)
            .await
            .with_context(|| format!("failed to connect to Unix socket '{endpoint}'"))?;
        stream.write_all(payload.as_bytes()).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("Unix socket '{endpoint}' closed before response"));
        }
        let resp: Resp =
            serde_json::from_str(line.trim()).context("failed to decode IPC response JSON")?;
        Ok(resp)
    }
}

/// Plane 1 IPC server hosting `bypax-service`.
pub struct ServiceIpcServer {
    endpoint: String,
    acl: PipeAclMode,
    handler: Arc<dyn ServiceHandler>,
}

impl ServiceIpcServer {
    pub fn new(
        endpoint: impl Into<String>,
        acl: PipeAclMode,
        handler: Arc<dyn ServiceHandler>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            acl,
            handler,
        }
    }

    pub async fn run(self, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        let handler = self.handler;
        run_line_server(
            &self.endpoint,
            self.acl,
            shutdown_rx,
            Arc::new(move |line: String| {
                let handler = Arc::clone(&handler);
                Box::pin(async move {
                    match serde_json::from_str::<ServiceEnvelope>(&line) {
                        Ok(env) => {
                            let (resp, should_exit) = handler.handle(env).await;
                            let encoded = serde_json::to_string(&resp).unwrap_or_else(|_| {
                                r#"{"id":"err","ok":false,"message":"serialize error"}"#.to_string()
                            });
                            (encoded, should_exit)
                        }
                        Err(e) => {
                            let resp =
                                ServiceResponse::error("parse", format!("Bad envelope: {e}"));
                            let encoded = serde_json::to_string(&resp).unwrap_or_default();
                            (encoded, false)
                        }
                    }
                })
            }),
        )
        .await
    }
}

/// Plane 2 IPC server hosted inside the non-elevated `bypax` GUI for `bypax-cli` and MCP.
pub struct CtlIpcServer {
    endpoint: String,
    handler: Arc<dyn CtlHandler>,
}

impl CtlIpcServer {
    pub fn new(endpoint: impl Into<String>, handler: Arc<dyn CtlHandler>) -> Self {
        Self {
            endpoint: endpoint.into(),
            handler,
        }
    }

    pub async fn run(self, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        let handler = self.handler;
        run_line_server(
            &self.endpoint,
            PipeAclMode::CurrentUserControl,
            shutdown_rx,
            Arc::new(move |line: String| {
                let handler = Arc::clone(&handler);
                Box::pin(async move {
                    match serde_json::from_str::<CtlEnvelope>(&line) {
                        Ok(env) => {
                            let resp = handler.handle(env).await;
                            let encoded = serde_json::to_string(&resp).unwrap_or_else(|_| {
                                r#"{"id":"err","ok":false,"message":"serialize error"}"#.to_string()
                            });
                            (encoded, false)
                        }
                        Err(e) => {
                            let resp = CtlResponse::error("parse", format!("Bad envelope: {e}"));
                            let encoded = serde_json::to_string(&resp).unwrap_or_default();
                            (encoded, false)
                        }
                    }
                })
            }),
        )
        .await
    }
}

type LineDispatchFn = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = (String, bool)> + Send>> + Send + Sync + 'static,
>;

async fn handle_stream_lines<S>(
    stream: S,
    dispatch: LineDispatchFn,
    internal_shutdown_tx: Arc<tokio::sync::Notify>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (mut encoded, should_shutdown) = dispatch(trimmed.to_string()).await;
        encoded.push('\n');
        if write_half.write_all(encoded.as_bytes()).await.is_err() {
            break;
        }
        let _ = write_half.flush().await;
        if should_shutdown {
            internal_shutdown_tx.notify_one();
            break;
        }
    }
}

#[cfg(windows)]
async fn run_line_server(
    endpoint: &str,
    acl: PipeAclMode,
    mut shutdown_rx: oneshot::Receiver<()>,
    dispatch: LineDispatchFn,
) -> Result<()> {
    let mut server = create_windows_pipe_instance(endpoint, acl, true)?;
    let internal_shutdown = Arc::new(tokio::sync::Notify::new());
    info!(pipe = %endpoint, ?acl, "Windows Named Pipe IPC listener ready");

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(pipe = %endpoint, "Named Pipe IPC listener stopping");
                break;
            }
            _ = internal_shutdown.notified() => {
                info!(pipe = %endpoint, "Named Pipe IPC listener received Shutdown command");
                break;
            }
            res = server.connect() => {
                match res {
                    Ok(()) => {
                        let connected = server;
                        server = match create_windows_pipe_instance(endpoint, acl, false) {
                            Ok(next) => next,
                            Err(err) => {
                                warn!(?err, pipe = %endpoint, "failed to create next pipe instance");
                                break;
                            }
                        };
                        let disp = Arc::clone(&dispatch);
                        let notify = Arc::clone(&internal_shutdown);
                        tokio::spawn(async move {
                            handle_stream_lines(connected, disp, notify).await;
                        });
                    }
                    Err(err) => {
                        debug!(?err, pipe = %endpoint, "Named Pipe accept error");
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn run_line_server(
    endpoint: &str,
    acl: PipeAclMode,
    mut shutdown_rx: oneshot::Receiver<()>,
    dispatch: LineDispatchFn,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let path = Path::new(endpoint);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(path);

    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("failed to bind Unix socket '{endpoint}'"))?;
    let mode = match acl {
        PipeAclMode::PrivilegedService => 0o666,
        PipeAclMode::CurrentUserControl => 0o600,
    };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));

    let internal_shutdown = Arc::new(tokio::sync::Notify::new());
    info!(socket = %endpoint, ?acl, "Unix Domain Socket IPC listener ready");

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(socket = %endpoint, "Unix IPC listener stopping");
                break;
            }
            _ = internal_shutdown.notified() => {
                info!(socket = %endpoint, "Unix IPC listener received Shutdown command");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => {
                        let disp = Arc::clone(&dispatch);
                        let notify = Arc::clone(&internal_shutdown);
                        tokio::spawn(async move {
                            handle_stream_lines(stream, disp, notify).await;
                        });
                    }
                    Err(err) => {
                        debug!(?err, socket = %endpoint, "Unix IPC accept error");
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(windows)]
async fn connect_windows_pipe(
    endpoint: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;

    for attempt in 0..10 {
        match ClientOptions::new().open(endpoint) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < 9 => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => {
                return Err(anyhow!("failed to connect to IPC pipe '{endpoint}': {err}"));
            }
        }
    }
    Err(anyhow!("IPC pipe '{endpoint}' remained busy"))
}

#[cfg(windows)]
fn create_windows_pipe_instance(
    endpoint: &str,
    acl: PipeAclMode,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first_instance)
        .reject_remote_clients(true);

    if acl == PipeAclMode::CurrentUserControl {
        return opts
            .create(endpoint)
            .with_context(|| format!("failed to create user control Named Pipe '{endpoint}'"));
    }

    struct OwnedSd(PSECURITY_DESCRIPTOR);
    impl Drop for OwnedSd {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0));
                }
            }
        }
    }

    let mut wide: Vec<u16> = WINDOWS_PIPE_SDDL.encode_utf16().collect();
    wide.push(0);

    let mut sd = PSECURITY_DESCRIPTOR::default();
    let sd_ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    };

    if sd_ok.is_ok() {
        let _guard = OwnedSd(sd);
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let server = unsafe {
            opts.create_with_security_attributes_raw(
                endpoint,
                (&mut sa as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
        .with_context(|| format!("failed to create Named Pipe '{endpoint}' with SDDL ACL"))?;
        Ok(server)
    } else {
        opts.create(endpoint)
            .with_context(|| format!("failed to create Named Pipe '{endpoint}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl_proto::CtlRequest;
    use crate::service_proto::ServiceCommand;

    struct EchoSvcHandler {
        token: String,
    }

    impl ServiceHandler for EchoSvcHandler {
        fn handle(
            &self,
            env: ServiceEnvelope,
        ) -> Pin<Box<dyn Future<Output = (ServiceResponse, bool)> + Send + '_>> {
            Box::pin(async move {
                if env.session_token != self.token {
                    return (ServiceResponse::error(env.id, "Unauthorized"), false);
                }
                match env.command {
                    ServiceCommand::Ping => (ServiceResponse::success(env.id, "pong"), false),
                    ServiceCommand::Shutdown => {
                        (ServiceResponse::success(env.id, "bye"), true)
                    }
                    _ => (ServiceResponse::success(env.id, "ok"), false),
                }
            })
        }
    }

    struct EchoCtlHandler;

    impl CtlHandler for EchoCtlHandler {
        fn handle(
            &self,
            env: CtlEnvelope,
        ) -> Pin<Box<dyn Future<Output = CtlResponse> + Send + '_>> {
            Box::pin(async move {
                CtlResponse::success(
                    env.id,
                    "ok",
                    Some(serde_json::json!({ "echo": env.request })),
                )
            })
        }
    }

    #[tokio::test]
    async fn dual_plane_ipc_roundtrip_and_token_auth() {
        #[cfg(windows)]
        let svc_ep = format!(r"\\.\pipe\bypax-svc-test-{}", std::process::id());
        #[cfg(unix)]
        let _tmp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let svc_ep = _tmp.path().join("svc.sock").to_string_lossy().to_string();

        #[cfg(windows)]
        let ctl_ep = format!(r"\\.\pipe\bypax-ctl-test-{}", std::process::id());
        #[cfg(unix)]
        let ctl_ep = _tmp.path().join("ctl.sock").to_string_lossy().to_string();

        let token = crate::generate_session_token();
        let svc_server = ServiceIpcServer::new(
            svc_ep.clone(),
            PipeAclMode::PrivilegedService,
            Arc::new(EchoSvcHandler {
                token: token.clone(),
            }),
        );
        let (svc_tx, svc_rx) = oneshot::channel();
        let svc_task = tokio::spawn(svc_server.run(svc_rx));

        let ctl_server = CtlIpcServer::new(ctl_ep.clone(), Arc::new(EchoCtlHandler));
        let (ctl_tx, ctl_rx) = oneshot::channel();
        let ctl_task = tokio::spawn(ctl_server.run(ctl_rx));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Plane 1 rejects wrong token
        let bad = send_service_request(
            &svc_ep,
            &ServiceEnvelope {
                id: "1".into(),
                session_token: "wrong".into(),
                command: ServiceCommand::Ping,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(!bad.ok);

        // Plane 1 accepts right token
        let good = send_service_request(
            &svc_ep,
            &ServiceEnvelope {
                id: "2".into(),
                session_token: token,
                command: ServiceCommand::Ping,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(good.ok);
        assert_eq!(good.message, "pong");

        // Plane 2 control request roundtrips JSON data
        let ctl_resp = send_ctl_request(
            &ctl_ep,
            &CtlEnvelope {
                id: "c1".into(),
                request: CtlRequest::Status,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(ctl_resp.ok);
        assert!(ctl_resp.data.is_some());

        let _ = svc_tx.send(());
        let _ = ctl_tx.send(());
        let _ = svc_task.await;
        let _ = ctl_task.await;
    }
}
