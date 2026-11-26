use crate::capture::{build_udp_ip_packet, CaptureEngine, FiveTuple, PacketMeta};
use crate::engine::RuntimeSnapshot;
use crate::origin::OriginRegistry;
use crate::process::ProcessTracker;
use crate::sniff::{sniff_udp_payload, SniffResult};
use crate::socks5::{associate_internal_udp, decode_udp_packet, encode_udp_packet, TargetAddr};
use crate::telemetry::AppProxyTelemetry;
use bypax_ipc::FlowOriginDto;
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    src_ip: IpAddr,
    src_port: u16,
    auth_user: String,
}

struct UdpOutboundDatagram {
    dst_ip: IpAddr,
    dst_port: u16,
    payload: Vec<u8>,
    meta: PacketMeta,
}

pub struct UdpPacketContext {
    pub pid: Option<u32>,
    pub process_name: String,
    pub exe_path: Option<String>,
    pub ancestor_app: Option<String>,
    pub ancestor_chain: Vec<String>,
    pub rule_id: String,
    pub rule_name: String,
    pub target: String,
    pub auth_user: String,
}

pub struct UdpRelay {
    capture: Arc<dyn CaptureEngine>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
    sessions: Arc<DashMap<UdpSessionKey, mpsc::Sender<UdpOutboundDatagram>>>,
    quic_logged: DashMap<FiveTuple, Instant>,
}

impl UdpRelay {
    pub(crate) fn new(
        capture: Arc<dyn CaptureEngine>,
        tracker: Arc<dyn ProcessTracker>,
        runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
        origins: Arc<OriginRegistry>,
        telemetry: Arc<AppProxyTelemetry>,
    ) -> Self {
        Self {
            capture,
            tracker,
            runtime,
            origins,
            telemetry,
            sessions: Arc::new(DashMap::new()),
            quic_logged: DashMap::new(),
        }
    }

    pub async fn handle_outbound_udp(
        &self,
        tuple: FiveTuple,
        payload: Vec<u8>,
        meta: PacketMeta,
        ctx: UdpPacketContext,
    ) {
        let rt = Arc::clone(&self.runtime.read().expect("runtime lock poisoned"));
        let is_quic = tuple.dst_port == 443
            || matches!(sniff_udp_payload(&payload), Some(SniffResult::QuicInitial));

        // Drop encrypted QUIC when domain-reject rules require TCP SNI inspection.
        if is_quic
            && rt.block_quic_when_needed
            && rt
                .rules
                .has_domain_block_rules_for_flow(ctx.pid, &tuple, self.tracker.as_ref())
        {
            if self.should_log_quic(&tuple) {
                self.telemetry.record_local_reject(
                    ctx.pid,
                    ctx.process_name,
                    ctx.ancestor_app,
                    ctx.ancestor_chain,
                    SocketAddr::new(tuple.dst_ip, tuple.dst_port).to_string(),
                    ctx.rule_name,
                );
            }
            return;
        }

        let key = UdpSessionKey {
            src_ip: tuple.src_ip,
            src_port: tuple.src_port,
            auth_user: ctx.auth_user.clone(),
        };

        let datagram = UdpOutboundDatagram {
            dst_ip: tuple.dst_ip,
            dst_port: tuple.dst_port,
            payload,
            meta,
        };

        if let Some(existing) = self.sessions.get(&key) {
            if existing.try_send(datagram).is_ok() {
                return;
            }
            drop(existing);
            self.sessions.remove(&key);
            return;
        }

        let (tx, rx) = mpsc::channel::<UdpOutboundDatagram>(128);
        let _ = tx.try_send(datagram);
        self.sessions.insert(key.clone(), tx);

        let sessions = Arc::clone(&self.sessions);
        let capture = Arc::clone(&self.capture);
        let origins = Arc::clone(&self.origins);
        let telemetry = Arc::clone(&self.telemetry);
        let app_proxy_port = rt.app_proxy_port;
        let control_secret = rt.control_secret.clone();

        tokio::spawn(async move {
            run_udp_session(
                key.clone(),
                app_proxy_port,
                control_secret,
                ctx,
                rx,
                capture,
                origins,
                telemetry,
            )
            .await;
            sessions.remove(&key);
        });
    }

    fn should_log_quic(&self, tuple: &FiveTuple) -> bool {
        let now = Instant::now();
        if let Some(prev) = self.quic_logged.get(tuple) {
            if now.duration_since(*prev) < Duration::from_secs(30) {
                return false;
            }
        }
        self.quic_logged.insert(*tuple, now);
        true
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    key: UdpSessionKey,
    app_proxy_port: u16,
    control_secret: String,
    ctx: UdpPacketContext,
    mut rx: mpsc::Receiver<UdpOutboundDatagram>,
    capture: Arc<dyn CaptureEngine>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
) {
    let assoc = match associate_internal_udp(app_proxy_port, &ctx.auth_user, &control_secret).await
    {
        Ok(a) => a,
        Err(err) => {
            warn!(proc = %ctx.process_name, error = %err, "internal SOCKS5 UDP ASSOCIATE failed");
            return;
        }
    };

    origins.register(FlowOriginDto {
        local_port: assoc.local_udp_port,
        pid: ctx.pid.unwrap_or(0),
        process_name: ctx.process_name,
        exe_path: ctx.exe_path,
        ancestor_name: ctx.ancestor_app,
        ancestor_chain: ctx.ancestor_chain,
        rule_id: Some(ctx.rule_id),
        rule_name: ctx.rule_name,
        target: ctx.target,
        auth_user: ctx.auth_user,
        sniffed_host: None,
        action: "proxy".to_string(),
        expired: false,
    });
    telemetry.on_proxied_open();

    let mut last_meta: Option<PacketMeta> = None;
    let mut recv_buf = vec![0u8; 65_535];

    loop {
        tokio::select! {
            maybe_out = rx.recv() => {
                match maybe_out {
                    Some(dgram) => {
                        last_meta = Some(dgram.meta);
                        let target = TargetAddr::Ip(SocketAddr::new(dgram.dst_ip, dgram.dst_port));
                        if let Ok(encoded) = encode_udp_packet(&target, &dgram.payload) {
                            if assoc.udp_socket.send_to(&encoded, assoc.relay_addr).await.is_err() {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }
            recv_res = assoc.udp_socket.recv_from(&mut recv_buf) => {
                match recv_res {
                    Ok((n, _from)) => {
                        if let Some(meta) = last_meta {
                            if let Ok((remote_addr, payload)) = decode_udp_packet(&recv_buf[..n]) {
                                if let Some(raw_ip) = build_udp_ip_packet(
                                    remote_addr.ip(),
                                    remote_addr.port(),
                                    key.src_ip,
                                    key.src_port,
                                    payload,
                                ) {
                                    let reply_meta = meta.as_inbound_reply();
                                    if let Err(err) = capture.inject(&raw_ip, &reply_meta) {
                                        debug!(?err, "failed injecting UDP reply packet");
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep(UDP_IDLE_TIMEOUT) => {
                break;
            }
        }
    }

    origins.mark_closed(assoc.local_udp_port);
    telemetry.on_proxied_close();
}
