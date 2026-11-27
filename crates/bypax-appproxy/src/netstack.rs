use crate::capture::{
    build_tcp_rst_ip_packet, parse_ip_packet, CaptureEngine, FiveTuple, PacketMeta,
    TransportProtocol,
};
use crate::engine::RuntimeSnapshot;
use crate::origin::OriginRegistry;
use crate::process::ProcessTracker;
use crate::rules::L7DomainDecision;
use crate::sniff::{needs_more_tls_bytes, sniff_tcp_payload, SniffResult};
use crate::socks5::{connect_internal_tcp, TargetAddr};
use crate::telemetry::AppProxyTelemetry;
use bypax_ipc::FlowOriginDto;
use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, warn};

const TCP_RX_BUF_SIZE: usize = 65_536;
const TCP_TX_BUF_SIZE: usize = 65_536;
const CHANNEL_CAPACITY: usize = 64;
const SNIFF_PEEK_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_SNIFF_BUFFER_BYTES: usize = 8_192;
const TCP_FIN_FLAG: u8 = 0x01;
const TCP_SYN_FLAG: u8 = 0x02;
const TCP_RST_FLAG: u8 = 0x04;
const TCP_ACK_FLAG: u8 = 0x10;

pub struct NetstackInput {
    pub packet: Vec<u8>,
    pub tuple: FiveTuple,
    pub meta: PacketMeta,
    pub pid: Option<u32>,
    pub process_name: String,
    pub exe_path: Option<String>,
    pub ancestor_app: Option<String>,
    pub ancestor_chain: Vec<String>,
    pub rule_id: String,
    pub rule_name: String,
    pub target: Option<String>,    // None => InspectDirect
    pub auth_user: Option<String>, // None => InspectDirect
    pub is_syn_only: bool,
}

enum UpstreamEvent {
    Data(Bytes),
    Eof,
    Abort,
}

struct VirtualRxToken(Vec<u8>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

struct VirtualIpDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualIpDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(256),
            tx_queue: VecDeque::with_capacity(256),
            mtu,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((VirtualRxToken(pkt), VirtualTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        let mut csum = ChecksumCapabilities::ignored();
        csum.ipv4 = Checksum::Tx;
        csum.tcp = Checksum::Tx;
        csum.udp = Checksum::Tx;
        caps.checksum = csum;
        caps
    }
}

enum NetstackControl {
    ResetProxiedSessions {
        reason: &'static str,
    },
    ShutdownAndResetAll {
        done_tx: oneshot::Sender<usize>,
    },
}

struct ActiveTcpSession {
    handle: SocketHandle,
    is_proxied: bool,
    to_upstream: Option<mpsc::Sender<Bytes>>,
    from_upstream: mpsc::Receiver<UpstreamEvent>,
    pending_write: VecDeque<u8>,
    upstream_eof: bool,
    upstream_abort: bool,
    abort_pending_flush: bool,
    client_next_seq: u32,
    client_acked_seq: Option<u32>,
    server_next_seq: Option<u32>,
    rst_injected: bool,
    created_at: Instant,
}

pub struct TcpNetstack {
    input_tx: mpsc::Sender<NetstackInput>,
    control_tx: mpsc::UnboundedSender<NetstackControl>,
}

impl TcpNetstack {
    pub(crate) fn spawn(
        capture: Arc<dyn CaptureEngine>,
        tracker: Arc<dyn ProcessTracker>,
        runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
        origins: Arc<OriginRegistry>,
        telemetry: Arc<AppProxyTelemetry>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (input_tx, input_rx) = mpsc::channel::<NetstackInput>(1024);
        let (control_tx, control_rx) = mpsc::unbounded_channel::<NetstackControl>();
        let handle = tokio::spawn(run_netstack_loop(
            capture, tracker, runtime, origins, telemetry, input_rx, control_rx,
        ));
        (
            Self {
                input_tx,
                control_tx,
            },
            handle,
        )
    }

    pub fn try_feed(&self, input: NetstackInput) -> Result<(), &'static str> {
        self.input_tx.try_send(input).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => "netstack channel full",
            mpsc::error::TrySendError::Closed(_) => "netstack channel closed",
        })
    }

    /// Actively injects TCP RST to every active proxied session (e.g. when `sing-box`
    /// restarts or `127.0.0.1:<app_proxy_port>` listener changes) so long-lived client
    /// sockets reconnect immediately instead of hanging in half-open limbo.
    pub fn reset_proxied_sessions(&self, reason: &'static str) {
        let _ = self
            .control_tx
            .send(NetstackControl::ResetProxiedSessions { reason });
    }

    /// Injects TCP RST into every active intercepted session and flushes them while the
    /// underlying WinDivert capture handle is still open, then exits the netstack loop.
    pub async fn shutdown_and_reset_all(&self) -> usize {
        let (done_tx, done_rx) = oneshot::channel();
        if self
            .control_tx
            .send(NetstackControl::ShutdownAndResetAll { done_tx })
            .is_err()
        {
            return 0;
        }
        tokio::time::timeout(Duration::from_millis(1500), done_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0)
    }
}

async fn run_netstack_loop(
    capture: Arc<dyn CaptureEngine>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
    mut input_rx: mpsc::Receiver<NetstackInput>,
    mut control_rx: mpsc::UnboundedReceiver<NetstackControl>,
) {
    let mut device = VirtualIpDevice::new(1500);
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = 0xB9A7_C0DE;

    let origin = Instant::now();
    let now_smol = |origin: Instant| -> SmolInstant {
        SmolInstant::from_millis(origin.elapsed().as_millis() as i64)
    };

    let mut iface = Interface::new(iface_cfg, &mut device, now_smol(origin));
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 0));
        let _ = addrs.push(IpCidr::new(
            IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            0,
        ));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1));
    let _ = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

    let mut sockets = SocketSet::new(vec![]);
    let mut sessions: HashMap<FiveTuple, ActiveTcpSession> = HashMap::new();
    let mut flow_metas: HashMap<FiveTuple, PacketMeta> = HashMap::new();
    let wake_notify = Arc::new(Notify::new());

    loop {
        let now = now_smol(origin);
        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_millis(d.total_millis().clamp(1, 25)))
            .unwrap_or(Duration::from_millis(25));

        let mut shutdown_done_tx: Option<oneshot::Sender<usize>> = None;

        tokio::select! {
            biased;
            maybe_ctrl = control_rx.recv() => {
                match maybe_ctrl {
                    Some(NetstackControl::ResetProxiedSessions { reason }) => {
                        let count = abort_matching_sessions(
                            &mut sockets,
                            &mut sessions,
                            |s| s.is_proxied,
                        );
                        if count > 0 {
                            info!(count, reason, "actively resetting proxied TCP sessions via RST");
                        }
                    }
                    Some(NetstackControl::ShutdownAndResetAll { done_tx }) => {
                        shutdown_done_tx = Some(done_tx);
                    }
                    None => {}
                }
            }
            maybe_input = input_rx.recv() => {
                match maybe_input {
                    Some(first_input) => {
                        handle_input(
                            first_input,
                            &mut device,
                            &mut iface,
                            &mut sockets,
                            &mut sessions,
                            &mut flow_metas,
                            &wake_notify,
                            now_smol(origin),
                            &capture,
                            &origins,
                            &telemetry,
                            &tracker,
                            &runtime,
                        );
                        while let Ok(extra) = input_rx.try_recv() {
                            handle_input(
                                extra,
                                &mut device,
                                &mut iface,
                                &mut sockets,
                                &mut sessions,
                                &mut flow_metas,
                                &wake_notify,
                                now_smol(origin),
                                &capture,
                                &origins,
                                &telemetry,
                                &tracker,
                                &runtime,
                            );
                        }
                    }
                    None => {
                        let count = abort_and_flush_all_sessions(
                            &mut device,
                            &mut iface,
                            &mut sockets,
                            &mut sessions,
                            &mut flow_metas,
                            now_smol(origin),
                            capture.as_ref(),
                        );
                        if count > 0 {
                            info!(count, "flushed TCP RSTs on netstack channel close");
                        }
                        break;
                    }
                }
            }
            _ = wake_notify.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }

        if let Some(done_tx) = shutdown_done_tx {
            let count = abort_and_flush_all_sessions(
                &mut device,
                &mut iface,
                &mut sockets,
                &mut sessions,
                &mut flow_metas,
                now_smol(origin),
                capture.as_ref(),
            );
            let _ = done_tx.send(count);
            break;
        }

        iface.poll(now_smol(origin), &mut device, &mut sockets);
        pump_sessions(&mut sockets, &mut sessions, &mut flow_metas);
        iface.poll(now_smol(origin), &mut device, &mut sockets);
        flush_tx_packets(&mut device, &flow_metas, &mut sessions, capture.as_ref());
        finalize_aborted_sessions(&mut sockets, &mut sessions, &mut flow_metas, capture.as_ref());
    }
}

fn abort_matching_sessions<F>(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    predicate: F,
) -> usize
where
    F: Fn(&ActiveTcpSession) -> bool,
{
    let mut count = 0usize;
    for sess in sessions.values_mut() {
        if !sess.abort_pending_flush && predicate(sess) {
            sess.to_upstream = None;
            sess.upstream_abort = true;
            sess.abort_pending_flush = true;
            let sock = sockets.get_mut::<TcpSocket>(sess.handle);
            sock.abort();
            count += 1;
        }
    }
    count
}

fn abort_and_flush_all_sessions(
    device: &mut VirtualIpDevice,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    flow_metas: &mut HashMap<FiveTuple, PacketMeta>,
    now: SmolInstant,
    capture: &dyn CaptureEngine,
) -> usize {
    let count = abort_matching_sessions(sockets, sessions, |_| true);
    if count == 0 {
        return 0;
    }
    iface.poll(now, device, sockets);
    flush_tx_packets(device, flow_metas, sessions, capture);
    finalize_aborted_sessions(sockets, sessions, flow_metas, capture);
    count
}

fn tcp_seq_advance(flags: u8, payload_len: usize) -> u32 {
    (payload_len as u32)
        .wrapping_add(u32::from((flags & TCP_SYN_FLAG) != 0))
        .wrapping_add(u32::from((flags & TCP_FIN_FLAG) != 0))
}

fn inject_rst_for_session(
    tuple: FiveTuple,
    sess: &ActiveTcpSession,
    meta: &PacketMeta,
    capture: &dyn CaptureEngine,
) {
    let (rst_seq, rst_ack) = match sess.server_next_seq.or(sess.client_acked_seq) {
        Some(server_seq) => (server_seq, Some(sess.client_next_seq)),
        None => (0, Some(sess.client_next_seq)),
    };
    if let Some(rst_pkt) = build_tcp_rst_ip_packet(
        tuple.dst_ip,
        tuple.dst_port,
        tuple.src_ip,
        tuple.src_port,
        rst_seq,
        rst_ack,
    ) {
        let reply_meta = meta.as_inbound_reply();
        if let Err(err) = capture.inject(&rst_pkt, &reply_meta) {
            debug!(?err, ?tuple, "failed to inject synthetic TCP RST");
        }
    }
}

fn inject_rst_for_orphan_packet(packet: &[u8], meta: &PacketMeta, capture: &dyn CaptureEngine) {
    let Some(parsed) = parse_ip_packet(packet) else {
        return;
    };
    if parsed.tuple.protocol != TransportProtocol::Tcp || (parsed.tcp_flags & TCP_RST_FLAG) != 0 {
        return;
    }
    // RFC 9293 Section 3.5.2 / RFC 5961:
    // - If incoming segment has ACK, reply with RST where seq = SEG.ACK (matches client RCV.NXT).
    // - Otherwise, reply with RST+ACK where seq = 0 and ack = SEG.SEQ + SEG.LEN.
    let (rst_seq, rst_ack) = if (parsed.tcp_flags & TCP_ACK_FLAG) != 0 {
        (parsed.tcp_ack, None)
    } else {
        let adv = tcp_seq_advance(parsed.tcp_flags, parsed.payload_len);
        (0, Some(parsed.tcp_seq.wrapping_add(adv)))
    };
    if let Some(rst_pkt) = build_tcp_rst_ip_packet(
        parsed.tuple.dst_ip,
        parsed.tuple.dst_port,
        parsed.tuple.src_ip,
        parsed.tuple.src_port,
        rst_seq,
        rst_ack,
    ) {
        let reply_meta = meta.as_inbound_reply();
        if let Err(err) = capture.inject(&rst_pkt, &reply_meta) {
            debug!(?err, tuple = ?parsed.tuple, "failed to inject orphan TCP RST");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_input(
    mut input: NetstackInput,
    device: &mut VirtualIpDevice,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    flow_metas: &mut HashMap<FiveTuple, PacketMeta>,
    wake_notify: &Arc<Notify>,
    now: SmolInstant,
    capture: &Arc<dyn CaptureEngine>,
    origins: &Arc<OriginRegistry>,
    telemetry: &Arc<AppProxyTelemetry>,
    tracker: &Arc<dyn ProcessTracker>,
    runtime: &Arc<RwLock<Arc<RuntimeSnapshot>>>,
) {
    normalize_offloaded_ip_lengths(&mut input.packet);
    let parsed_client = parse_ip_packet(&input.packet);

    if input.is_syn_only {
        let should_replace = sessions.get(&input.tuple).is_some_and(|existing| {
            let state = sockets.get::<TcpSocket>(existing.handle).state();
            matches!(
                state,
                TcpState::TimeWait | TcpState::Closed | TcpState::Closing | TcpState::LastAck
            ) || existing.abort_pending_flush
        });
        if should_replace {
            if let Some(old) = sessions.remove(&input.tuple) {
                sockets.remove(old.handle);
            }
        }
    }

    if input.is_syn_only && !sessions.contains_key(&input.tuple) {
        flow_metas.insert(input.tuple, input.meta);
        let rx_buf = TcpSocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = TcpSocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut sock = TcpSocket::new(rx_buf, tx_buf);
        sock.set_nagle_enabled(false);
        sock.set_ack_delay(None);

        let listen_ep = IpEndpoint::new(to_smol_ip(input.tuple.dst_ip), input.tuple.dst_port);
        if let Err(err) = sock.listen(listen_ep) {
            warn!(?err, tuple = ?input.tuple, "smoltcp socket listen failed");
            return;
        }

        let handle = sockets.add(sock);
        let (to_up_tx, to_up_rx) = mpsc::channel::<Bytes>(CHANNEL_CAPACITY);
        let (from_up_tx, from_up_rx) = mpsc::channel::<UpstreamEvent>(CHANNEL_CAPACITY);

        let initial_client_next_seq = parsed_client
            .map(|p| {
                p.tcp_seq
                    .wrapping_add(tcp_seq_advance(p.tcp_flags, p.payload_len))
            })
            .unwrap_or(1);

        let is_proxied = input.auth_user.is_some() && input.target.is_some();
        sessions.insert(
            input.tuple,
            ActiveTcpSession {
                handle,
                is_proxied,
                to_upstream: Some(to_up_tx),
                from_upstream: from_up_rx,
                pending_write: VecDeque::new(),
                upstream_eof: false,
                upstream_abort: false,
                abort_pending_flush: false,
                client_next_seq: initial_client_next_seq,
                client_acked_seq: None,
                server_next_seq: None,
                rst_injected: false,
                created_at: Instant::now(),
            },
        );

        let notify_clone = Arc::clone(wake_notify);
        let capture_clone = Arc::clone(capture);
        let origins_clone = Arc::clone(origins);
        let telemetry_clone = Arc::clone(telemetry);
        let tracker_clone = Arc::clone(tracker);
        let runtime_clone = Arc::clone(runtime);

        tokio::spawn(async move {
            run_upstream_tcp_relay(
                input.pid,
                input.process_name,
                input.exe_path,
                input.ancestor_app,
                input.ancestor_chain,
                input.rule_id,
                input.rule_name,
                input.target,
                input.auth_user,
                input.tuple,
                to_up_rx,
                from_up_tx,
                notify_clone,
                capture_clone,
                origins_clone,
                telemetry_clone,
                tracker_clone,
                runtime_clone,
            )
            .await;
        });

        device.rx_queue.push_back(input.packet);
        iface.poll(now, device, sockets);
        return;
    }

    if let Some(sess) = sessions.get_mut(&input.tuple) {
        flow_metas.insert(input.tuple, input.meta);
        if let Some(p) = parsed_client {
            sess.client_next_seq = p
                .tcp_seq
                .wrapping_add(tcp_seq_advance(p.tcp_flags, p.payload_len));
            if (p.tcp_flags & TCP_ACK_FLAG) != 0 {
                sess.client_acked_seq = Some(p.tcp_ack);
            }
        }
        device.rx_queue.push_back(input.packet);
    } else if !input.is_syn_only {
        // Non-SYN packet arrived for an intercepted flow whose session was already torn down
        // (e.g. after upstream abort, sing-box restart, or cleanup). Inject an immediate
        // RFC 9293/5961 compliant TCP RST instead of silently dropping it.
        inject_rst_for_orphan_packet(&input.packet, &input.meta, capture.as_ref());
    }
}

fn pump_sessions(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    flow_metas: &mut HashMap<FiveTuple, PacketMeta>,
) {
    let mut to_remove_closed = Vec::new();

    for (tuple, sess) in sessions.iter_mut() {
        if sess.abort_pending_flush {
            continue;
        }
        let sock = sockets.get_mut::<TcpSocket>(sess.handle);

        while let Ok(evt) = sess.from_upstream.try_recv() {
            match evt {
                UpstreamEvent::Data(bytes) => sess.pending_write.extend(bytes.iter().copied()),
                UpstreamEvent::Eof => sess.upstream_eof = true,
                UpstreamEvent::Abort => sess.upstream_abort = true,
            }
        }

        if sess.upstream_abort {
            // Keep socket and flow_meta alive through the next `iface.poll()` + `flush_tx_packets()`
            // cycle so smoltcp (or our synthetic fallback) actually emits the TCP RST packet!
            sess.to_upstream = None;
            sock.abort();
            sess.abort_pending_flush = true;
            continue;
        }

        if sock.can_recv() {
            if let Some(ref tx) = sess.to_upstream {
                if let Ok(permit) = tx.try_reserve() {
                    let mut tmp = vec![0u8; 16_384];
                    if let Ok(n) = sock.recv_slice(&mut tmp) {
                        if n > 0 {
                            tmp.truncate(n);
                            permit.send(Bytes::from(tmp));
                        }
                    }
                }
            }
        } else if matches!(
            sock.state(),
            TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::Closing
                | TcpState::TimeWait
                | TcpState::Closed
        ) && sess.to_upstream.is_some()
        {
            sess.to_upstream = None;
        }

        if sock.can_send() && !sess.pending_write.is_empty() {
            for _ in 0..2 {
                if !sock.can_send() || sess.pending_write.is_empty() {
                    break;
                }
                let (first, _) = sess.pending_write.as_slices();
                if first.is_empty() {
                    break;
                }
                if let Ok(sent) = sock.send_slice(first) {
                    if sent > 0 {
                        sess.pending_write.drain(..sent);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        if sess.upstream_eof && sess.pending_write.is_empty() && sock.may_send() {
            sock.close();
        }

        let stale_handshake =
            matches!(sock.state(), TcpState::Listen | TcpState::SynReceived)
                && sess.created_at.elapsed() > Duration::from_secs(15);
        if stale_handshake {
            sess.to_upstream = None;
            sock.abort();
            sess.abort_pending_flush = true;
            continue;
        }
        if !sock.is_active() || sock.state() == TcpState::Closed {
            to_remove_closed.push(*tuple);
        }
    }

    for tuple in to_remove_closed {
        if let Some(sess) = sessions.remove(&tuple) {
            sockets.remove(sess.handle);
        }
        flow_metas.remove(&tuple);
    }
}

fn finalize_aborted_sessions(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    flow_metas: &mut HashMap<FiveTuple, PacketMeta>,
    capture: &dyn CaptureEngine,
) {
    let aborted_tuples: Vec<FiveTuple> = sessions
        .iter()
        .filter_map(|(t, s)| s.abort_pending_flush.then_some(*t))
        .collect();

    for tuple in aborted_tuples {
        if let Some(sess) = sessions.remove(&tuple) {
            if !sess.rst_injected {
                if let Some(meta) = flow_metas.get(&tuple) {
                    inject_rst_for_session(tuple, &sess, meta, capture);
                }
            }
            sockets.remove(sess.handle);
        }
        flow_metas.remove(&tuple);
    }
}

fn flush_tx_packets(
    device: &mut VirtualIpDevice,
    flow_metas: &HashMap<FiveTuple, PacketMeta>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    capture: &dyn CaptureEngine,
) {
    while let Some(pkt) = device.tx_queue.pop_front() {
        let Some(parsed) = parse_ip_packet(&pkt) else {
            continue;
        };
        if parsed.tuple.protocol != TransportProtocol::Tcp {
            continue;
        }
        let orig_tuple = parsed.tuple.reversed();
        if let Some(sess) = sessions.get_mut(&orig_tuple) {
            let adv = tcp_seq_advance(parsed.tcp_flags, parsed.payload_len);
            sess.server_next_seq = Some(parsed.tcp_seq.wrapping_add(adv));
            if (parsed.tcp_flags & TCP_RST_FLAG) != 0 {
                sess.rst_injected = true;
            }
        }
        if let Some(meta) = flow_metas.get(&orig_tuple) {
            let reply_meta = meta.as_inbound_reply();
            if let Err(err) = capture.inject(&pkt, &reply_meta) {
                debug!(?err, tuple = ?orig_tuple, "failed to inject TCP reply");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_upstream_tcp_relay(
    pid: Option<u32>,
    process_name: String,
    exe_path: Option<String>,
    ancestor_app: Option<String>,
    ancestor_chain: Vec<String>,
    mut rule_id: String,
    mut rule_name: String,
    mut target: Option<String>,
    mut auth_user: Option<String>,
    tuple: FiveTuple,
    mut to_upstream_rx: mpsc::Receiver<Bytes>,
    from_upstream_tx: mpsc::Sender<UpstreamEvent>,
    wake_notify: Arc<Notify>,
    capture: Arc<dyn CaptureEngine>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
) {
    // Accumulate initial client bytes across TCP segments so large PQ-TLS ClientHello payloads
    // (`X25519MLKEM768` > 1460B MSS) have their SNI cleanly sniffed.
    let first_chunk = match read_initial_sniff_buffer(&mut to_upstream_rx, SNIFF_PEEK_TIMEOUT).await
    {
        InitialRead::Data(bytes) => Some(bytes),
        InitialRead::Closed => return,
        InitialRead::Timeout => None,
    };

    let (target_addr, sniffed_host) = match first_chunk.as_deref().and_then(sniff_tcp_payload) {
        Some(SniffResult::TlsSni(host)) | Some(SniffResult::HttpHost(host)) => {
            (TargetAddr::Domain(host.clone(), tuple.dst_port), Some(host))
        }
        _ => (
            TargetAddr::Ip(SocketAddr::new(tuple.dst_ip, tuple.dst_port)),
            None,
        ),
    };

    // Phase 2 L7 domain override evaluation.
    if let Some(ref host) = sniffed_host {
        let rt = Arc::clone(&runtime.read().expect("runtime lock poisoned"));
        if let Some(decision) = rt.rules.evaluate_l7(pid, &tuple, host, tracker.as_ref()) {
            match decision {
                L7DomainDecision::Reject {
                    rule_name: ov_rule, ..
                } => {
                    telemetry.record_local_reject(
                        pid,
                        process_name,
                        ancestor_app,
                        ancestor_chain,
                        format!("{host}:{}", tuple.dst_port),
                        ov_rule,
                    );
                    let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                    wake_notify.notify_one();
                    return;
                }
                L7DomainDecision::Direct {
                    rule_id: ov_id,
                    rule_name: ov_rule,
                    ..
                } => {
                    rule_id = ov_id;
                    rule_name = ov_rule;
                    target = None;
                    auth_user = None;
                }
                L7DomainDecision::Proxy {
                    rule_id: ov_id,
                    rule_name: ov_rule,
                    target: ov_target,
                    auth_user: ov_user,
                    ..
                } => {
                    rule_id = ov_id;
                    rule_name = ov_rule;
                    target = Some(ov_target);
                    auth_user = Some(ov_user);
                }
            }
        }
    }

    let rt = Arc::clone(&runtime.read().expect("runtime lock poisoned"));
    let app_proxy_port = rt.app_proxy_port;
    let upstream_listener_pid = capture.find_local_tcp_listener_pid(app_proxy_port);

    let (stream, registered_port, local_direct_id) = match (auth_user, target) {
        (Some(user), Some(tgt)) => {
            match connect_internal_tcp(app_proxy_port, &user, &rt.control_secret, &target_addr)
                .await
            {
                Ok((s, local_port)) => {
                    origins.register(FlowOriginDto {
                        local_port,
                        pid: pid.unwrap_or(0),
                        process_name: process_name.clone(),
                        exe_path: exe_path.clone(),
                        ancestor_name: ancestor_app.clone(),
                        ancestor_chain: ancestor_chain.clone(),
                        rule_id: Some(rule_id),
                        rule_name,
                        target: tgt,
                        auth_user: user,
                        sniffed_host,
                        action: "proxy".to_string(),
                        expired: false,
                    });
                    telemetry.on_proxied_open();
                    (s, Some(local_port), None)
                }
                Err(err) => {
                    warn!(proc = %process_name, target = %target_addr, error = %err, "internal app-proxy-in dial failed");
                    let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                    wake_notify.notify_one();
                    return;
                }
            }
        }
        _ => {
            let direct_addr = SocketAddr::new(tuple.dst_ip, tuple.dst_port);
            match TcpStream::connect(direct_addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    let dest_str = sniffed_host
                        .map(|h| format!("{h}:{}", tuple.dst_port))
                        .unwrap_or_else(|| direct_addr.to_string());
                    let lid = telemetry.open_local_direct(
                        pid,
                        process_name,
                        ancestor_app,
                        ancestor_chain,
                        dest_str,
                        rule_name,
                    );
                    (s, None, Some(lid))
                }
                Err(_) => {
                    let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                    wake_notify.notify_one();
                    return;
                }
            }
        }
    };

    let (mut up_read, mut up_write) = stream.into_split();

    if let Some(first) = first_chunk {
        let len = first.len() as u64;
        if up_write.write_all(&first).await.is_err() {
            cleanup_relay(registered_port, local_direct_id.as_deref(), &origins, &telemetry);
            let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
            wake_notify.notify_one();
            return;
        }
        if let Some(ref lid) = local_direct_id {
            telemetry.add_local_direct_bytes(lid, len, 0);
        }
    }

    let writer_tel = Arc::clone(&telemetry);
    let writer_lid = local_direct_id.clone();
    let writer_from_up = from_upstream_tx.clone();
    let writer_notify = Arc::clone(&wake_notify);
    let writer = tokio::spawn(async move {
        while let Some(chunk) = to_upstream_rx.recv().await {
            let len = chunk.len() as u64;
            if up_write.write_all(&chunk).await.is_err() {
                // Upstream socket broke while writing: immediately trigger TCP RST to client.
                let _ = writer_from_up.try_send(UpstreamEvent::Abort);
                writer_notify.notify_one();
                return false;
            }
            if let Some(ref lid) = writer_lid {
                writer_tel.add_local_direct_bytes(lid, len, 0);
            }
        }
        let _ = up_write.shutdown().await;
        true
    });

    let mut aborted = false;
    let mut buf = vec![0u8; 16_384];
    loop {
        match up_read.read(&mut buf).await {
            Ok(0) => {
                // If this was a proxied connection and the local app-proxy listener (sing-box)
                // vanished or changed PID, treat the EOF as an upstream crash/restart and inject
                // TCP RST so long-lived clients reconnect immediately instead of staying half-open.
                let upstream_restarted_or_down = registered_port.is_some() && {
                    let current_listener = capture.find_local_tcp_listener_pid(app_proxy_port);
                    current_listener.is_none()
                        || (upstream_listener_pid.is_some()
                            && current_listener != upstream_listener_pid)
                };
                if upstream_restarted_or_down {
                    aborted = true;
                    let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                } else {
                    let _ = from_upstream_tx.send(UpstreamEvent::Eof).await;
                }
                wake_notify.notify_one();
                break;
            }
            Ok(n) => {
                if let Some(ref lid) = local_direct_id {
                    telemetry.add_local_direct_bytes(lid, 0, n as u64);
                }
                let data = Bytes::copy_from_slice(&buf[..n]);
                if from_upstream_tx.send(UpstreamEvent::Data(data)).await.is_err() {
                    aborted = true;
                    break;
                }
                wake_notify.notify_one();
            }
            Err(_) => {
                aborted = true;
                let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                wake_notify.notify_one();
                break;
            }
        }
    }

    if aborted {
        writer.abort();
    } else if tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .is_err()
    {
        // Client never closed its write half after remote EOF; let cleanup finish without leaking.
    }
    cleanup_relay(registered_port, local_direct_id.as_deref(), &origins, &telemetry);
}

fn cleanup_relay(
    registered_port: Option<u16>,
    local_direct_id: Option<&str>,
    origins: &OriginRegistry,
    telemetry: &AppProxyTelemetry,
) {
    if let Some(port) = registered_port {
        origins.mark_closed(port);
        telemetry.on_proxied_close();
    }
    if let Some(lid) = local_direct_id {
        telemetry.close_local_direct(lid);
    }
}

enum InitialRead {
    Data(Bytes),
    Closed,
    Timeout,
}

async fn read_initial_sniff_buffer(
    rx: &mut mpsc::Receiver<Bytes>,
    budget: Duration,
) -> InitialRead {
    let deadline = tokio::time::Instant::now() + budget;
    let first = match tokio::time::timeout_at(deadline, rx.recv()).await {
        Ok(Some(b)) => b,
        Ok(None) => return InitialRead::Closed,
        Err(_) => return InitialRead::Timeout,
    };

    if sniff_tcp_payload(&first).is_some() || !needs_more_tls_bytes(&first, MAX_SNIFF_BUFFER_BYTES)
    {
        return InitialRead::Data(first);
    }

    let mut acc = Vec::with_capacity(MAX_SNIFF_BUFFER_BYTES.min(first.len() + 2048));
    acc.extend_from_slice(&first);

    while acc.len() < MAX_SNIFF_BUFFER_BYTES && needs_more_tls_bytes(&acc, MAX_SNIFF_BUFFER_BYTES) {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(more)) => {
                acc.extend_from_slice(&more);
                if sniff_tcp_payload(&acc).is_some() {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }

    InitialRead::Data(Bytes::from(acc))
}

fn to_smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())),
        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
    }
}

/// Repairs IPv4/IPv6 total length headers when Windows NIC LSO/GSO offload leaves them zeroed.
fn normalize_offloaded_ip_lengths(packet: &mut [u8]) {
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let len = packet.len();
        if total_len == 0 && len <= u16::MAX as usize {
            packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        }
    } else if packet.len() >= 40 && (packet[0] >> 4) == 6 {
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        if payload_len == 0 {
            let actual = packet.len() - 40;
            if actual <= u16::MAX as usize {
                packet[4..6].copy_from_slice(&(actual as u16).to_be_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CapturedPacket, ParsedPacketHeader};
    use crate::process::ProcessInfo;
    use crate::rules::RuleEngine;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    struct RecordingCapture {
        injected: Mutex<Vec<(Vec<u8>, PacketMeta)>>,
    }

    impl RecordingCapture {
        fn new() -> Self {
            Self {
                injected: Mutex::new(Vec::new()),
            }
        }

        fn drain_packets(&self) -> Vec<(ParsedPacketHeader, PacketMeta)> {
            let pkts = std::mem::take(&mut *self.injected.lock().unwrap());
            pkts.into_iter()
                .filter_map(|(raw, meta)| parse_ip_packet(&raw).map(|p| (p, meta)))
                .collect()
        }
    }

    impl CaptureEngine for RecordingCapture {
        fn start(&self, _tx: mpsc::Sender<CapturedPacket>) -> anyhow::Result<()> {
            Ok(())
        }
        fn inject(&self, packet: &[u8], meta: &PacketMeta) -> anyhow::Result<()> {
            self.injected.lock().unwrap().push((packet.to_vec(), *meta));
            Ok(())
        }
        fn lookup_pid(&self, _tuple: &FiveTuple) -> Option<u32> {
            None
        }
        fn find_local_tcp_listener_pid(&self, _port: u16) -> Option<u32> {
            None
        }
        fn shutdown(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct StubTracker;

    impl ProcessTracker for StubTracker {
        fn get_process(&self, _pid: u32) -> Option<ProcessInfo> {
            None
        }
        fn ancestor_chain(&self, _pid: u32) -> Vec<ProcessInfo> {
            Vec::new()
        }
        fn list_processes(&self) -> Vec<ProcessInfo> {
            Vec::new()
        }
        fn refresh(&self) {}
    }

    #[allow(clippy::too_many_arguments)]
    fn build_ipv4_tcp_segment(
        src: Ipv4Addr,
        src_port: u16,
        dst: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[6] = 0x40;
        buf[8] = 64;
        buf[9] = 6;
        buf[12..16].copy_from_slice(&src.octets());
        buf[16..20].copy_from_slice(&dst.octets());
        buf[20..22].copy_from_slice(&src_port.to_be_bytes());
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
        buf[24..28].copy_from_slice(&seq.to_be_bytes());
        buf[28..32].copy_from_slice(&ack.to_be_bytes());
        buf[32] = 0x50;
        buf[33] = flags;
        buf[34..36].copy_from_slice(&64_240u16.to_be_bytes());
        buf[40..].copy_from_slice(payload);
        buf
    }

    fn make_input(
        tuple: FiveTuple,
        packet: Vec<u8>,
        is_syn_only: bool,
    ) -> NetstackInput {
        NetstackInput {
            packet,
            tuple,
            meta: PacketMeta {
                iface_index: 12,
                sub_iface_index: 0,
                outbound: true,
                is_ipv6: false,
            },
            pid: Some(4242),
            process_name: "Antigravity.exe".to_string(),
            exe_path: None,
            ancestor_app: Some("Antigravity".to_string()),
            ancestor_chain: vec!["Antigravity.exe".to_string()],
            rule_id: "r1".to_string(),
            rule_name: "Antigravity".to_string(),
            target: Some("main".to_string()),
            auth_user: Some("u-main".to_string()),
            is_syn_only,
        }
    }

    async fn wait_for_packet<F>(
        capture: &RecordingCapture,
        predicate: F,
    ) -> Option<(ParsedPacketHeader, PacketMeta)>
    where
        F: Fn(&ParsedPacketHeader, &PacketMeta) -> bool,
    {
        for _ in 0..80 {
            for (hdr, meta) in capture.drain_packets() {
                if predicate(&hdr, &meta) {
                    return Some((hdr, meta));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    #[tokio::test]
    async fn injects_in_window_tcp_rst_on_upstream_abort_reset_orphan_and_shutdown() {
        // Bind then drop a local listener to obtain a guaranteed-closed port for Case 1.
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let capture = Arc::new(RecordingCapture::new());
        let tracker = Arc::new(StubTracker);
        let rules = Arc::new(RuleEngine::from_wire(&[], &[], true, &[]).unwrap());
        let runtime = Arc::new(RwLock::new(Arc::new(RuntimeSnapshot {
            app_proxy_port: closed_port,
            control_secret: "secret".to_string(),
            block_quic_when_needed: true,
            rules,
        })));
        let origins = Arc::new(OriginRegistry::new());
        let telemetry = AppProxyTelemetry::new();

        let (netstack, handle) = TcpNetstack::spawn(
            Arc::clone(&capture) as Arc<dyn CaptureEngine>,
            tracker,
            Arc::clone(&runtime),
            origins,
            telemetry,
        );

        let cli_ip = Ipv4Addr::new(192, 168, 10, 5);
        let srv_ip = Ipv4Addr::new(142, 250, 72, 14);
        let tuple1 = FiveTuple {
            protocol: TransportProtocol::Tcp,
            src_ip: IpAddr::V4(cli_ip),
            src_port: 51001,
            dst_ip: IpAddr::V4(srv_ip),
            dst_port: 443,
        };

        // Case 1: Upstream dial failure (127.0.0.1:closed_port refused) MUST inject in-window RST.
        let syn1 = build_ipv4_tcp_segment(cli_ip, 51001, srv_ip, 443, 1000, 0, TCP_SYN_FLAG, &[]);
        netstack.try_feed(make_input(tuple1, syn1, true)).unwrap();

        let (syn_ack1, meta1) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple1.reversed()
                && (hdr.tcp_flags & (TCP_SYN_FLAG | TCP_ACK_FLAG)) == (TCP_SYN_FLAG | TCP_ACK_FLAG)
        })
        .await
        .expect("smoltcp should reply with SYN+ACK");
        assert!(!meta1.outbound);
        let expected_srv_seq1 = syn_ack1.tcp_seq.wrapping_add(1);

        let ack_data1 = build_ipv4_tcp_segment(
            cli_ip,
            51001,
            srv_ip,
            443,
            1001,
            expected_srv_seq1,
            TCP_ACK_FLAG,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        netstack
            .try_feed(make_input(tuple1, ack_data1, false))
            .unwrap();

        let (rst1, rst_meta1) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple1.reversed() && (hdr.tcp_flags & TCP_RST_FLAG) != 0
        })
        .await
        .expect("upstream dial failure must actively inject TCP RST to hijacked client");
        assert!(!rst_meta1.outbound);
        assert_eq!(rst1.tcp_seq, expected_srv_seq1);

        // Case 2: Orphaned non-SYN packet on a reset flow MUST immediately get RFC 5961 RST.
        let orphan_ack = build_ipv4_tcp_segment(
            cli_ip,
            51001,
            srv_ip,
            443,
            1050,
            expected_srv_seq1,
            TCP_ACK_FLAG,
            b"ping",
        );
        netstack
            .try_feed(make_input(tuple1, orphan_ack, false))
            .unwrap();

        let (orphan_rst, _) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple1.reversed() && (hdr.tcp_flags & TCP_RST_FLAG) != 0
        })
        .await
        .expect("orphan non-SYN packet must trigger immediate TCP RST");
        assert_eq!(orphan_rst.tcp_seq, expected_srv_seq1);

        // Case 3: Active session during `reset_proxied_sessions` (e.g. sing-box restart)
        // MUST receive an in-window TCP RST immediately even while idle.
        let tuple2 = FiveTuple {
            protocol: TransportProtocol::Tcp,
            src_ip: IpAddr::V4(cli_ip),
            src_port: 51002,
            dst_ip: IpAddr::V4(srv_ip),
            dst_port: 443,
        };
        let syn2 = build_ipv4_tcp_segment(cli_ip, 51002, srv_ip, 443, 2000, 0, TCP_SYN_FLAG, &[]);
        netstack.try_feed(make_input(tuple2, syn2, true)).unwrap();

        let (syn_ack2, _) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple2.reversed()
                && (hdr.tcp_flags & (TCP_SYN_FLAG | TCP_ACK_FLAG)) == (TCP_SYN_FLAG | TCP_ACK_FLAG)
        })
        .await
        .expect("smoltcp should reply with SYN+ACK for tuple2");
        let expected_srv_seq2 = syn_ack2.tcp_seq.wrapping_add(1);

        let ack2 = build_ipv4_tcp_segment(
            cli_ip,
            51002,
            srv_ip,
            443,
            2001,
            expected_srv_seq2,
            TCP_ACK_FLAG,
            &[],
        );
        netstack.try_feed(make_input(tuple2, ack2, false)).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = capture.drain_packets();

        netstack.reset_proxied_sessions("test sing-box restart");

        let (rst2, _) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple2.reversed() && (hdr.tcp_flags & TCP_RST_FLAG) != 0
        })
        .await
        .expect("reset_proxied_sessions must inject TCP RST into idle proxied session");
        assert_eq!(rst2.tcp_seq, expected_srv_seq2);

        // Case 4: `shutdown_and_reset_all` MUST flush TCP RSTs BEFORE returning.
        let tuple3 = FiveTuple {
            protocol: TransportProtocol::Tcp,
            src_ip: IpAddr::V4(cli_ip),
            src_port: 51003,
            dst_ip: IpAddr::V4(srv_ip),
            dst_port: 443,
        };
        let syn3 = build_ipv4_tcp_segment(cli_ip, 51003, srv_ip, 443, 3000, 0, TCP_SYN_FLAG, &[]);
        netstack.try_feed(make_input(tuple3, syn3, true)).unwrap();
        let (syn_ack3, _) = wait_for_packet(&capture, |hdr, _| {
            hdr.tuple == tuple3.reversed()
                && (hdr.tcp_flags & (TCP_SYN_FLAG | TCP_ACK_FLAG)) == (TCP_SYN_FLAG | TCP_ACK_FLAG)
        })
        .await
        .expect("smoltcp should reply with SYN+ACK for tuple3");
        let expected_srv_seq3 = syn_ack3.tcp_seq.wrapping_add(1);
        let ack3 = build_ipv4_tcp_segment(
            cli_ip,
            51003,
            srv_ip,
            443,
            3001,
            expected_srv_seq3,
            TCP_ACK_FLAG,
            &[],
        );
        netstack.try_feed(make_input(tuple3, ack3, false)).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = capture.drain_packets();

        let reset_count = netstack.shutdown_and_reset_all().await;
        assert_eq!(reset_count, 1);
        let flushed = capture.drain_packets();
        assert!(
            flushed.iter().any(|(hdr, meta)| {
                !meta.outbound
                    && hdr.tuple == tuple3.reversed()
                    && (hdr.tcp_flags & TCP_RST_FLAG) != 0
                    && hdr.tcp_seq == expected_srv_seq3
            }),
            "shutdown_and_reset_all must inject in-window TCP RST before WinDivert closes"
        );

        let _ = handle.await;
    }
}
