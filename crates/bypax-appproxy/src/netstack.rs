use crate::capture::{parse_ip_packet, CaptureEngine, FiveTuple, PacketMeta, TransportProtocol};
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
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

const TCP_RX_BUF_SIZE: usize = 65_536;
const TCP_TX_BUF_SIZE: usize = 65_536;
const CHANNEL_CAPACITY: usize = 64;
const SNIFF_PEEK_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_SNIFF_BUFFER_BYTES: usize = 8_192;

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

struct ActiveTcpSession {
    handle: SocketHandle,
    to_upstream: Option<mpsc::Sender<Bytes>>,
    from_upstream: mpsc::Receiver<UpstreamEvent>,
    pending_write: VecDeque<u8>,
    upstream_eof: bool,
    upstream_abort: bool,
    created_at: Instant,
}

pub struct TcpNetstack {
    input_tx: mpsc::Sender<NetstackInput>,
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
        let handle = tokio::spawn(run_netstack_loop(
            capture, tracker, runtime, origins, telemetry, input_rx,
        ));
        (Self { input_tx }, handle)
    }

    pub fn try_feed(&self, input: NetstackInput) -> Result<(), &'static str> {
        self.input_tx.try_send(input).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => "netstack channel full",
            mpsc::error::TrySendError::Closed(_) => "netstack channel closed",
        })
    }
}

async fn run_netstack_loop(
    capture: Arc<dyn CaptureEngine>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
    mut input_rx: mpsc::Receiver<NetstackInput>,
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

        tokio::select! {
            biased;
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
                                &origins,
                                &telemetry,
                                &tracker,
                                &runtime,
                            );
                        }
                    }
                    None => break,
                }
            }
            _ = wake_notify.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }

        iface.poll(now_smol(origin), &mut device, &mut sockets);
        pump_sessions(&mut sockets, &mut sessions, &mut flow_metas);
        iface.poll(now_smol(origin), &mut device, &mut sockets);
        flush_tx_packets(&mut device, &flow_metas, capture.as_ref());
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
    origins: &Arc<OriginRegistry>,
    telemetry: &Arc<AppProxyTelemetry>,
    tracker: &Arc<dyn ProcessTracker>,
    runtime: &Arc<RwLock<Arc<RuntimeSnapshot>>>,
) {
    normalize_offloaded_ip_lengths(&mut input.packet);
    flow_metas.insert(input.tuple, input.meta);

    if input.is_syn_only {
        let should_replace = sessions.get(&input.tuple).is_some_and(|existing| {
            let state = sockets.get::<TcpSocket>(existing.handle).state();
            matches!(
                state,
                TcpState::TimeWait | TcpState::Closed | TcpState::Closing | TcpState::LastAck
            )
        });
        if should_replace {
            if let Some(old) = sessions.remove(&input.tuple) {
                sockets.remove(old.handle);
            }
        }
    }

    if input.is_syn_only && !sessions.contains_key(&input.tuple) {
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

        sessions.insert(
            input.tuple,
            ActiveTcpSession {
                handle,
                to_upstream: Some(to_up_tx),
                from_upstream: from_up_rx,
                pending_write: VecDeque::new(),
                upstream_eof: false,
                upstream_abort: false,
                created_at: Instant::now(),
            },
        );

        let notify_clone = Arc::clone(wake_notify);
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

    if sessions.contains_key(&input.tuple) {
        device.rx_queue.push_back(input.packet);
    }
}

fn pump_sessions(
    sockets: &mut SocketSet<'_>,
    sessions: &mut HashMap<FiveTuple, ActiveTcpSession>,
    flow_metas: &mut HashMap<FiveTuple, PacketMeta>,
) {
    let mut to_remove = Vec::new();

    for (tuple, sess) in sessions.iter_mut() {
        let sock = sockets.get_mut::<TcpSocket>(sess.handle);

        while let Ok(evt) = sess.from_upstream.try_recv() {
            match evt {
                UpstreamEvent::Data(bytes) => sess.pending_write.extend(bytes.iter().copied()),
                UpstreamEvent::Eof => sess.upstream_eof = true,
                UpstreamEvent::Abort => sess.upstream_abort = true,
            }
        }

        if sess.upstream_abort {
            sock.abort();
            to_remove.push(*tuple);
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
        if !sock.is_active() || sock.state() == TcpState::Closed || stale_handshake {
            if stale_handshake {
                sock.abort();
            }
            to_remove.push(*tuple);
        }
    }

    for tuple in to_remove {
        if let Some(sess) = sessions.remove(&tuple) {
            sockets.remove(sess.handle);
        }
        flow_metas.remove(&tuple);
    }
}

fn flush_tx_packets(
    device: &mut VirtualIpDevice,
    flow_metas: &HashMap<FiveTuple, PacketMeta>,
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

    let (stream, registered_port, local_direct_id) = match (auth_user, target) {
        (Some(user), Some(tgt)) => {
            match connect_internal_tcp(rt.app_proxy_port, &user, &rt.control_secret, &target_addr)
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
    let writer = tokio::spawn(async move {
        while let Some(chunk) = to_upstream_rx.recv().await {
            let len = chunk.len() as u64;
            if up_write.write_all(&chunk).await.is_err() {
                break;
            }
            if let Some(ref lid) = writer_lid {
                writer_tel.add_local_direct_bytes(lid, len, 0);
            }
        }
        let _ = up_write.shutdown().await;
    });

    let mut buf = vec![0u8; 16_384];
    loop {
        match up_read.read(&mut buf).await {
            Ok(0) => {
                let _ = from_upstream_tx.send(UpstreamEvent::Eof).await;
                wake_notify.notify_one();
                break;
            }
            Ok(n) => {
                if let Some(ref lid) = local_direct_id {
                    telemetry.add_local_direct_bytes(lid, 0, n as u64);
                }
                let data = Bytes::copy_from_slice(&buf[..n]);
                if from_upstream_tx.send(UpstreamEvent::Data(data)).await.is_err() {
                    break;
                }
                wake_notify.notify_one();
            }
            Err(_) => {
                let _ = from_upstream_tx.send(UpstreamEvent::Abort).await;
                wake_notify.notify_one();
                break;
            }
        }
    }

    let _ = writer.await;
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
