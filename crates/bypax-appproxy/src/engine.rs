use crate::capture::{parse_ip_packet, CaptureEngine, CapturedPacket, FiveTuple, TransportProtocol};
use crate::netstack::{NetstackInput, TcpNetstack};
use crate::origin::OriginRegistry;
use crate::process::ProcessTracker;
use crate::rules::{L4RouteDecision, RuleEngine};
use crate::telemetry::AppProxyTelemetry;
use crate::udp_relay::{UdpPacketContext, UdpRelay};
use anyhow::Result;
use bypax_ipc::{AppProxyLocalStatsDto, AppProxyStartConfig, FlowOriginDto};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn};

const FLOW_CACHE_TTL: Duration = Duration::from_secs(120);
const TCP_SYN_FLAG: u8 = 0x02;
const TCP_ACK_FLAG: u8 = 0x10;
const TCP_FIN_FLAG: u8 = 0x01;
const TCP_RST_FLAG: u8 = 0x04;

#[derive(Clone)]
struct CachedFlow {
    decision: L4RouteDecision,
    pid: Option<u32>,
    process_name: String,
    exe_path: Option<String>,
    ancestor_app: Option<String>,
    ancestor_chain: Vec<String>,
    intercepted_tcp: bool,
    last_seen: Instant,
}

pub(crate) struct RuntimeSnapshot {
    pub(crate) app_proxy_port: u16,
    pub(crate) control_secret: String,
    pub(crate) block_quic_when_needed: bool,
    pub(crate) rules: Arc<RuleEngine>,
}

/// Live control handle for hot-reloading App Proxy rules, querying FlowOrigins, and reading stats.
#[derive(Clone)]
pub struct AppProxyHandle {
    capture: Arc<dyn CaptureEngine>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    flow_cache: Arc<DashMap<FiveTuple, CachedFlow>>,
    netstack: Arc<RwLock<Option<Arc<TcpNetstack>>>>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
}

impl AppProxyHandle {
    pub fn reload_config(&self, cfg: &AppProxyStartConfig) -> Result<()> {
        let built = build_runtime_snapshot(cfg, self.capture.as_ref())?;
        let active_rules = built.rules.active_rule_count();
        {
            let mut guard = self.runtime.write().expect("runtime lock poisoned");
            *guard = Arc::new(built);
        }
        // Keep active intercepted TCP sockets intact while clearing Direct/Reject/UDP decisions.
        self.flow_cache.retain(|_, v| v.intercepted_tcp);
        info!(active_rules, "hot-reloaded bypax-appproxy rules");
        Ok(())
    }

    /// Actively injects TCP RST to all currently proxied TCP sessions so hijacked clients
    /// immediately reconnect instead of stalling in half-open limbo when `sing-box` restarts.
    pub fn reset_proxied_sessions(&self, reason: &'static str) {
        if let Ok(guard) = self.netstack.read() {
            if let Some(ref ns) = *guard {
                ns.reset_proxied_sessions(reason);
            }
        }
    }

    pub fn lookup_origins(&self, local_ports: &[u16]) -> Vec<FlowOriginDto> {
        self.origins.lookup_batch(local_ports)
    }

    pub fn stats_snapshot(&self) -> AppProxyLocalStatsDto {
        self.telemetry.snapshot()
    }

    pub fn active_rule_count(&self) -> usize {
        self.runtime
            .read()
            .map(|r| r.rules.active_rule_count())
            .unwrap_or(0)
    }

    pub fn exempt_pids(&self) -> Vec<u32> {
        self.runtime
            .read()
            .map(|r| r.rules.exempt_pids_snapshot())
            .unwrap_or_default()
    }

    /// Registers a PID as exempt from WinDivert interception (e.g., a reloaded `sing-box` core).
    pub fn add_exempt_pid(&self, pid: u32) {
        if let Ok(rt) = self.runtime.read() {
            rt.rules.add_exempt_pid(pid);
        }
    }

    /// Queries the live OS TCP listener PID currently bound to the configured `app_proxy_port`.
    pub fn find_upstream_listener_pid(&self) -> Option<u32> {
        let port = self.runtime.read().ok().map(|r| r.app_proxy_port)?;
        self.capture.find_local_tcp_listener_pid(port)
    }
}

#[derive(Clone)]
struct EngineCtx {
    capture: Arc<dyn CaptureEngine>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    flow_cache: Arc<DashMap<FiveTuple, CachedFlow>>,
    netstack: Arc<TcpNetstack>,
    udp_relay: Arc<UdpRelay>,
    telemetry: Arc<AppProxyTelemetry>,
}

/// Transparent per-application proxy engine driving capture, L4/L7 rules, smoltcp, and UDP relay.
pub struct AppProxyEngine {
    capture: Arc<dyn CaptureEngine>,
    tracker: Arc<dyn ProcessTracker>,
    runtime: Arc<RwLock<Arc<RuntimeSnapshot>>>,
    flow_cache: Arc<DashMap<FiveTuple, CachedFlow>>,
    netstack_slot: Arc<RwLock<Option<Arc<TcpNetstack>>>>,
    origins: Arc<OriginRegistry>,
    telemetry: Arc<AppProxyTelemetry>,
}

impl AppProxyEngine {
    pub fn new(
        config: &AppProxyStartConfig,
        capture: Arc<dyn CaptureEngine>,
        tracker: Arc<dyn ProcessTracker>,
    ) -> Result<Self> {
        let built = build_runtime_snapshot(config, capture.as_ref())?;
        Ok(Self {
            capture,
            tracker,
            runtime: Arc::new(RwLock::new(Arc::new(built))),
            flow_cache: Arc::new(DashMap::new()),
            netstack_slot: Arc::new(RwLock::new(None)),
            origins: Arc::new(OriginRegistry::new()),
            telemetry: AppProxyTelemetry::new(),
        })
    }

    pub fn handle(&self) -> AppProxyHandle {
        AppProxyHandle {
            capture: Arc::clone(&self.capture),
            runtime: Arc::clone(&self.runtime),
            flow_cache: Arc::clone(&self.flow_cache),
            netstack: Arc::clone(&self.netstack_slot),
            origins: Arc::clone(&self.origins),
            telemetry: Arc::clone(&self.telemetry),
        }
    }

    pub async fn run(self, shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
        self.run_with_ready(shutdown_rx, None).await
    }

    pub async fn run_with_ready(
        self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        mut started_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    ) -> Result<()> {
        let (pkt_tx, mut pkt_rx) = mpsc::channel::<CapturedPacket>(4096);
        let (netstack, netstack_handle) = TcpNetstack::spawn(
            Arc::clone(&self.capture),
            Arc::clone(&self.tracker),
            Arc::clone(&self.runtime),
            Arc::clone(&self.origins),
            Arc::clone(&self.telemetry),
        );
        let netstack = Arc::new(netstack);
        if let Ok(mut slot) = self.netstack_slot.write() {
            *slot = Some(Arc::clone(&netstack));
        }
        let udp_relay = Arc::new(UdpRelay::new(
            Arc::clone(&self.capture),
            Arc::clone(&self.tracker),
            Arc::clone(&self.runtime),
            Arc::clone(&self.origins),
            Arc::clone(&self.telemetry),
        ));

        let ctx = EngineCtx {
            capture: Arc::clone(&self.capture),
            tracker: Arc::clone(&self.tracker),
            runtime: Arc::clone(&self.runtime),
            flow_cache: Arc::clone(&self.flow_cache),
            netstack: Arc::clone(&netstack),
            udp_relay,
            telemetry: Arc::clone(&self.telemetry),
        };

        if let Err(err) = self.capture.start(pkt_tx) {
            if let Some(tx) = started_tx.take() {
                let _ = tx.send(Err(err.to_string()));
            }
            if let Ok(mut slot) = self.netstack_slot.write() {
                *slot = None;
            }
            drop(ctx);
            drop(netstack);
            let _ = netstack_handle.await;
            return Err(err);
        }
        if let Some(tx) = started_tx.take() {
            let _ = tx.send(Ok(()));
        }
        info!("bypax-appproxy engine started");

        let initial_port = self
            .runtime
            .read()
            .map(|r| r.app_proxy_port)
            .unwrap_or(10818);
        let mut last_listener_pid = self.capture.find_local_tcp_listener_pid(initial_port);
        let mut upstream_watch = tokio::time::interval(Duration::from_secs(1));
        upstream_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut gc_interval = tokio::time::interval(Duration::from_secs(15));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    info!("bypax-appproxy engine shutting down");
                    break;
                }
                _ = upstream_watch.tick() => {
                    let rt = Arc::clone(&self.runtime.read().expect("runtime lock poisoned"));
                    let current_pid = self.capture.find_local_tcp_listener_pid(rt.app_proxy_port);
                    if let Some(pid) = current_pid {
                        rt.rules.add_exempt_pid(pid);
                    }
                    if last_listener_pid.is_some() && current_pid != last_listener_pid {
                        warn!(
                            old_pid = ?last_listener_pid,
                            new_pid = ?current_pid,
                            port = rt.app_proxy_port,
                            "upstream app-proxy listener disappeared or restarted; resetting active proxied TCP sessions via RST"
                        );
                        ctx.netstack.reset_proxied_sessions("upstream listener changed");
                    }
                    last_listener_pid = current_pid;
                }
                _ = gc_interval.tick() => {
                    let now = Instant::now();
                    self.flow_cache.retain(|_, v| now.duration_since(v.last_seen) < FLOW_CACHE_TTL);
                    self.origins.gc_expired();
                }
                maybe_pkt = pkt_rx.recv() => {
                    match maybe_pkt {
                        Some(pkt) => dispatch_packet(&ctx, pkt),
                        None => {
                            warn!("bypax-appproxy capture channel closed");
                            break;
                        }
                    }
                }
            }
        }

        // CRITICAL: Actively inject TCP RST into all hijacked client sockets BEFORE closing
        // the WinDivert capture handle so long-lived clients never get stranded half-open!
        if let Ok(mut slot) = self.netstack_slot.write() {
            *slot = None;
        }
        let reset_count = ctx.netstack.shutdown_and_reset_all().await;
        if reset_count > 0 {
            info!(
                reset_count,
                "injected TCP RST for active sessions prior to WinDivert shutdown"
            );
        }
        self.flow_cache.clear();
        let _ = self.capture.shutdown();
        drop(ctx);
        drop(netstack);
        let _ = netstack_handle.await;
        Ok(())
    }
}

fn build_runtime_snapshot(
    cfg: &AppProxyStartConfig,
    capture: &dyn CaptureEngine,
) -> Result<RuntimeSnapshot> {
    let rules = Arc::new(RuleEngine::from_wire(
        &cfg.rules,
        &cfg.target_bindings,
        cfg.bypass_lan,
        &cfg.exempt_pids,
    )?);
    if let Some(listener_pid) = capture.find_local_tcp_listener_pid(cfg.app_proxy_port) {
        rules.add_exempt_pid(listener_pid);
    }
    Ok(RuntimeSnapshot {
        app_proxy_port: if cfg.app_proxy_port == 0 {
            10818
        } else {
            cfg.app_proxy_port
        },
        control_secret: cfg.control_secret.clone(),
        block_quic_when_needed: cfg.block_quic_when_needed,
        rules,
    })
}

fn dispatch_packet(ctx: &EngineCtx, pkt: CapturedPacket) {
    if !pkt.meta.outbound {
        let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
        return;
    }

    let Some(parsed) = parse_ip_packet(&pkt.payload) else {
        let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
        return;
    };

    let tuple = parsed.tuple;
    let is_syn_only = tuple.protocol == TransportProtocol::Tcp
        && (parsed.tcp_flags & TCP_SYN_FLAG) != 0
        && (parsed.tcp_flags & TCP_ACK_FLAG) == 0;
    let is_tcp_close = tuple.protocol == TransportProtocol::Tcp
        && (parsed.tcp_flags & (TCP_FIN_FLAG | TCP_RST_FLAG)) != 0;

    if !is_syn_only {
        if let Some(mut entry) = ctx.flow_cache.get_mut(&tuple) {
            entry.last_seen = Instant::now();
            let cloned = entry.clone();
            drop(entry);
            apply_decision(
                ctx,
                pkt,
                tuple,
                parsed.l4_payload_offset,
                is_syn_only,
                is_tcp_close,
                cloned,
                false,
            );
            return;
        }
        if tuple.protocol == TransportProtocol::Tcp {
            let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
            return;
        }
    }

    if let Some(pid) = ctx.capture.lookup_pid(&tuple) {
        let entry = classify_and_cache(ctx, Some(pid), &tuple);
        apply_decision(
            ctx,
            pkt,
            tuple,
            parsed.l4_payload_offset,
            is_syn_only,
            is_tcp_close,
            entry,
            true,
        );
        return;
    }

    let ctx_clone = ctx.clone();
    let payload_offset = parsed.l4_payload_offset;
    tokio::spawn(async move {
        let mut resolved = None;
        for delay_ms in [1u64, 4] {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if let Some(pid) = ctx_clone.capture.lookup_pid(&tuple) {
                resolved = Some(pid);
                break;
            }
        }
        let entry = classify_and_cache(&ctx_clone, resolved, &tuple);
        apply_decision(
            &ctx_clone,
            pkt,
            tuple,
            payload_offset,
            is_syn_only,
            is_tcp_close,
            entry,
            true,
        );
    });
}

fn classify_and_cache(ctx: &EngineCtx, pid: Option<u32>, tuple: &FiveTuple) -> CachedFlow {
    let chain = pid
        .map(|p| ctx.tracker.ancestor_chain(p))
        .unwrap_or_default();
    let (process_name, exe_path) = match chain.first() {
        Some(info) => (info.name.clone(), info.exe_path.clone()),
        None => (
            pid.map(|p| format!("pid:{p}"))
                .unwrap_or_else(|| "unknown".to_string()),
            None,
        ),
    };
    let ancestor_chain: Vec<String> = chain.iter().map(|c| c.name.clone()).collect();

    let rt = Arc::clone(&ctx.runtime.read().expect("runtime lock poisoned"));
    let decision = rt.rules.evaluate_l4(pid, tuple, ctx.tracker.as_ref());
    let ancestor_app = match &decision {
        L4RouteDecision::Proxy {
            matched_ancestor, ..
        }
        | L4RouteDecision::InspectDirect {
            matched_ancestor, ..
        }
        | L4RouteDecision::Reject {
            matched_ancestor, ..
        } => matched_ancestor.clone(),
        L4RouteDecision::Direct { .. } => None,
    };

    let intercepted_tcp = tuple.protocol == TransportProtocol::Tcp
        && matches!(
            decision,
            L4RouteDecision::Proxy { .. } | L4RouteDecision::InspectDirect { .. }
        );

    let entry = CachedFlow {
        decision,
        pid,
        process_name,
        exe_path,
        ancestor_app,
        ancestor_chain,
        intercepted_tcp,
        last_seen: Instant::now(),
    };
    ctx.flow_cache.insert(*tuple, entry.clone());
    entry
}

#[allow(clippy::too_many_arguments)]
fn apply_decision(
    ctx: &EngineCtx,
    pkt: CapturedPacket,
    tuple: FiveTuple,
    l4_payload_offset: usize,
    is_syn_only: bool,
    is_tcp_close: bool,
    entry: CachedFlow,
    is_new: bool,
) {
    match entry.decision {
        L4RouteDecision::Direct { .. } => {
            let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
        }
        L4RouteDecision::Reject { ref rule_name, .. } => {
            if is_new {
                ctx.telemetry.record_local_reject(
                    entry.pid,
                    entry.process_name,
                    entry.ancestor_app,
                    entry.ancestor_chain,
                    SocketAddr::new(tuple.dst_ip, tuple.dst_port).to_string(),
                    rule_name.clone(),
                );
            }
        }
        L4RouteDecision::InspectDirect {
            ref rule_id,
            ref rule_name,
            ..
        } => {
            if tuple.protocol != TransportProtocol::Tcp || !entry.intercepted_tcp {
                let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
                return;
            }
            let _ = ctx.netstack.try_feed(NetstackInput {
                packet: pkt.payload,
                tuple,
                meta: pkt.meta,
                pid: entry.pid,
                process_name: entry.process_name,
                exe_path: entry.exe_path,
                ancestor_app: entry.ancestor_app,
                ancestor_chain: entry.ancestor_chain,
                rule_id: rule_id.clone(),
                rule_name: rule_name.clone(),
                target: None,
                auth_user: None,
                is_syn_only,
            });
            if is_tcp_close {
                if let Some(mut e) = ctx.flow_cache.get_mut(&tuple) {
                    e.last_seen = Instant::now();
                }
            }
        }
        L4RouteDecision::Proxy {
            ref rule_id,
            ref rule_name,
            ref target,
            ref auth_user,
            ..
        } => match tuple.protocol {
            TransportProtocol::Tcp => {
                if !entry.intercepted_tcp {
                    let _ = ctx.capture.inject(&pkt.payload, &pkt.meta);
                    return;
                }
                let _ = ctx.netstack.try_feed(NetstackInput {
                    packet: pkt.payload,
                    tuple,
                    meta: pkt.meta,
                    pid: entry.pid,
                    process_name: entry.process_name,
                    exe_path: entry.exe_path,
                    ancestor_app: entry.ancestor_app,
                    ancestor_chain: entry.ancestor_chain,
                    rule_id: rule_id.clone(),
                    rule_name: rule_name.clone(),
                    target: Some(target.clone()),
                    auth_user: Some(auth_user.clone()),
                    is_syn_only,
                });
                if is_tcp_close {
                    if let Some(mut e) = ctx.flow_cache.get_mut(&tuple) {
                        e.last_seen = Instant::now();
                    }
                }
            }
            TransportProtocol::Udp => {
                let udp_payload = pkt.payload[l4_payload_offset..].to_vec();
                let udp_relay = Arc::clone(&ctx.udp_relay);
                let udp_ctx = UdpPacketContext {
                    pid: entry.pid,
                    process_name: entry.process_name,
                    exe_path: entry.exe_path,
                    ancestor_app: entry.ancestor_app,
                    ancestor_chain: entry.ancestor_chain,
                    rule_id: rule_id.clone(),
                    rule_name: rule_name.clone(),
                    target: target.clone(),
                    auth_user: auth_user.clone(),
                };
                tokio::spawn(async move {
                    udp_relay
                        .handle_outbound_udp(tuple, udp_payload, pkt.meta, udp_ctx)
                        .await;
                });
            }
        },
    }
}
