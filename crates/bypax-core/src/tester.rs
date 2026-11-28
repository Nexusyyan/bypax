use crate::compiler::{
    chain_outbound_tag, compile_dns_server, compile_proxy_outbound,
    compile_proxy_outbound_with_overrides, compile_wireguard_endpoint,
    compile_wireguard_endpoint_with_overrides, validate_chain_hops,
};
use crate::control::ControlClient;
use crate::model::{LatencyProgressEvent, LatencyResult, NodeIR, Protocol, ProxyChain};
use crate::supervisor::spawn_managed_process;
use anyhow::{anyhow, Result};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

fn allocate_free_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Isolated zero-disruption batch real-delay tester (defaults to unified strip-handshake RTT):
/// launches a temporary no-TUN `sing-box` process bound to ephemeral loopback ports,
/// probes all target nodes concurrently, and unconditionally kills and cleans up the process
/// via RAII guard + Windows Job Object (leaving zero orphan processes).
pub async fn batch_real_delay(
    sing_box_path: &Path,
    nodes: &[NodeIR],
    test_url: &str,
    timeout_ms: u32,
    concurrency: usize,
) -> Result<Vec<LatencyResult>> {
    batch_real_delay_with_progress(
        sing_box_path,
        nodes,
        nodes,
        test_url,
        timeout_ms,
        concurrency,
        None,
        true,
        |_| {},
    )
    .await
}

/// Measures single-node or chain real HTTP RTT over an ephemeral `socks` (SOCKS5) inbound
/// (`auth_user` routed strictly to the target outbound tag):
/// - `strip_handshake == true` (Unified RTT):
///   - Pass 1 (Warmup, NOT timed): opens the persistent SOCKS5 tunnel, absorbing DNS +
///     proxy TCP/QUIC + outer TLS/Reality + inner HTTPS TLS handshakes, and returns the warm
///     tunnel to hyper's keep-alive pool.
///   - Pass 2 (Timed): measures a clean single HTTP HEAD round-trip over the warm tunnel,
///     stripping first-connection handshake overhead for both `http://` and `https://` URLs.
/// - `strip_handshake == false` (Cold RTT):
///   - Measures a single cold HTTP HEAD request including full connection & TLS setup.
async fn probe_node_rtt(
    proxy_port: u16,
    auth_user: &str,
    test_url: &str,
    timeout_ms: u32,
    strip_handshake: bool,
) -> Result<i32> {
    let proxy_url = format!("socks5h://{}:p@127.0.0.1:{}", auth_user, proxy_port);
    let per_req_timeout = Duration::from_millis((timeout_ms as u64).max(800));
    let http = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(&proxy_url)?)
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(per_req_timeout)
        .build()?;

    let is_https = test_url.trim().to_ascii_lowercase().starts_with("https://");

    if strip_handshake {
        // Pass 1: Warm up DNS + proxy tunnel + inner TLS handshake.
        let mut req1 = http.head(test_url);
        if !is_https {
            req1 = req1.header(reqwest::header::CONNECTION, "keep-alive");
        }
        let resp1 = req1.send().await?;
        let _ = resp1.bytes().await;

        // Pass 2: Timed pure round-trip over the warm keep-alive tunnel.
        let started = Instant::now();
        let mut req2 = http.head(test_url);
        if !is_https {
            req2 = req2.header(reqwest::header::CONNECTION, "keep-alive");
        }
        let resp2 = req2.send().await?;
        let elapsed_ms = started.elapsed().as_millis().clamp(1, i32::MAX as u128) as i32;
        let _ = resp2.bytes().await;
        Ok(elapsed_ms)
    } else {
        let started = Instant::now();
        let resp = http.head(test_url).send().await?;
        let elapsed_ms = started.elapsed().as_millis().clamp(1, i32::MAX as u128) as i32;
        let _ = resp.bytes().await;
        Ok(elapsed_ms)
    }
}

fn build_ephemeral_dns_servers(local_dns_server: Option<&str>) -> Vec<Value> {
    let dns_spec = local_dns_server.unwrap_or("223.5.5.5");
    let (local_dns, needs_boot) = compile_dns_server("dns-local", dns_spec, None);
    let mut dns_servers = Vec::new();
    if needs_boot {
        dns_servers.push(json!({
            "type": "udp",
            "tag": "dns-bootstrap",
            "server": "223.5.5.5"
        }));
    }
    dns_servers.push(local_dns);
    dns_servers
}

/// Isolated batch real-delay tester with incremental progress reporting, transitive detour
/// dependency inclusion, and optional first-handshake stripping (Unified RTT).
/// Unreachable or timed-out nodes report `delay_ms: Some(-1)`.
#[allow(clippy::too_many_arguments)]
pub async fn batch_real_delay_with_progress<F>(
    sing_box_path: &Path,
    nodes: &[NodeIR],
    all_nodes: &[NodeIR],
    test_url: &str,
    timeout_ms: u32,
    concurrency: usize,
    local_dns_server: Option<&str>,
    strip_handshake: bool,
    on_progress: F,
) -> Result<Vec<LatencyResult>>
where
    F: Fn(LatencyProgressEvent) + Send + Sync + 'static,
{
    let total = nodes.len();
    let cb = Arc::new(on_progress);
    if total == 0 {
        cb(LatencyProgressEvent {
            kind: "real".to_string(),
            phase: "done".to_string(),
            completed: 0,
            total: 0,
            passed: 0,
            failed: 0,
            strip_handshake,
            latest: None,
        });
        return Ok(Vec::new());
    }
    if !sing_box_path.exists() {
        return Err(anyhow!(
            "sing-box binary not found at {}",
            sing_box_path.display()
        ));
    }

    cb(LatencyProgressEvent {
        kind: "real".to_string(),
        phase: "starting".to_string(),
        completed: 0,
        total,
        passed: 0,
        failed: 0,
        strip_handshake,
        latest: None,
    });

    let control_port = allocate_free_loopback_port()?;
    let proxy_port = allocate_free_loopback_port()?;
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let tmp_dir = std::env::temp_dir().join(format!("bypax-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir)?;
    let cfg_path = tmp_dir.join("tester.json");

    let all_map: HashMap<&str, &NodeIR> = all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut emitted_ids: HashSet<String> = HashSet::new();
    let mut outbounds: Vec<Value> = vec![json!({ "type": "direct", "tag": "direct" })];
    let mut endpoints: Vec<Value> = Vec::new();
    let mut users: Vec<Value> = Vec::new();
    let mut route_rules: Vec<Value> = Vec::new();
    let mut probe_items: Vec<(NodeIR, String)> = Vec::with_capacity(nodes.len());

    let mut queue: Vec<NodeIR> = Vec::new();
    for (idx, node) in nodes.iter().enumerate() {
        if emitted_ids.insert(node.id.clone()) {
            queue.push(node.clone());
        }
        let auth_user = format!("u{}", idx);
        users.push(json!({ "username": auth_user, "password": "p" }));
        route_rules.push(json!({ "auth_user": [auth_user], "outbound": node.id }));
        probe_items.push((node.clone(), auth_user));
    }

    // Transitively include any upstream `detour` dependencies so nodes referencing another
    // node as a detour compile cleanly in the isolated sing-box tester.
    while let Some(node) = queue.pop() {
        if let Some(ref detour_id) = node.detour {
            if let Some(dep) = all_map.get(detour_id.as_str()) {
                if emitted_ids.insert(dep.id.clone()) {
                    queue.push((*dep).clone());
                }
            }
        }
        if node.protocol == Protocol::Wireguard {
            endpoints.push(compile_wireguard_endpoint(&node));
        } else {
            outbounds.push(compile_proxy_outbound(&node));
        }
    }

    let dns_servers = build_ephemeral_dns_servers(local_dns_server);

    let inbounds = json!([{
        "type": "socks",
        "tag": "probe-socks",
        "listen": "127.0.0.1",
        "listen_port": proxy_port,
        "users": users
    }]);

    let mut route_obj = serde_json::Map::new();
    route_obj.insert("auto_detect_interface".to_string(), json!(true));
    route_obj.insert("default_domain_resolver".to_string(), json!("dns-local"));
    if !route_rules.is_empty() {
        route_obj.insert("rules".to_string(), Value::Array(route_rules));
    }
    route_obj.insert("final".to_string(), json!("direct"));

    let mut cfg = serde_json::Map::new();
    cfg.insert("log".to_string(), json!({ "level": "error" }));
    cfg.insert(
        "dns".to_string(),
        json!({
            "servers": dns_servers,
            "final": "dns-local"
        }),
    );
    if !endpoints.is_empty() {
        cfg.insert("endpoints".to_string(), Value::Array(endpoints));
    }
    cfg.insert("inbounds".to_string(), inbounds);
    cfg.insert("outbounds".to_string(), Value::Array(outbounds));
    cfg.insert("route".to_string(), Value::Object(route_obj));
    cfg.insert(
        "experimental".to_string(),
        json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", control_port),
                "secret": secret
            }
        }),
    );
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&Value::Object(cfg))?)?;

    // Spawn temporary isolated sing-box with RAII kill-on-drop guard.
    let mut guard = spawn_managed_process(sing_box_path, &cfg_path)?;
    let client = Arc::new(ControlClient::new(control_port, &secret)?);

    // Wait up to 4 seconds for ephemeral Clash API and SOCKS5 probe inbound to come up.
    let mut ready = false;
    for _ in 0..40 {
        let api_ok = client.get_version().await.is_ok();
        let proxy_ok = TcpStream::connect(("127.0.0.1", proxy_port)).await.is_ok();
        if api_ok && proxy_ok {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let results = if ready {
        cb(LatencyProgressEvent {
            kind: "real".to_string(),
            phase: "testing".to_string(),
            completed: 0,
            total,
            passed: 0,
            failed: 0,
            strip_handshake,
            latest: None,
        });

        let completed = Arc::new(AtomicUsize::new(0));
        let passed = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let url_arc = Arc::new(test_url.to_string());
        let limit = concurrency.clamp(1, 32);

        stream::iter(probe_items)
            .map(|(node, auth_user)| {
                let u = Arc::clone(&url_arc);
                let cb = Arc::clone(&cb);
                let completed = Arc::clone(&completed);
                let passed = Arc::clone(&passed);
                let failed = Arc::clone(&failed);
                async move {
                    let probe =
                        probe_node_rtt(proxy_port, &auth_user, &u, timeout_ms, strip_handshake)
                            .await;
                    let res = match probe {
                        Ok(ms) => LatencyResult {
                            node_id: node.id,
                            kind: "real".to_string(),
                            delay_ms: Some(ms.max(1)),
                            error: None,
                        },
                        Err(err) => LatencyResult {
                            node_id: node.id,
                            kind: "real".to_string(),
                            delay_ms: Some(-1),
                            error: Some(err.to_string()),
                        },
                    };
                    let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
                    let is_ok = res.delay_ms.is_some_and(|ms| ms > 0);
                    let p = if is_ok {
                        passed.fetch_add(1, Ordering::SeqCst) + 1
                    } else {
                        passed.load(Ordering::SeqCst)
                    };
                    let f = if !is_ok {
                        failed.fetch_add(1, Ordering::SeqCst) + 1
                    } else {
                        failed.load(Ordering::SeqCst)
                    };
                    cb(LatencyProgressEvent {
                        kind: "real".to_string(),
                        phase: if done >= total { "done" } else { "testing" }.to_string(),
                        completed: done,
                        total,
                        passed: p,
                        failed: f,
                        strip_handshake,
                        latest: Some(res.clone()),
                    });
                    res
                }
            })
            .buffer_unordered(limit)
            .collect()
            .await
    } else {
        let errs: Vec<LatencyResult> = nodes
            .iter()
            .map(|n| LatencyResult {
                node_id: n.id.clone(),
                kind: "real".to_string(),
                delay_ms: Some(-1),
                error: Some("Isolated tester failed to start".to_string()),
            })
            .collect();
        cb(LatencyProgressEvent {
            kind: "real".to_string(),
            phase: "done".to_string(),
            completed: total,
            total,
            passed: 0,
            failed: total,
            strip_handshake,
            latest: None,
        });
        errs
    };

    guard.terminate();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(results)
}

/// Measures the true end-to-end HTTP RTT of a multi-hop `ProxyChain` by spawning an isolated
/// ephemeral `sing-box` instance containing only the chain's detour hops. Returns `Some(-1)` on
/// probe failure or timeout.
pub async fn test_proxy_chain_real_delay(
    sing_box_path: &Path,
    chain: &ProxyChain,
    all_nodes: &[NodeIR],
    test_url: &str,
    timeout_ms: u32,
    local_dns_server: Option<&str>,
    strip_handshake: bool,
) -> Result<LatencyResult> {
    if !sing_box_path.exists() {
        return Err(anyhow!(
            "sing-box binary not found at {}",
            sing_box_path.display()
        ));
    }
    let node_map: HashMap<&str, &NodeIR> = all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    if let Err(missing) = validate_chain_hops(chain, &node_map) {
        return Ok(LatencyResult {
            node_id: format!("chain:{}", chain.id),
            kind: "real".to_string(),
            delay_ms: Some(-1),
            error: Some(if missing.is_empty() {
                "Proxy chain has no valid hops".to_string()
            } else {
                format!("Missing hop nodes: {}", missing.join(", "))
            }),
        });
    }

    let control_port = allocate_free_loopback_port()?;
    let proxy_port = allocate_free_loopback_port()?;
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let tmp_dir = std::env::temp_dir().join(format!("bypax-chain-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir)?;
    let cfg_path = tmp_dir.join("chain-tester.json");

    let mut outbounds: Vec<Value> = vec![json!({ "type": "direct", "tag": "direct" })];
    let mut endpoints: Vec<Value> = Vec::new();
    let base_tag = chain_outbound_tag(&chain.id);
    let hop_count = chain.hops.len();
    for (idx, hop_id) in chain.hops.iter().enumerate() {
        if let Some(node) = node_map.get(hop_id.as_str()) {
            let is_last = idx + 1 == hop_count;
            let hop_tag = if is_last {
                base_tag.clone()
            } else {
                format!("{}-hop-{}", base_tag, idx)
            };
            let prev_detour = if idx == 0 {
                None
            } else {
                Some(format!("{}-hop-{}", base_tag, idx - 1))
            };
            if node.protocol == Protocol::Wireguard {
                endpoints.push(compile_wireguard_endpoint_with_overrides(
                    node,
                    Some(&hop_tag),
                    prev_detour.as_deref(),
                ));
            } else {
                outbounds.push(compile_proxy_outbound_with_overrides(
                    node,
                    Some(&hop_tag),
                    prev_detour.as_deref(),
                ));
            }
        }
    }

    let dns_servers = build_ephemeral_dns_servers(local_dns_server);
    let mut cfg = serde_json::Map::new();
    cfg.insert("log".to_string(), json!({ "level": "error" }));
    cfg.insert(
        "dns".to_string(),
        json!({
            "servers": dns_servers,
            "final": "dns-local"
        }),
    );
    if !endpoints.is_empty() {
        cfg.insert("endpoints".to_string(), Value::Array(endpoints));
    }
    cfg.insert(
        "inbounds".to_string(),
        json!([{
            "type": "socks",
            "tag": "probe-socks",
            "listen": "127.0.0.1",
            "listen_port": proxy_port,
            "users": [{ "username": "chain", "password": "p" }]
        }]),
    );
    cfg.insert("outbounds".to_string(), Value::Array(outbounds));
    cfg.insert(
        "route".to_string(),
        json!({
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-local",
            "rules": [{ "auth_user": ["chain"], "outbound": base_tag }],
            "final": "direct"
        }),
    );
    cfg.insert(
        "experimental".to_string(),
        json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", control_port),
                "secret": secret
            }
        }),
    );
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&Value::Object(cfg))?)?;

    let mut guard = spawn_managed_process(sing_box_path, &cfg_path)?;
    let client = ControlClient::new(control_port, &secret)?;

    let mut ready = false;
    for _ in 0..40 {
        let api_ok = client.get_version().await.is_ok();
        let proxy_ok = TcpStream::connect(("127.0.0.1", proxy_port)).await.is_ok();
        if api_ok && proxy_ok {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let result = if ready {
        match probe_node_rtt(proxy_port, "chain", test_url, timeout_ms, strip_handshake).await {
            Ok(ms) => LatencyResult {
                node_id: format!("chain:{}", chain.id),
                kind: "real".to_string(),
                delay_ms: Some(ms.max(1)),
                error: None,
            },
            Err(err) => LatencyResult {
                node_id: format!("chain:{}", chain.id),
                kind: "real".to_string(),
                delay_ms: Some(-1),
                error: Some(err.to_string()),
            },
        }
    } else {
        LatencyResult {
            node_id: format!("chain:{}", chain.id),
            kind: "real".to_string(),
            delay_ms: Some(-1),
            error: Some("Isolated chain tester failed to start".to_string()),
        }
    };

    guard.terminate();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(result)
}
