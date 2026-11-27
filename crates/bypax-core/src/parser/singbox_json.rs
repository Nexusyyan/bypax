use crate::model::{NodeIR, Protocol, TlsConfig, TransportConfig};
use crate::parser::{
    first_port_from_ranges, normalize_hop_interval, normalize_port_ranges, parse_bandwidth_mbps,
    ImportSummary,
};
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn parse_singbox_json(raw: &str, default_group: &str) -> Result<ImportSummary> {
    let root: Value = serde_json::from_str(raw)?;
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    let mut warnings = Vec::new();

    if let Some(arr) = root.as_array() {
        for item in arr {
            match parse_outbound_obj(item, default_group) {
                Some(n) => nodes.push(n),
                None => skipped += 1,
            }
        }
    } else if let Some(obj) = root.as_object() {
        if let Some(outbounds) = obj.get("outbounds").and_then(|v| v.as_array()) {
            for item in outbounds {
                match parse_outbound_obj(item, default_group) {
                    Some(n) => nodes.push(n),
                    None => skipped += 1,
                }
            }
        }
        if let Some(endpoints) = obj.get("endpoints").and_then(|v| v.as_array()) {
            for item in endpoints {
                match parse_endpoint_obj(item, default_group) {
                    Some(n) => nodes.push(n),
                    None => skipped += 1,
                }
            }
        }
        if nodes.is_empty() && obj.get("type").is_some() {
            if let Some(n) = parse_outbound_obj(&root, default_group)
                .or_else(|| parse_endpoint_obj(&root, default_group))
            {
                nodes.push(n);
            } else {
                warnings.push("Single JSON object is not a supported proxy outbound".to_string());
            }
        }
    }

    Ok(ImportSummary {
        nodes,
        skipped,
        warnings,
    })
}

fn next_id(prefix: &str) -> String {
    let raw = Uuid::new_v4().simple().to_string();
    format!("n-{}-{}", prefix, &raw[..8])
}

fn parse_tls_obj(v: &Value) -> Option<TlsConfig> {
    let tls = v.get("tls")?.as_object()?;
    let enabled = tls.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
    if !enabled {
        return None;
    }
    let alpn = tls
        .get("alpn")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(|t| t.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let fp = tls
        .get("utls")
        .and_then(|u| u.get("fingerprint"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    let reality = tls.get("reality");
    Some(TlsConfig {
        enabled: true,
        server_name: tls.get("server_name").and_then(|s| s.as_str()).map(|s| s.to_string()),
        insecure: tls.get("insecure").and_then(|b| b.as_bool()).unwrap_or(false),
        alpn,
        fingerprint: fp,
        reality_public_key: reality
            .and_then(|r| r.get("public_key"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        reality_short_id: reality
            .and_then(|r| r.get("short_id"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
    })
}

fn parse_transport_obj(v: &Value) -> Option<TransportConfig> {
    let tr = v.get("transport")?.as_object()?;
    let t = tr.get("type")?.as_str()?.to_string();
    let mut headers = BTreeMap::new();
    if let Some(hm) = tr.get("headers").and_then(|h| h.as_object()) {
        for (k, val) in hm {
            if let Some(s) = val.as_str() {
                headers.insert(k.clone(), s.to_string());
            }
        }
    }
    Some(TransportConfig {
        transport_type: t,
        path: tr.get("path").and_then(|s| s.as_str()).map(|s| s.to_string()),
        host: tr.get("host").and_then(|s| s.as_str()).map(|s| s.to_string()),
        service_name: tr
            .get("service_name")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        headers,
    })
}

fn parse_outbound_obj(item: &Value, group: &str) -> Option<NodeIR> {
    let p_type = item.get("type")?.as_str()?;
    let protocol = match p_type {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "shadowsocks" => Protocol::Shadowsocks,
        "hysteria2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "anytls" => Protocol::Anytls,
        "wireguard" => Protocol::Wireguard,
        "http" => Protocol::Http,
        "socks" => Protocol::Socks,
        _ => return None,
    };

    let server = item.get("server")?.as_str()?.to_string();
    let mut server_ports: Vec<String> = Vec::new();
    if let Some(raw_ports) = item.get("server_ports") {
        match raw_ports {
            Value::Array(arr) => {
                for entry in arr {
                    if let Some(s) = entry.as_str() {
                        for norm in normalize_port_ranges(s) {
                            if !server_ports.contains(&norm) {
                                server_ports.push(norm);
                            }
                        }
                    } else if let Some(n) = entry.as_u64().and_then(|v| u16::try_from(v).ok()) {
                        if n > 0 {
                            let norm = format!("{}:{}", n, n);
                            if !server_ports.contains(&norm) {
                                server_ports.push(norm);
                            }
                        }
                    }
                }
            }
            Value::String(s) => {
                server_ports = normalize_port_ranges(s);
            }
            _ => {}
        }
    }
    let port = item
        .get("server_port")
        .and_then(|v| {
            v.as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u16>().ok()))
        })
        .filter(|&p| p > 0)
        .or_else(|| first_port_from_ranges(&server_ports))?;
    let remark = item
        .get("tag")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}:{}", server, port));

    let mut node = NodeIR::new(next_id(p_type), protocol, remark, server, port, group);
    node.uuid = item.get("uuid").and_then(|s| s.as_str()).map(|s| s.to_string());
    node.username = item
        .get("username")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.password = item
        .get("password")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.socks_version = item
        .get("version")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.method = item.get("method").and_then(|s| s.as_str()).map(|s| s.to_string());
    node.flow = item.get("flow").and_then(|s| s.as_str()).map(|s| s.to_string());
    node.security = item
        .get("security")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.alter_id = item.get("alter_id").and_then(|n| n.as_u64()).map(|n| n as u16);
    node.congestion_control = item
        .get("congestion_control")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.up_mbps = item.get("up_mbps").and_then(parse_json_mbps);
    node.down_mbps = item.get("down_mbps").and_then(parse_json_mbps);
    if let Some(obfs) = item.get("obfs").and_then(|v| v.as_object()) {
        node.obfs_type = obfs
            .get("type")
            .and_then(|s| s.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
            .map(|s| s.to_string());
        node.obfs_password = obfs
            .get("password")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
    }
    node.server_ports = server_ports;
    node.hop_interval = item.get("hop_interval").and_then(|v| match v {
        Value::String(s) => normalize_hop_interval(s),
        Value::Number(n) => n.as_u64().and_then(|s| normalize_hop_interval(&s.to_string())),
        _ => None,
    });
    node.tls = parse_tls_obj(item);
    node.transport = parse_transport_obj(item);
    Some(node)
}

fn parse_json_mbps(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()).filter(|&x| x > 0),
        Value::String(s) => parse_bandwidth_mbps(s),
        _ => None,
    }
}

fn parse_endpoint_obj(item: &Value, group: &str) -> Option<NodeIR> {
    if item.get("type")?.as_str()? != "wireguard" {
        return None;
    }
    let peer = item.get("peers")?.as_array()?.first()?;
    let server = peer.get("address")?.as_str()?.to_string();
    let port = peer.get("port")?.as_u64().unwrap_or(51820) as u16;
    let remark = item
        .get("tag")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("wg-{}:{}", server, port));
    let mut node = NodeIR::new(next_id("wg"), Protocol::Wireguard, remark, server, port, group);
    node.wg_private_key = item
        .get("private_key")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.wg_peer_public_key = peer
        .get("public_key")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    node.wg_local_address = item
        .get("address")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["10.0.0.2/32".to_string()]);
    Some(node)
}
