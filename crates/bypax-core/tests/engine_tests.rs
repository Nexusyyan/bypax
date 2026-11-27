use anyhow::Result;
use bypax_core::compiler::{CompileInput, CompilePlatform, SingBox114Compiler};
use bypax_core::control::ControlClient;
use bypax_core::model::{
    AppProxyRule, AppSettings, DomainOverride, DomainOverrideAction, InboundPort, NetworkSnapshot,
    NodeIR, Protocol, RouteMode, SimpleRoutingRule, TlsConfig, TransportConfig,
};
use bypax_core::netguard::{NetGuard, SystemNetworkAdapter};
use bypax_core::parser::parse_payload;
use bypax_core::rule_cache::RuleCache;
use bypax_core::storage::{default_simple_rules, DataPaths, Store};
use bypax_core::supervisor::{CoreSupervisor, LogRing};
use bypax_core::tester::{batch_real_delay, batch_tcping};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn find_test_singbox() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("BYPAX_TEST_SINGBOX") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    let bin = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join(bin);
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

fn build_all_8_protocol_nodes() -> Vec<NodeIR> {
    let mut vless = NodeIR::new(
        "n-vless",
        Protocol::Vless,
        "JP-Tokyo-01 Reality",
        "jp1.example.com",
        443,
        "VPS",
    );
    vless.uuid = Some("11111111-1111-1111-1111-111111111111".to_string());
    vless.flow = Some("xtls-rprx-vision".to_string());
    vless.tls = Some(TlsConfig {
        enabled: true,
        server_name: Some("www.microsoft.com".to_string()),
        insecure: false,
        alpn: Vec::new(),
        fingerprint: Some("chrome".to_string()),
        reality_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
        reality_short_id: Some("abcd".to_string()),
    });

    let mut vmess = NodeIR::new(
        "n-vmess",
        Protocol::Vmess,
        "TW-Taipei-01",
        "tw1.example.com",
        8080,
        "Sub",
    );
    vmess.uuid = Some("22222222-2222-2222-2222-222222222222".to_string());
    vmess.security = Some("auto".to_string());
    vmess.alter_id = Some(0);
    vmess.transport = Some(TransportConfig {
        transport_type: "ws".to_string(),
        path: Some("/ws".to_string()),
        host: Some("tw1.example.com".to_string()),
        service_name: None,
        headers: BTreeMap::from([("Host".to_string(), "tw1.example.com".to_string())]),
    });

    let mut trojan = NodeIR::new(
        "n-trojan",
        Protocol::Trojan,
        "UK-London-01",
        "uk1.example.com",
        443,
        "VPS",
    );
    trojan.password = Some("secret-trojan".to_string());
    trojan.tls = Some(TlsConfig {
        enabled: true,
        server_name: Some("uk1.example.com".to_string()),
        ..Default::default()
    });

    let mut ss = NodeIR::new(
        "n-ss",
        Protocol::Shadowsocks,
        "HK-IPLC-01",
        "hk1.example.com",
        10443,
        "Sub",
    );
    ss.method = Some("2022-blake3-aes-128-gcm".to_string());
    ss.password = Some("AAAAAAAAAAAAAAAAAAAAAA==".to_string());

    let mut hy2 = NodeIR::new(
        "n-hy2",
        Protocol::Hysteria2,
        "US-LA-Residential-01",
        "us1.example.com",
        8443,
        "US",
    );
    hy2.password = Some("secret-hy2".to_string());
    hy2.tls = Some(TlsConfig {
        enabled: true,
        server_name: Some("us1.example.com".to_string()),
        ..Default::default()
    });

    let mut tuic = NodeIR::new(
        "n-tuic",
        Protocol::Tuic,
        "SG-Unlock-01",
        "sg1.example.com",
        20443,
        "Sub",
    );
    tuic.uuid = Some("33333333-3333-3333-3333-333333333333".to_string());
    tuic.password = Some("secret-tuic".to_string());
    tuic.congestion_control = Some("bbr".to_string());
    tuic.tls = Some(TlsConfig {
        enabled: true,
        server_name: Some("sg1.example.com".to_string()),
        alpn: vec!["h3".to_string()],
        ..Default::default()
    });

    let mut anytls = NodeIR::new(
        "n-anytls",
        Protocol::Anytls,
        "US-Seattle-02",
        "us2.example.com",
        443,
        "US",
    );
    anytls.password = Some("secret-anytls".to_string());
    anytls.tls = Some(TlsConfig {
        enabled: true,
        server_name: Some("us2.example.com".to_string()),
        ..Default::default()
    });

    let mut wg = NodeIR::new(
        "n-wg",
        Protocol::Wireguard,
        "DE-Frankfurt-WG",
        "1.2.3.4",
        51820,
        "VPS",
    );
    wg.wg_private_key = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
    wg.wg_peer_public_key = Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string());
    wg.wg_local_address = vec!["10.0.0.2/32".to_string()];

    let mut http_n = NodeIR::new(
        "n-http",
        Protocol::Http,
        "AU-Sydney-HTTP",
        "au1.example.com",
        8080,
        "Proxy",
    );
    http_n.username = Some("user".to_string());
    http_n.password = Some("pass".to_string());

    let mut socks_n = NodeIR::new(
        "n-socks",
        Protocol::Socks,
        "AU-Melbourne-SOCKS5",
        "au2.example.com",
        1080,
        "Proxy",
    );
    socks_n.socks_version = Some("5".to_string());
    socks_n.username = Some("suser".to_string());
    socks_n.password = Some("spass".to_string());

    vec![
        vless, vmess, trojan, ss, hy2, tuic, anytls, wg, http_n, socks_n,
    ]
}

fn sample_app_proxy_rules() -> Vec<AppProxyRule> {
    vec![
        AppProxyRule {
            id: "preset-cursor".to_string(),
            name: "Cursor".to_string(),
            enabled: true,
            priority: 10,
            preset_id: Some("cursor".to_string()),
            process_names: vec!["Cursor.exe".to_string(), "Cursor".to_string()],
            path_prefixes: Vec::new(),
            path_contains: vec!["cursor".to_string()],
            mac_bundle_paths: vec!["/Applications/Cursor.app".to_string()],
            ignored_external_children: Vec::new(),
            include_children: true,
            domains: vec![DomainOverride {
                pattern: "*.local.internal".to_string(),
                action: DomainOverrideAction::Direct,
            }],
            dst_cidrs: Vec::new(),
            dst_ports: Vec::new(),
            protocols: Vec::new(),
            target: "auto:US".to_string(),
        },
        AppProxyRule {
            id: "r-pinned-node".to_string(),
            name: "Antigravity".to_string(),
            enabled: true,
            priority: 20,
            preset_id: Some("antigravity".to_string()),
            process_names: vec!["Antigravity.exe".to_string()],
            path_prefixes: Vec::new(),
            path_contains: vec!["Antigravity".to_string()],
            mac_bundle_paths: vec!["/Applications/Antigravity.app".to_string()],
            ignored_external_children: Vec::new(),
            include_children: true,
            domains: vec![],
            dst_cidrs: Vec::new(),
            dst_ports: Vec::new(),
            protocols: Vec::new(),
            target: "n-vless".to_string(),
        },
        AppProxyRule {
            id: "r-missing-node".to_string(),
            name: "Orphan Target".to_string(),
            enabled: true,
            priority: 30,
            preset_id: None,
            process_names: vec!["demo.exe".to_string()],
            path_prefixes: Vec::new(),
            path_contains: Vec::new(),
            mac_bundle_paths: Vec::new(),
            ignored_external_children: Vec::new(),
            include_children: false,
            domains: Vec::new(),
            dst_cidrs: Vec::new(),
            dst_ports: Vec::new(),
            protocols: Vec::new(),
            target: "node:deleted-node-999".to_string(),
        },
    ]
}

#[test]
fn test_tree_shaking_2000_nodes_and_dynamic_matcher() {
    let mut nodes = Vec::with_capacity(2000);
    for i in 0..2000 {
        let remark = if i < 3 {
            format!("US-Residential-{:02}", i + 1)
        } else {
            format!("JP-Bulk-{:04}", i)
        };
        let mut n = NodeIR::new(
            format!("n-bulk-{:04}", i),
            Protocol::Vless,
            remark,
            format!("node{}.example.com", i),
            443,
            "MassivePool",
        );
        n.uuid = Some("11111111-1111-1111-1111-111111111111".to_string());
        nodes.push(n);
    }

    let settings = AppSettings {
        main_node_id: Some("n-bulk-0500".to_string()),
        ..Default::default()
    };
    let rules = vec![
        SimpleRoutingRule {
            id: "r-ai".to_string(),
            title: "AI".to_string(),
            title_en: "AI".to_string(),
            description: "OpenAI".to_string(),
            patterns: vec!["openai.com".to_string()],
            domain_keywords: Vec::new(),
            ip_cidrs: Vec::new(),
            process_names: Vec::new(),
            rule_set: None,
            target: "auto:US".to_string(),
            enabled: true,
            priority: 1,
        },
        SimpleRoutingRule {
            id: "r-pinned".to_string(),
            title: "Pinned".to_string(),
            title_en: "Pinned".to_string(),
            description: "GitHub".to_string(),
            patterns: vec!["github.com".to_string()],
            domain_keywords: Vec::new(),
            ip_cidrs: Vec::new(),
            process_names: Vec::new(),
            rule_set: None,
            target: "n-bulk-0999".to_string(),
            enabled: true,
            priority: 2,
        },
    ];

    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &rules,
        app_rules: &[],
        extra_ports: &[],
        settings: &settings,
        control_secret: "secret",
        cache_db_path: None,
        rule_cache: None,
        platform: CompilePlatform::Windows,
    })
    .expect("compile");

    // Only main (1) + 3 US nodes + 1 pinned = 5 nodes out of 2,000.
    assert_eq!(compiled.total_nodes, 2000);
    assert_eq!(compiled.reachable_nodes, 5);

    nodes[0].remark = "US-NewName-LA".to_string();
    nodes[1].remark = "US-NewName-SJ".to_string();
    let recompiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &[SimpleRoutingRule {
            target: "auto:regex:NewName".to_string(),
            ..rules[0].clone()
        }],
        app_rules: &[],
        extra_ports: &[],
        settings: &settings,
        control_secret: "secret",
        cache_db_path: None,
        rule_cache: None,
        platform: CompilePlatform::Windows,
    })
    .expect("recompile");
    assert_eq!(recompiled.reachable_nodes, 3);
}

#[test]
fn test_windows_app_proxy_single_port_auth_user_and_missing_node_fallback() {
    let nodes = build_all_8_protocol_nodes();
    let rules = default_simple_rules();
    let app_rules = sample_app_proxy_rules();
    let settings = AppSettings {
        main_node_id: Some("n-vmess".to_string()),
        app_proxy_enabled: true,
        app_proxy_port: 10818,
        tun_enabled: false,
        ..Default::default()
    };

    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &rules,
        app_rules: &app_rules,
        extra_ports: &[],
        settings: &settings,
        control_secret: "win-app-proxy",
        cache_db_path: None,
        rule_cache: None,
        platform: CompilePlatform::Windows,
    })
    .expect("compile windows app proxy");

    // Missing node target must safely fall back to bx_follow and record a warning.
    assert_eq!(compiled.missing_app_rule_targets.len(), 1);
    assert_eq!(compiled.missing_app_rule_targets[0].rule_id, "r-missing-node");
    assert_eq!(compiled.missing_app_rule_targets[0].fallback_target, "follow");

    let inbounds = compiled.config["inbounds"].as_array().unwrap();
    let app_in = inbounds
        .iter()
        .find(|i| i["tag"] == "app-proxy-in")
        .expect("Windows app-proxy-in inbound must exist");
    assert_eq!(app_in["type"], "socks");
    assert_eq!(app_in["listen"], "127.0.0.1");
    assert_eq!(app_in["listen_port"], 10818);

    let users = app_in["users"].as_array().unwrap();
    let usernames: Vec<&str> = users
        .iter()
        .filter_map(|u| u["username"].as_str())
        .collect();
    assert!(usernames.contains(&"bx_follow"));
    assert!(usernames.contains(&"bx_main"));
    assert!(usernames.contains(&"bx_auto_us"));
    assert!(usernames.contains(&"bx_node_n_vless"));

    // Verify route rules dispatch auth_user accurately.
    let route_rules = compiled.config["route"]["rules"].as_array().unwrap();
    assert!(route_rules.iter().any(|r| {
        r["inbound"] == serde_json::json!(["app-proxy-in"])
            && r["auth_user"] == serde_json::json!(["bx_auto_us"])
            && r["outbound"] == "auto-us"
    }));
    assert!(route_rules.iter().any(|r| {
        r["inbound"] == serde_json::json!(["app-proxy-in"])
            && r["auth_user"] == serde_json::json!(["bx_node_n_vless"])
            && r["outbound"] == "n-vless"
    }));

    // Real sing-box v1.14 preflight check when binary is available.
    if let Some(sb) = find_test_singbox() {
        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(
            report.ok,
            "Windows app-proxy-in sing-box check failed: {}",
            report.stderr
        );
        assert!(
            report.deprecated_warnings.is_empty(),
            "Unexpected deprecation warnings: {:?}",
            report.deprecated_warnings
        );
    }
}

#[test]
fn test_macos_utun_app_proxy_nested_invert_gate_and_preflight() {
    let nodes = build_all_8_protocol_nodes();
    let rules = default_simple_rules();
    let app_rules = sample_app_proxy_rules();
    let settings = AppSettings {
        main_node_id: Some("n-vmess".to_string()),
        app_proxy_enabled: true,
        tun_enabled: false,
        tun_route_exclude_cidrs: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
        ..Default::default()
    };

    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &rules,
        app_rules: &app_rules,
        extra_ports: &[],
        settings: &settings,
        control_secret: "mac-utun-secret",
        cache_db_path: None,
        rule_cache: None,
        platform: CompilePlatform::MacOs,
    })
    .expect("compile macos utun app proxy");

    // macOS App Proxy uses tun-in (utun) with strict_route: false and find_process: true.
    assert_eq!(compiled.config["route"]["find_process"], true);
    let inbounds = compiled.config["inbounds"].as_array().unwrap();
    let tun_in = inbounds
        .iter()
        .find(|i| i["tag"] == "tun-in")
        .expect("macOS tun-in inbound must exist for app_proxy_enabled");
    assert_eq!(tun_in["strict_route"], false);
    assert!(tun_in["route_exclude_address"].is_array());
    // macOS utun must NOT set non-utun interface_name like "bypax-tun0".
    assert!(tun_in.get("interface_name").is_none());

    // Must contain nested logical invert: true direct gate scoped strictly to tun-in
    // so mixed-in system proxy traffic is unaffected.
    let route_rules = compiled.config["route"]["rules"].as_array().unwrap();
    let has_scoped_invert_gate = route_rules.iter().any(|r| {
        r["type"] == "logical"
            && r["mode"] == "and"
            && r["outbound"] == "direct"
            && r["rules"].as_array().is_some_and(|sub| {
                sub.iter().any(|s| s["inbound"] == serde_json::json!(["tun-in"]))
                    && sub.iter().any(|s| s["invert"] == true)
            })
    });
    assert!(
        has_scoped_invert_gate,
        "macOS App Proxy config must include tun-in scoped nested invert: true direct gate"
    );

    if let Some(sb) = find_test_singbox() {
        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(
            report.ok,
            "macOS utun App Proxy sing-box check failed: {}",
            report.stderr
        );
        assert!(
            report.deprecated_warnings.is_empty(),
            "Unexpected macOS deprecation warnings: {:?}",
            report.deprecated_warnings
        );
    }
}

#[test]
fn test_sqlite_wal_concurrency_and_app_proxy_rules_crud() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().join("bypax.db");

    let mut writer = Store::open(&db_path)?;
    let reader = Store::open(&db_path)?;

    // Upsert 3 rules from writer, verify reader sees them immediately under WAL mode.
    let rules = sample_app_proxy_rules();
    for r in &rules {
        writer.upsert_app_proxy_rule(r)?;
    }

    let read_back = reader.list_app_proxy_rules()?;
    assert_eq!(read_back.len(), 3);
    assert_eq!(read_back[0].id, "preset-cursor");
    assert_eq!(read_back[0].domains.len(), 1);
    assert_eq!(read_back[0].domains[0].action, DomainOverrideAction::Direct);

    // Reorder rules and verify new priority sequence.
    writer.reorder_app_proxy_rules(&[
        "r-missing-node".to_string(),
        "r-pinned-node".to_string(),
        "preset-cursor".to_string(),
    ])?;
    let reordered = reader.list_app_proxy_rules()?;
    assert_eq!(reordered[0].id, "r-missing-node");
    assert_eq!(reordered[1].id, "r-pinned-node");
    assert_eq!(reordered[2].id, "preset-cursor");

    // Delete one rule and verify.
    writer.delete_app_proxy_rule("r-missing-node")?;
    assert_eq!(reader.list_app_proxy_rules()?.len(), 2);

    // Concurrent multi-threaded WAL reads/writes must succeed without SQLITE_BUSY failure.
    let db_path_a = db_path.clone();
    let db_path_b = db_path.clone();
    let t1 = std::thread::spawn(move || -> Result<()> {
        let s = Store::open(&db_path_a)?;
        for i in 0..25 {
            let mut r = sample_app_proxy_rules()[0].clone();
            r.id = format!("concurrent-{i}");
            r.priority = 100 + i;
            s.upsert_app_proxy_rule(&r)?;
        }
        Ok(())
    });
    let t2 = std::thread::spawn(move || -> Result<usize> {
        let s = Store::open(&db_path_b)?;
        let mut max_seen = 0usize;
        for _ in 0..25 {
            max_seen = max_seen.max(s.list_app_proxy_rules()?.len());
        }
        Ok(max_seen)
    });
    t1.join().unwrap()?;
    assert!(t2.join().unwrap()? >= 2);
    assert_eq!(reader.list_app_proxy_rules()?.len(), 27);
    Ok(())
}

#[test]
fn test_multi_format_parsers_uri_base64_json_yaml() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let raw_uris = [
        "vless://11111111-1111-1111-1111-111111111111@jp1.example.com:443?security=reality&pbk=PUBKEY&sid=abcd&sni=www.microsoft.com&fp=chrome#JP-Reality",
        "trojan://pass123@uk1.example.com:443?sni=uk1.example.com#UK-Trojan",
        "hysteria2://hy2pass@us1.example.com:8443?sni=us1.example.com#US-Hy2",
        "tuic://22222222-2222-2222-2222-222222222222:tuicpass@sg1.example.com:20443?congestion_control=bbr#SG-TUIC",
        "anytls://anypass@us2.example.com:443?sni=us2.example.com#US-AnyTLS",
        "wireguard://PRIVKEY@1.2.3.4:51820?publickey=PUBKEY&address=10.0.0.2/32#DE-WG",
        "http://alice:secret@au1.example.com:8080#\u{1f1e6}\u{1f1fa}%20oracle-arm-http",
        "https://bob:pw@au2.example.com:443#AU-HTTPS-Proxy",
        "socks5://suser:spass@au3.example.com:1080#AU-SOCKS5",
        "socks://c3VzZXI6c3Bhc3M=@au4.example.com:1080#AU-V2rayN-SOCKS",
    ]
    .join("\n");

    let direct = parse_payload(&raw_uris, "Imported").expect("parse direct");
    assert_eq!(direct.nodes.len(), 10);
    assert_eq!(direct.nodes[0].region, "JP");
    assert_eq!(direct.nodes[2].region, "US");
    assert_eq!(direct.nodes[6].protocol, Protocol::Http);
    assert_eq!(direct.nodes[6].region, "AU");
    assert_eq!(direct.nodes[6].username.as_deref(), Some("alice"));
    assert_eq!(direct.nodes[7].tls.as_ref().map(|t| t.enabled), Some(true));
    assert_eq!(direct.nodes[8].protocol, Protocol::Socks);
    assert_eq!(direct.nodes[9].username.as_deref(), Some("suser"));
    assert_eq!(direct.nodes[9].password.as_deref(), Some("spass"));

    let b64 = STANDARD.encode(raw_uris.as_bytes());
    let from_b64 = parse_payload(&b64, "Sub").expect("parse base64");
    assert_eq!(from_b64.nodes.len(), 10);

    let yaml = r#"
proxies:
  - name: "US-Clash-Trojan"
    type: trojan
    server: us-clash.example.com
    port: 443
    password: secret
    sni: us-clash.example.com
  - name: "HK-Clash-SS"
    type: ss
    server: hk-clash.example.com
    port: 8388
    cipher: aes-256-gcm
    password: sspw
"#;
    let from_yaml = parse_payload(yaml, "ClashSub").expect("parse yaml");
    assert_eq!(from_yaml.nodes.len(), 2);
    assert_eq!(from_yaml.nodes[0].region, "US");
    assert_eq!(from_yaml.nodes[1].region, "HK");
}

#[test]
fn test_portable_mode_and_sqlite_store() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("portable.json"), r#"{"portable":true}"#).expect("write");
    let paths = DataPaths::resolve_from_exe_dir(tmp.path()).expect("resolve");
    assert!(paths.portable_mode);
    assert!(paths.root_dir.ends_with("bypax-data"));

    let mut store = Store::open(&paths.db_path).expect("open store");
    assert_eq!(store.list_rules().expect("rules").len(), 4);

    let custom_rule = SimpleRoutingRule {
        id: "r-custom-work".to_string(),
        title: "Work".to_string(),
        title_en: "Work".to_string(),
        description: "corp.internal".to_string(),
        patterns: vec!["corp.internal".to_string()],
        domain_keywords: Vec::new(),
        ip_cidrs: Vec::new(),
        process_names: Vec::new(),
        rule_set: None,
        target: "direct".to_string(),
        enabled: true,
        priority: 5,
    };
    store.upsert_rule(&custom_rule).expect("upsert custom");
    let gfw_rules = store
        .apply_routing_strategy("gfw-list")
        .expect("apply gfw-list");
    assert!(gfw_rules.iter().any(|r| r.id == "r-custom-work"));
    assert!(gfw_rules
        .iter()
        .any(|r| r.rule_set.as_deref() == Some("geosite-gfw")));
    assert!(gfw_rules
        .iter()
        .any(|r| r.rule_set.as_deref() == Some("geoip-cn")));

    let nodes = build_all_8_protocol_nodes();
    store.upsert_nodes(&nodes).expect("upsert");
    assert_eq!(store.list_nodes().expect("list").len(), 10);
}

#[derive(Default)]
struct MockOsState {
    proxy_enable: bool,
    proxy_server: String,
    proxy_override: String,
    dns_servers: Vec<String>,
}

struct MockNetAdapter {
    state: Arc<Mutex<MockOsState>>,
}

impl SystemNetworkAdapter for MockNetAdapter {
    fn capture_snapshot(&self) -> Result<NetworkSnapshot> {
        let g = self.state.lock().unwrap();
        Ok(NetworkSnapshot {
            platform: "mock".to_string(),
            proxy_enable: g.proxy_enable,
            proxy_server: g.proxy_server.clone(),
            proxy_override: g.proxy_override.clone(),
            dns_servers: g.dns_servers.clone(),
            macos_services: Vec::new(),
            captured_at: "2026-11-26T00:00:00Z".to_string(),
            active_sentinel: false,
        })
    }

    fn apply_system_proxy(&self, host: &str, port: u16, bypass: &str) -> Result<()> {
        let mut g = self.state.lock().unwrap();
        g.proxy_enable = true;
        g.proxy_server = format!("{}:{}", host, port);
        g.proxy_override = bypass.to_string();
        Ok(())
    }

    fn restore_snapshot(&self, snapshot: &NetworkSnapshot) -> Result<()> {
        let mut g = self.state.lock().unwrap();
        g.proxy_enable = snapshot.proxy_enable;
        g.proxy_server = snapshot.proxy_server.clone();
        g.proxy_override = snapshot.proxy_override.clone();
        g.dns_servers = snapshot.dns_servers.clone();
        Ok(())
    }
}

#[test]
fn test_netguard_crash_recovery_snapshot_rollback() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let os = Arc::new(Mutex::new(MockOsState {
        proxy_enable: false,
        proxy_server: String::new(),
        proxy_override: "corp.local".to_string(),
        dns_servers: vec!["8.8.8.8".to_string()],
    }));

    {
        let guard = NetGuard::with_adapter(
            tmp.path(),
            MockNetAdapter {
                state: Arc::clone(&os),
            },
        );
        guard.enable_system_proxy("127.0.0.1", 10808).expect("enable");
        assert!(guard.is_armed());
        assert_eq!(os.lock().unwrap().proxy_server, "127.0.0.1:10808");
    }

    let guard2 = NetGuard::with_adapter(
        tmp.path(),
        MockNetAdapter {
            state: Arc::clone(&os),
        },
    );
    let recovered = guard2.recover_if_dirty().expect("recover");
    assert!(recovered);
    assert!(!guard2.is_armed());
    assert!(!os.lock().unwrap().proxy_enable);
    assert_eq!(os.lock().unwrap().proxy_override, "corp.local");
    assert_eq!(os.lock().unwrap().dns_servers, vec!["8.8.8.8".to_string()]);
}

#[tokio::test]
async fn test_srs_offline_graceful_degradation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cache = RuleCache::new(tmp.path().to_path_buf());
    let status = cache
        .refresh_rule_set(
            "geosite-openai",
            "http://127.0.0.1:1/nonexistent.srs",
            None,
        )
        .await;
    assert!(status.fallback_mode);
    assert!(!status.cached_locally);
}

#[tokio::test]
async fn test_tcping_against_local_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let node = NodeIR::new("n-local", Protocol::Vless, "Local", "127.0.0.1", port, "Test");
    let results = batch_tcping(&[node], 1500, 4).await;
    assert_eq!(results.len(), 1);
    assert!(results[0].delay_ms.is_some());
}

#[test]
fn test_singbox_v114_all_8_protocols_strict_check() {
    let Some(sb) = find_test_singbox() else {
        eprintln!("Skipping real sing-box check test (set BYPAX_TEST_SINGBOX to enable)");
        return;
    };

    let nodes = build_all_8_protocol_nodes();
    let mut rules = default_simple_rules();
    rules[0].target = "auto:ALL".to_string();

    let extra_ports = vec![InboundPort {
        id: "in-10809".to_string(),
        port: 10809,
        note: "AI CLI".to_string(),
        note_en: "AI CLI".to_string(),
        target: "auto:US".to_string(),
        enabled: true,
        allow_lan: false,
    }];

    for (mode, fake_ip, local_dns) in [
        (RouteMode::Rule, false, "223.5.5.5"),
        (RouteMode::Rule, true, "https://dns.alidns.com/dns-query"),
        (RouteMode::Global, false, "119.29.29.29"),
        (RouteMode::Direct, false, "223.5.5.5"),
    ] {
        let settings = AppSettings {
            route_mode: mode,
            main_node_id: Some("n-vless".to_string()),
            dns_local_server: local_dns.to_string(),
            dns_remote_server: "https://1.1.1.1/dns-query".to_string(),
            dns_strategy: "prefer_ipv4".to_string(),
            dns_fake_ip: fake_ip,
            ..Default::default()
        };
        let compiled = SingBox114Compiler::compile(&CompileInput {
            nodes: &nodes,
            rules: &rules,
            app_rules: &[],
            extra_ports: &extra_ports,
            settings: &settings,
            control_secret: "strict-check",
            cache_db_path: None,
            rule_cache: None,
            platform: CompilePlatform::Windows,
        })
        .expect("compile");

        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(
            report.ok,
            "sing-box v1.14 check failed for mode {:?}: stderr={} stdout={}",
            mode, report.stderr, report.stdout
        );
        assert!(
            report.deprecated_warnings.is_empty(),
            "Found deprecation warnings in mode {:?}: {:?}",
            mode,
            report.deprecated_warnings
        );
    }
}

#[tokio::test]
async fn test_real_singbox_multiport_hotswitch_and_bad_config_rollback() {
    let Some(sb) = find_test_singbox() else {
        eprintln!("Skipping live sing-box multiport/hotswitch test (set BYPAX_TEST_SINGBOX)");
        return;
    };

    let p1 = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let p2 = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ctrl_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let nodes = build_all_8_protocol_nodes();
    let mut rules = default_simple_rules();
    rules[0].target = "auto:US".to_string();

    let settings = AppSettings {
        route_mode: RouteMode::Rule,
        main_node_id: Some("n-vless".to_string()),
        mixed_port: p1,
        control_port: ctrl_port,
        ..Default::default()
    };
    let extra_ports = vec![InboundPort {
        id: format!("in-{}", p2),
        port: p2,
        note: "Dedicated CLI".to_string(),
        note_en: "Dedicated CLI".to_string(),
        target: "n-hy2".to_string(),
        enabled: true,
        allow_lan: false,
    }];

    let tmp = tempfile::tempdir().expect("tempdir");
    let cache_db = tmp.path().join("cache.db");
    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &rules,
        app_rules: &[],
        extra_ports: &extra_ports,
        settings: &settings,
        control_secret: "e2e-secret",
        cache_db_path: Some(&cache_db),
        rule_cache: None,
        platform: CompilePlatform::Windows,
    })
    .expect("compile");

    let logs = Arc::new(Mutex::new(LogRing::new(500)));
    let mut supervisor = CoreSupervisor::new(tmp.path().to_path_buf(), logs);

    let report = supervisor
        .apply_config(&sb, compiled.config.clone())
        .expect("start core");
    assert!(report.ok);
    let initial_pid = supervisor.require_running_pid().expect("running pid");

    let client = ControlClient::new(ctrl_port, "e2e-secret").expect("client");
    let mut online = false;
    for _ in 0..40 {
        if client.get_version().await.is_ok() {
            online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(online, "sing-box Clash API did not come online");

    assert!(tokio::net::TcpStream::connect(("127.0.0.1", p1))
        .await
        .is_ok());
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", p2))
        .await
        .is_ok());

    assert_eq!(client.get_proxy_now("main-exit").await.unwrap(), "n-vless");
    client
        .select_proxy("main-exit", "n-hy2")
        .await
        .expect("hot switch");
    assert_eq!(client.get_proxy_now("main-exit").await.unwrap(), "n-hy2");
    assert_eq!(supervisor.require_running_pid().unwrap(), initial_pid);

    assert_eq!(client.get_mode().await.unwrap(), "rule");
    client.set_mode("direct").await.expect("set direct mode");
    assert_eq!(client.get_mode().await.unwrap(), "direct");
    client.set_mode("global").await.expect("set global mode");
    assert_eq!(client.get_mode().await.unwrap(), "global");
    client.set_mode("rule").await.expect("set rule mode");
    assert_eq!(client.get_mode().await.unwrap(), "rule");
    assert_eq!(supervisor.require_running_pid().unwrap(), initial_pid);

    let mut bad_cfg = compiled.config.clone();
    bad_cfg["outbounds"] =
        serde_json::json!([{ "type": "nonexistent_proto_xyz", "tag": "broken" }]);
    let bad_report = supervisor.apply_config(&sb, bad_cfg).expect("apply bad");
    assert!(!bad_report.ok);
    assert_eq!(
        supervisor.require_running_pid().unwrap(),
        initial_pid,
        "Bad config must NOT interrupt active sing-box process"
    );

    let test_nodes = vec![nodes[0].clone()];
    let _res = batch_real_delay(&sb, &test_nodes, "http://127.0.0.1:1/204", 600, 2)
        .await
        .expect("batch real delay");
    assert_eq!(supervisor.require_running_pid().unwrap(), initial_pid);

    supervisor.stop();
    assert!(!supervisor.is_running());
}

#[test]
fn test_singbox_log_level_and_inbound_label_parsing() {
    use bypax_core::control::normalize_inbound_label;
    use bypax_core::supervisor::parse_singbox_log_line;

    let (lvl, msg) = parse_singbox_log_line(
        "+0800 2026-11-26 00:46:45 INFO inbound/mixed[in-20808]: tcp server started",
    );
    assert_eq!(lvl, "INFO");
    assert_eq!(msg, "inbound/mixed[in-20808]: tcp server started");

    let (lvl2, msg2) = parse_singbox_log_line(
        "\x1b[31m+0800 2026-11-26 00:46:45 ERROR outbound/vless: dial tcp timeout\x1b[0m",
    );
    assert_eq!(lvl2, "ERROR");
    assert_eq!(msg2, "outbound/vless: dial tcp timeout");

    assert_eq!(normalize_inbound_label("mixed/in-20808"), ":20808");
    assert_eq!(normalize_inbound_label("in-10809"), ":10809");
    assert_eq!(normalize_inbound_label("tun/tun-in"), "TUN");
    assert_eq!(normalize_inbound_label("socks/app-proxy-in"), "App Proxy");
}

#[test]
fn test_route_eval_history_platform_and_extended_dns_v114_check() {
    use bypax_core::model::{ConnectionHistoryRecord, DnsHostEntry, DnsRuleItem};
    use bypax_core::route_eval::{evaluate_route_target, normalize_test_target};
    use bypax_core::storage::{classify_platform, extract_host, rule_preset_catalog};

    assert_eq!(
        normalize_test_target("https://api.openai.com:443/v1/chat"),
        "api.openai.com"
    );
    assert_eq!(normalize_test_target("192.168.1.10:8080"), "192.168.1.10");
    assert_eq!(normalize_test_target("[2001:db8::1]:443"), "2001:db8::1");
    assert_eq!(
        extract_host("rr1---sn.googlevideo.com:443"),
        "rr1---sn.googlevideo.com"
    );
    assert_eq!(
        classify_platform("rr1---sn.googlevideo.com", "chrome.exe"),
        "YouTube"
    );
    assert_eq!(
        classify_platform("api.openai.com", "node.exe"),
        "OpenAI / ChatGPT"
    );
    assert_eq!(
        classify_platform("sub.custom-site.co.uk", "chrome.exe"),
        "custom-site.co.uk"
    );
    assert!(rule_preset_catalog().len() >= 25);

    let nodes = build_all_8_protocol_nodes();
    let rules = default_simple_rules();
    let settings = AppSettings {
        main_node_id: Some("n-vless".to_string()),
        dns_local_server: "https://dns.alidns.com/dns-query".to_string(),
        dns_remote_server: "https://1.1.1.1/dns-query".to_string(),
        dns_bootstrap_server: "223.5.5.5".to_string(),
        dns_remote_detour: "main".to_string(),
        dns_fake_ip: true,
        dns_reverse_mapping: true,
        dns_hosts: vec![DnsHostEntry {
            domain: "nas.internal".to_string(),
            ips: vec!["192.168.1.50".to_string()],
        }],
        dns_custom_rules: vec![DnsRuleItem {
            id: "dr-1".to_string(),
            title: "Block tracker".to_string(),
            domains: vec!["tracker.example".to_string()],
            rule_set: None,
            server: "reject".to_string(),
            enabled: true,
        }],
        tun_enabled: true,
        tun_stack: "mixed".to_string(),
        tun_mtu: 9000,
        log_level: "debug".to_string(),
        ..Default::default()
    };

    let res_cn = evaluate_route_target(
        "https://www.baidu.com/s?wd=1",
        None,
        &settings,
        &rules,
        &nodes,
        None,
        None,
    );
    assert_eq!(res_cn.matched_rule_id.as_deref(), Some("classic-geosite-cn"));
    assert_eq!(res_cn.target, "direct");

    let res_overseas = evaluate_route_target(
        "https://chatgpt.com/c/123",
        None,
        &settings,
        &rules,
        &nodes,
        None,
        None,
    );
    assert_eq!(res_overseas.matched_rule_id, None);
    assert_eq!(res_overseas.target, "main");
    assert_eq!(res_overseas.dns_server, "dns-fakeip");

    let res_lan = evaluate_route_target(
        "192.168.1.5:80",
        None,
        &settings,
        &rules,
        &nodes,
        None,
        None,
    );
    assert!(res_lan.is_private_ip);
    assert_eq!(res_lan.target, "direct");

    let res_host =
        evaluate_route_target("nas.internal", None, &settings, &rules, &nodes, None, None);
    assert_eq!(res_host.dns_server, "dns-hosts");

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut store = Store::open(&tmp.path().join("hist.db")).expect("open");
    let recs = vec![
        ConnectionHistoryRecord {
            id: "c1".to_string(),
            process: "chrome.exe".to_string(),
            destination: "rr1.googlevideo.com:443".to_string(),
            host: "rr1.googlevideo.com".to_string(),
            platform: "YouTube".to_string(),
            inbound: ":10808".to_string(),
            rule: "final".to_string(),
            chain: vec!["n-vless".to_string(), "main-exit".to_string()],
            upload_bytes: 1000,
            download_bytes: 500_000,
            started_at: "2026-11-25T10:00:00Z".to_string(),
            closed_at: "2026-11-25T10:01:00Z".to_string(),
        },
        ConnectionHistoryRecord {
            id: "c2".to_string(),
            process: "code.exe".to_string(),
            destination: "api.github.com:443".to_string(),
            host: "api.github.com".to_string(),
            platform: "GitHub".to_string(),
            inbound: ":10808".to_string(),
            rule: "r-dev".to_string(),
            chain: vec!["n-vless".to_string(), "main-exit".to_string()],
            upload_bytes: 5000,
            download_bytes: 20_000,
            started_at: "2026-11-25T10:02:00Z".to_string(),
            closed_at: "2026-11-25T10:03:00Z".to_string(),
        },
    ];
    store
        .insert_connection_history(&recs)
        .expect("insert history");
    let (page_items, total) = store.query_connection_history("", 1, 10).expect("query");
    assert_eq!(total, 2);
    assert_eq!(page_items[0].id, "c2");

    let stats = store.query_platform_traffic(None).expect("stats");
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[0].platform, "YouTube");
    assert_eq!(stats[0].total_bytes, 501_000);

    if let Some(sb) = find_test_singbox() {
        let compiled = SingBox114Compiler::compile(&CompileInput {
            nodes: &nodes,
            rules: &rules,
            app_rules: &[],
            extra_ports: &[],
            settings: &settings,
            control_secret: "strict-ext",
            cache_db_path: None,
            rule_cache: None,
            platform: CompilePlatform::Windows,
        })
        .expect("compile extended");
        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(report.ok, "extended v1.14 check failed: {}", report.stderr);
        assert!(
            report.deprecated_warnings.is_empty(),
            "unexpected deprecation warnings: {:?}",
            report.deprecated_warnings
        );
    }
}

#[tokio::test]
async fn test_unified_rtt_strips_first_handshake_overhead() {
    use bypax_core::tester::batch_real_delay_with_progress;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as AsyncTcpListener;

    let Some(sb) = find_test_singbox() else {
        eprintln!("Skipping unified RTT test (set BYPAX_TEST_SINGBOX)");
        return;
    };

    let listener = AsyncTcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mock_port = listener.local_addr().unwrap().port();
    let server_task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let Ok(n) = socket.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.starts_with("CONNECT ") {
                    tokio::time::sleep(Duration::from_millis(240)).await;
                    if socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                    while let Ok(rn) = socket.read(&mut buf).await {
                        if rn == 0 {
                            break;
                        }
                        if socket
                            .write_all(
                                b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            });
        }
    });

    let node = NodeIR::new(
        "n-mock-http",
        Protocol::Http,
        "Mock-HTTP-Node",
        "127.0.0.1",
        mock_port,
        "Test",
    );
    let test_url = "http://probe.test/generate_204";

    let cold = batch_real_delay_with_progress(
        &sb,
        std::slice::from_ref(&node),
        test_url,
        3000,
        2,
        None,
        false,
        |_| {},
    )
    .await
    .expect("cold test");
    let cold_ms = cold[0]
        .delay_ms
        .unwrap_or_else(|| panic!("cold delay should succeed, got: {:?}", cold[0]));

    let unified = batch_real_delay_with_progress(
        &sb,
        std::slice::from_ref(&node),
        test_url,
        3000,
        2,
        None,
        true,
        |_| {},
    )
    .await
    .expect("unified test");
    let unified_ms = unified[0]
        .delay_ms
        .unwrap_or_else(|| panic!("unified delay should succeed, got: {:?}", unified[0]));

    server_task.abort();

    assert!(
        cold_ms >= 200,
        "Expected cold delay >= 200ms, got {}ms",
        cold_ms
    );
    assert!(
        unified_ms < 120,
        "Expected unified strip-handshake RTT < 120ms, got {}ms (cold={}ms)",
        unified_ms,
        cold_ms
    );
}

#[test]
fn test_autostart_defaults_off_and_command_format() {
    use bypax_core::autostart::{launch_command_for_exe, AUTOSTART_ARG};

    let defaults = AppSettings::default();
    assert!(
        !defaults.launch_at_login,
        "launch_at_login must default to false"
    );

    let cmd = launch_command_for_exe(std::path::Path::new(r"C:\Program Files\Bypax\bypax.exe"));
    assert_eq!(
        cmd,
        format!("\"C:\\Program Files\\Bypax\\bypax.exe\" {}", AUTOSTART_ARG)
    );
}

#[test]
fn test_updater_staging_swap_preserves_portable_data_and_results() -> Result<()> {
    use bypax_core::updater::{
        ensure_target_dir_writable, extract_zip_safely, parse_app_release_json, parse_sha256sums,
        replace_binary_atomically, take_last_update_result, validate_pe_header, UpdateApplyResult,
    };
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let tmp = tempfile::tempdir()?;
    let install_dir = tmp.path().join("bypax-portable");
    let data_dir = install_dir.join("bypax-data");
    std::fs::create_dir_all(&data_dir)?;
    ensure_target_dir_writable(&install_dir)?;

    let db_file = data_dir.join("bypax.db");
    let portable_marker = install_dir.join("portable.json");
    let target_exe = install_dir.join("bypax.exe");
    std::fs::write(&db_file, b"precious-user-sqlite-data")?;
    std::fs::write(&portable_marker, b"{\"portable\":true}\n")?;
    std::fs::write(&target_exe, b"old-bypax-v0.1.0")?;

    let mut fake_pe = vec![0u8; 72 * 1024];
    fake_pe[0..2].copy_from_slice(b"MZ");
    let pe_off: u32 = 128;
    fake_pe[60..64].copy_from_slice(&pe_off.to_le_bytes());
    fake_pe[128..132].copy_from_slice(b"PE\0\0");
    fake_pe[512..523].copy_from_slice(b"BYPAX-0.2.0");

    let zip_path = tmp.path().join("bypax-v0.2.0-x86_64-windows-portable.zip");
    {
        let f = std::fs::File::create(&zip_path)?;
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zw.start_file("bypax.exe", opts)?;
        zw.write_all(&fake_pe)?;
        zw.start_file("portable.json", opts)?;
        zw.write_all(b"{\"portable\":false}")?;
        zw.start_file("bypax-data/bypax.db", opts)?;
        zw.write_all(b"corrupted-overwrite")?;
        zw.finish()?;
    }

    let zip_bytes = std::fs::read(&zip_path)?;
    let zip_hash = hex::encode(Sha256::digest(&zip_bytes));
    let sums = format!("{}  bypax-v0.2.0-x86_64-windows-portable.zip\n", zip_hash);
    assert_eq!(
        parse_sha256sums(&sums, "bypax-v0.2.0-x86_64-windows-portable.zip").as_deref(),
        Some(zip_hash.as_str())
    );

    let staged_dir = tmp.path().join("staged");
    extract_zip_safely(&zip_path, &staged_dir)?;
    let staged_exe = staged_dir.join("bypax.exe");
    validate_pe_header(&staged_exe)?;
    assert!(!staged_dir.join("portable.json").exists());
    assert!(!staged_dir.join("bypax-data").exists());

    replace_binary_atomically(&staged_exe, &target_exe)?;
    assert_eq!(std::fs::read(&target_exe)?, fake_pe);
    assert_eq!(
        std::fs::read(install_dir.join("bypax.prev.exe"))?,
        b"old-bypax-v0.1.0"
    );
    assert_eq!(std::fs::read(&db_file)?, b"precious-user-sqlite-data");
    assert_eq!(std::fs::read(&portable_marker)?, b"{\"portable\":true}\n");

    let res_path = tmp.path().join("last-update-result.json");
    let expected = UpdateApplyResult {
        success: true,
        from_version: "0.1.0".to_string(),
        to_version: "0.2.0".to_string(),
        to_tag: "v0.2.0".to_string(),
        error: None,
        applied_at: "2026-11-26T08:00:00Z".to_string(),
    };
    std::fs::write(&res_path, serde_json::to_string(&expected)?)?;
    assert_eq!(take_last_update_result(&res_path), Some(expected));
    assert_eq!(take_last_update_result(&res_path), None);

    let api_json = r#"{
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/Nexusyyan/bypax/releases/tag/v0.2.0",
        "assets": [
            {
                "name": "bypax-v0.2.0-x86_64-windows.exe",
                "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-x86_64-windows.exe",
                "size": 7000000
            },
            {
                "name": "bypax-v0.2.0-aarch64-macos.dmg",
                "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-aarch64-macos.dmg",
                "size": 19000000
            },
            {
                "name": "bypax-v0.2.0-x86_64-macos.dmg",
                "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/bypax-v0.2.0-x86_64-macos.dmg",
                "size": 19500000
            },
            {
                "name": "SHA256SUMS.txt",
                "browser_download_url": "https://github.com/Nexusyyan/bypax/releases/download/v0.2.0/SHA256SUMS.txt",
                "size": 256
            }
        ]
    }"#;
    let rep = parse_app_release_json("0.1.0", api_json, "proxy:bypax", true, true)?;
    assert!(rep.update_available);
    if cfg!(target_os = "windows") {
        assert_eq!(rep.selected_asset_kind.as_deref(), Some("standalone_exe"));
        assert!(rep.in_app_update_supported);
    } else if cfg!(target_os = "macos") {
        assert_eq!(rep.selected_asset_kind.as_deref(), Some("macos_dmg"));
        assert!(rep.in_app_update_supported);
    }

    let mac_arm_rep = bypax_core::updater::parse_app_release_json_for_platform(
        "0.1.0",
        api_json,
        "proxy:bypax",
        false,
        false,
        bypax_core::updater::UpdatePlatform::MacosArm64,
        true,
    )?;
    assert_eq!(
        mac_arm_rep.selected_asset_name.as_deref(),
        Some("bypax-v0.2.0-aarch64-macos.dmg")
    );
    assert_eq!(mac_arm_rep.selected_asset_kind.as_deref(), Some("macos_dmg"));
    assert!(mac_arm_rep.in_app_update_supported);

    let mac_x64_rep = bypax_core::updater::parse_app_release_json_for_platform(
        "0.1.0",
        api_json,
        "proxy:bypax",
        false,
        false,
        bypax_core::updater::UpdatePlatform::MacosX64,
        true,
    )?;
    assert_eq!(
        mac_x64_rep.selected_asset_name.as_deref(),
        Some("bypax-v0.2.0-x86_64-macos.dmg")
    );
    assert!(mac_x64_rep.in_app_update_supported);

    Ok(())
}

#[test]
fn test_hysteria2_parsers_obfs_mport_and_singbox_compile() {
    use bypax_core::compiler::compile_proxy_outbound;

    // 1. sing-box JSON with salamander obfs + single port AND port-hopping-only entry
    let sb_json = r#"{
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "JP-HY2-Obfs",
                "server": "jp-hy2.example.com",
                "server_port": 22371,
                "password": "secret-hy2-password",
                "up_mbps": 50,
                "down_mbps": 200,
                "obfs": {
                    "type": "salamander",
                    "password": "salamander-obfs-key"
                },
                "tls": {
                    "enabled": true,
                    "server_name": "jp-hy2.example.com",
                    "alpn": ["h3"]
                }
            },
            {
                "type": "hysteria2",
                "tag": "US-HY2-Hop",
                "server": "us-hy2.example.com",
                "server_ports": ["20000:30000", "40000"],
                "hop_interval": "30s",
                "password": "hop-password",
                "tls": {
                    "enabled": true,
                    "server_name": "us-hy2.example.com",
                    "insecure": true
                }
            }
        ]
    }"#;
    let parsed_json = parse_payload(sb_json, "JsonSub").expect("parse sing-box json");
    assert_eq!(parsed_json.nodes.len(), 2);

    let j0 = &parsed_json.nodes[0];
    assert_eq!(j0.protocol, Protocol::Hysteria2);
    assert_eq!(j0.port, 22371);
    assert_eq!(j0.password.as_deref(), Some("secret-hy2-password"));
    assert_eq!(j0.obfs_type.as_deref(), Some("salamander"));
    assert_eq!(j0.obfs_password.as_deref(), Some("salamander-obfs-key"));
    assert_eq!(j0.up_mbps, Some(50));
    assert_eq!(j0.down_mbps, Some(200));
    assert_eq!(
        j0.tls.as_ref().map(|t| t.alpn.as_slice()),
        Some(&["h3".to_string()][..])
    );

    let j1 = &parsed_json.nodes[1];
    assert_eq!(j1.port, 20000);
    assert_eq!(
        j1.server_ports,
        vec!["20000:30000".to_string(), "40000:40000".to_string()]
    );
    assert_eq!(j1.hop_interval.as_deref(), Some("30s"));

    // 2. Clash YAML with obfs, obfs-password, ports, hop-interval, bandwidth units, alpn, and auth fallback
    let clash_yaml = r#"
proxies:
  - name: "SG-Clash-HY2"
    type: hysteria2
    server: sg-hy2.example.com
    port: 443
    ports: "20000-30000,40000"
    hop-interval: 30
    auth: "clash-auth-pw"
    up: "80 Mbps"
    down: "1 Gbps"
    obfs: salamander
    obfs-password: "clash-obfs-password"
    sni: sg-hy2.example.com
    skip-cert-verify: true
    client-fingerprint: chrome
    alpn:
      - h3
"#;
    let parsed_yaml = parse_payload(clash_yaml, "ClashSub").expect("parse clash yaml");
    assert_eq!(parsed_yaml.nodes.len(), 1);
    let y0 = &parsed_yaml.nodes[0];
    assert_eq!(y0.protocol, Protocol::Hysteria2);
    assert_eq!(y0.password.as_deref(), Some("clash-auth-pw"));
    assert_eq!(y0.obfs_type.as_deref(), Some("salamander"));
    assert_eq!(y0.obfs_password.as_deref(), Some("clash-obfs-password"));
    assert_eq!(y0.up_mbps, Some(80));
    assert_eq!(y0.down_mbps, Some(1000));
    assert_eq!(
        y0.server_ports,
        vec!["20000:30000".to_string(), "40000:40000".to_string()]
    );
    assert_eq!(y0.hop_interval.as_deref(), Some("30s"));
    assert_eq!(y0.tls.as_ref().map(|t| t.insecure), Some(true));
    assert_eq!(
        y0.tls.as_ref().map(|t| t.alpn.as_slice()),
        Some(&["h3".to_string()][..])
    );

    // 3. hy2:// and hysteria2:// URIs with user:pass auth, obfs, mport, and inline port range
    let uri_batch = [
        "hy2://user1:pass%3A2@hk-hy2.example.com:8443/?obfs=salamander&obfs-password=uri-obfs-pw&mport=25000-26000,27000&hop-interval=45&upmbps=100&downmbps=500&sni=hk.example.com&alpn=h3&insecure=1#HK-HY2-URI",
        "hysteria2://plainpw@uk-hy2.example.com:30000-31000/?sni=uk.example.com&obfs=salamander&obfs_password=inline-obfs#UK-HY2-Range",
    ]
    .join("\n");
    let parsed_uri = parse_payload(&uri_batch, "UriSub").expect("parse hy2 uris");
    assert_eq!(parsed_uri.nodes.len(), 2);

    let u0 = &parsed_uri.nodes[0];
    assert_eq!(u0.password.as_deref(), Some("user1:pass:2"));
    assert_eq!(u0.obfs_type.as_deref(), Some("salamander"));
    assert_eq!(u0.obfs_password.as_deref(), Some("uri-obfs-pw"));
    assert_eq!(
        u0.server_ports,
        vec!["25000:26000".to_string(), "27000:27000".to_string()]
    );
    assert_eq!(u0.hop_interval.as_deref(), Some("45s"));
    assert_eq!(u0.up_mbps, Some(100));
    assert_eq!(u0.down_mbps, Some(500));
    assert_eq!(u0.tls.as_ref().map(|t| t.insecure), Some(true));

    let u1 = &parsed_uri.nodes[1];
    assert_eq!(u1.port, 30000);
    assert_eq!(u1.server_ports, vec!["30000:31000".to_string()]);
    assert_eq!(u1.obfs_type.as_deref(), Some("salamander"));
    assert_eq!(u1.obfs_password.as_deref(), Some("inline-obfs"));

    // 4. Verify compiled sing-box v1.14 outbounds preserve obfs/server_ports and omit utls on QUIC
    let c_obfs = compile_proxy_outbound(j0);
    assert_eq!(c_obfs["obfs"]["type"], "salamander");
    assert_eq!(c_obfs["obfs"]["password"], "salamander-obfs-key");
    assert_eq!(c_obfs["server_port"], 22371);
    assert!(c_obfs.get("server_ports").is_none());

    let c_yaml = compile_proxy_outbound(y0);
    assert!(c_yaml.get("server_port").is_none());
    assert_eq!(
        c_yaml["server_ports"],
        serde_json::json!(["20000:30000", "40000:40000"])
    );
    assert_eq!(c_yaml["hop_interval"], "30s");
    assert_eq!(c_yaml["obfs"]["type"], "salamander");
    assert_eq!(c_yaml["obfs"]["password"], "clash-obfs-password");
    assert!(
        c_yaml["tls"].get("utls").is_none(),
        "QUIC hysteria2 outbound must not emit tls.utls"
    );

    // 5. Real sing-box v1.14 check -c validation across all parsed HY2 variants
    if let Some(sb) = find_test_singbox() {
        let mut all_hy2 = Vec::new();
        all_hy2.extend(parsed_json.nodes);
        all_hy2.extend(parsed_yaml.nodes);
        all_hy2.extend(parsed_uri.nodes);
        let settings = AppSettings {
            main_node_id: Some(all_hy2[0].id.clone()),
            ..Default::default()
        };
        let mut rules = default_simple_rules();
        rules[0].target = "auto:ALL".to_string();
        let compiled = SingBox114Compiler::compile(&CompileInput {
            nodes: &all_hy2,
            rules: &rules,
            app_rules: &[],
            extra_ports: &[],
            settings: &settings,
            control_secret: "hy2-check",
            cache_db_path: None,
            rule_cache: None,
            platform: CompilePlatform::Windows,
        })
        .expect("compile hy2 variants");

        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(
            report.ok,
            "sing-box check failed on compiled HY2 outbounds: stderr={} stdout={}",
            report.stderr, report.stdout
        );
        assert!(
            report.deprecated_warnings.is_empty(),
            "Unexpected HY2 deprecation warnings: {:?}",
            report.deprecated_warnings
        );
    }
}

#[test]
fn test_cgnat_mesh_vpn_bypass_compiler_dns_and_rule_set_mirrors() {
    use bypax_core::netguard::DEFAULT_BYPASS_LIST;
    use bypax_core::route_eval::evaluate_route_target;
    use bypax_core::rule_cache::default_rule_set_urls;

    // 1. Windows ProxyOverride must cover RFC 6598 100.64.0.0/10 exactly, link-local,
    // and LAN/mesh internal domains while remaining well below WinINet's 2048-char limit.
    assert!(DEFAULT_BYPASS_LIST.len() < 1500);
    for octet in 64..=127 {
        assert!(
            DEFAULT_BYPASS_LIST.contains(&format!("100.{}.*", octet)),
            "Missing CGNAT octet 100.{}.* in DEFAULT_BYPASS_LIST",
            octet
        );
    }
    assert!(!DEFAULT_BYPASS_LIST.contains("100.63.*"));
    assert!(!DEFAULT_BYPASS_LIST.contains("100.128.*"));
    for suffix in [
        "169.254.*",
        "*.local",
        "*.lan",
        "*.home.arpa",
        "*.internal",
        "*.ts.net",
        "*.netbird.selfhosted",
        "*.netbird.cloud",
    ] {
        assert!(
            DEFAULT_BYPASS_LIST.contains(suffix),
            "Missing {} in DEFAULT_BYPASS_LIST",
            suffix
        );
    }

    // 2. Service GeoIP tags must include MetaCubeX meta-rules-dat@sing mirror fallback.
    let tg_urls = default_rule_set_urls("geoip-telegram");
    assert!(
        tg_urls
            .iter()
            .any(|u| u.contains("MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs")),
        "geoip-telegram URLs missing MetaCubeX mirror: {:?}",
        tg_urls
    );
    let google_urls = default_rule_set_urls("geoip-google");
    assert!(
        google_urls
            .iter()
            .any(|u| u.contains("MetaCubeX/meta-rules-dat@sing/geo/geoip/google.srs")),
        "geoip-google URLs missing MetaCubeX mirror: {:?}",
        google_urls
    );

    // 3. Compiler emits explicit 100.64.0.0/10 & mesh-domain direct rules plus dns-system
    // and routes geosite-private/geosite-cn cleanly even when FakeIP is enabled.
    let nodes = build_all_8_protocol_nodes();
    let rules = default_simple_rules();
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("geosite-private.srs"), b"stub").expect("write private stub");
    std::fs::write(tmp.path().join("geosite-cn.srs"), b"stub").expect("write cn stub");
    let cache = RuleCache::new(tmp.path().to_path_buf());
    let settings = AppSettings {
        main_node_id: Some("n-vless".to_string()),
        dns_fake_ip: true,
        ..Default::default()
    };

    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: &nodes,
        rules: &rules,
        app_rules: &[],
        extra_ports: &[],
        settings: &settings,
        control_secret: "cgnat-test",
        cache_db_path: None,
        rule_cache: Some(&cache),
        platform: CompilePlatform::Windows,
    })
    .expect("compile cgnat/mesh");

    let route_rules = compiled.config["route"]["rules"].as_array().unwrap();
    let cgnat_pos = route_rules
        .iter()
        .position(|r| {
            r["ip_cidr"] == serde_json::json!(["100.64.0.0/10"]) && r["outbound"] == "direct"
        })
        .expect("route.rules must contain explicit 100.64.0.0/10 -> direct");
    let mesh_pos = route_rules
        .iter()
        .position(|r| {
            r["outbound"] == "direct"
                && r["domain_suffix"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|v| v == "netbird.selfhosted"))
        })
        .expect("route.rules must contain mesh/local domain_suffix -> direct");
    let global_pos = route_rules
        .iter()
        .position(|r| r["clash_mode"] == "global")
        .expect("clash_mode global must exist");
    assert!(cgnat_pos < global_pos);
    assert!(mesh_pos < global_pos);

    let dns_servers = compiled.config["dns"]["servers"].as_array().unwrap();
    assert!(dns_servers
        .iter()
        .any(|s| s["tag"] == "dns-system" && s["type"] == "local"));

    let dns_rules = compiled.config["dns"]["rules"].as_array().unwrap();
    let fakeip_pos = dns_rules
        .iter()
        .position(|r| r["server"] == "dns-fakeip")
        .expect("dns-fakeip rule must exist");
    let dns_mesh_pos = dns_rules
        .iter()
        .position(|r| {
            r["server"] == "dns-system"
                && r["domain_suffix"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|v| v == "netbird.selfhosted"))
        })
        .expect("dns.rules must route mesh/local suffixes to dns-system");
    let dns_priv_pos = dns_rules
        .iter()
        .position(|r| {
            r["server"] == "dns-system" && r["rule_set"] == serde_json::json!(["geosite-private"])
        })
        .expect("dns.rules must route geosite-private to dns-system");
    let dns_cn_pos = dns_rules
        .iter()
        .position(|r| {
            r["server"] == "dns-local" && r["rule_set"] == serde_json::json!(["geosite-cn"])
        })
        .expect("dns.rules must route geosite-cn to dns-local even with FakeIP enabled");
    assert!(dns_mesh_pos < fakeip_pos);
    assert!(dns_priv_pos < fakeip_pos);
    assert!(dns_cn_pos < fakeip_pos);

    // 4. Route evaluator matches CGNAT IPs and NetBird/Tailscale domains consistently.
    let res_cgnat = evaluate_route_target(
        "100.64.0.101:18789",
        None,
        &settings,
        &rules,
        &nodes,
        None,
        None,
    );
    assert!(res_cgnat.is_private_ip);
    assert_eq!(res_cgnat.target, "direct");
    assert_eq!(res_cgnat.matched_by, "ip_cidr:100.64.0.0/10");

    let mut global_settings = settings.clone();
    global_settings.route_mode = RouteMode::Global;
    let res_mesh = evaluate_route_target(
        "peer.netbird.selfhosted",
        None,
        &global_settings,
        &rules,
        &nodes,
        None,
        None,
    );
    assert_eq!(res_mesh.target, "direct");
    assert_eq!(res_mesh.dns_server, "dns-system");
    assert_eq!(res_mesh.matched_by, "private_domain_suffix:netbird.selfhosted");

    // 5. Real sing-box v1.14 check -c validation (without stub files).
    if let Some(sb) = find_test_singbox() {
        let compiled_real = SingBox114Compiler::compile(&CompileInput {
            nodes: &nodes,
            rules: &rules,
            app_rules: &[],
            extra_ports: &[],
            settings: &settings,
            control_secret: "cgnat-real-check",
            cache_db_path: None,
            rule_cache: None,
            platform: CompilePlatform::Windows,
        })
        .expect("compile for sing-box check");
        let report =
            SingBox114Compiler::preflight_check(&sb, &compiled_real.config).expect("preflight");
        assert!(
            report.ok,
            "sing-box check failed: stderr={} stdout={}",
            report.stderr, report.stdout
        );
        assert!(
            report.deprecated_warnings.is_empty(),
            "Unexpected deprecation warnings: {:?}",
            report.deprecated_warnings
        );
    }
}

#[test]
fn test_tun_route_exclude_subtracts_tun_subnet_and_fakeip_pool() {
    let node = NodeIR::new(
        "n-tuic-1",
        Protocol::Tuic,
        "AU-Test",
        "example.com",
        443,
        "Test",
    );
    let settings = AppSettings {
        main_node_id: Some(node.id.clone()),
        app_proxy_enabled: true,
        tun_enabled: false,
        tun_inet4_address: "172.19.0.1/30".to_string(),
        dns_fake_ip: true,
        dns_fake_ip_inet4: "198.18.0.0/15".to_string(),
        dns_fake_ip_inet6: "fc00::/18".to_string(),
        tun_route_exclude_cidrs: vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
            "198.19.0.0/16".to_string(),
            "fc00::/7".to_string(),
        ],
        ..Default::default()
    };

    let compiled = SingBox114Compiler::compile(&CompileInput {
        nodes: std::slice::from_ref(&node),
        rules: &[],
        app_rules: &[],
        extra_ports: &[],
        settings: &settings,
        control_secret: "tun-cidr-test",
        cache_db_path: None,
        rule_cache: None,
        platform: CompilePlatform::MacOs,
    })
    .expect("compile macOS utun config");

    let tun = compiled.config["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["tag"] == "tun-in")
        .expect("tun-in present");
    let excludes: Vec<String> = tun["route_exclude_address"]
        .as_array()
        .expect("route_exclude_address array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let v4_contains = |cidr: &str, ip: &str| -> bool {
        let Some((net_s, pfx_s)) = cidr.split_once('/') else {
            return false;
        };
        let (Ok(net_ip), Ok(pfx), Ok(target)) = (
            net_s.parse::<std::net::Ipv4Addr>(),
            pfx_s.parse::<u8>(),
            ip.parse::<std::net::Ipv4Addr>(),
        ) else {
            return false;
        };
        let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
        (u32::from(target) & mask) == (u32::from(net_ip) & mask)
    };

    // TUN host (172.19.0.1) and NAT peer (172.19.0.2) MUST NOT be excluded!
    assert!(
        !excludes.iter().any(|c| v4_contains(c, "172.19.0.1")),
        "172.19.0.1 must not be in route_exclude_address: {:?}",
        excludes
    );
    assert!(
        !excludes.iter().any(|c| v4_contains(c, "172.19.0.2")),
        "172.19.0.2 must not be in route_exclude_address: {:?}",
        excludes
    );
    // Neighboring RFC1918 172.16.0.0/12 addresses MUST STILL be excluded!
    assert!(excludes.iter().any(|c| v4_contains(c, "172.16.0.1")));
    assert!(excludes.iter().any(|c| v4_contains(c, "172.19.0.4")));
    assert!(excludes.iter().any(|c| v4_contains(c, "172.31.255.254")));
    // FakeIP pool (198.18.0.0/15, including 198.19.x.x) MUST NOT be excluded!
    assert!(
        !excludes.iter().any(|c| v4_contains(c, "198.19.0.1")),
        "FakeIP 198.19.0.1 must not be excluded: {:?}",
        excludes
    );

    if let Some(sb) = find_test_singbox() {
        let report = SingBox114Compiler::preflight_check(&sb, &compiled.config).expect("preflight");
        assert!(
            report.ok,
            "sing-box check failed on CIDR-subtracted tun-in: {}",
            report.stderr
        );
    }
}
