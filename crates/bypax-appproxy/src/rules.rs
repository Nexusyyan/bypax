use crate::capture::{FiveTuple, TransportProtocol};
use crate::process::{MockProcessTracker, ProcessInfo, ProcessTracker};
use bypax_core::compiler::{build_app_proxy_target_bindings, match_auto_nodes};
use bypax_core::model::{AppProxyRule, DomainOverrideAction, NodeIR, ProxyChain};
use bypax_ipc::{AppProxyRuleWire, AppProxyTargetBinding};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::RwLock;

fn default_test_port() -> u16 {
    443
}

fn default_test_protocol() -> String {
    "tcp".to_string()
}

/// Dry-run input query for GUI Drawer, CLI `ctl`, and MCP `bypax_app_test_rule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRuleTestQuery {
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub ancestor_name: Option<String>,
    #[serde(default)]
    pub ancestor_path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default = "default_test_port")]
    pub dst_port: u16,
    #[serde(default = "default_test_protocol")]
    pub protocol: String,
}

/// Structured 3-step dry-run trace aligned with `bypax-ux-spec.md` section 3.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRuleTestTrace {
    pub step1_process_match: String,
    pub step2_domain_override: String,
    pub step3_final_exit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_via_ancestor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_domain_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_override_action: Option<String>, // "proxy" | "direct" | "reject"
    pub final_action: String, // "proxy" | "direct" | "reject"
    pub final_target: String, // "follow" | "main" | "auto:US" | "node:..." | "direct" | "reject"
    pub resolved_label: String,
    pub bypassed_to_routing: bool,
}

/// Phase 1 (L4) verdict before SNI/HTTP Host inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4RouteDecision {
    Direct {
        reason: &'static str,
    },
    /// Rule itself targets `direct` but carries L7 domain overrides -> intercept TCP to sniff SNI/Host.
    InspectDirect {
        rule_id: String,
        rule_name: String,
        matched_ancestor: Option<String>,
    },
    Reject {
        rule_id: String,
        rule_name: String,
        matched_ancestor: Option<String>,
    },
    Proxy {
        rule_id: String,
        rule_name: String,
        target: String,
        auth_user: String,
        matched_ancestor: Option<String>,
    },
}

/// Phase 2 (L7) domain override verdict after TLS SNI or HTTP Host recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7DomainDecision {
    Direct {
        rule_id: String,
        rule_name: String,
        pattern: String,
    },
    Reject {
        rule_id: String,
        rule_name: String,
        pattern: String,
    },
    Proxy {
        rule_id: String,
        rule_name: String,
        pattern: String,
        target: String,
        auth_user: String,
    },
}

#[derive(Debug, Clone)]
enum DomainPattern {
    Exact(String),
    Suffix(String),
    Glob(String),
}

impl DomainPattern {
    fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            return None;
        }
        if let Some(rest) = trimmed.strip_prefix("*.") {
            if !rest.is_empty() && !rest.contains('*') && !rest.contains('?') {
                return Some(Self::Suffix(rest.to_string()));
            }
        }
        if let Some(rest) = trimmed.strip_prefix('.') {
            if !rest.is_empty() && !rest.contains('*') && !rest.contains('?') {
                return Some(Self::Suffix(rest.to_string()));
            }
        }
        if trimmed.contains('*') || trimmed.contains('?') {
            return Some(Self::Glob(trimmed));
        }
        Some(Self::Exact(trimmed))
    }

    fn matches(&self, normalized_host: &str) -> bool {
        match self {
            Self::Exact(d) => normalized_host == d,
            Self::Suffix(suffix) => {
                normalized_host == suffix
                    || (normalized_host.len() > suffix.len()
                        && normalized_host.ends_with(suffix)
                        && normalized_host.as_bytes()[normalized_host.len() - suffix.len() - 1]
                            == b'.')
            }
            Self::Glob(pat) => glob_matches(pat.as_bytes(), normalized_host.as_bytes()),
        }
    }
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

struct CompiledDomainOverride {
    raw_pattern: String,
    pattern: DomainPattern,
    action: DomainOverrideAction,
}

struct CompiledAppRule {
    id: String,
    name: String,
    process_names_lower: Vec<String>,
    path_prefixes_norm: Vec<String>,
    path_contains_norm: Vec<String>,
    mac_bundle_paths_norm: Vec<String>,
    include_children: bool,
    dst_cidrs: Vec<IpNet>,
    dst_ports: Vec<u16>,
    protocols: Vec<TransportProtocol>,
    domains: Vec<CompiledDomainOverride>,
    target: String,
    auth_user: String,
    local_action: Option<String>, // Some("direct") | Some("reject") | None (proxy)
}

impl CompiledAppRule {
    fn has_proc_criteria(&self) -> bool {
        !self.process_names_lower.is_empty()
            || !self.path_prefixes_norm.is_empty()
            || !self.path_contains_norm.is_empty()
            || !self.mac_bundle_paths_norm.is_empty()
    }
}

/// Cross-platform two-phase (L4 process tree + L7 SNI/Host override) rule engine.
pub struct RuleEngine {
    bypass_lan: bool,
    exempt_pids: RwLock<HashSet<u32>>,
    rules: Vec<CompiledAppRule>,
    lan_nets: Vec<IpNet>,
}

impl RuleEngine {
    pub fn from_rules(
        rules: &[AppProxyRule],
        bindings: &[AppProxyTargetBinding],
        bypass_lan: bool,
        exempt_pids: &[u32],
    ) -> anyhow::Result<Self> {
        let binding_map: HashMap<&str, &AppProxyTargetBinding> = bindings
            .iter()
            .map(|b| (b.target.as_str(), b))
            .collect();

        let mut enabled: Vec<&AppProxyRule> = rules.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| r.priority);

        let mut compiled = Vec::with_capacity(enabled.len());
        for rule in enabled {
            compiled.push(compile_app_rule(rule, &binding_map)?);
        }

        let mut exempt: HashSet<u32> = exempt_pids.iter().copied().filter(|&p| p != 0).collect();
        exempt.insert(std::process::id());

        let lan_nets = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "fc00::/7",
            "fe80::/10",
        ]
        .iter()
        .map(|s| s.parse::<IpNet>().expect("valid built-in CIDR"))
        .collect();

        Ok(Self {
            bypass_lan,
            exempt_pids: RwLock::new(exempt),
            rules: compiled,
            lan_nets,
        })
    }

    pub fn from_wire(
        wire_rules: &[AppProxyRuleWire],
        bindings: &[AppProxyTargetBinding],
        bypass_lan: bool,
        exempt_pids: &[u32],
    ) -> anyhow::Result<Self> {
        let domain_rules: Vec<AppProxyRule> =
            wire_rules.iter().cloned().map(AppProxyRule::from).collect();
        Self::from_rules(&domain_rules, bindings, bypass_lan, exempt_pids)
    }

    pub fn add_exempt_pid(&self, pid: u32) -> bool {
        if pid != 0 {
            if let Ok(mut guard) = self.exempt_pids.write() {
                return guard.insert(pid);
            }
        }
        false
    }

    pub fn exempt_pids_snapshot(&self) -> Vec<u32> {
        self.exempt_pids
            .read()
            .map(|g| {
                let mut v: Vec<u32> = g.iter().copied().collect();
                v.sort_unstable();
                v
            })
            .unwrap_or_default()
    }

    pub fn active_rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns the first enabled rule matching a running process (for GUI Process Picker badge).
    pub fn match_process_rule(
        &self,
        pid: u32,
        tracker: &dyn ProcessTracker,
    ) -> Option<(String, String)> {
        let chain = tracker.ancestor_chain(pid);
        for rule in &self.rules {
            if !rule.has_proc_criteria() {
                continue;
            }
            if match_process_chain(rule, &chain).is_some() {
                return Some((rule.id.clone(), rule.name.clone()));
            }
        }
        None
    }

    /// Phase 1 (L4) evaluation before SNI/Host sniffing.
    pub fn evaluate_l4(
        &self,
        pid: Option<u32>,
        tuple: &FiveTuple,
        tracker: &dyn ProcessTracker,
    ) -> L4RouteDecision {
        if is_always_direct_ip(tuple.dst_ip) {
            return L4RouteDecision::Direct {
                reason: "loopback_or_special",
            };
        }
        if let Some(p) = pid {
            if let Ok(guard) = self.exempt_pids.read() {
                if guard.contains(&p) {
                    return L4RouteDecision::Direct {
                        reason: "exempt_pid",
                    };
                }
            }
        }
        if self.bypass_lan && self.lan_nets.iter().any(|net| net.contains(&tuple.dst_ip)) {
            return L4RouteDecision::Direct { reason: "lan_cidr" };
        }

        let chain: Vec<ProcessInfo> = match pid {
            Some(p) if p != 0 => tracker.ancestor_chain(p),
            _ => Vec::new(),
        };

        for rule in &self.rules {
            let Some(matched_ancestor) = rule_matches_l4_and_proc(rule, tuple, &chain) else {
                continue;
            };
            match rule.local_action.as_deref() {
                Some("reject") => {
                    return L4RouteDecision::Reject {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        matched_ancestor,
                    };
                }
                Some("direct") => {
                    if !rule.domains.is_empty() && tuple.protocol == TransportProtocol::Tcp {
                        return L4RouteDecision::InspectDirect {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            matched_ancestor,
                        };
                    }
                    return L4RouteDecision::Direct {
                        reason: "matched_direct_rule",
                    };
                }
                _ => {
                    return L4RouteDecision::Proxy {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        target: rule.target.clone(),
                        auth_user: rule.auth_user.clone(),
                        matched_ancestor,
                    };
                }
            }
        }

        L4RouteDecision::Direct {
            reason: "default_direct",
        }
    }

    /// Phase 2 (L7) domain override evaluation after TLS SNI or HTTP Host recovery.
    pub fn evaluate_l7(
        &self,
        pid: Option<u32>,
        tuple: &FiveTuple,
        host: &str,
        tracker: &dyn ProcessTracker,
    ) -> Option<L7DomainDecision> {
        let norm_host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_host.is_empty() {
            return None;
        }
        if !self.rules.iter().any(|r| !r.domains.is_empty()) {
            return None;
        }

        let chain: Vec<ProcessInfo> = match pid {
            Some(p) if p != 0 => tracker.ancestor_chain(p),
            _ => Vec::new(),
        };

        for rule in &self.rules {
            if rule_matches_l4_and_proc(rule, tuple, &chain).is_none() {
                continue;
            }
            if let Some(ov) = rule.domains.iter().find(|d| d.pattern.matches(&norm_host)) {
                return Some(match ov.action {
                    DomainOverrideAction::Reject => L7DomainDecision::Reject {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        pattern: ov.raw_pattern.clone(),
                    },
                    DomainOverrideAction::Direct => L7DomainDecision::Direct {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        pattern: ov.raw_pattern.clone(),
                    },
                    DomainOverrideAction::Proxy => {
                        let (target, auth_user) = if rule.local_action.is_some() {
                            ("follow".to_string(), "bx_follow".to_string())
                        } else {
                            (rule.target.clone(), rule.auth_user.clone())
                        };
                        L7DomainDecision::Proxy {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            pattern: ov.raw_pattern.clone(),
                            target,
                            auth_user,
                        }
                    }
                });
            }
            // First matching process rule owns its flow; stop scanning lower-priority rules.
            break;
        }
        None
    }

    /// Returns true if the matching rule for this flow defines any domain-reject override,
    /// signalling that encrypted QUIC (`UDP/443`) should be dropped to trigger TCP SNI fallback.
    pub fn has_domain_block_rules_for_flow(
        &self,
        pid: Option<u32>,
        tuple: &FiveTuple,
        tracker: &dyn ProcessTracker,
    ) -> bool {
        let chain: Vec<ProcessInfo> = match pid {
            Some(p) if p != 0 => tracker.ancestor_chain(p),
            _ => Vec::new(),
        };
        for rule in &self.rules {
            if rule_matches_proc_and_target(rule, tuple, &chain).is_some() {
                return rule
                    .domains
                    .iter()
                    .any(|d| d.action == DomainOverrideAction::Reject);
            }
        }
        false
    }

    /// Runs a deterministic 3-step dry-run trace for GUI Drawer, CLI, and MCP tools.
    pub fn dry_run_trace(
        rules: &[AppProxyRule],
        query: &AppRuleTestQuery,
        nodes: &[NodeIR],
        chains: &[ProxyChain],
        main_node_id: Option<&str>,
        bypass_lan: bool,
    ) -> AppRuleTestTrace {
        let bindings = build_app_proxy_target_bindings(rules, nodes, chains);
        let engine = match Self::from_rules(rules, &bindings, bypass_lan, &[]) {
            Ok(e) => e,
            Err(err) => {
                return AppRuleTestTrace {
                    step1_process_match: format!("Rule compilation error: {err}"),
                    step2_domain_override: "None".to_string(),
                    step3_final_exit: "Direct".to_string(),
                    matched_rule_id: None,
                    matched_rule_name: None,
                    matched_via_ancestor: None,
                    matched_domain_pattern: None,
                    domain_override_action: None,
                    final_action: "direct".to_string(),
                    final_target: "direct".to_string(),
                    resolved_label: "Direct".to_string(),
                    bypassed_to_routing: true,
                };
            }
        };

        let protocol = match query.protocol.trim().to_ascii_lowercase().as_str() {
            "udp" | "quic" => TransportProtocol::Udp,
            _ => TransportProtocol::Tcp,
        };
        let dst_ip = query
            .dst_ip
            .as_deref()
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 78)));
        let tuple = FiveTuple {
            protocol,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port: 55000,
            dst_ip,
            dst_port: query.dst_port,
        };

        let mut procs = Vec::new();
        let mut parent_pid = 4u32;
        if let Some(anc_name) = query
            .ancestor_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            parent_pid = 41000;
            procs.push(ProcessInfo {
                pid: parent_pid,
                parent_pid: 4,
                name: anc_name.to_string(),
                exe_path: query
                    .ancestor_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            });
        }

        let proc_name = query
            .process_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                query
                    .exe_path
                    .as_deref()
                    .and_then(|p| p.rsplit(['\\', '/']).next())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            });

        let pid = if let Some(name) = proc_name {
            procs.push(ProcessInfo {
                pid: 42424,
                parent_pid,
                name,
                exe_path: query
                    .exe_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            });
            Some(42424)
        } else {
            None
        };

        let tracker = MockProcessTracker::with_processes(procs);
        let p1 = engine.evaluate_l4(pid, &tuple, &tracker);

        let (
            step1,
            mut matched_rule_id,
            mut matched_rule_name,
            matched_via_ancestor,
            mut final_action,
            mut final_target,
            mut bypassed_to_routing,
        ) = match p1 {
            L4RouteDecision::Direct { reason } => (
                format!("No App Proxy rule matched ({reason})"),
                None,
                None,
                None,
                "direct".to_string(),
                "direct".to_string(),
                true,
            ),
            L4RouteDecision::InspectDirect {
                rule_id,
                rule_name,
                matched_ancestor,
            } => {
                let via = matched_ancestor
                    .as_deref()
                    .map(|a| format!(" (via ancestor {a})"))
                    .unwrap_or_default();
                (
                    format!("Matched rule {rule_name}{via} -> inspect SNI/Host"),
                    Some(rule_id),
                    Some(rule_name),
                    matched_ancestor,
                    "direct".to_string(),
                    "direct".to_string(),
                    false,
                )
            }
            L4RouteDecision::Reject {
                rule_id,
                rule_name,
                matched_ancestor,
            } => {
                let via = matched_ancestor
                    .as_deref()
                    .map(|a| format!(" (via ancestor {a})"))
                    .unwrap_or_default();
                (
                    format!("Matched rule {rule_name}{via}"),
                    Some(rule_id),
                    Some(rule_name),
                    matched_ancestor,
                    "reject".to_string(),
                    "reject".to_string(),
                    false,
                )
            }
            L4RouteDecision::Proxy {
                rule_id,
                rule_name,
                target,
                matched_ancestor,
                ..
            } => {
                let via = matched_ancestor
                    .as_deref()
                    .map(|a| format!(" (via ancestor {a})"))
                    .unwrap_or_default();
                (
                    format!("Matched rule {rule_name}{via}"),
                    Some(rule_id),
                    Some(rule_name),
                    matched_ancestor,
                    "proxy".to_string(),
                    target,
                    false,
                )
            }
        };

        let mut step2 = "No domain override matched".to_string();
        let mut matched_domain_pattern: Option<String> = None;
        let mut domain_override_action: Option<String> = None;
        if !bypassed_to_routing {
            if let Some(host) = query
                .host
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let norm_host = normalize_host_input(host);
                if let Some(d2) = engine.evaluate_l7(pid, &tuple, &norm_host, &tracker) {
                    match d2 {
                        L7DomainDecision::Reject {
                            rule_id,
                            rule_name,
                            pattern,
                        } => {
                            step2 = format!("{norm_host} matched override {pattern} -> Reject");
                            matched_domain_pattern = Some(pattern);
                            domain_override_action = Some("reject".to_string());
                            matched_rule_id = Some(rule_id);
                            matched_rule_name = Some(rule_name);
                            final_action = "reject".to_string();
                            final_target = "reject".to_string();
                        }
                        L7DomainDecision::Direct {
                            rule_id,
                            rule_name,
                            pattern,
                        } => {
                            step2 = format!("{norm_host} matched override {pattern} -> Direct");
                            matched_domain_pattern = Some(pattern);
                            domain_override_action = Some("direct".to_string());
                            matched_rule_id = Some(rule_id);
                            matched_rule_name = Some(rule_name);
                            final_action = "direct".to_string();
                            final_target = "direct".to_string();
                        }
                        L7DomainDecision::Proxy {
                            rule_id,
                            rule_name,
                            pattern,
                            target,
                            ..
                        } => {
                            step2 = format!("{norm_host} matched override {pattern} -> Proxy");
                            matched_domain_pattern = Some(pattern);
                            domain_override_action = Some("proxy".to_string());
                            matched_rule_id = Some(rule_id);
                            matched_rule_name = Some(rule_name);
                            final_action = "proxy".to_string();
                            final_target = target;
                            bypassed_to_routing = false;
                        }
                    }
                }
            }
        }

        let resolved_label = describe_target(&final_target, nodes, chains, main_node_id);
        let step3 = if bypassed_to_routing {
            "Bypasses App Proxy (handled by Routing or Direct)".to_string()
        } else {
            resolved_label.clone()
        };

        AppRuleTestTrace {
            step1_process_match: step1,
            step2_domain_override: step2,
            step3_final_exit: step3,
            matched_rule_id,
            matched_rule_name,
            matched_via_ancestor,
            matched_domain_pattern,
            domain_override_action,
            final_action,
            final_target,
            resolved_label,
            bypassed_to_routing,
        }
    }
}

fn normalize_host_input(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(idx) = trimmed.find("://") {
        let rest = &trimmed[idx + 3..];
        let before_slash = rest.split('/').next().unwrap_or(rest);
        let host = before_slash.split(':').next().unwrap_or(before_slash);
        return host.trim_end_matches('.').to_ascii_lowercase();
    }
    let before_slash = trimmed.split('/').next().unwrap_or(trimmed);
    let host = before_slash.split(':').next().unwrap_or(before_slash);
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn describe_target(
    target: &str,
    nodes: &[NodeIR],
    chains: &[ProxyChain],
    main_node_id: Option<&str>,
) -> String {
    let main_label = main_node_id
        .and_then(|id| {
            if let Some(cid) = id.strip_prefix("chain:") {
                chains
                    .iter()
                    .find(|c| c.id == cid)
                    .map(|c| format!("Chain: {}", c.name))
            } else {
                nodes.iter().find(|n| n.id == id).map(|n| n.remark.clone())
            }
        })
        .or_else(|| nodes.first().map(|n| n.remark.clone()));

    match target {
        "direct" => "Direct".to_string(),
        "reject" => "Reject".to_string(),
        "follow" => match main_label {
            Some(name) => format!("Follow Routing (Main Exit: {name})"),
            None => "Follow Routing".to_string(),
        },
        "main" => match main_label {
            Some(name) => format!("Main Exit: {name}"),
            None => "Main Exit".to_string(),
        },
        t if t.starts_with("auto:") => {
            let matched = match_auto_nodes(t, nodes);
            let region = t.strip_prefix("auto:").unwrap_or("ALL");
            format!("Auto Region {} ({} nodes)", region, matched.len())
        }
        t if t.starts_with("chain:") => {
            let cid = t.strip_prefix("chain:").unwrap_or("");
            if let Some(chain) = chains.iter().find(|c| c.id == cid) {
                format!("Chain: {} ({} hops)", chain.name, chain.hops.len())
            } else {
                "Follow Routing (chain missing fallback)".to_string()
            }
        }
        other => {
            let clean = other.strip_prefix("node:").unwrap_or(other);
            if let Some(n) = nodes.iter().find(|n| n.id == clean) {
                format!("Node: {}", n.remark)
            } else {
                "Follow Routing (node missing fallback)".to_string()
            }
        }
    }
}

fn compile_app_rule(
    rule: &AppProxyRule,
    binding_map: &HashMap<&str, &AppProxyTargetBinding>,
) -> anyhow::Result<CompiledAppRule> {
    let mut dst_cidrs = Vec::with_capacity(rule.dst_cidrs.len());
    for cidr in &rule.dst_cidrs {
        let trimmed = cidr.trim();
        if !trimmed.is_empty() {
            dst_cidrs.push(trimmed.parse::<IpNet>()?);
        }
    }

    let mut protocols = Vec::with_capacity(rule.protocols.len());
    for p in &rule.protocols {
        match p.trim().to_ascii_lowercase().as_str() {
            "tcp" => protocols.push(TransportProtocol::Tcp),
            "udp" | "quic" => protocols.push(TransportProtocol::Udp),
            "" => {}
            other => anyhow::bail!("unsupported protocol '{other}' in rule '{}'", rule.name),
        }
    }

    let domains = rule
        .domains
        .iter()
        .filter_map(|d| {
            DomainPattern::parse(&d.pattern).map(|pattern| CompiledDomainOverride {
                raw_pattern: d.pattern.trim().to_string(),
                pattern,
                action: d.action,
            })
        })
        .collect();

    let target = if rule.target.trim().is_empty() {
        "follow".to_string()
    } else {
        rule.target.trim().to_string()
    };

    let (auth_user, local_action) = match target.as_str() {
        "direct" => (String::new(), Some("direct".to_string())),
        "reject" => (String::new(), Some("reject".to_string())),
        other => {
            if let Some(binding) = binding_map.get(other) {
                (binding.auth_user.clone(), binding.local_action.clone())
            } else if other == "main" {
                ("bx_main".to_string(), None)
            } else {
                ("bx_follow".to_string(), None)
            }
        }
    };

    Ok(CompiledAppRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        process_names_lower: rule
            .process_names
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        path_prefixes_norm: rule
            .path_prefixes
            .iter()
            .map(|s| normalize_path(s))
            .filter(|s| !s.is_empty())
            .collect(),
        path_contains_norm: rule
            .path_contains
            .iter()
            .map(|s| normalize_path(s))
            .filter(|s| !s.is_empty())
            .collect(),
        mac_bundle_paths_norm: rule
            .mac_bundle_paths
            .iter()
            .map(|s| normalize_path(s))
            .filter(|s| !s.is_empty())
            .collect(),
        include_children: rule.include_children,
        dst_cidrs,
        dst_ports: rule.dst_ports.clone(),
        protocols,
        domains,
        target,
        auth_user,
        local_action,
    })
}

/// Normalizes both `/` and `\` path separators to lowercase forward slashes so rules match
/// identically regardless of which slash style the user or preset supplied.
pub fn normalize_path(p: &str) -> String {
    p.trim().replace('\\', "/").to_ascii_lowercase()
}

fn is_always_direct_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_multicast(),
    }
}

/// Returns `Some(matched_ancestor_name_if_not_self)` when the rule matches, or `None`.
fn rule_matches_l4_and_proc(
    rule: &CompiledAppRule,
    tuple: &FiveTuple,
    chain: &[ProcessInfo],
) -> Option<Option<String>> {
    if !rule.protocols.is_empty() && !rule.protocols.contains(&tuple.protocol) {
        return None;
    }
    rule_matches_proc_and_target(rule, tuple, chain)
}

fn rule_matches_proc_and_target(
    rule: &CompiledAppRule,
    tuple: &FiveTuple,
    chain: &[ProcessInfo],
) -> Option<Option<String>> {
    if !rule.dst_ports.is_empty() && !rule.dst_ports.contains(&tuple.dst_port) {
        return None;
    }
    if !rule.dst_cidrs.is_empty() && !rule.dst_cidrs.iter().any(|net| net.contains(&tuple.dst_ip)) {
        return None;
    }
    if !rule.has_proc_criteria() {
        return Some(None);
    }
    match_process_chain(rule, chain)
}

fn match_process_chain(rule: &CompiledAppRule, chain: &[ProcessInfo]) -> Option<Option<String>> {
    if chain.is_empty() {
        return None;
    }
    let candidates: &[ProcessInfo] = if rule.include_children {
        chain
    } else {
        &chain[..1]
    };
    for (idx, proc_info) in candidates.iter().enumerate() {
        let name_lower = proc_info.name.to_ascii_lowercase();
        let mut hit = rule.process_names_lower.iter().any(|n| n == &name_lower);
        if !hit {
            if let Some(ref exe) = proc_info.exe_path {
                let norm = normalize_path(exe);
                if rule.path_prefixes_norm.iter().any(|pref| norm.starts_with(pref))
                    || rule.path_contains_norm.iter().any(|sub| norm.contains(sub))
                    || rule.mac_bundle_paths_norm.iter().any(|b| {
                        let trimmed = b.trim_end_matches('/');
                        norm == trimmed || norm.starts_with(&format!("{trimmed}/"))
                    })
                {
                    hit = true;
                }
            }
        }
        if hit {
            let ancestor = if idx > 0 {
                Some(proc_info.name.clone())
            } else {
                None
            };
            return Some(ancestor);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets::preset_to_rule;
    use bypax_core::model::{DomainOverride, Protocol};

    fn tcp_tuple(dst: [u8; 4], port: u16) -> FiveTuple {
        FiveTuple {
            protocol: TransportProtocol::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            src_port: 55000,
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            dst_port: port,
        }
    }

    #[test]
    fn grandchild_inherits_rule_and_path_separators_normalize() {
        let mut rule = preset_to_rule("antigravity", "auto:US", 10).unwrap();
        rule.path_contains.push(r"Programs\Antigravity".to_string());
        rule.domains.push(DomainOverride {
            pattern: "*.telemetry.example.com".to_string(),
            action: DomainOverrideAction::Reject,
        });
        let nodes = vec![NodeIR::new("n-us", Protocol::Vless, "US-01", "us.example.com", 443, "Sub")];
        let bindings = build_app_proxy_target_bindings(std::slice::from_ref(&rule), &nodes, &[]);
        let engine = RuleEngine::from_rules(
            std::slice::from_ref(&rule),
            &bindings,
            true,
            &[9999],
        )
        .unwrap();

        let tracker = MockProcessTracker::with_processes([
            ProcessInfo {
                pid: 1000,
                parent_pid: 4,
                name: "Antigravity.exe".into(),
                exe_path: Some("C:/Users/dev/AppData/Local/Programs/Antigravity/Antigravity.exe".into()),
            },
            ProcessInfo {
                pid: 1001,
                parent_pid: 1000,
                name: "language_server_windows_x64.exe".into(),
                exe_path: Some(r"C:\Users\dev\AppData\Local\Programs\Antigravity\ls.exe".into()),
            },
            ProcessInfo {
                pid: 1002,
                parent_pid: 1001,
                name: "node.exe".into(),
                exe_path: Some(r"C:\Program Files\nodejs\node.exe".into()),
            },
        ]);

        // Grandchild node.exe inherits Antigravity rule -> bx_auto_us
        let d = engine.evaluate_l4(Some(1002), &tcp_tuple([142, 250, 190, 78], 443), &tracker);
        assert!(matches!(
            d,
            L4RouteDecision::Proxy { ref auth_user, matched_ancestor: Some(_), .. }
            if auth_user == "bx_auto_us"
        ));

        // Phase 2 domain override blocks telemetry subdomain
        let d7 = engine.evaluate_l7(
            Some(1002),
            &tcp_tuple([142, 250, 190, 78], 443),
            "metrics.telemetry.example.com",
            &tracker,
        );
        assert!(matches!(d7, Some(L7DomainDecision::Reject { .. })));

        // Dry-run 3-step trace works end-to-end
        let trace = RuleEngine::dry_run_trace(
            std::slice::from_ref(&rule),
            &AppRuleTestQuery {
                process_name: Some("node.exe".into()),
                exe_path: Some(r"C:\Program Files\nodejs\node.exe".into()),
                ancestor_name: Some("Antigravity.exe".into()),
                ancestor_path: Some(r"C:\Users\dev\Programs\Antigravity\Antigravity.exe".into()),
                host: Some("metrics.telemetry.example.com".into()),
                dst_ip: None,
                dst_port: 443,
                protocol: "tcp".into(),
            },
            &nodes,
            &[],
            Some("n-us"),
            true,
        );
        assert_eq!(trace.final_action, "reject");
        assert_eq!(trace.matched_via_ancestor.as_deref(), Some("Antigravity.exe"));
        assert_eq!(
            trace.matched_domain_pattern.as_deref(),
            Some("*.telemetry.example.com")
        );
        assert_eq!(trace.domain_override_action.as_deref(), Some("reject"));
        assert!(!trace.bypassed_to_routing);
    }
}
