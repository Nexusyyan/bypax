import type {
  AppProxyStatusDto,
  CaptureMode,
  DriverProbeDto,
  InboundPort,
  NodeIR,
  PrivilegedServiceStatus,
  Protocol,
  RouteMode,
  SimpleRoutingRule,
} from "../types";

export type NodeSortMode = "default" | "delay" | "name";

export const PROTO_BADGES: Record<Protocol, string> = {
  vless: "VLESS",
  vmess: "VMESS",
  trojan: "TROJAN",
  shadowsocks: "SS",
  hysteria2: "HY2",
  tuic: "TUIC",
  anytls: "ANYTLS",
  wireguard: "WG",
  http: "HTTP",
  socks: "SOCKS",
};

export interface RegionBucket {
  code: string;
  count: number;
}

export function computeAvailableRegions(nodes: NodeIR[]): RegionBucket[] {
  const counts = new Map<string, number>();
  for (const n of nodes) {
    const code = (n.region || "OTHER").toUpperCase();
    if (code === "OTHER" || !code) continue;
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}

export function filterAndSortNodes(
  nodes: NodeIR[],
  group: string,
  query: string,
  sortMode: NodeSortMode
): NodeIR[] {
  const q = query.trim().toLowerCase();
  const filtered = nodes.filter((n) => {
    if (group !== "ALL" && n.group !== group) {
      return false;
    }
    if (!q) {
      return true;
    }
    return (
      n.remark.toLowerCase().includes(q) ||
      n.server.toLowerCase().includes(q) ||
      n.protocol.toLowerCase().includes(q) ||
      PROTO_BADGES[n.protocol].toLowerCase().includes(q) ||
      n.region.toLowerCase().includes(q)
    );
  });

  if (sortMode === "delay") {
    return filtered.slice().sort((a, b) => {
      const da = a.realDelayMs ?? a.tcpingMs ?? 999999;
      const db = b.realDelayMs ?? b.tcpingMs ?? 999999;
      return da - db;
    });
  }
  if (sortMode === "name") {
    return filtered.slice().sort((a, b) => a.remark.localeCompare(b.remark));
  }
  return filtered;
}

export interface TargetResolution {
  kind: "direct" | "reject" | "auto" | "node";
  label: string;
  node: NodeIR | null;
}

export interface TargetLabels {
  direct: string;
  reject: string;
  noNode: string;
}

export function resolveTargetExit(
  target: string,
  nodes: NodeIR[],
  mainNodeId: string | null | undefined,
  labels: TargetLabels
): TargetResolution {
  if (target === "direct") {
    return { kind: "direct", label: labels.direct, node: null };
  }
  if (target === "reject") {
    return { kind: "reject", label: labels.reject, node: null };
  }
  const mainNode = nodes.find((n) => n.id === mainNodeId) ?? nodes[0] ?? null;
  if (target === "main") {
    return {
      kind: "node",
      label: mainNode ? mainNode.remark : labels.noNode,
      node: mainNode,
    };
  }
  if (target.startsWith("auto:")) {
    const key = target.slice("auto:".length).toUpperCase();
    const candidates =
      key === "ALL"
        ? nodes
        : nodes.filter(
            (n) =>
              n.region.toUpperCase() === key ||
              n.remark.toUpperCase().includes(key)
          );
    const pool = candidates.length > 0 ? candidates : nodes;
    const best =
      pool
        .slice()
        .sort(
          (a, b) =>
            (a.realDelayMs ?? a.tcpingMs ?? 999999) -
            (b.realDelayMs ?? b.tcpingMs ?? 999999)
        )[0] ?? null;
    return {
      kind: "auto",
      label: best ? best.remark : labels.noNode,
      node: best,
    };
  }
  const specific = nodes.find((n) => n.id === target) ?? mainNode;
  return {
    kind: "node",
    label: specific ? specific.remark : labels.noNode,
    node: specific,
  };
}

export interface SimResult {
  matchedRuleId: string | null;
  ruleLabel: string;
  exit: TargetResolution;
}

export function evaluateRouteSimulation(
  rawHost: string,
  routeMode: RouteMode,
  rules: SimpleRoutingRule[],
  nodes: NodeIR[],
  mainNodeId: string | null | undefined,
  labels: TargetLabels & {
    defaultFallback: string;
    directMode: string;
    globalMode: string;
    matchedPrefix: string;
  },
  useEnglishTitle: boolean,
  presetTitles?: Record<string, string>
): SimResult {
  const host = rawHost.trim().toLowerCase();
  if (routeMode === "direct") {
    return {
      matchedRuleId: null,
      ruleLabel: labels.directMode,
      exit: { kind: "direct", label: labels.direct, node: null },
    };
  }
  if (routeMode === "global") {
    return {
      matchedRuleId: null,
      ruleLabel: labels.globalMode,
      exit: resolveTargetExit("main", nodes, mainNodeId, labels),
    };
  }

  for (const rule of rules) {
    if (!rule.enabled) continue;
    const hit = rule.patterns.some((p) => {
      const needle = p.trim().toLowerCase().replace(/^\./, "");
      if (!needle) return false;
      return host === needle || host.endsWith(`.${needle}`) || host.includes(needle);
    });
    if (hit) {
      const title =
        presetTitles?.[rule.id] ?? (useEnglishTitle ? rule.titleEn : rule.title);
      return {
        matchedRuleId: rule.id,
        ruleLabel: `${labels.matchedPrefix} ${title}`,
        exit: resolveTargetExit(rule.target, nodes, mainNodeId, labels),
      };
    }
  }

  return {
    matchedRuleId: null,
    ruleLabel: labels.defaultFallback,
    exit: resolveTargetExit("main", nodes, mainNodeId, labels),
  };
}

export function pushRingBuffer<T>(items: T[], next: T, cap = 500): T[] {
  const safeCap = Math.max(1, cap);
  if (items.length < safeCap) {
    return [next, ...items];
  }
  return [next, ...items.slice(0, safeCap - 1)];
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 100 || idx === 0 ? Math.round(val) : val.toFixed(1)} ${units[idx]}`;
}

export function formatSpeed(bps: number): string {
  return `${formatBytes(bps)}/s`;
}

export function delayColorVar(
  ms?: number | null,
  kind: "tcping" | "real" = "tcping"
): string {
  if (ms == null) return "var(--latency-none)";
  if (kind === "real") {
    if (ms <= 120) return "var(--latency-fast)";
    if (ms <= 260) return "var(--latency-ok)";
    if (ms <= 500) return "var(--latency-slow)";
    return "var(--latency-bad)";
  }
  if (ms <= 80) return "var(--latency-fast)";
  if (ms <= 180) return "var(--latency-ok)";
  if (ms <= 350) return "var(--latency-slow)";
  return "var(--latency-bad)";
}

export function middleTruncate(text: string, maxLen = 40): string {
  if (!text || text.length <= maxLen) return text;
  const keep = Math.max(6, Math.floor((maxLen - 3) / 2));
  return `${text.slice(0, keep)}...${text.slice(text.length - keep)}`;
}

export interface TakeoverSummaryLabels {
  modeRule: string;
  modeGlobal: string;
  modeDirect: string;
  sysProxy: string;
  apps: string;
  appsOne?: string;
  noApps: string;
  tun: string;
  none: string;
}

export function buildTakeoverSummary(
  routeMode: RouteMode,
  sysProxyEnabled: boolean,
  captureMode: "off" | "apps" | "tun",
  enabledAppCount: number,
  labels: TakeoverSummaryLabels
): string {
  const modeLabel =
    routeMode === "direct"
      ? labels.modeDirect
      : routeMode === "global"
        ? labels.modeGlobal
        : labels.modeRule;

  const parts: string[] = [modeLabel];
  if (sysProxyEnabled) {
    parts.push(labels.sysProxy);
  }
  if (captureMode === "tun") {
    parts.push(labels.tun);
  } else if (captureMode === "apps") {
    parts.push(
      enabledAppCount === 1 && labels.appsOne
        ? labels.appsOne
        : enabledAppCount > 0
          ? labels.apps.replace("{count}", String(enabledAppCount))
          : labels.noApps
    );
  }
  if (!sysProxyEnabled && captureMode === "off") {
    parts.push(labels.none);
  }
  return parts.join(" \u00b7 ");
}

export type NormalizedRecoveryFault =
  | "hvci_blocked"
  | "driver_missing"
  | "signature_failed"
  | "pipe_timeout";

/**
 * Canonicalizes backend/driver error kinds to the 4 actionable UI recovery banners.
 * Unknown kinds, "access_denied", and "other" NEVER fall through to "pipe_timeout".
 */
export function normalizeRecoveryFaultKind(
  raw?: string | null
): NormalizedRecoveryFault | null {
  if (!raw) return null;
  const k = raw.trim().toLowerCase();
  if (k === "hvci_blocked" || k === "blocked_by_security") return "hvci_blocked";
  if (k === "driver_missing" || k === "missing_dll" || k === "missing_sys") {
    return "driver_missing";
  }
  if (k === "signature_failed" || k === "invalid_signature") return "signature_failed";
  if (k === "pipe_timeout" || k === "service_error") return "pipe_timeout";
  return null;
}

/**
 * Single-source-of-truth recovery fault gate shared by AppsView, App (Sidebar/TitleBar),
 * and TrayPopup. Never triggers false alarms or amber dots during healthy standby
 * (serviceMode="off", not installed, and captureMode="off").
 */
export function resolveActiveRecoveryFault(params: {
  captureMode: CaptureMode;
  serviceStatus?: PrivilegedServiceStatus | null;
  appProxyStatus?: AppProxyStatusDto | null;
  driverStatus?: DriverProbeDto | null;
}): NormalizedRecoveryFault | null {
  const { captureMode, serviceStatus, appProxyStatus, driverStatus } = params;
  const serviceRequestedOrActive =
    captureMode === "apps" ||
    (serviceStatus != null && (serviceStatus.mode !== "off" || serviceStatus.installed));

  if (!serviceRequestedOrActive) {
    return null;
  }

  const candidates = [
    serviceStatus?.errorKind,
    appProxyStatus?.errorKind,
    driverStatus?.errorKind,
  ];
  for (const raw of candidates) {
    const normalized = normalizeRecoveryFaultKind(raw);
    if (normalized) return normalized;
  }
  return null;
}

export interface ExitDisplayLabels {
  direct: string;
  reject: string;
  mainExit: string;
  autoAll: string;
  autoRegionPrefix: string;
  regions: Record<string, string>;
}

export interface ResolvedExit {
  label: string;
  protocol?: string;
  region?: string;
  groupHint?: string;
  kind: "node" | "direct" | "reject" | "unknown";
  rawTag: string;
}

function formatGroupTag(tag: string, labels: ExitDisplayLabels): string | undefined {
  if (tag === "main-exit") return labels.mainExit;
  if (tag === "auto-all") return labels.autoAll;
  if (tag.startsWith("auto-")) {
    const code = tag.slice("auto-".length).toUpperCase();
    const regionName = labels.regions[code] ?? code;
    return `${labels.autoRegionPrefix} ${regionName}`;
  }
  return undefined;
}

export function formatConnectionExit(
  chain: string[],
  nodeById: Map<string, NodeIR>,
  labels: ExitDisplayLabels
): ResolvedExit {
  if (!chain || chain.length === 0) {
    return { label: labels.direct, kind: "direct", rawTag: "direct" };
  }

  let matchedNode: NodeIR | undefined;
  for (const tag of chain) {
    const found = nodeById.get(tag);
    if (found) {
      matchedNode = found;
      break;
    }
  }

  let groupHint: string | undefined;
  for (const tag of chain) {
    if (matchedNode && tag === matchedNode.id) continue;
    const hint = formatGroupTag(tag, labels);
    if (hint) {
      groupHint = hint;
      break;
    }
  }

  if (matchedNode) {
    return {
      label: matchedNode.remark,
      protocol: PROTO_BADGES[matchedNode.protocol],
      region: matchedNode.region,
      groupHint,
      kind: "node",
      rawTag: matchedNode.id,
    };
  }

  const primary = chain[0];
  if (primary === "direct") {
    return { label: labels.direct, groupHint, kind: "direct", rawTag: "direct" };
  }
  if (primary === "reject" || primary === "block") {
    return { label: labels.reject, groupHint, kind: "reject", rawTag: primary };
  }

  const groupLabel = formatGroupTag(primary, labels);
  if (groupLabel) {
    return { label: groupLabel, kind: "unknown", rawTag: primary };
  }
  return { label: primary, groupHint, kind: "unknown", rawTag: primary };
}

export interface RuleDisplayLabels {
  defaultFallback: string;
  directMode: string;
  globalMode: string;
  lanDirect: string;
  portRulePrefix: string;
  domainRuleFallback: string;
  processRuleFallback: string;
}

export interface FormattedRule {
  label: string;
  raw: string;
  kind: "fallback" | "rule" | "port" | "lan" | "mode";
}

function ruleTargetTag(target: string): string {
  if (target === "main") return "main-exit";
  if (target.startsWith("auto:")) {
    const suffix = target
      .slice("auto:".length)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "-")
      .replace(/^-+|-+$/g, "");
    return `auto-${suffix}`;
  }
  return target;
}

function localizedRuleTitle(
  rule: SimpleRoutingRule,
  presetTitles: Record<string, string>,
  useEnglish: boolean
): string {
  return presetTitles[rule.id] ?? (useEnglish ? rule.titleEn : rule.title);
}

export function formatConnectionRule(
  rawRule: string,
  rules: SimpleRoutingRule[],
  extraPorts: InboundPort[],
  labels: RuleDisplayLabels,
  presetTitles: Record<string, string>,
  useEnglish: boolean
): FormattedRule {
  const trimmed = (rawRule || "").trim();
  if (!trimmed || trimmed.toLowerCase() === "final") {
    return {
      label: labels.defaultFallback,
      raw: trimmed || "final",
      kind: "fallback",
    };
  }

  if (trimmed.includes("ip_is_private")) {
    return { label: labels.lanDirect, raw: trimmed, kind: "lan" };
  }

  if (trimmed.includes("clash_mode=direct")) {
    return { label: labels.directMode, raw: trimmed, kind: "mode" };
  }

  if (trimmed.includes("clash_mode=global")) {
    return { label: labels.globalMode, raw: trimmed, kind: "mode" };
  }

  const inboundMatch = trimmed.match(/inbound=\[([^\]]+)\]/);
  if (inboundMatch) {
    const tag = inboundMatch[1].trim().split(/\s+/)[0] ?? "";
    const port = extraPorts.find((p) => p.id === tag);
    if (port) {
      const note = (useEnglish ? port.noteEn : port.note).trim();
      return {
        label: note ? `:${port.port} (${note})` : `${labels.portRulePrefix} :${port.port}`,
        raw: trimmed,
        kind: "port",
      };
    }
    const cleanPort = tag.startsWith("in-") ? `:${tag.slice(3)}` : tag;
    return {
      label: `${labels.portRulePrefix} ${cleanPort}`,
      raw: trimmed,
      kind: "port",
    };
  }

  const routeTargetMatch = trimmed.match(/route\(([^)]+)\)/);
  const routeTarget = routeTargetMatch ? routeTargetMatch[1].trim() : null;

  const ruleSetMatch = trimmed.match(/rule_set=\[([^\]]+)\]/);
  if (ruleSetMatch) {
    const tag = ruleSetMatch[1].trim().split(/\s+/)[0] ?? "";
    const found = rules.find((r) => r.ruleSet === tag);
    if (found) {
      return {
        label: localizedRuleTitle(found, presetTitles, useEnglish),
        raw: trimmed,
        kind: "rule",
      };
    }
  }

  const domainMatch = trimmed.match(/domain_suffix=\[([^\]]+)\]/);
  if (domainMatch) {
    const tokens = domainMatch[1]
      .replace(/\.\.\./g, "")
      .trim()
      .split(/\s+/)
      .map((s) => s.toLowerCase().replace(/^\./, ""))
      .filter(Boolean);

    let bestRule: SimpleRoutingRule | null = null;
    let bestScore = 0;
    for (const rule of rules) {
      const patterns = new Set(
        rule.patterns.map((p) => p.trim().toLowerCase().replace(/^\./, ""))
      );
      let hits = 0;
      for (const tok of tokens) {
        if (patterns.has(tok)) hits += 1;
      }
      if (hits > 0) {
        const targetBonus =
          routeTarget && ruleTargetTag(rule.target) === routeTarget ? 10 : 0;
        const score = hits * 2 + targetBonus;
        if (score > bestScore) {
          bestScore = score;
          bestRule = rule;
        }
      }
    }
    if (bestRule) {
      return {
        label: localizedRuleTitle(bestRule, presetTitles, useEnglish),
        raw: trimmed,
        kind: "rule",
      };
    }
    return {
      label: tokens[0] ? `${labels.domainRuleFallback} (${tokens[0]})` : labels.domainRuleFallback,
      raw: trimmed,
      kind: "rule",
    };
  }

  if (trimmed.includes("process_name=")) {
    const procMatch = trimmed.match(/process_name=\[([^\]]+)\]/);
    const procTokens = procMatch
      ? procMatch[1].trim().split(/\s+/).map((s) => s.toLowerCase())
      : [];
    const found = rules.find((r) =>
      r.processNames.some((p) => procTokens.includes(p.toLowerCase()))
    );
    if (found) {
      return {
        label: localizedRuleTitle(found, presetTitles, useEnglish),
        raw: trimmed,
        kind: "rule",
      };
    }
    return { label: labels.processRuleFallback, raw: trimmed, kind: "rule" };
  }

  const compact = trimmed.replace(/\s*=>\s*route\([^)]+\)/g, "").trim();
  return { label: compact || trimmed, raw: trimmed, kind: "rule" };
}

export function humanizeLogMessage(
  message: string,
  nodeById: Map<string, NodeIR>,
  labels: ExitDisplayLabels
): string {
  let out = message.replace(/\bn-[a-z0-9]+-[a-f0-9]{6,12}\b/g, (id) => {
    const node = nodeById.get(id);
    return node ? node.remark : id;
  });
  out = out.replace(/\[main-exit\]/g, `[${labels.mainExit}]`);
  out = out.replace(/\[auto-([a-z0-9-]+)\]/g, (full, suffix: string) => {
    const tag = `auto-${suffix}`;
    const label = formatGroupTag(tag, labels);
    return label ? `[${label}]` : full;
  });
  return out;
}

export const SAMPLE_SHARE_URIS = [
  "vless://11111111-1111-1111-1111-111111111111@jp1.edge-node.example:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#JP-Tokyo-01-Reality",
  "hysteria2://samplepass@us1.homeip.example:8443?sni=us1.homeip.example#US-LosAngeles-Residential-01",
  "anytls://samplepass@us2.homeip.example:443?sni=us2.homeip.example#US-SanJose-Native-02",
  "tuic://22222222-2222-2222-2222-222222222222:samplepass@sg1.fastline.example:20443?congestion_control=bbr&sni=sg1.fastline.example#SG-Streaming-01",
  "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQT09@hk1.fastline.example:10443#HK-IPLC-01",
  "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@198.51.100.10:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&address=10.0.0.2/32#DE-Frankfurt-WG",
].join("\n");
