import type {
  AppProxyStatusDto,
  CaptureMode,
  DriverProbeDto,
  InboundPort,
  NodeIR,
  PrivilegedServiceStatus,
  Protocol,
  ProxyChain,
  RouteMode,
  SimpleRoutingRule,
} from "../types";

export type NodeSortMode = "default" | "delay" | "name";

export const CHAINS_GROUP_ID = "__CHAINS__";

export type NodesListEntry =
  | { kind: "chain"; chain: ProxyChain }
  | { kind: "node"; node: NodeIR };

export interface ChainHopSummary {
  entryRegion: string | null;
  exitRegion: string | null;
  compactPath: string;
  shortPath: string;
  fullPath: string;
  missingCount: number;
}

const FLAG_PAIR_RE = /[\u{1F1E6}-\u{1F1FF}]{2}/gu;

function cleanHopRemark(remark: string): string {
  const cleaned = remark.replace(FLAG_PAIR_RE, "").replace(/\s{2,}/g, " ").trim();
  return cleaned || remark.trim();
}

function shortHopToken(label: string, region?: string | null): string {
  let text = label;
  if (region && region.length === 2) {
    const prefixRe = new RegExp(`^${region}[\\s_-]+`, "i");
    const stripped = text.replace(prefixRe, "").trim();
    if (stripped) text = stripped;
  }
  const firstWord = text.split(/\s+/)[0] ?? text;
  if (firstWord.length >= 2 && firstWord.length <= 12) {
    return firstWord;
  }
  return text.length > 10 ? `${text.slice(0, 9)}..` : text;
}

export function summarizeChainHops(
  chain: ProxyChain,
  nodeById: Map<string, NodeIR>,
): ChainHopSummary {
  const hops = chain.hops;
  const resolved = hops.map((id) => nodeById.get(id) ?? null);
  const missingCount = resolved.filter((n) => n === null).length;
  const labels = hops.map((id, idx) => {
    const node = resolved[idx];
    return node ? cleanHopRemark(node.remark) : id;
  });
  const fullPath = labels.join(" -> ");

  let compactPath = fullPath;
  if (labels.length === 2) {
    compactPath = `${labels[0]} -> ${labels[1]}`;
  } else if (labels.length > 2) {
    compactPath = `${labels[0]} -> +${labels.length - 2} -> ${labels[labels.length - 1]}`;
  }

  const firstNode = resolved[0] ?? null;
  const lastNode = resolved.length > 0 ? resolved[resolved.length - 1] : null;
  let shortPath = compactPath;
  if (labels.length === 2) {
    shortPath = `${shortHopToken(labels[0], firstNode?.region)} -> ${shortHopToken(labels[1], lastNode?.region)}`;
  } else if (labels.length > 2) {
    shortPath = `${shortHopToken(labels[0], firstNode?.region)} -> +${labels.length - 2} -> ${shortHopToken(labels[labels.length - 1], lastNode?.region)}`;
  }

  return {
    entryRegion: firstNode?.region ?? null,
    exitRegion: lastNode?.region ?? null,
    compactPath,
    shortPath,
    fullPath,
    missingCount,
  };
}

/**
 * Canonical latency sort key: positive RTT sorts ascending first,
 * untested (`null`/`undefined`) sorts next (`999998`), and failed (`<= 0`, e.g. `-1ms`)
 * sorts strictly last (`999999`) so failed nodes never float to the top.
 */
export function latencySortKey(ms?: number | null): number {
  if (ms != null && ms > 0) return ms;
  if (ms == null) return 999_998;
  return 999_999;
}

export function formatLatency(ms?: number | null): string {
  if (ms == null) return "--";
  if (ms < 0) return "-1ms";
  return `${ms} ms`;
}

export interface ChainProtocolWarning {
  hopIndex: number;
  relayRemark: string;
  nextRemark: string;
  nextProtocol: Protocol;
}

export interface ChainValidationResult {
  valid: boolean;
  tooFewHops: boolean;
  missingHopIds: string[];
  duplicateHopIds: string[];
  httpOverUdpWarnings: ChainProtocolWarning[];
}

const UDP_QUIC_PROTOCOLS: ReadonlySet<Protocol> = new Set([
  "hysteria2",
  "tuic",
  "wireguard",
]);

export function validateChainHops(
  hops: string[],
  nodeById: Map<string, NodeIR>,
): ChainValidationResult {
  const seen = new Set<string>();
  const duplicateHopIds: string[] = [];
  const missingHopIds: string[] = [];
  const httpOverUdpWarnings: ChainProtocolWarning[] = [];

  for (let i = 0; i < hops.length; i += 1) {
    const hopId = hops[i];
    if (seen.has(hopId)) {
      duplicateHopIds.push(hopId);
    } else {
      seen.add(hopId);
    }
    const cur = nodeById.get(hopId);
    if (!cur) {
      missingHopIds.push(hopId);
      continue;
    }
    if (cur.protocol === "http" && i + 1 < hops.length) {
      const next = nodeById.get(hops[i + 1]);
      if (next && UDP_QUIC_PROTOCOLS.has(next.protocol)) {
        httpOverUdpWarnings.push({
          hopIndex: i,
          relayRemark: cur.remark,
          nextRemark: next.remark,
          nextProtocol: next.protocol,
        });
      }
    }
  }

  const tooFewHops = hops.length < 2;
  const valid =
    !tooFewHops && missingHopIds.length === 0 && duplicateHopIds.length === 0;
  return {
    valid,
    tooFewHops,
    missingHopIds,
    duplicateHopIds,
    httpOverUdpWarnings,
  };
}

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
      return latencySortKey(a.realDelayMs) - latencySortKey(b.realDelayMs);
    });
  }
  if (sortMode === "name") {
    return filtered.slice().sort((a, b) => a.remark.localeCompare(b.remark));
  }
  return filtered;
}

export function filterAndSortNodesAndChains(
  nodes: NodeIR[],
  chains: ProxyChain[],
  group: string,
  query: string,
  sortMode: NodeSortMode,
): NodesListEntry[] {
  const q = query.trim().toLowerCase();
  const nodeById = new Map(nodes.map((n) => [n.id, n]));

  const includeChains = group === "ALL" || group === CHAINS_GROUP_ID;
  const includeNodes = group !== CHAINS_GROUP_ID;

  const matchedChains: NodesListEntry[] = includeChains
    ? chains
        .filter((c) => {
          if (!q) return true;
          if (
            c.name.toLowerCase().includes(q) ||
            c.id.toLowerCase().includes(q) ||
            "chain".includes(q) ||
            `${c.hops.length}h`.includes(q)
          ) {
            return true;
          }
          return c.hops.some((hid) => {
            const hop = nodeById.get(hid);
            if (!hop) return hid.toLowerCase().includes(q);
            return (
              hop.remark.toLowerCase().includes(q) ||
              hop.server.toLowerCase().includes(q) ||
              hop.protocol.toLowerCase().includes(q) ||
              PROTO_BADGES[hop.protocol].toLowerCase().includes(q) ||
              hop.region.toLowerCase().includes(q)
            );
          });
        })
        .map((chain) => ({ kind: "chain", chain }))
    : [];

  const matchedNodes: NodesListEntry[] = includeNodes
    ? filterAndSortNodes(nodes, group, query, "default").map((node) => ({
        kind: "node",
        node,
      }))
    : [];

  const combined = [...matchedChains, ...matchedNodes];

  if (sortMode === "delay") {
    return combined.slice().sort((a, b) => {
      const aDelay = a.kind === "chain" ? a.chain.realDelayMs : a.node.realDelayMs;
      const bDelay = b.kind === "chain" ? b.chain.realDelayMs : b.node.realDelayMs;
      const diff = latencySortKey(aDelay) - latencySortKey(bDelay);
      if (diff !== 0) return diff;
      if (a.kind !== b.kind) return a.kind === "chain" ? -1 : 1;
      const aName = a.kind === "chain" ? a.chain.name : a.node.remark;
      const bName = b.kind === "chain" ? b.chain.name : b.node.remark;
      return aName.localeCompare(bName);
    });
  }

  if (sortMode === "name") {
    return combined.slice().sort((a, b) => {
      const aName = a.kind === "chain" ? a.chain.name : a.node.remark;
      const bName = b.kind === "chain" ? b.chain.name : b.node.remark;
      return aName.localeCompare(bName);
    });
  }

  return combined;
}

export interface TargetResolution {
  kind: "direct" | "reject" | "auto" | "node" | "chain";
  label: string;
  node: NodeIR | null;
  chain?: ProxyChain | null;
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
  labels: TargetLabels,
  chains: ProxyChain[] = [],
): TargetResolution {
  if (target === "direct") {
    return { kind: "direct", label: labels.direct, node: null };
  }
  if (target === "reject") {
    return { kind: "reject", label: labels.reject, node: null };
  }

  const mainChain =
    mainNodeId && mainNodeId.startsWith("chain:")
      ? chains.find((c) => c.id === mainNodeId.slice("chain:".length)) ?? null
      : null;
  const mainNode = mainChain
    ? null
    : nodes.find((n) => n.id === mainNodeId) ?? nodes[0] ?? null;

  if (target === "main") {
    if (mainChain) {
      return { kind: "chain", label: mainChain.name, node: null, chain: mainChain };
    }
    return {
      kind: "node",
      label: mainNode ? mainNode.remark : labels.noNode,
      node: mainNode,
    };
  }
  if (target.startsWith("chain:")) {
    const cid = target.slice("chain:".length);
    const chain = chains.find((c) => c.id === cid) ?? null;
    if (chain) {
      return { kind: "chain", label: chain.name, node: null, chain };
    }
    if (mainChain) {
      return { kind: "chain", label: mainChain.name, node: null, chain: mainChain };
    }
    return {
      kind: "node",
      label: mainNode ? mainNode.remark : labels.noNode,
      node: mainNode,
    };
  }
  if (target.startsWith("auto:")) {
    const key = target.slice("auto:".length).toUpperCase();
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const tokenRe = new RegExp(`(^|[^A-Z0-9])${escaped}([^A-Z0-9]|$)`, "i");
    const exactRegion = nodes.filter((n) => n.region.toUpperCase() === key);
    const candidates =
      key === "ALL"
        ? nodes
        : exactRegion.length > 0
          ? exactRegion
          : nodes.filter((n) => tokenRe.test(n.remark));
    const pool = candidates.length > 0 ? candidates : nodes;
    const best =
      pool
        .slice()
        .sort(
          (a, b) =>
            latencySortKey(a.realDelayMs) - latencySortKey(b.realDelayMs)
        )[0] ?? null;
    return {
      kind: "auto",
      label: best ? best.remark : labels.noNode,
      node: best,
    };
  }
  const cleanId = target.startsWith("node:") ? target.slice("node:".length) : target;
  const specific = nodes.find((n) => n.id === cleanId) ?? mainNode;
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
  presetTitles?: Record<string, string>,
  chains: ProxyChain[] = [],
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
      exit: resolveTargetExit("main", nodes, mainNodeId, labels, chains),
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
        exit: resolveTargetExit(rule.target, nodes, mainNodeId, labels, chains),
      };
    }
  }

  return {
    matchedRuleId: null,
    ruleLabel: labels.defaultFallback,
    exit: resolveTargetExit("main", nodes, mainNodeId, labels, chains),
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

export function delayColorVar(ms?: number | null): string {
  if (ms == null) return "var(--latency-none)";
  if (ms < 0) return "var(--latency-bad)";
  if (ms <= 120) return "var(--latency-fast)";
  if (ms <= 260) return "var(--latency-ok)";
  if (ms <= 500) return "var(--latency-slow)";
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
  | "legacy_conflict"
  | "hvci_blocked"
  | "driver_missing"
  | "signature_failed"
  | "pipe_timeout";

/**
 * Canonicalizes backend/driver error kinds to the actionable UI recovery banners.
 * Unknown kinds, "access_denied", and "other" NEVER fall through to "pipe_timeout".
 */
export function normalizeRecoveryFaultKind(
  raw?: string | null
): NormalizedRecoveryFault | null {
  if (!raw) return null;
  const k = raw.trim().toLowerCase();
  if (k === "legacy_conflict") return "legacy_conflict";
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
 * (serviceMode="off", not installed, and captureMode="off"), except when conflicting
 * legacy Windows services or stale driver locks are actively detected.
 */
export function resolveActiveRecoveryFault(params: {
  captureMode: CaptureMode;
  serviceStatus?: PrivilegedServiceStatus | null;
  appProxyStatus?: AppProxyStatusDto | null;
  driverStatus?: DriverProbeDto | null;
}): NormalizedRecoveryFault | null {
  const { captureMode, serviceStatus, appProxyStatus, driverStatus } = params;
  if (
    (serviceStatus?.legacyServices && serviceStatus.legacyServices.length > 0) ||
    normalizeRecoveryFaultKind(serviceStatus?.errorKind) === "legacy_conflict" ||
    normalizeRecoveryFaultKind(appProxyStatus?.errorKind) === "legacy_conflict" ||
    normalizeRecoveryFaultKind(driverStatus?.errorKind) === "legacy_conflict"
  ) {
    return "legacy_conflict";
  }

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

export function chainOutboundTag(chainId: string): string {
  const sanitized = chainId
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `chain-${sanitized || "custom"}`;
}

export function formatConnectionExit(
  chain: string[],
  nodeById: Map<string, NodeIR>,
  labels: ExitDisplayLabels,
  proxyChains: ProxyChain[] = [],
): ResolvedExit {
  if (!chain || chain.length === 0) {
    return { label: labels.direct, kind: "direct", rawTag: "direct" };
  }

  for (const tag of chain) {
    const matchedChain = proxyChains.find((c) => chainOutboundTag(c.id) === tag);
    if (matchedChain) {
      return {
        label: matchedChain.name,
        protocol: `${matchedChain.hops.length}H`,
        kind: "node",
        rawTag: tag,
      };
    }
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
  if (target.startsWith("chain:")) {
    return chainOutboundTag(target.slice("chain:".length));
  }
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

  if (
    trimmed.includes("ip_is_private") ||
    (trimmed.includes("100.64.0.0/10") && trimmed.includes("route(direct)")) ||
    (trimmed.includes("netbird.selfhosted") && trimmed.includes("route(direct)"))
  ) {
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
  labels: ExitDisplayLabels,
  proxyChains: ProxyChain[] = [],
): string {
  let out = message.replace(/\bn-[a-z0-9]+-[a-f0-9]{6,12}\b/g, (id) => {
    const node = nodeById.get(id);
    return node ? node.remark : id;
  });
  for (const c of proxyChains) {
    const tag = chainOutboundTag(c.id);
    out = out.split(`[${tag}]`).join(`[${c.name}]`);
  }
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
