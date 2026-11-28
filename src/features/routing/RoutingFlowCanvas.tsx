import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  ArrowRight,
  Ban,
  ChevronRight,
  Globe,
  LayoutGrid,
  Maximize2,
  Pencil,
  Pin,
  Play,
  Router,
  Shield,
  Sparkles,
  Waypoints,
  X,
} from "lucide-react";
import {
  FlowEdge,
  type BypaxFlowEdge,
  type FlowEdgeVariant,
} from "../../components/flow/FlowEdge";
import { NodeLabel, RegionFlag } from "../../components/RegionFlag";
import { SignalBars } from "../../components/SignalBars";
import type { Dict } from "../../i18n";
import type {
  Locale,
  NodeIR,
  ProxyChain,
  RouteMode,
  RouteTestResult,
  RuleSetStatus,
  SimpleRoutingRule,
} from "../../types";
import {
  computeAvailableRegions,
  delayColorVar,
  formatLatency,
  PROTO_BADGES,
  resolveTargetExit,
} from "../../utils/nodes";

const LAYOUT_STORAGE_KEY = "bypax-routing-flow-layout-v1";
const INPUT_HUB_ID = "routing-input-hub";
const FALLBACK_ID = "routing-fallback";
const RULE_PREFIX = "rule:";
const EXIT_PREFIX = "exit:";

interface RoutingFlowCanvasProps {
  dict: Dict;
  locale: Locale;
  routeMode: RouteMode;
  nodes: NodeIR[];
  chains: ProxyChain[];
  rules: SimpleRoutingRule[];
  ruleSets: RuleSetStatus[];
  mainNodeId?: string | null;
  mixedPort: number;
  testInput: string;
  onChangeTestInput: (v: string) => void;
  testResult: RouteTestResult | null;
  testingRoute: boolean;
  activeMatchedRuleId: string | null;
  displayMatchedRule: string;
  displayExitLabel: string;
  displayDns: string;
  onRunRouteTest: (overrideInput?: string) => void;
  onSaveRule: (rule: SimpleRoutingRule) => void;
  onEditRule: (rule: SimpleRoutingRule) => void;
  onOpenChains: (chainId?: string) => void;
}

interface HubNodeData extends Record<string, unknown> {
  title: string;
  modeLabel: string;
  mixedPort: number;
  activeRulesCount: number;
}

interface RuleNodeData extends Record<string, unknown> {
  rule: SimpleRoutingRule | null;
  isFallback?: boolean;
  title: string;
  subtitle: string;
  priorityBadge: string;
  ruleSetTag?: string | null;
  ruleSetCached?: boolean;
  enabled: boolean;
  isHit: boolean;
  isDimmed: boolean;
  wireActive: boolean;
  onToggleEnabled?: () => void;
  onEdit?: () => void;
  onStartWire?: () => void;
  onHover?: (id: string | null) => void;
}

interface ExitNodeData extends Record<string, unknown> {
  targetValue: string;
  kind: "main" | "direct" | "reject" | "auto" | "chain" | "node";
  title: string;
  subtitle?: string;
  regionCode?: string | null;
  latencyMs?: number | null;
  protocolBadge?: string;
  hopBadge?: string;
  isHit: boolean;
  isDimmed: boolean;
  wireCandidate: boolean;
  canUnpin?: boolean;
  onCompleteWire?: () => void;
  onUnpin?: () => void;
  onOpenChain?: () => void;
  onHover?: (id: string | null) => void;
}

type RoutingCanvasNode =
  | Node<HubNodeData, "routingHub">
  | Node<RuleNodeData, "routingRule">
  | Node<ExitNodeData, "routingExit">;

function RoutingHubCard({ data }: NodeProps<Node<HubNodeData, "routingHub">>) {
  return (
    <div className="w-[196px] rounded-[14px] border border-[var(--border-strong)] bg-[var(--bg-surface)] p-3.5 shadow-[var(--shadow-card)]">
      <div className="flex items-center gap-2.5">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--accent-focus)]">
          <Router className="h-4 w-4" strokeWidth={1.6} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-semibold text-[var(--text-primary)]">
            {data.title}
          </div>
          <div className="flex items-center gap-1.5 font-mono text-[11px] text-[var(--text-secondary)] num-tabular">
            <span>{data.modeLabel}</span>
            <span>{"\u00b7"}</span>
            <span>:{data.mixedPort}</span>
          </div>
        </div>
      </div>

      <Handle
        id="out"
        type="source"
        position={Position.Right}
        className="bypax-flow-handle bypax-flow-handle-connected"
      />
    </div>
  );
}

function RoutingRuleCard({ data }: NodeProps<Node<RuleNodeData, "routingRule">>) {
  return (
    <div
      onMouseEnter={() =>
        data.onHover?.(data.isFallback ? FALLBACK_ID : `${RULE_PREFIX}${data.rule?.id}`)
      }
      onMouseLeave={() => data.onHover?.(null)}
      className={`w-[266px] rounded-[13px] border bg-[var(--bg-surface)] px-3 py-2.5 shadow-[var(--shadow-card)] transition-all ${
        !data.enabled ? "opacity-55" : ""
      } ${
        data.isHit || data.wireActive
          ? "border-[var(--accent-focus)] hit-ring"
          : data.isDimmed
            ? "border-[var(--border-hairline)] opacity-45"
            : "border-[var(--border-hairline)] hover:border-[var(--border-strong)]"
      }`}
    >
      <Handle
        id="in"
        type="target"
        position={Position.Left}
        className="bypax-flow-handle"
      />

      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="shrink-0 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold text-[var(--text-secondary)] num-tabular">
            {data.priorityBadge}
          </span>
          <span
            className="truncate text-[12.5px] font-semibold text-[var(--text-primary)]"
            title={data.title}
          >
            {data.title}
          </span>
        </div>

        <div className="nodrag nopan flex shrink-0 items-center gap-1">
          {!data.isFallback && data.onEdit && (
            <button
              type="button"
              aria-label="Edit rule"
              onClick={(e) => {
                e.stopPropagation();
                data.onEdit?.();
              }}
              className="ui-btn-ghost h-6 w-6 p-0"
            >
              <Pencil className="h-3 w-3" strokeWidth={1.6} />
            </button>
          )}
          {!data.isFallback && data.onToggleEnabled && (
            <button
              type="button"
              role="switch"
              aria-checked={data.enabled}
              aria-label={data.title}
              onClick={(e) => {
                e.stopPropagation();
                data.onToggleEnabled?.();
              }}
              className="ui-switch"
            >
              <span className="ui-switch-knob" />
            </button>
          )}
          {!data.isFallback && data.onStartWire && (
            <button
              type="button"
              aria-label="Wire rule to exit"
              onClick={(e) => {
                e.stopPropagation();
                data.onStartWire?.();
              }}
              className={`flex h-6 w-6 items-center justify-center rounded-[6px] border text-[10px] transition-colors cursor-pointer ${
                data.wireActive
                  ? "border-[var(--accent-focus)] bg-[var(--accent-soft)] text-[var(--accent-focus)]"
                  : "border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              <ArrowRight className="h-3 w-3" strokeWidth={1.8} />
            </button>
          )}
        </div>
      </div>

      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-[var(--text-secondary)]">
        <span className="truncate" title={data.subtitle}>
          {data.subtitle}
        </span>
        {data.ruleSetTag && (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[10px]">
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{
                backgroundColor: data.ruleSetCached
                  ? "var(--success-dot)"
                  : "var(--text-tertiary)",
              }}
            />
            <span className="max-w-[92px] truncate">{data.ruleSetTag}</span>
          </span>
        )}
      </div>

      <Handle
        id="out"
        type="source"
        position={Position.Right}
        className={`bypax-flow-handle ${
          data.enabled ? "bypax-flow-handle-connected" : ""
        }`}
      />
    </div>
  );
}

function RoutingExitCard({ data }: NodeProps<Node<ExitNodeData, "routingExit">>) {
  const handleClass =
    data.kind === "direct"
      ? "bypax-flow-handle bypax-flow-handle-success"
      : data.kind === "reject"
        ? "bypax-flow-handle bypax-flow-handle-danger"
        : "bypax-flow-handle bypax-flow-handle-connected";

  return (
    <div
      onMouseEnter={() => data.onHover?.(`${EXIT_PREFIX}${data.targetValue}`)}
      onMouseLeave={() => data.onHover?.(null)}
      onClick={() => {
        if (data.wireCandidate) {
          data.onCompleteWire?.();
        }
      }}
      className={`w-[244px] rounded-[13px] border bg-[var(--bg-surface)] px-3 py-2.5 shadow-[var(--shadow-card)] transition-all ${
        data.isHit || data.wireCandidate
          ? "border-[var(--accent-focus)] hit-ring cursor-pointer"
          : data.isDimmed
            ? "border-[var(--border-hairline)] opacity-45"
            : "border-[var(--border-strong)]"
      }`}
    >
      <Handle id="in" type="target" position={Position.Left} className={handleClass} />

      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          {data.kind === "direct" ? (
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[7px] bg-[var(--success-bg)] text-[var(--success-text)]">
              <Globe className="h-3.5 w-3.5" strokeWidth={1.6} />
            </span>
          ) : data.kind === "reject" ? (
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[7px] bg-[var(--danger-bg)] text-[var(--danger-text)]">
              <Ban className="h-3.5 w-3.5" strokeWidth={1.6} />
            </span>
          ) : data.kind === "chain" ? (
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[7px] bg-[var(--accent-soft)] text-[var(--accent-focus)]">
              <Waypoints className="h-3.5 w-3.5" strokeWidth={1.6} />
            </span>
          ) : data.kind === "main" ? (
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[7px] bg-[var(--bg-subtle)] text-[var(--accent-focus)]">
              <Shield className="h-3.5 w-3.5" strokeWidth={1.6} />
            </span>
          ) : data.regionCode ? (
            <RegionFlag code={data.regionCode} size="sm" />
          ) : (
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-[7px] bg-[var(--bg-subtle)] text-[var(--text-secondary)]">
              <Sparkles className="h-3.5 w-3.5" strokeWidth={1.5} />
            </span>
          )}

          <div className="min-w-0">
            <div
              className="truncate text-[12.5px] font-semibold text-[var(--text-primary)]"
              title={data.title}
            >
              {data.title}
            </div>
            {data.subtitle && (
              <div
                className="truncate text-[11px] text-[var(--text-secondary)]"
                title={data.subtitle}
              >
                {data.subtitle}
              </div>
            )}
          </div>
        </div>

        <div className="nodrag nopan flex shrink-0 items-center gap-1">
          {data.hopBadge && (
            <span className="rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold text-[var(--accent-focus)]">
              {data.hopBadge}
            </span>
          )}
          {data.protocolBadge && (
            <span className="rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[10.5px] text-[var(--text-secondary)]">
              {data.protocolBadge}
            </span>
          )}
          {data.onOpenChain && (
            <button
              type="button"
              aria-label="Edit proxy chain"
              onClick={(e) => {
                e.stopPropagation();
                data.onOpenChain?.();
              }}
              className="ui-btn-ghost h-6 w-6 p-0"
            >
              <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.6} />
            </button>
          )}
          {data.canUnpin && data.onUnpin && (
            <button
              type="button"
              aria-label="Unpin node"
              onClick={(e) => {
                e.stopPropagation();
                data.onUnpin?.();
              }}
              className="ui-btn-ghost h-6 w-6 p-0"
            >
              <X className="h-3 w-3" strokeWidth={1.6} />
            </button>
          )}
        </div>
      </div>

      {data.latencyMs !== undefined && (
        <div className="mt-1.5 flex items-center justify-end gap-1.5 font-mono text-[11px] font-medium num-tabular">
          <SignalBars ms={data.latencyMs} />
          <span style={{ color: delayColorVar(data.latencyMs) }}>
            {formatLatency(data.latencyMs)}
          </span>
        </div>
      )}
    </div>
  );
}

const NODE_TYPES = {
  routingHub: RoutingHubCard,
  routingRule: RoutingRuleCard,
  routingExit: RoutingExitCard,
};

const EDGE_TYPES = {
  bypaxEdge: FlowEdge,
};

function readSavedPositions(): Record<string, { x: number; y: number }> {
  try {
    const raw = window.localStorage.getItem(LAYOUT_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, { x: number; y: number }>;
    }
  } catch {
    // ignore storage errors
  }
  return {};
}

function writeSavedPositions(map: Record<string, { x: number; y: number }>) {
  try {
    window.localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(map));
  } catch {
    // ignore
  }
}

function RoutingFlowInner({
  dict,
  locale,
  routeMode,
  nodes,
  chains,
  rules,
  ruleSets,
  mainNodeId,
  mixedPort,
  testInput,
  onChangeTestInput,
  testResult,
  testingRoute,
  activeMatchedRuleId,
  displayMatchedRule,
  displayExitLabel,
  displayDns,
  onRunRouteTest,
  onSaveRule,
  onEditRule,
  onOpenChains,
}: RoutingFlowCanvasProps) {
  const { fitView } = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  const [savedPositions, setSavedPositions] = useState<Record<string, { x: number; y: number }>>(
    readSavedPositions,
  );
  const [pinnedNodeIds, setPinnedNodeIds] = useState<string[]>([]);
  const [pinMenuOpen, setPinMenuOpen] = useState(false);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [wiringRuleId, setWiringRuleId] = useState<string | null>(null);
  const pinMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (
        pinMenuOpen &&
        pinMenuRef.current &&
        !pinMenuRef.current.contains(e.target as globalThis.Node | null)
      ) {
        setPinMenuOpen(false);
      }
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [pinMenuOpen]);

  const presets = dict.routing.presetTitles as Record<string, string>;
  const regionNames = dict.routing.regions as Record<string, string>;
  const availableRegions = useMemo(() => computeAvailableRegions(nodes), [nodes]);
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const ruleSetMap = useMemo(
    () => new Map(ruleSets.map((s) => [s.tag, s])),
    [ruleSets],
  );
  const targetLabels = useMemo(
    () => ({
      direct: dict.routing.optDirect,
      reject: dict.routing.optReject,
      noNode: dict.nav.noNodeSelected,
    }),
    [dict],
  );

  // Build canonical right-column exit target list (core + chains + active/top auto regions + referenced/pinned nodes)
  const exitEntries = useMemo(() => {
    const seen = new Set<string>();
    const list: Array<{
      targetValue: string;
      kind: ExitNodeData["kind"];
      title: string;
      subtitle?: string;
      regionCode?: string | null;
      latencyMs?: number | null;
      protocolBadge?: string;
      hopBadge?: string;
      canUnpin?: boolean;
      chainId?: string;
      nodeId?: string;
    }> = [];

    const pushUnique = (entry: (typeof list)[number]) => {
      if (seen.has(entry.targetValue)) return;
      seen.add(entry.targetValue);
      list.push(entry);
    };

    // 1. Main Exit
    const mainResolved = resolveTargetExit("main", nodes, mainNodeId, targetLabels, chains);
    pushUnique({
      targetValue: "main",
      kind: "main",
      title: dict.routing.optMain,
      subtitle: mainResolved.label,
      latencyMs:
        mainResolved.kind === "chain"
          ? mainResolved.chain?.realDelayMs ?? null
          : mainResolved.node?.realDelayMs ?? null,
    });

    // 2. Direct & Reject
    pushUnique({
      targetValue: "direct",
      kind: "direct",
      title: dict.routing.optDirect,
      subtitle: dict.routing.canvasDirectSub,
    });
    pushUnique({
      targetValue: "reject",
      kind: "reject",
      title: dict.routing.optReject,
      subtitle: dict.routing.canvasRejectSub,
    });

    // 3. Saved Proxy Chains
    for (const c of chains) {
      const hopPreview = c.hops
        .map((hid) => nodeById.get(hid)?.region || "?")
        .join(" -> ");
      pushUnique({
        targetValue: `chain:${c.id}`,
        kind: "chain",
        title: c.name,
        subtitle: hopPreview,
        hopBadge: `${c.hops.length}H`,
        latencyMs: c.realDelayMs ?? null,
        chainId: c.id,
      });
    }

    // 4. Auto regions referenced by rules + top 3 regions + auto:ALL if referenced
    const referencedAutoTargets = rules
      .map((r) => r.target)
      .filter((t) => t.startsWith("auto:"));
    const regionTargets = new Set<string>(referencedAutoTargets);
    for (const b of availableRegions.slice(0, 3)) {
      regionTargets.add(`auto:${b.code}`);
    }
    for (const target of regionTargets) {
      const code = target.slice("auto:".length).toUpperCase();
      const resolved = resolveTargetExit(target, nodes, mainNodeId, targetLabels, chains);
      pushUnique({
        targetValue: target,
        kind: "auto",
        title:
          code === "ALL"
            ? dict.routing.optAutoAll
            : `${dict.routing.optAutoRegionPrefix} ${regionNames[code] ?? code}`,
        subtitle: resolved.node ? resolved.node.remark : undefined,
        regionCode: code === "ALL" ? null : code,
        latencyMs: resolved.node?.realDelayMs ?? null,
      });
    }

    // 5. Referenced specific nodes + user-pinned nodes
    const referencedNodeIds = new Set<string>();
    for (const r of rules) {
      if (
        r.target !== "main" &&
        r.target !== "direct" &&
        r.target !== "reject" &&
        !r.target.startsWith("auto:") &&
        !r.target.startsWith("chain:")
      ) {
        referencedNodeIds.add(r.target.replace(/^node:/, ""));
      }
    }
    for (const nid of [...referencedNodeIds, ...pinnedNodeIds]) {
      const node = nodeById.get(nid);
      if (!node) continue;
      pushUnique({
        targetValue: node.id,
        kind: "node",
        title: node.remark,
        subtitle: `${node.server}:${node.port}`,
        regionCode: node.region,
        protocolBadge: PROTO_BADGES[node.protocol],
        latencyMs: node.realDelayMs ?? null,
        canUnpin: !referencedNodeIds.has(node.id),
        nodeId: node.id,
      });
    }

    return list;
  }, [
    availableRegions,
    chains,
    dict.routing,
    mainNodeId,
    nodeById,
    nodes,
    pinnedNodeIds,
    regionNames,
    rules,
    targetLabels,
  ]);

  // Determine active route-test hit exit target
  const hitExitTarget = useMemo(() => {
    if (!testResult) return null;
    if (testResult.isPrivateIp || testResult.routeMode === "direct") return "direct";
    if (testResult.routeMode === "global") return "main";
    if (activeMatchedRuleId) {
      const matched = rules.find((r) => r.id === activeMatchedRuleId);
      if (matched) return matched.target.replace(/^node:/, "");
    }
    return "main";
  }, [activeMatchedRuleId, rules, testResult]);

  const fallbackIsHit = Boolean(
    testResult &&
      routeMode === "rule" &&
      activeMatchedRuleId === null &&
      !testResult.isPrivateIp,
  );

  const rewireRuleToExit = useCallback(
    (ruleId: string, exitTargetValue: string) => {
      const rule = rules.find((r) => r.id === ruleId);
      if (!rule || rule.target === exitTargetValue) return;
      onSaveRule({ ...rule, target: exitTargetValue });
      setWiringRuleId(null);
    },
    [onSaveRule, rules],
  );

  const computedGraph = useMemo(() => {
    const col1X = 28;
    const col2X = 284;
    const col3X = 640;
    const ruleStepY = 82;
    const exitStepY = 78;

    const totalRulesH = (rules.length + 1) * ruleStepY;
    const totalExitsH = Math.max(1, exitEntries.length) * exitStepY;
    const maxH = Math.max(totalRulesH, totalExitsH, 320);

    const hubDefaultPos = { x: col1X, y: Math.max(40, Math.round(maxH / 2 - 48)) };
    const modeLabel =
      routeMode === "direct"
        ? dict.titlebar.modeDirect
        : routeMode === "global"
          ? dict.titlebar.modeGlobal
          : dict.titlebar.modeRule;

    const nextNodes: RoutingCanvasNode[] = [
      {
        id: INPUT_HUB_ID,
        type: "routingHub",
        position: savedPositions[INPUT_HUB_ID] ?? hubDefaultPos,
        data: {
          title: dict.routing.canvasInputHub,
          modeLabel,
          mixedPort,
          activeRulesCount: rules.filter((r) => r.enabled).length,
        },
      },
    ];

    const nextEdges: BypaxFlowEdge[] = [];

    const hoveredRuleId =
      hoveredId && hoveredId.startsWith(RULE_PREFIX)
        ? hoveredId.slice(RULE_PREFIX.length)
        : null;
    const hoveredExitVal =
      hoveredId && hoveredId.startsWith(EXIT_PREFIX)
        ? hoveredId.slice(EXIT_PREFIX.length)
        : null;

    // Column 2: Rules
    rules.forEach((r, idx) => {
      const canvasId = `${RULE_PREFIX}${r.id}`;
      const normTarget = r.target.replace(/^node:/, "");
      const exitCanvasId = `${EXIT_PREFIX}${normTarget}`;
      const isHit = activeMatchedRuleId === r.id && routeMode === "rule";
      const isRelatedHover =
        !hoveredId ||
        hoveredId === canvasId ||
        (hoveredExitVal !== null && hoveredExitVal === normTarget);

      nextNodes.push({
        id: canvasId,
        type: "routingRule",
        position: savedPositions[canvasId] ?? { x: col2X, y: 24 + idx * ruleStepY },
        data: {
          rule: r,
          title: presets[r.id] ?? (locale === "en" ? r.titleEn : r.title),
          subtitle: r.description,
          priorityBadge: `#${idx + 1}`,
          ruleSetTag: r.ruleSet ?? null,
          ruleSetCached: r.ruleSet ? ruleSetMap.get(r.ruleSet)?.cachedLocally : false,
          enabled: r.enabled,
          isHit,
          isDimmed: Boolean(hoveredId) && !isRelatedHover,
          wireActive: wiringRuleId === r.id,
          onToggleEnabled: () => onSaveRule({ ...r, enabled: !r.enabled }),
          onEdit: () => onEditRule(r),
          onStartWire: () =>
            setWiringRuleId((prev) => (prev === r.id ? null : r.id)),
          onHover: setHoveredId,
        },
      });

      // Hub -> Rule edge
      nextEdges.push({
        id: `e:${INPUT_HUB_ID}->${canvasId}`,
        type: "bypaxEdge",
        source: INPUT_HUB_ID,
        sourceHandle: "out",
        target: canvasId,
        targetHandle: "in",
        data: {
          variant: isHit
            ? "hit"
            : hoveredId && !isRelatedHover
              ? "dimmed"
              : "default",
          animated: isHit,
        },
      });

      // Rule -> Exit edge (if exit node exists)
      if (exitEntries.some((e) => e.targetValue === normTarget)) {
        const edgeVariant: FlowEdgeVariant = isHit
          ? "hit"
          : hoveredId && !isRelatedHover
            ? "dimmed"
            : !r.enabled
              ? "dimmed"
              : normTarget === "direct"
                ? "direct"
                : normTarget === "reject"
                  ? "reject"
                  : normTarget.startsWith("chain:")
                    ? "chain"
                    : "proxy";

        nextEdges.push({
          id: `e:${canvasId}->${exitCanvasId}`,
          type: "bypaxEdge",
          source: canvasId,
          sourceHandle: "out",
          target: exitCanvasId,
          targetHandle: "in",
          markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13 },
          data: {
            variant: edgeVariant,
            animated: isHit || (r.enabled && normTarget.startsWith("chain:") && edgeVariant !== "dimmed"),
          },
        });
      }
    });

    // Column 2 bottom: Default Fallback
    const fbRelatedHover =
      !hoveredId || hoveredId === FALLBACK_ID || hoveredExitVal === "main";
    nextNodes.push({
      id: FALLBACK_ID,
      type: "routingRule",
      position: savedPositions[FALLBACK_ID] ?? {
        x: col2X,
        y: 24 + rules.length * ruleStepY,
      },
      data: {
        rule: null,
        isFallback: true,
        title: dict.routing.fallbackTitle,
        subtitle: dict.routing.alwaysOn,
        priorityBadge: "END",
        enabled: true,
        isHit: fallbackIsHit,
        isDimmed: Boolean(hoveredId) && !fbRelatedHover,
        wireActive: false,
        onHover: setHoveredId,
      },
    });

    nextEdges.push(
      {
        id: `e:${INPUT_HUB_ID}->${FALLBACK_ID}`,
        type: "bypaxEdge",
        source: INPUT_HUB_ID,
        sourceHandle: "out",
        target: FALLBACK_ID,
        targetHandle: "in",
        data: {
          variant: fallbackIsHit
            ? "hit"
            : hoveredId && !fbRelatedHover
              ? "dimmed"
              : "default",
          animated: fallbackIsHit,
        },
      },
      {
        id: `e:${FALLBACK_ID}->${EXIT_PREFIX}main`,
        type: "bypaxEdge",
        source: FALLBACK_ID,
        sourceHandle: "out",
        target: `${EXIT_PREFIX}main`,
        targetHandle: "in",
        markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13 },
        data: {
          variant: fallbackIsHit
            ? "hit"
            : hoveredId && !fbRelatedHover
              ? "dimmed"
              : "proxy",
          animated: fallbackIsHit,
        },
      },
    );

    // Column 3: Outbound Exits
    exitEntries.forEach((entry, idx) => {
      const canvasId = `${EXIT_PREFIX}${entry.targetValue}`;
      const isHit = hitExitTarget === entry.targetValue;
      const isRelatedHover =
        !hoveredId ||
        hoveredId === canvasId ||
        (hoveredId === FALLBACK_ID && entry.targetValue === "main") ||
        (hoveredRuleId !== null &&
          rules.find((r) => r.id === hoveredRuleId)?.target.replace(/^node:/, "") ===
            entry.targetValue);

      nextNodes.push({
        id: canvasId,
        type: "routingExit",
        position: savedPositions[canvasId] ?? { x: col3X, y: 24 + idx * exitStepY },
        data: {
          targetValue: entry.targetValue,
          kind: entry.kind,
          title: entry.title,
          subtitle: entry.subtitle,
          regionCode: entry.regionCode,
          latencyMs: entry.latencyMs,
          protocolBadge: entry.protocolBadge,
          hopBadge: entry.hopBadge,
          isHit,
          isDimmed: Boolean(hoveredId) && !isRelatedHover,
          wireCandidate: wiringRuleId !== null,
          canUnpin: entry.canUnpin,
          onCompleteWire: () => {
            if (wiringRuleId) rewireRuleToExit(wiringRuleId, entry.targetValue);
          },
          onUnpin: entry.nodeId
            ? () =>
                setPinnedNodeIds((prev) => prev.filter((id) => id !== entry.nodeId))
            : undefined,
          onOpenChain: entry.chainId
            ? () => onOpenChains(entry.chainId)
            : undefined,
          onHover: setHoveredId,
        },
      });
    });

    return { nextNodes, nextEdges };
  }, [
    activeMatchedRuleId,
    dict.routing,
    dict.titlebar,
    exitEntries,
    fallbackIsHit,
    hitExitTarget,
    hoveredId,
    locale,
    mixedPort,
    onEditRule,
    onOpenChains,
    onSaveRule,
    presets,
    rewireRuleToExit,
    routeMode,
    ruleSetMap,
    rules,
    savedPositions,
    wiringRuleId,
  ]);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<RoutingCanvasNode>(
    computedGraph.nextNodes,
  );
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<BypaxFlowEdge>(
    computedGraph.nextEdges,
  );

  useEffect(() => {
    setRfNodes(computedGraph.nextNodes);
    setRfEdges(computedGraph.nextEdges);
  }, [computedGraph, setRfEdges, setRfNodes]);

  useEffect(() => {
    if (!nodesInitialized) return;
    const timer = window.setTimeout(() => {
      void fitView({ padding: 0.14, maxZoom: 1.05, duration: 150 });
    }, 30);
    return () => window.clearTimeout(timer);
  }, [nodesInitialized, fitView]);

  const handleNodeDragStop = useCallback(
    (_event: unknown, node: RoutingCanvasNode) => {
      setSavedPositions((prev) => {
        const merged = {
          ...prev,
          [node.id]: {
            x: Math.round(node.position.x),
            y: Math.round(node.position.y),
          },
        };
        writeSavedPositions(merged);
        return merged;
      });
    },
    [],
  );

  const handleConnect = useCallback(
    (conn: Connection) => {
      if (!conn.source || !conn.target) return;
      if (!conn.source.startsWith(RULE_PREFIX) || !conn.target.startsWith(EXIT_PREFIX)) {
        return;
      }
      const ruleId = conn.source.slice(RULE_PREFIX.length);
      const exitTarget = conn.target.slice(EXIT_PREFIX.length);
      rewireRuleToExit(ruleId, exitTarget);
    },
    [rewireRuleToExit],
  );

  const isValidConnection = useCallback((conn: Edge | Connection) => {
    return Boolean(
      conn.source?.startsWith(RULE_PREFIX) && conn.target?.startsWith(EXIT_PREFIX),
    );
  }, []);

  const handleAutoLayout = () => {
    setSavedPositions({});
    writeSavedPositions({});
    window.requestAnimationFrame(() => {
      void fitView({ padding: 0.16, duration: 220 });
    });
  };

  const pinnableNodes = useMemo(() => {
    const shown = new Set(exitEntries.map((e) => e.targetValue));
    return nodes.filter((n) => !shown.has(n.id));
  }, [exitEntries, nodes]);

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Compact Non-Overlapping Studio Toolbar (Route Tester + Pin Node + Auto Layout) */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 py-2 lg:px-5">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
          <div className="flex min-w-[200px] max-w-[340px] flex-1 items-center gap-1.5">
            <label htmlFor="bypax-flow-route-test" className="sr-only">
              {dict.routing.testTitle}
            </label>
            <input
              id="bypax-flow-route-test"
              type="text"
              value={testInput}
              onChange={(e) => onChangeTestInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.nativeEvent.isComposing || e.keyCode === 229) return;
                if (e.key === "Enter") onRunRouteTest();
              }}
              placeholder={dict.routing.simPlaceholder}
              className="ui-input h-8 min-w-0 flex-1 px-2.5 font-mono text-[12px]"
            />
            <button
              type="button"
              disabled={testingRoute || !testInput.trim()}
              onClick={() => onRunRouteTest()}
              className="ui-btn-primary h-8 shrink-0 px-2.5 text-[12px]"
            >
              <Play className="h-3 w-3" strokeWidth={1.6} />
              {dict.routing.testBtn}
            </button>
          </div>

          <div className="hidden items-center gap-1 xl:flex">
            {["chatgpt.com", "github.com", "baidu.com", "192.168.1.1"].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => {
                  onChangeTestInput(sample);
                  onRunRouteTest(sample);
                }}
                className="rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-mono text-[11px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                {sample}
              </button>
            ))}
          </div>

          {/* Live Test Hit Pill */}
          <div className="inline-flex max-w-[340px] items-center gap-1.5 rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2.5 py-1 text-[11.5px]">
            <span className="truncate font-medium text-[var(--text-primary)]">
              {displayMatchedRule}
            </span>
            <ArrowRight className="h-3 w-3 shrink-0 text-[var(--text-tertiary)]" strokeWidth={1.6} />
            <span className="truncate font-semibold text-[var(--accent-focus)]">
              {displayExitLabel}
            </span>
            <span className="shrink-0 font-mono text-[10.5px] text-[var(--text-secondary)]">
              {"\u00b7"} {displayDns}
            </span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {/* Pin Specific Node Menu */}
          <div ref={pinMenuRef} className="relative">
            <button
              type="button"
              disabled={pinnableNodes.length === 0}
              onClick={() => setPinMenuOpen((v) => !v)}
              className="ui-btn-secondary h-8 text-[11.5px]"
            >
              <Pin className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
              {dict.routing.canvasPinNode}
            </button>
            {pinMenuOpen && (
              <div className="ui-popover absolute right-0 top-9 z-40 max-h-64 w-64 space-y-0.5 overflow-y-auto p-1.5">
                {pinnableNodes.map((n) => (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() => {
                      setPinnedNodeIds((prev) => [...prev, n.id]);
                      setPinMenuOpen(false);
                    }}
                    className="flex w-full items-center justify-between gap-2 rounded-[8px] px-2.5 py-1.5 text-left text-[12px] text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                  >
                    <NodeLabel remark={n.remark} region={n.region} size="xs" />
                    <span
                      className="shrink-0 font-mono text-[11px] num-tabular"
                      style={{ color: delayColorVar(n.realDelayMs) }}
                    >
                      {formatLatency(n.realDelayMs)}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={handleAutoLayout}
            className="ui-btn-secondary h-8 text-[11.5px]"
          >
            <LayoutGrid className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            {dict.routing.canvasAutoLayout}
          </button>

          <button
            type="button"
            aria-label={dict.routing.canvasFitView}
            title={dict.routing.canvasFitView}
            onClick={() => void fitView({ padding: 0.16, duration: 220 })}
            className="ui-btn-secondary h-8 w-8 p-0"
          >
            <Maximize2 className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
          </button>
        </div>
      </div>

      {/* Interactive ReactFlow Canvas */}
      <div className="relative min-h-0 flex-1 overflow-hidden">
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
          onNodesChange={onNodesChange}
          onNodeDragStop={handleNodeDragStop}
          onEdgesChange={onEdgesChange}
          onConnect={handleConnect}
          isValidConnection={isValidConnection}
          onPaneClick={() => setWiringRuleId(null)}
          fitView
          fitViewOptions={{ padding: 0.14, maxZoom: 1.05 }}
          minZoom={0.4}
          maxZoom={1.5}
          className="bypax-flow h-full w-full"
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={18}
            size={1.2}
            color="var(--border-strong)"
          />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
      </div>

      {/* Non-Overlapping Studio Footer Hint Bar */}
      <div className="flex h-7 shrink-0 items-center justify-between gap-2 border-t border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 text-[11px] text-[var(--text-secondary)] lg:px-5">
        <span
          className="truncate"
          style={wiringRuleId ? { color: "var(--accent-focus)", fontWeight: 500 } : undefined}
        >
          {wiringRuleId
            ? dict.routing.canvasClickExitHint
            : dict.routing.canvasDragHint}
        </span>
        <span className="shrink-0 font-mono num-tabular text-[var(--text-tertiary)]">
          {rules.filter((r) => r.enabled).length} / {rules.length}
        </span>
      </div>
    </div>
  );
}

export function RoutingFlowCanvas(props: RoutingFlowCanvasProps) {
  return (
    <ReactFlowProvider>
      <RoutingFlowInner {...props} />
    </ReactFlowProvider>
  );
}
