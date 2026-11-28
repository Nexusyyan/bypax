import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowUpDown,
  Check,
  Copy,
  Download,
  FolderOpen,
  Gauge,
  Link2,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { BrandLogo } from "../../components/BrandLogo";
import { NodeLabel } from "../../components/RegionFlag";
import { SignalBars } from "../../components/SignalBars";
import type { Dict } from "../../i18n";
import type {
  CoreInfo,
  LatencyProgressEvent,
  NodeIR,
  SimpleRoutingRule,
  SubscriptionGroup,
} from "../../types";
import {
  delayColorVar,
  filterAndSortNodes,
  formatLatency,
  middleTruncate,
  PROTO_BADGES,
  resolveTargetExit,
  SAMPLE_SHARE_URIS,
  type NodeSortMode,
} from "../../utils/nodes";

interface NodesViewProps {
  dict: Dict;
  coreInfo: CoreInfo;
  nodes: NodeIR[];
  subscriptions: SubscriptionGroup[];
  rules: SimpleRoutingRule[];
  mainNodeId?: string | null;
  testingLatency: boolean;
  testProgress: LatencyProgressEvent | null;
  testAvgMs?: number | null;
  downloadingCore: boolean;
  coreDownloadPercent?: number | null;
  onDownloadCore: () => Promise<void>;
  onImportCoreBinary: () => Promise<void>;
  onSelectMainNode: (id: string) => void;
  onDeleteNode: (id: string) => void;
  onCopyText: (text: string) => void;
  onRunRealDelayTest: (nodeIds: string[]) => void;
  onImportPayload: (payload: string, groupName: string) => Promise<void>;
  onImportSubscription: (name: string, url: string) => Promise<void>;
  onRefreshSubscription: (id: string) => Promise<void>;
  onDeleteSubscription: (id: string) => Promise<void>;
}

function compactRuleTag(title: string): string {
  return title.replace(/\s*\((?:Geosite|GeoIP)\)\s*$/i, "").trim();
}

export function NodesView({
  dict,
  coreInfo,
  nodes,
  subscriptions,
  rules,
  mainNodeId,
  testingLatency,
  testProgress,
  testAvgMs,
  downloadingCore,
  coreDownloadPercent,
  onDownloadCore,
  onImportCoreBinary,
  onSelectMainNode,
  onDeleteNode,
  onCopyText,
  onRunRealDelayTest,
  onImportPayload,
  onImportSubscription,
  onRefreshSubscription,
  onDeleteSubscription,
}: NodesViewProps) {
  const [activeGroup, setActiveGroup] = useState<string>("ALL");
  const [query, setQuery] = useState<string>("");
  const [sortMode, setSortMode] = useState<NodeSortMode>("default");
  const [showImport, setShowImport] = useState(false);
  const [importTab, setImportTab] = useState<"paste" | "sub">("paste");
  const [importGroup, setImportGroup] = useState("");
  const [importPayload, setImportPayload] = useState("");
  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [importing, setImporting] = useState(false);
  const [showSubs, setShowSubs] = useState(false);
  const [refreshingSubId, setRefreshingSubId] = useState<string | null>(null);
  const [failedSubIds, setFailedSubIds] = useState<Set<string>>(new Set());
  const [hoveredTags, setHoveredTags] = useState<{
    tags: string[];
    x: number;
    y: number;
    placeBelow: boolean;
  } | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    node: NodeIR;
    x: number;
    y: number;
  } | null>(null);
  const contextMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setShowImport(false);
        setShowSubs(false);
        setContextMenu(null);
      }
    };
    const onPointer = (e: MouseEvent) => {
      if (
        contextMenu &&
        contextMenuRef.current &&
        !contextMenuRef.current.contains(e.target as Node)
      ) {
        setContextMenu(null);
      }
    };
    const onWindowBlurOrResize = () => setContextMenu(null);
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("resize", onWindowBlurOrResize);
    window.addEventListener("blur", onWindowBlurOrResize);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("resize", onWindowBlurOrResize);
      window.removeEventListener("blur", onWindowBlurOrResize);
    };
  }, [contextMenu]);

  const openNodeContextMenu = (e: React.MouseEvent, node: NodeIR) => {
    e.preventDefault();
    e.stopPropagation();
    const menuWidth = 224;
    const menuHeight = node.rawUri ? 268 : 236;
    const pad = 10;
    const x = Math.max(pad, Math.min(e.clientX, window.innerWidth - menuWidth - pad));
    const y = Math.max(pad, Math.min(e.clientY, window.innerHeight - menuHeight - pad));
    setHoveredTags(null);
    setContextMenu({ node, x, y });
  };

  const groups = useMemo(() => {
    const names = Array.from(new Set(nodes.map((n) => n.group)));
    return ["ALL", ...names];
  }, [nodes]);

  const visibleNodes = useMemo(
    () => filterAndSortNodes(nodes, activeGroup, query, sortMode),
    [nodes, activeGroup, query, sortMode],
  );

  const ruleUsageMap = useMemo(() => {
    const map = new Map<string, string[]>();
    const labels = {
      direct: dict.routing.optDirect,
      reject: dict.routing.optReject,
      noNode: dict.nav.noNodeSelected,
    };
    const presets = dict.routing.presetTitles as Record<string, string>;
    for (const r of rules) {
      if (!r.enabled || r.target === "direct" || r.target === "reject" || r.target === "main") {
        continue;
      }
      const res = resolveTargetExit(r.target, nodes, mainNodeId, labels);
      if (res.node) {
        const title = presets[r.id] ?? r.title;
        const arr = map.get(res.node.id) ?? [];
        arr.push(title);
        map.set(res.node.id, arr);
      }
    }
    return map;
  }, [rules, nodes, mainNodeId, dict]);

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const virtualizer = useVirtualizer({
    count: visibleNodes.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 44,
    overscan: 12,
  });

  const cycleSort = () => {
    setSortMode((prev) =>
      prev === "default" ? "delay" : prev === "delay" ? "name" : "default",
    );
  };

  const sortLabel =
    sortMode === "delay"
      ? dict.nodes.sortDelay
      : sortMode === "name"
        ? dict.nodes.sortName
        : dict.nodes.sortDefault;

  const handleConfirmImport = async () => {
    setImporting(true);
    try {
      if (importTab === "paste") {
        if (!importPayload.trim()) return;
        await onImportPayload(
          importPayload,
          importGroup.trim() || dict.nodes.groupNamePlaceholder,
        );
        setImportPayload("");
        setImportGroup("");
        setShowImport(false);
      } else {
        if (!subUrl.trim()) return;
        await onImportSubscription(
          subName.trim() || dict.nodes.subNamePlaceholder,
          subUrl.trim(),
        );
        setSubName("");
        setSubUrl("");
        setShowImport(false);
      }
    } finally {
      setImporting(false);
    }
  };

  const handleSubRefresh = async (id: string) => {
    setRefreshingSubId(id);
    try {
      await onRefreshSubscription(id);
      setFailedSubIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    } catch {
      setFailedSubIds((prev) => new Set(prev).add(id));
    } finally {
      setRefreshingSubId(null);
    }
  };

  const progressTotal = testProgress?.total ?? visibleNodes.length;
  const progressDone = testProgress?.completed ?? 0;
  const progressPct =
    progressTotal > 0 ? Math.min(100, Math.round((progressDone / progressTotal) * 100)) : 0;
  const isStartingPhase = testingLatency && testProgress?.phase === "starting";
  const modeTag =
    testProgress?.stripHandshake === false
      ? dict.nodes.testingColdTag
      : dict.nodes.testingUnifiedTag;
  const latestNode = useMemo(() => {
    const id = testProgress?.latest?.nodeId;
    if (!id) return null;
    return nodes.find((n) => n.id === id) ?? null;
  }, [testProgress?.latest?.nodeId, nodes]);
  const latestDelayMs = testProgress?.latest?.delayMs ?? null;

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Unified Single-Row 40px Page Header */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <h1 className="text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
          {dict.nodes.title}
        </h1>

        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            disabled={testingLatency || visibleNodes.length === 0}
            onClick={() => onRunRealDelayTest(visibleNodes.map((n) => n.id))}
            className={nodes.length === 0 ? "ui-btn-secondary h-8" : "ui-btn-primary h-8"}
          >
            <Gauge
              className={`h-3.5 w-3.5 ${nodes.length === 0 ? "text-[var(--text-secondary)]" : ""}`}
              strokeWidth={1.5}
            />
            {dict.nodes.realDelay}
          </button>

          <button
            type="button"
            onClick={() => setShowSubs(true)}
            className="ui-btn-secondary h-8"
          >
            <Link2 className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            <span>{dict.nodes.subsBtn}</span>
            {subscriptions.length > 0 && (
              <span className="font-mono text-[11.5px] text-[var(--text-secondary)] num-tabular">
                {subscriptions.length}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setShowImport(true)}
            className={nodes.length === 0 ? "ui-btn-primary h-8" : "ui-btn-secondary h-8"}
          >
            <Plus
              className={`h-3.5 w-3.5 ${nodes.length === 0 ? "" : "text-[var(--text-secondary)]"}`}
              strokeWidth={1.5}
            />
            {dict.nodes.importBtn}
          </button>
        </div>
      </div>

      {/* Group Tabs + Search Bar (hidden when 0 nodes) */}
      {nodes.length > 0 && (
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2 lg:px-5">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {groups.map((g) => {
              const active = activeGroup === g;
              const count =
                g === "ALL" ? nodes.length : nodes.filter((n) => n.group === g).length;
              return (
                <button
                  key={g}
                  type="button"
                  onClick={() => setActiveGroup(g)}
                  className={`rounded-[9px] px-2.5 py-1 text-[12px] font-medium transition-colors cursor-pointer ${
                    active
                      ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                      : "border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span>{g === "ALL" ? dict.nodes.groupAll : g}</span>
                  <span className="ml-1.5 font-mono text-[11.5px] opacity-75 num-tabular">
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search
                className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]"
                strokeWidth={1.5}
              />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={dict.nodes.searchPlaceholder}
                className="ui-input h-8 w-44 pr-3 pl-8 text-[12px] xl:w-56"
              />
            </div>
            <button
              type="button"
              onClick={cycleSort}
              className="ui-btn-secondary h-8 shrink-0 px-2.5 font-mono text-[11.5px] text-[var(--text-secondary)]"
            >
              <ArrowUpDown className="h-3 w-3 text-[var(--text-secondary)]" strokeWidth={1.5} />
              {sortLabel}
            </button>
          </div>
        </div>
      )}

      {/* Offline-First Core Setup Banner */}
      {!coreInfo.installed && (
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-4 py-2 text-[12px] lg:px-5">
          <span className="text-[var(--text-secondary)]">{dict.nodes.coreBannerText}</span>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              onClick={() => void onImportCoreBinary()}
              className="ui-btn-primary h-7 text-[11.5px]"
            >
              <FolderOpen className="h-3.5 w-3.5" strokeWidth={1.5} />
              {dict.nodes.coreBannerImportBtn}
            </button>
            <button
              type="button"
              disabled={downloadingCore}
              onClick={() => void onDownloadCore()}
              className="ui-btn-secondary h-7 text-[11.5px]"
            >
              <Download className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
              {downloadingCore
                ? coreDownloadPercent != null
                  ? `${dict.nodes.coreBannerDownloading} ${coreDownloadPercent}%`
                  : dict.nodes.coreBannerDownloading
                : dict.nodes.coreBannerBtn}
            </button>
          </div>
        </div>
      )}

      {/* Precision Telemetry Progress HUD */}
      {testingLatency && (
        <div className="telemetry-panel shrink-0 space-y-2 border-b border-[var(--border-hairline)] px-4 py-3 text-[12px] lg:px-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <span
                className="h-2 w-2 shrink-0 rounded-full animate-pulse"
                style={{ backgroundColor: "var(--success-dot)" }}
              />
              <span className="font-medium text-[var(--text-primary)]">
                {isStartingPhase ? dict.nodes.testingStarting : dict.nodes.testingReal}
              </span>
              <span className="rounded-[6px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-1.5 py-0.5 font-mono text-[11.5px] font-semibold tracking-wider text-[var(--text-primary)]">
                {modeTag}
              </span>
            </div>
            <div className="flex items-center gap-3 font-mono text-[11px] num-tabular">
              <span style={{ color: "var(--success-text)" }}>
                {dict.nodes.testingPassed} {testProgress?.passed ?? 0}
              </span>
              <span className="text-[var(--text-secondary)]">
                {dict.nodes.testingFailed} {testProgress?.failed ?? 0}
              </span>
              {testAvgMs != null && (
                <span className="text-[var(--text-secondary)]">
                  {dict.nodes.testingAvg} {testAvgMs} ms
                </span>
              )}
              <span className="font-semibold text-[var(--text-primary)]">
                {isStartingPhase ? "--%" : `${progressPct}%`}
              </span>
            </div>
          </div>

          <div className="telemetry-track">
            {isStartingPhase ? (
              <div className="telemetry-radar" />
            ) : (
              <div className="telemetry-fill" style={{ width: `${Math.max(3, progressPct)}%` }}>
                {progressPct > 0 && progressPct < 100 && <span className="telemetry-tip" />}
              </div>
            )}
            <div className="telemetry-ticks" />
          </div>

          <div className="flex items-center justify-between gap-3 font-mono text-[11px] num-tabular">
            <div className="flex min-w-0 items-center gap-2 text-[var(--text-secondary)]">
              {latestNode ? (
                <>
                  <NodeLabel
                    remark={latestNode.remark}
                    region={latestNode.region}
                    size="xs"
                    className="text-[var(--text-primary)]"
                  />
                  <span
                    className="shrink-0 font-medium"
                    style={{
                      color:
                        latestDelayMs != null && latestDelayMs > 0
                          ? delayColorVar(latestDelayMs)
                          : "var(--danger-text)",
                    }}
                  >
                    {latestDelayMs != null && latestDelayMs > 0
                      ? `${latestDelayMs} ms`
                      : "-1ms"}
                  </span>
                </>
              ) : (
                <span className="text-[var(--text-secondary)]">
                  {isStartingPhase ? dict.nodes.testingStarting : `${progressDone} / ${progressTotal}`}
                </span>
              )}
            </div>
            <span className="shrink-0 text-[var(--text-secondary)]">
              {progressDone} / {progressTotal}
            </span>
          </div>
        </div>
      )}

      {/* Empty State (>= 48px Full-Color Rainbow Overpass X Squircle) OR @container Virtualized Table */}
      {visibleNodes.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <BrandLogo variant="color" className="h-14 w-14" />
          <div className="text-[15px] font-semibold text-[var(--text-primary)]">
            {dict.nodes.emptyTitle}
          </div>
          <p className="max-w-md text-[12.5px] text-[var(--text-secondary)]">
            {dict.nodes.emptyDesc}
          </p>
          <div className="mt-2 flex flex-col items-center gap-2">
            <button
              type="button"
              onClick={() => setShowImport(true)}
              className="ui-btn-primary h-9 px-4"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={1.6} />
              {dict.nodes.emptyImportBtn}
            </button>
            {nodes.length === 0 && (
              <button
                type="button"
                title={dict.nodes.sampleTooltip}
                onClick={() =>
                  void onImportPayload(SAMPLE_SHARE_URIS, dict.nodes.demoGroupName)
                }
                className="ui-btn-ghost h-8 text-[12px] text-[var(--text-secondary)]"
              >
                {dict.nodes.importSample}
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="nodes-table-container flex min-h-0 flex-1 flex-col overflow-hidden">
          {/* Header */}
          <div className="nodes-grid shrink-0 border-b border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)] lg:px-5">
            <div>{dict.nodes.colName}</div>
            <div className="nodes-col-proto">{dict.nodes.colProto}</div>
            <div className="nodes-col-server">{dict.nodes.colServer}</div>
            <div className="nodes-col-rules">{dict.nodes.colRules}</div>
            <div className="text-right">{dict.nodes.colReal}</div>
            <div className="nodes-col-actions text-right">{dict.nodes.colAction}</div>
          </div>

          {/* Virtualized Rows */}
          <div
            ref={scrollRef}
            onScroll={() => {
              if (hoveredTags) setHoveredTags(null);
              if (contextMenu) setContextMenu(null);
            }}
            className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden"
          >
            <div
              style={{
                height: `${virtualizer.getTotalSize()}px`,
                width: "100%",
                position: "relative",
              }}
            >
              {virtualizer.getVirtualItems().map((vRow) => {
                const n = visibleNodes[vRow.index];
                const isMain = n.id === mainNodeId;
                const isContextTarget = contextMenu?.node.id === n.id;
                const tags = ruleUsageMap.get(n.id) ?? [];
                const displayMs = n.realDelayMs ?? null;
                const addrText = `${n.server}:${n.port}`;

                return (
                  <div
                    key={n.id}
                    tabIndex={0}
                    onDoubleClick={() => onSelectMainNode(n.id)}
                    onContextMenu={(e) => openNodeContextMenu(e, n)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") onSelectMainNode(n.id);
                    }}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: `${vRow.size}px`,
                      transform: `translateY(${vRow.start}px)`,
                      backgroundColor: isMain
                        ? "var(--accent-soft)"
                        : isContextTarget
                          ? "var(--bg-hover)"
                          : undefined,
                    }}
                    className={`group nodes-grid relative border-b border-[var(--border-hairline)] px-4 text-[12.5px] transition-colors cursor-pointer lg:px-5 ${
                      isMain || isContextTarget ? "" : "hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    {/* P1: Name (Flag + Remark + Group pill + responsive subline) */}
                    <div className="flex min-w-0 flex-col justify-center overflow-hidden">
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{
                            backgroundColor: isMain
                              ? "var(--accent-focus)"
                              : "var(--border-strong)",
                          }}
                        />
                        <div className="min-w-0 flex-1" title={n.remark}>
                          <NodeLabel
                            remark={n.remark}
                            region={n.region}
                            size="md"
                            className="font-medium text-[var(--text-primary)]"
                          />
                        </div>
                        <span
                          title={n.group}
                          className="hidden shrink-0 max-w-[96px] truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11.5px] text-[var(--text-secondary)] xl:inline-block"
                        >
                          {n.group}
                        </span>
                      </div>

                      {/* Folded subline when container < 960px (B3: secondary ink + >=11.5px floor) */}
                      <div className="nodes-subline-meta items-center gap-1.5 pl-3.5 text-[11.5px] text-[var(--text-secondary)]">
                        <span className="nodes-subline-proto rounded-[4px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1 font-mono text-[11.5px] text-[var(--text-secondary)]">
                          {PROTO_BADGES[n.protocol]}
                        </span>
                        <span className="truncate font-mono" title={addrText}>
                          {middleTruncate(addrText, 28)}
                        </span>
                      </div>
                    </div>

                    {/* P2: Protocol */}
                    <div className="nodes-col-proto">
                      <span className="inline-block rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11.5px] font-medium text-[var(--text-primary)]">
                        {PROTO_BADGES[n.protocol]}
                      </span>
                    </div>

                    {/* P3: Address */}
                    <div
                      className="nodes-col-server truncate font-mono text-[11.5px] text-[var(--text-secondary)]"
                      title={addrText}
                    >
                      {middleTruncate(addrText, 24)}
                    </div>

                    {/* P4: Rule usage tags */}
                    <div className="nodes-col-rules min-w-0">
                      {tags.length > 0 ? (
                        <div
                          className="flex items-center gap-1"
                          onMouseEnter={(e) => {
                            const r = e.currentTarget.getBoundingClientRect();
                            const placeBelow = r.top < 150;
                            setHoveredTags({
                              tags,
                              x: Math.max(
                                140,
                                Math.min(r.left + r.width / 2, window.innerWidth - 140),
                              ),
                              y: placeBelow ? r.bottom + 6 : r.top - 6,
                              placeBelow,
                            });
                          }}
                          onMouseLeave={() => setHoveredTags(null)}
                        >
                          <span
                            title={tags.join(", ")}
                            className="max-w-[82px] truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11.5px] text-[var(--text-secondary)]"
                          >
                            {compactRuleTag(tags[0])}
                          </span>
                          {tags.length > 1 && (
                            <span className="shrink-0 rounded-[6px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-1.5 py-0.5 font-mono text-[11.5px] font-medium num-tabular text-[var(--text-primary)]">
                              +{tags.length - 1}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span
                          className={`text-[11.5px] ${
                            isMain ? "text-[var(--text-secondary)]" : "text-[var(--text-tertiary)]"
                          }`}
                        >
                          --
                        </span>
                      )}
                    </div>

                    {/* P1: Dual-Encoded Latency (SignalBars + ms, -1ms on failure) */}
                    <div
                      className="relative flex items-center justify-end gap-1.5 font-mono text-[12px] font-medium num-tabular"
                      title={
                        displayMs != null
                          ? `${dict.nodes.colReal}: ${formatLatency(displayMs)}`
                          : undefined
                      }
                    >
                      <SignalBars ms={displayMs} />
                      <span style={{ color: delayColorVar(displayMs) }}>
                        {formatLatency(displayMs)}
                      </span>

                      {/* Narrow < 760px Hover-Overlay Actions over Latency cell */}
                      <div className="nodes-col-actions-overlay row-actions absolute inset-y-0 right-0 items-center gap-1 bg-[var(--bg-surface)] pl-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectMainNode(n.id);
                          }}
                          className={`rounded-[7px] px-2 py-0.5 text-[11px] font-medium cursor-pointer ${
                            isMain
                              ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                              : "border border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-primary)]"
                          }`}
                        >
                          {isMain ? dict.nodes.actActive : dict.nodes.actUse}
                        </button>
                        <button
                          type="button"
                          aria-label={dict.nodes.actDelete}
                          onClick={(e) => {
                            e.stopPropagation();
                            onDeleteNode(n.id);
                          }}
                          className="ui-btn-danger-ghost h-6 w-6 p-0"
                        >
                          <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
                        </button>
                      </div>
                    </div>

                    {/* P2: Actions (>= 760px, hover-reveal on inactive rows) */}
                    <div className="nodes-col-actions flex items-center justify-end gap-1">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectMainNode(n.id);
                        }}
                        className={`rounded-[7px] px-2.5 py-1 text-[11.5px] font-medium transition-opacity cursor-pointer ${
                          isMain
                            ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                            : "row-actions border border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-primary)] hover:bg-[var(--bg-subtle)]"
                        }`}
                      >
                        {isMain ? dict.nodes.actActive : dict.nodes.actUse}
                      </button>
                      <button
                        type="button"
                        aria-label={dict.nodes.actDelete}
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteNode(n.id);
                        }}
                        className="row-actions ui-btn-danger-ghost h-7 w-7 p-0"
                      >
                        <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Floating Hover Popover for Overflowing Rule Tags */}
      {hoveredTags && (
        <div
          className="ui-popover pointer-events-none fixed z-50 w-max max-w-[260px] p-2.5"
          style={{
            left: `${hoveredTags.x}px`,
            top: `${hoveredTags.y}px`,
            transform: hoveredTags.placeBelow
              ? "translate(-50%, 0)"
              : "translate(-50%, -100%)",
          }}
        >
          <div className="mb-1.5 flex items-center justify-between gap-3 border-b border-[var(--border-hairline)] pb-1 text-[11px] font-medium text-[var(--text-secondary)]">
            <span>{dict.nodes.assignedRulesTitle}</span>
            <span className="font-mono num-tabular text-[var(--text-secondary)]">
              {hoveredTags.tags.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-1">
            {hoveredTags.tags.map((tag) => (
              <span
                key={tag}
                className="rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11px] text-[var(--text-primary)]"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Desktop Node Row Context Menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          role="menu"
          className="ui-popover fixed z-50 min-w-[216px] max-w-[260px] space-y-0.5 p-1.5 text-[12px]"
          style={{ left: `${contextMenu.x}px`, top: `${contextMenu.y}px` }}
          onContextMenu={(e) => e.preventDefault()}
        >
          <div className="mb-1 flex items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-2 pb-1.5">
            <span
              className="truncate font-medium text-[var(--text-primary)]"
              title={contextMenu.node.remark}
            >
              {contextMenu.node.remark}
            </span>
            <span className="shrink-0 rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[10.5px] text-[var(--text-secondary)]">
              {PROTO_BADGES[contextMenu.node.protocol]}
            </span>
          </div>

          <button
            type="button"
            role="menuitem"
            disabled={contextMenu.node.id === mainNodeId}
            onClick={() => {
              onSelectMainNode(contextMenu.node.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-55 cursor-pointer disabled:cursor-default"
          >
            <Check
              className="h-3.5 w-3.5 shrink-0"
              style={{
                color:
                  contextMenu.node.id === mainNodeId
                    ? "var(--accent-focus)"
                    : "var(--text-secondary)",
              }}
              strokeWidth={1.6}
            />
            <span>
              {contextMenu.node.id === mainNodeId ? dict.nodes.ctxIsMain : dict.nodes.ctxUseMain}
            </span>
          </button>

          <button
            type="button"
            role="menuitem"
            disabled={testingLatency}
            onClick={() => {
              onRunRealDelayTest([contextMenu.node.id]);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] disabled:opacity-50 cursor-pointer disabled:cursor-not-allowed"
          >
            <Gauge className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
            <span>{dict.nodes.ctxRealDelay}</span>
          </button>

          <div className="my-1 border-t border-[var(--border-hairline)]" />

          {contextMenu.node.rawUri && (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                if (contextMenu.node.rawUri) onCopyText(contextMenu.node.rawUri);
                setContextMenu(null);
              }}
              className="flex w-full items-center gap-2 whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
            >
              <Link2 className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
              <span>{dict.nodes.ctxCopyUri}</span>
            </button>
          )}

          <button
            type="button"
            role="menuitem"
            onClick={() => {
              onCopyText(`${contextMenu.node.server}:${contextMenu.node.port}`);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
          >
            <Copy className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
            <span>{dict.nodes.ctxCopyAddr}</span>
          </button>

          <div className="my-1 border-t border-[var(--border-hairline)]" />

          <button
            type="button"
            role="menuitem"
            onClick={() => {
              onDeleteNode(contextMenu.node.id);
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--danger-bg-hover)] hover:text-[var(--danger-text-on-bg)] cursor-pointer"
          >
            <Trash2 className="h-3.5 w-3.5 shrink-0" strokeWidth={1.5} />
            <span>{dict.nodes.ctxDelete}</span>
          </button>
        </div>
      )}

      {/* Import Modal */}
      {showImport && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: "var(--backdrop-scrim)" }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setShowImport(false);
          }}
        >
          <div role="dialog" aria-modal="true" className="ui-modal w-full max-w-lg overflow-hidden">
            <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-5 py-3.5">
              <h3 className="text-[16px] font-semibold text-[var(--text-primary)]">
                {dict.nodes.importTitle}
              </h3>
              <button
                type="button"
                onClick={() => setShowImport(false)}
                aria-label={dict.nodes.cancel}
                className="ui-btn-ghost h-7 w-7 p-0"
              >
                <X className="h-4 w-4" strokeWidth={1.5} />
              </button>
            </div>

            <div className="space-y-3.5 p-5">
              <div className="inline-flex rounded-[9px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[12px]">
                <button
                  type="button"
                  onClick={() => setImportTab("paste")}
                  className={`rounded-[7px] px-3 py-1 font-medium cursor-pointer ${
                    importTab === "paste"
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-secondary)]"
                  }`}
                >
                  {dict.nodes.tabPaste}
                </button>
                <button
                  type="button"
                  onClick={() => setImportTab("sub")}
                  className={`rounded-[7px] px-3 py-1 font-medium cursor-pointer ${
                    importTab === "sub"
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-secondary)]"
                  }`}
                >
                  {dict.nodes.tabSub}
                </button>
              </div>

              {importTab === "paste" ? (
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                      {dict.nodes.groupNameLabel}
                    </label>
                    <input
                      type="text"
                      value={importGroup}
                      onChange={(e) => setImportGroup(e.target.value)}
                      placeholder={dict.nodes.groupNamePlaceholder}
                      className="ui-input h-8 w-full px-3 text-[12.5px]"
                    />
                  </div>
                  <textarea
                    rows={5}
                    value={importPayload}
                    onChange={(e) => setImportPayload(e.target.value)}
                    placeholder={dict.nodes.payloadPlaceholder}
                    className="ui-input w-full p-3 font-mono text-[11.5px]"
                  />
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                      {dict.nodes.subNameLabel}
                    </label>
                    <input
                      type="text"
                      value={subName}
                      onChange={(e) => setSubName(e.target.value)}
                      placeholder={dict.nodes.subNamePlaceholder}
                      className="ui-input h-8 w-full px-3 text-[12.5px]"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                      {dict.nodes.subUrlLabel}
                    </label>
                    <input
                      type="url"
                      value={subUrl}
                      onChange={(e) => setSubUrl(e.target.value)}
                      placeholder={dict.nodes.subUrlPlaceholder}
                      className="ui-input h-8 w-full px-3 font-mono text-[12px]"
                    />
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-1">
                {importTab === "paste" ? (
                  <button
                    type="button"
                    title={dict.nodes.sampleTooltip}
                    onClick={() => {
                      setImportPayload(SAMPLE_SHARE_URIS);
                      if (!importGroup.trim()) {
                        setImportGroup(dict.nodes.demoGroupName);
                      }
                    }}
                    className="text-[12px] text-[var(--text-secondary)] underline hover:text-[var(--text-primary)] cursor-pointer"
                  >
                    {dict.nodes.fillSample}
                  </button>
                ) : (
                  <span />
                )}
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setShowImport(false)}
                    className="ui-btn-secondary"
                  >
                    {dict.nodes.cancel}
                  </button>
                  <button
                    type="button"
                    disabled={importing}
                    onClick={() => void handleConfirmImport()}
                    className="ui-btn-primary"
                  >
                    {importTab === "paste" ? dict.nodes.confirmImport : dict.nodes.confirmSync}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Subscriptions Manager Modal */}
      {showSubs && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ backgroundColor: "var(--backdrop-scrim)" }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setShowSubs(false);
          }}
        >
          <div role="dialog" aria-modal="true" className="ui-modal w-full max-w-lg overflow-hidden">
            <div className="flex items-center justify-between border-b border-[var(--border-hairline)] px-5 py-3.5">
              <h3 className="text-[16px] font-semibold text-[var(--text-primary)]">
                {dict.nodes.subsTitle}
              </h3>
              <button
                type="button"
                onClick={() => setShowSubs(false)}
                aria-label={dict.nodes.cancel}
                className="ui-btn-ghost h-7 w-7 p-0"
              >
                <X className="h-4 w-4" strokeWidth={1.5} />
              </button>
            </div>

            <div className="max-h-[60vh] divide-y divide-[var(--border-hairline)] overflow-y-auto">
              {subscriptions.length === 0 ? (
                <div className="p-8 text-center text-[12.5px] text-[var(--text-secondary)]">
                  {dict.nodes.subsEmpty}
                </div>
              ) : (
                subscriptions.map((sub) => {
                  const busy = refreshingSubId === sub.id;
                  const failed = failedSubIds.has(sub.id);
                  return (
                    <div
                      key={sub.id}
                      className="flex items-center justify-between gap-3 px-5 py-3 text-[12px]"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate font-medium text-[var(--text-primary)]">
                            {sub.name}
                          </span>
                          <span className="shrink-0 font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                            {sub.nodeCount} {dict.nodes.subsNodes}
                          </span>
                          {failed && (
                            <button
                              type="button"
                              onClick={() => void handleSubRefresh(sub.id)}
                              className="shrink-0 rounded-[6px] border px-1.5 py-0.5 text-[11.5px] font-medium cursor-pointer"
                              style={{
                                borderColor: "var(--danger-border)",
                                backgroundColor: "var(--danger-bg)",
                                color: "var(--danger-text-on-bg)",
                              }}
                            >
                              {dict.nodes.subsFailed} {"\u00b7"} {dict.nodes.subsRetry}
                            </button>
                          )}
                        </div>
                        <div
                          className="truncate font-mono text-[11px] text-[var(--text-tertiary)]"
                          title={sub.url}
                        >
                          {sub.url}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void handleSubRefresh(sub.id)}
                          className="ui-btn-secondary h-7 px-2.5 text-[11.5px]"
                        >
                          <RefreshCw
                            className={`h-3 w-3 ${busy ? "animate-spin" : ""}`}
                            strokeWidth={1.6}
                          />
                          {dict.nodes.subsRefresh}
                        </button>
                        <button
                          type="button"
                          onClick={() => void onDeleteSubscription(sub.id)}
                          aria-label={dict.nodes.actDelete}
                          className="ui-btn-danger-ghost h-7 w-7 p-0"
                        >
                          <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
