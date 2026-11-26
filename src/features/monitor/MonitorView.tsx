import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Info,
  Play,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { NodeLabel } from "../../components/RegionFlag";
import type { Dict } from "../../i18n";
import type {
  ConnectionHistoryPage,
  ConnectionItem,
  InboundPort,
  Locale,
  LogEntry,
  NodeIR,
  PlatformTrafficPayload,
  SimpleRoutingRule,
  TrafficSample,
} from "../../types";
import {
  formatBytes,
  formatConnectionExit,
  formatConnectionRule,
  formatSpeed,
  humanizeLogMessage,
} from "../../utils/nodes";

interface MonitorViewProps {
  dict: Dict;
  locale: Locale;
  coreRunning: boolean;
  nodes: NodeIR[];
  rules: SimpleRoutingRule[];
  extraPorts: InboundPort[];
  connections: ConnectionItem[];
  logs: LogEntry[];
  traffic: TrafficSample;
  localDirectBytes: number;
  localRejectCount: number;
  downHistory: number[];
  upHistory: number[];
  onStartCore: () => void;
  onFetchHistory: (
    query: string,
    page: number,
    pageSize: number,
  ) => Promise<ConnectionHistoryPage | null>;
  onFetchPlatforms: (range: string) => Promise<PlatformTrafficPayload | null>;
  onClearHistory: () => Promise<void>;
  onCloseConnection: (id: string) => void;
  onCloseAllConnections: () => void;
  onClearLogs: () => void;
}

type SubTab = "conns" | "history" | "platforms" | "logs";
type SourceFilter = "all" | "sys_proxy" | "app_proxy" | "tun";
type LogLevelFilter = "ALL" | "INFO" | "WARN" | "ERROR";
type RangeFilter = "today" | "7d" | "30d" | "all";

function formatShortTime(iso: string): string {
  if (!iso) return "--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(11, 19) || iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function resolveSourceKind(conn: ConnectionItem): "sys_proxy" | "app_proxy" | "tun" | "dedicated_port" {
  const k = conn.sourceKind;
  if (k === "sys_proxy" || k === "app_proxy" || k === "tun" || k === "dedicated_port") {
    return k;
  }
  const ib = conn.inbound.toLowerCase();
  if (ib.includes("app-proxy")) return "app_proxy";
  if (ib.includes("tun")) return "tun";
  if (ib.includes("mixed")) return "sys_proxy";
  return "dedicated_port";
}

export function MonitorView({
  dict,
  locale,
  coreRunning,
  nodes,
  rules,
  extraPorts,
  connections,
  logs,
  traffic,
  localDirectBytes,
  localRejectCount,
  downHistory,
  upHistory,
  onStartCore,
  onFetchHistory,
  onFetchPlatforms,
  onClearHistory,
  onCloseConnection,
  onCloseAllConnections,
  onClearLogs,
}: MonitorViewProps) {
  const [subTab, setSubTab] = useState<SubTab>("conns");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [logFilter, setLogFilter] = useState<LogLevelFilter>("ALL");
  const [platformRange, setPlatformRange] = useState<RangeFilter>("today");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const [historyData, setHistoryData] = useState<ConnectionHistoryPage>({
    items: [],
    total: 0,
    page: 1,
    pageSize: 25,
  });
  const [platformData, setPlatformData] = useState<PlatformTrafficPayload>({
    items: [],
    totalUpload: 0,
    totalDownload: 0,
    totalConnections: 0,
  });

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const useEnglish = locale === "en";

  const nodeById = useMemo(
    () => new Map<string, NodeIR>(nodes.map((n) => [n.id, n])),
    [nodes],
  );

  const exitLabels = useMemo(
    () => ({
      direct: dict.monitor.exitDirect,
      reject: dict.monitor.exitReject,
      mainExit: dict.monitor.exitMain,
      autoAll: dict.monitor.exitAutoAll,
      autoRegionPrefix: dict.monitor.exitAutoPrefix,
      regions: dict.routing.regions as Record<string, string>,
    }),
    [dict],
  );

  const ruleLabels = useMemo(
    () => ({
      defaultFallback: dict.monitor.ruleFallback,
      directMode: dict.routing.directMode,
      globalMode: dict.routing.globalMode,
      lanDirect: dict.monitor.ruleLan,
      portRulePrefix: dict.monitor.rulePortPrefix,
      domainRuleFallback: dict.monitor.ruleDomain,
      processRuleFallback: dict.monitor.ruleProcess,
    }),
    [dict],
  );

  const presetTitles = dict.routing.presetTitles as Record<string, string>;

  useEffect(() => {
    setPage(1);
  }, [subTab, sourceFilter, query, logFilter, platformRange, pageSize]);

  useEffect(() => {
    if (subTab !== "history") return;
    let alive = true;
    const load = async () => {
      const data = await onFetchHistory(query, page, pageSize);
      if (alive && data) setHistoryData(data);
    };
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [subTab, query, page, pageSize, onFetchHistory]);

  useEffect(() => {
    if (subTab !== "platforms") return;
    let alive = true;
    const load = async () => {
      const data = await onFetchPlatforms(platformRange);
      if (alive && data) setPlatformData(data);
    };
    void load();
    const timer = window.setInterval(() => void load(), 2500);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [subTab, platformRange, onFetchPlatforms]);

  // Throughput sparkline canvas (100% CSS-token-driven, zero hardcoded hexes)
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || canvas.offsetWidth === 0) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.offsetWidth;
    const h = 58;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cs = getComputedStyle(document.documentElement);
    const downColor = cs.getPropertyValue("--success-dot").trim() || "currentColor";
    const upColor = cs.getPropertyValue("--text-secondary").trim() || "currentColor";
    const maxV = Math.max(1024, ...downHistory, ...upHistory) * 1.15;

    const drawSeries = (series: number[], color: string, fillAlpha: number) => {
      if (series.length < 2) return;
      ctx.beginPath();
      series.forEach((v, i) => {
        const x = (i / (series.length - 1)) * w;
        const y = h - 6 - (v / maxV) * (h - 14);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();

      if (fillAlpha > 0) {
        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();
        ctx.globalAlpha = fillAlpha;
        ctx.fillStyle = color;
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    };

    drawSeries(downHistory, downColor, 0.12);
    drawSeries(upHistory, upColor, 0);
  }, [downHistory, upHistory]);

  const sourceLabel = (kind: "sys_proxy" | "app_proxy" | "tun" | "dedicated_port") => {
    if (kind === "app_proxy") return dict.monitor.sourceAppProxy;
    if (kind === "tun") return dict.monitor.sourceTun;
    if (kind === "dedicated_port") return dict.monitor.sourceDedicated;
    return dict.monitor.sourceSysProxy;
  };

  const decoratedConns = useMemo(() => {
    return connections
      .map((c) => {
        const srcKind = resolveSourceKind(c);
        const srcText = sourceLabel(srcKind);
        const rawProc =
          c.process === "Local App" || !c.process ? dict.monitor.localApp : c.process;
        const primaryProc = c.originExpired
          ? dict.monitor.originExpired
          : c.ancestorApp
            ? c.ancestorApp
            : rawProc;
        const secondaryProc =
          !c.originExpired && c.ancestorApp && rawProc !== c.ancestorApp ? rawProc : null;
        const procTooltip = c.originExpired
          ? dict.monitor.originExpired
          : [
              c.ancestorChain && c.ancestorChain.length > 0
                ? c.ancestorChain.join(" > ")
                : rawProc,
              c.pid ? `PID ${c.pid}` : "",
            ]
              .filter(Boolean)
              .join(" | ");

        const ruleInfo = formatConnectionRule(
          c.rule,
          rules,
          extraPorts,
          ruleLabels,
          presetTitles,
          useEnglish,
        );
        const exitInfo = formatConnectionExit(c.chain, nodeById, exitLabels);
        const totalBytes = c.uploadBytes + c.downloadBytes;
        return {
          conn: c,
          srcKind,
          srcText,
          primaryProc,
          secondaryProc,
          procTooltip,
          ruleInfo,
          exitInfo,
          totalBytes,
        };
      })
      .sort(
        (a, b) =>
          b.totalBytes - a.totalBytes ||
          b.conn.start.localeCompare(a.conn.start) ||
          a.conn.id.localeCompare(b.conn.id),
      );
  }, [
    connections,
    dict,
    rules,
    extraPorts,
    ruleLabels,
    presetTitles,
    useEnglish,
    nodeById,
    exitLabels,
  ]);

  const filteredConns = useMemo(() => {
    const q = query.trim().toLowerCase();
    return decoratedConns.filter(
      ({ conn, srcKind, srcText, primaryProc, secondaryProc, ruleInfo, exitInfo }) => {
        if (sourceFilter !== "all" && srcKind !== sourceFilter) return false;
        if (!q) return true;
        return (
          primaryProc.toLowerCase().includes(q) ||
          (secondaryProc && secondaryProc.toLowerCase().includes(q)) ||
          conn.destination.toLowerCase().includes(q) ||
          srcText.toLowerCase().includes(q) ||
          (conn.appRuleName && conn.appRuleName.toLowerCase().includes(q)) ||
          ruleInfo.label.toLowerCase().includes(q) ||
          exitInfo.label.toLowerCase().includes(q)
        );
      },
    );
  }, [decoratedConns, sourceFilter, query]);

  const filteredPlatforms = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return platformData.items;
    return platformData.items.filter(
      (p) =>
        p.platform.toLowerCase().includes(q) ||
        p.topDomains.some((d) => d.toLowerCase().includes(q)),
    );
  }, [platformData.items, query]);

  const logCounts = useMemo(() => {
    let info = 0;
    let warn = 0;
    let err = 0;
    for (const l of logs) {
      const upper = l.level.toUpperCase();
      if (upper === "ERROR") err += 1;
      else if (upper === "WARN") warn += 1;
      else info += 1;
    }
    return { all: logs.length, info, warn, err };
  }, [logs]);

  const filteredLogs = useMemo(() => {
    const q = query.trim().toLowerCase();
    return logs
      .filter((l) => {
        if (logFilter === "ALL") return true;
        const upper = l.level.toUpperCase();
        if (logFilter === "INFO") return upper === "INFO" || upper === "DEBUG";
        return upper === logFilter;
      })
      .map((entry) => ({
        entry,
        displayMessage: humanizeLogMessage(entry.message, nodeById, exitLabels),
      }))
      .filter(({ entry, displayMessage }) => {
        if (!q) return true;
        return (
          displayMessage.toLowerCase().includes(q) ||
          entry.message.toLowerCase().includes(q) ||
          entry.level.toLowerCase().includes(q)
        );
      });
  }, [logs, logFilter, query, nodeById, exitLabels]);

  const totalItemsForTab =
    subTab === "conns"
      ? filteredConns.length
      : subTab === "history"
        ? historyData.total
        : subTab === "platforms"
          ? filteredPlatforms.length
          : filteredLogs.length;

  const totalPages = Math.max(1, Math.ceil(totalItemsForTab / pageSize));
  const safePage = Math.min(page, totalPages);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const pagedConns = useMemo(
    () => filteredConns.slice((safePage - 1) * pageSize, safePage * pageSize),
    [filteredConns, safePage, pageSize],
  );

  const pagedPlatforms = useMemo(
    () => filteredPlatforms.slice((safePage - 1) * pageSize, safePage * pageSize),
    [filteredPlatforms, safePage, pageSize],
  );

  const pagedLogs = useMemo(
    () => filteredLogs.slice((safePage - 1) * pageSize, safePage * pageSize),
    [filteredLogs, safePage, pageSize],
  );

  const grandTotalPlatformBytes = Math.max(
    1,
    platformData.totalDownload + platformData.totalUpload,
  );

  const pageLabel = dict.monitor.pageInfo
    .replace("{page}", String(safePage))
    .replace("{totalPages}", String(totalPages));
  const totalCountLabel = dict.monitor.totalItems.replace(
    "{count}",
    String(totalItemsForTab),
  );

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Single-Row 40px Page Header */}
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <h1 className="text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
          {dict.monitor.title}
        </h1>
        <span className="flex items-center gap-2.5 font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
          <span className="inline-flex items-center gap-0.5">
            <ArrowDown
              className="h-3 w-3"
              style={{ color: "var(--success-text)" }}
              strokeWidth={1.6}
            />
            {formatSpeed(traffic.downBytesPerSec)}
          </span>
          <span className="inline-flex items-center gap-0.5">
            <ArrowUp className="h-3 w-3 text-[var(--text-secondary)]" strokeWidth={1.6} />
            {formatSpeed(traffic.upBytesPerSec)}
          </span>
        </span>
      </div>

      {/* Top Traffic Sparkline + De-duplicated KPI Row (B5: @container 2x2 below 900px) */}
      <div className="monitor-header-container shrink-0 border-b border-[var(--border-hairline)] px-4 py-3 lg:px-5">
        <div className="monitor-header-grid">
          <div className="flex min-w-0 flex-col gap-1">
            <div className="flex items-center justify-between text-[11.5px]">
              <span className="font-medium text-[var(--text-secondary)]">
                {dict.monitor.liveTraffic}
              </span>
            </div>
            <canvas
              ref={canvasRef}
              height={54}
              className="w-full rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)]"
            />
          </div>

          <div className="monitor-kpi-grid">
            {/* KPI 1: Active Connections + Zero-Double-Counting Tooltip & Outside-Core Sub-Counter */}
            <div
              className="min-w-0 rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-2.5"
              title={dict.monitor.dedupHint}
            >
              <div className="flex items-center justify-between gap-1 text-[11.5px] text-[var(--text-secondary)]">
                <span className="truncate" title={dict.monitor.kpiConns}>
                  {dict.monitor.kpiConns}
                </span>
                <Info className="h-3 w-3 shrink-0 text-[var(--text-tertiary)]" strokeWidth={1.5} />
              </div>
              <div className="mt-0.5 font-mono text-[15px] font-semibold num-tabular text-[var(--text-primary)]">
                {connections.length}
              </div>
              {(localDirectBytes > 0 || localRejectCount > 0) && (
                <div
                  className="mt-0.5 truncate font-mono text-[11.5px] num-tabular text-[var(--text-tertiary)]"
                  title={dict.monitor.dedupHint}
                >
                  {dict.monitor.localSubStat.replace("{bytes}", formatBytes(localDirectBytes))}
                </div>
              )}
            </div>

            {/* KPI 2: Core Status */}
            <div className="min-w-0 rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-2.5">
              <div className="flex items-center justify-between gap-1 text-[11.5px] text-[var(--text-secondary)]">
                <span className="truncate" title={dict.monitor.kpiCore}>
                  {dict.monitor.kpiCore}
                </span>
                {coreRunning && traffic.memoryBytes > 0 && (
                  <span className="shrink-0 font-mono text-[11.5px] num-tabular text-[var(--text-tertiary)]">
                    {formatBytes(traffic.memoryBytes)}
                  </span>
                )}
              </div>
              <div
                className="mt-0.5 text-[14px] font-semibold"
                style={{
                  color: coreRunning ? "var(--success-text)" : "var(--text-secondary)",
                }}
              >
                {coreRunning ? dict.monitor.statusRunning : dict.monitor.statusIdle}
              </div>
            </div>

            {/* KPI 3: Log Ring */}
            <div className="monitor-kpi-wide min-w-0 rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-2.5">
              <div className="flex items-center justify-between gap-1 text-[11.5px] text-[var(--text-secondary)]">
                <span className="truncate" title={dict.monitor.kpiLogRing}>
                  {dict.monitor.kpiLogRing}
                </span>
                {logCounts.err > 0 && (
                  <span
                    className="shrink-0 font-mono text-[11.5px] font-medium num-tabular"
                    style={{ color: "var(--danger-text)" }}
                  >
                    {logCounts.err} ERR
                  </span>
                )}
              </div>
              <div className="mt-0.5 font-mono text-[15px] font-semibold num-tabular text-[var(--text-primary)]">
                {logs.length}/500
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Tabs & Source/Log Filter Bar */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex items-center gap-1 text-[12px]">
            {(
              [
                ["conns", dict.monitor.tabConns],
                ["history", dict.monitor.tabHistory],
                ["platforms", dict.monitor.tabPlatforms],
                ["logs", dict.monitor.tabLogs],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setSubTab(key)}
                className={`rounded-[8px] px-2.5 py-1 font-medium transition-colors cursor-pointer ${
                  subTab === key
                    ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                    : "text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Plain-language Source Filter Pills */}
          {subTab === "conns" && (
            <div className="inline-flex items-center gap-0.5 rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[11px]">
              {(
                [
                  ["all", dict.monitor.sourceAll],
                  ["sys_proxy", dict.monitor.sourceSysProxy],
                  ["app_proxy", dict.monitor.sourceAppProxy],
                  ["tun", dict.monitor.sourceTun],
                ] as const
              ).map(([sKey, sLabel]) => (
                <button
                  key={sKey}
                  type="button"
                  onClick={() => setSourceFilter(sKey)}
                  className={`rounded-[6px] px-2 py-0.5 font-medium transition-colors cursor-pointer ${
                    sourceFilter === sKey
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {sLabel}
                </button>
              ))}
            </div>
          )}

          {subTab === "platforms" && (
            <div className="inline-flex items-center gap-0.5 rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[11px]">
              {(
                [
                  ["today", dict.monitor.rangeToday],
                  ["7d", dict.monitor.range7d],
                  ["30d", dict.monitor.range30d],
                  ["all", dict.monitor.rangeAll],
                ] as const
              ).map(([rKey, rLabel]) => (
                <button
                  key={rKey}
                  type="button"
                  onClick={() => setPlatformRange(rKey)}
                  className={`rounded-[6px] px-2 py-0.5 font-medium transition-colors cursor-pointer ${
                    platformRange === rKey
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {rLabel}
                </button>
              ))}
            </div>
          )}

          {subTab === "logs" && (
            <div className="inline-flex items-center gap-1 rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[11px]">
              {(
                [
                  ["ALL", dict.monitor.logAll, logCounts.all],
                  ["INFO", "INFO", logCounts.info],
                  ["WARN", "WARN", logCounts.warn],
                  ["ERROR", "ERROR", logCounts.err],
                ] as const
              ).map(([key, label, count]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setLogFilter(key)}
                  className={`inline-flex items-center gap-1 rounded-[6px] px-2 py-0.5 font-medium transition-colors cursor-pointer ${
                    logFilter === key
                      ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                      : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span>{label}</span>
                  <span className="font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
                    {count}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <div className="relative">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]"
              strokeWidth={1.5}
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={dict.monitor.searchPh}
              className="ui-input h-7 w-44 pr-2.5 pl-8 text-[12px] lg:w-52"
            />
          </div>
          {subTab === "conns" && (
            <button
              type="button"
              onClick={onCloseAllConnections}
              className="ui-btn-danger-subtle h-7"
            >
              <X className="h-3.5 w-3.5" strokeWidth={1.5} />
              {dict.monitor.closeAll}
            </button>
          )}
          {(subTab === "history" || subTab === "platforms") && (
            <button
              type="button"
              onClick={async () => {
                await onClearHistory();
                setHistoryData({ items: [], total: 0, page: 1, pageSize });
                const fresh = await onFetchPlatforms(platformRange);
                if (fresh) setPlatformData(fresh);
              }}
              className="ui-btn-danger-subtle h-7"
            >
              <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
              {dict.monitor.clearHistory}
            </button>
          )}
          {subTab === "logs" && (
            <button
              type="button"
              onClick={onClearLogs}
              className="ui-btn-danger-subtle h-7"
            >
              <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
              {dict.monitor.clearLogs}
            </button>
          )}
        </div>
      </div>

      {/* Body Content (@container Zero-Overflow Grids) */}
      {subTab === "conns" && (
        <div className="monitor-table-container min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
          {pagedConns.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2.5 p-8 text-center">
              <div className="text-[13px] text-[var(--text-secondary)]">
                {coreRunning ? dict.monitor.emptyConns : dict.monitor.emptyCoreStopped}
              </div>
              {!coreRunning && (
                <button type="button" onClick={onStartCore} className="ui-btn-primary h-8">
                  <Play className="h-3.5 w-3.5" strokeWidth={1.6} />
                  {dict.nav.startCore}
                </button>
              )}
            </div>
          ) : (
            <div>
              <div className="monitor-conns-grid sticky top-0 z-10 border-b border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)] lg:px-5">
                <div>{dict.monitor.colProcess}</div>
                <div>{dict.monitor.colDest}</div>
                <div>{dict.monitor.colSource}</div>
                <div className="mon-col-rule">{dict.monitor.colRule}</div>
                <div className="mon-col-exit">{dict.monitor.colExit}</div>
                <div className="text-right">{dict.monitor.colTraffic}</div>
                <div />
              </div>

              <div className="divide-y divide-[var(--border-hairline)] text-[12px]">
                {pagedConns.map(
                  ({
                    conn,
                    srcText,
                    primaryProc,
                    secondaryProc,
                    procTooltip,
                    ruleInfo,
                    exitInfo,
                    totalBytes,
                  }) => {
                    const trafficTooltip = `${dict.monitor.uploadShort}: ${formatBytes(conn.uploadBytes)} | ${dict.monitor.downloadShort}: ${formatBytes(conn.downloadBytes)}`;
                    return (
                      <div
                        key={conn.id}
                        className="group monitor-conns-grid min-h-[44px] px-4 py-2 transition-colors hover:bg-[var(--bg-hover)] lg:px-5"
                      >
                        {/* Process (Ancestor > Real Process) */}
                        <div className="min-w-0 truncate" title={procTooltip}>
                          <span
                            className={`font-medium ${
                              conn.originExpired
                                ? "text-[var(--text-tertiary)] italic"
                                : "text-[var(--text-primary)]"
                            }`}
                          >
                            {primaryProc}
                          </span>
                          {secondaryProc && (
                            <span className="ml-1 font-mono text-[11px] text-[var(--text-secondary)]">
                              {"\u203a"} {secondaryProc}
                            </span>
                          )}
                        </div>

                        {/* Destination */}
                        <div
                          className="min-w-0 truncate font-mono text-[11.5px] text-[var(--text-secondary)]"
                          title={conn.destination}
                        >
                          {conn.destination}
                        </div>

                        {/* Plain-Language Source */}
                        <div className="min-w-0">
                          <span
                            title={conn.inbound}
                            className="inline-block max-w-full truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]"
                          >
                            {srcText}
                          </span>
                        </div>

                        {/* Rule / Local Action Chip */}
                        <div className="mon-col-rule min-w-0" title={ruleInfo.raw}>
                          {conn.localAction === "local_reject" ? (
                            <span
                              className="inline-block max-w-full truncate rounded-[6px] border px-1.5 py-0.5 text-[11px] font-medium"
                              style={{
                                borderColor: "var(--danger-border)",
                                backgroundColor: "var(--danger-bg)",
                                color: "var(--danger-text-on-bg)",
                              }}
                            >
                              {dict.monitor.localReject}
                            </span>
                          ) : conn.localAction === "local_direct" ? (
                            <span
                              className="inline-block max-w-full truncate rounded-[6px] border px-1.5 py-0.5 text-[11px] font-medium"
                              style={{
                                borderColor: "var(--success-border)",
                                backgroundColor: "var(--success-bg)",
                                color: "var(--success-text)",
                              }}
                            >
                              {dict.monitor.localDirect}
                            </span>
                          ) : conn.appRuleName ? (
                            <span className="inline-block max-w-full truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--text-primary)]">
                              {dict.monitor.appRulePrefix} {"\u00b7"} {conn.appRuleName}
                            </span>
                          ) : (
                            <span className="block truncate text-[11.5px] text-[var(--text-secondary)]">
                              {ruleInfo.label}
                            </span>
                          )}
                        </div>

                        {/* Exit */}
                        <div className="mon-col-exit min-w-0" title={exitInfo.label}>
                          <div className="flex min-w-0 items-center gap-1.5">
                            <span
                              className="h-1.5 w-1.5 shrink-0 rounded-full"
                              style={{
                                backgroundColor:
                                  exitInfo.kind === "direct"
                                    ? "var(--success-dot)"
                                    : exitInfo.kind === "reject"
                                      ? "var(--danger-dot)"
                                      : "var(--accent-focus)",
                              }}
                            />
                            {exitInfo.kind === "node" ? (
                              <NodeLabel
                                remark={exitInfo.label}
                                region={exitInfo.region}
                                size="xs"
                                className="font-medium text-[var(--text-primary)]"
                              />
                            ) : (
                              <span className="truncate font-medium text-[var(--text-primary)]">
                                {exitInfo.label}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Traffic */}
                        <div
                          className="text-right font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]"
                          title={trafficTooltip}
                        >
                          {formatBytes(totalBytes)}
                        </div>

                        {/* Close */}
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={() => onCloseConnection(conn.id)}
                            title={dict.monitor.closeConn}
                            aria-label={dict.monitor.closeConn}
                            className="row-actions ui-btn-danger-ghost h-6 w-6 p-0"
                          >
                            <X className="h-3.5 w-3.5" strokeWidth={1.5} />
                          </button>
                        </div>
                      </div>
                    );
                  },
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {subTab === "history" && (
        <div className="monitor-table-container min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
          {historyData.items.length === 0 ? (
            <div className="flex h-full items-center justify-center p-8 text-[12.5px] text-[var(--text-secondary)]">
              {dict.monitor.emptyHistory}
            </div>
          ) : (
            <div>
              <div className="monitor-hist-grid sticky top-0 z-10 border-b border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)] lg:px-5">
                <div className="mon-hist-time">{dict.monitor.colClosedAt}</div>
                <div>{dict.monitor.colPlatform}</div>
                <div>{dict.monitor.colDest}</div>
                <div>{dict.monitor.colProcess}</div>
                <div className="mon-hist-exit">{dict.monitor.colExit}</div>
                <div className="text-right">{dict.monitor.colTraffic}</div>
              </div>
              <div className="divide-y divide-[var(--border-hairline)] text-[12px]">
                {historyData.items.map((rec) => {
                  const exitInfo = formatConnectionExit(rec.chain, nodeById, exitLabels);
                  const total = rec.uploadBytes + rec.downloadBytes;
                  const proc = rec.process === "Local App" ? dict.monitor.localApp : rec.process;
                  return (
                    <div
                      key={rec.id}
                      className="monitor-hist-grid min-h-[44px] px-4 py-2 hover:bg-[var(--bg-hover)] lg:px-5"
                    >
                      <div className="mon-hist-time truncate font-mono text-[11px] num-tabular text-[var(--text-tertiary)]">
                        {formatShortTime(rec.closedAt)}
                      </div>
                      <div className="min-w-0">
                        <span className="inline-block max-w-full truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11px] font-medium text-[var(--text-primary)]">
                          {rec.platform}
                        </span>
                      </div>
                      <div
                        className="min-w-0 truncate font-mono text-[11.5px] text-[var(--text-secondary)]"
                        title={rec.destination}
                      >
                        {rec.destination}
                      </div>
                      <div
                        className="min-w-0 truncate font-mono text-[11.5px] text-[var(--text-primary)]"
                        title={proc}
                      >
                        {proc}
                      </div>
                      <div className="mon-hist-exit min-w-0 truncate text-[var(--text-secondary)]">
                        {exitInfo.label}
                      </div>
                      <div className="text-right font-mono text-[11.5px] num-tabular text-[var(--text-primary)]">
                        {formatBytes(total)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {subTab === "platforms" && (
        <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
          <div className="grid grid-cols-3 gap-2.5 border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-4 py-3 lg:px-5">
            <div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                {dict.monitor.kpiTotalDown}
              </div>
              <div className="mt-0.5 font-mono text-[14px] font-semibold num-tabular text-[var(--text-primary)]">
                {formatBytes(platformData.totalDownload)}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                {dict.monitor.kpiTotalUp}
              </div>
              <div className="mt-0.5 font-mono text-[14px] font-semibold num-tabular text-[var(--text-primary)]">
                {formatBytes(platformData.totalUpload)}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                {dict.monitor.kpiTrackedConns}
              </div>
              <div className="mt-0.5 font-mono text-[14px] font-semibold num-tabular text-[var(--text-primary)]">
                {platformData.totalConnections}
              </div>
            </div>
          </div>

          {pagedPlatforms.length === 0 ? (
            <div className="flex h-48 items-center justify-center p-8 text-[12.5px] text-[var(--text-secondary)]">
              {dict.monitor.emptyPlatforms}
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-hairline)] text-[12px]">
              {pagedPlatforms.map((item) => {
                const pct = Math.min(
                  100,
                  Math.round((item.totalBytes / grandTotalPlatformBytes) * 1000) / 10,
                );
                return (
                  <div
                    key={item.platform}
                    className="grid grid-cols-12 items-center gap-2 px-4 py-2.5 hover:bg-[var(--bg-hover)] lg:px-5"
                  >
                    <div className="col-span-4 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate font-medium text-[var(--text-primary)]">
                          {item.platform}
                        </span>
                        {item.activeCount > 0 && (
                          <span
                            className="shrink-0 rounded-full px-1.5 py-0.5 font-mono text-[11.5px] font-medium"
                            style={{
                              backgroundColor: "var(--success-bg)",
                              color: "var(--success-text)",
                            }}
                          >
                            {dict.monitor.activeTag} {item.activeCount}
                          </span>
                        )}
                      </div>
                      {item.topDomains.length > 0 && (
                        <div
                          className="mt-0.5 truncate font-mono text-[11.5px] text-[var(--text-secondary)]"
                          title={item.topDomains.join(", ")}
                        >
                          {item.topDomains.join(", ")}
                        </div>
                      )}
                    </div>
                    <div className="col-span-4 flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--bg-track)]">
                        <div
                          className="h-full rounded-full bg-[var(--accent-primary)]"
                          style={{ width: `${Math.max(2, pct)}%` }}
                        />
                      </div>
                      <span className="w-11 shrink-0 text-right font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                        {pct.toFixed(1)}%
                      </span>
                    </div>
                    <div className="col-span-2 text-right font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
                      {item.connectionCount} {dict.monitor.colConns}
                    </div>
                    <div className="col-span-2 text-right font-mono text-[11.5px] font-semibold num-tabular text-[var(--text-primary)]">
                      {formatBytes(item.totalBytes)}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {subTab === "logs" && (
        <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden bg-[var(--bg-subtle)] p-4 font-mono text-[11.5px]">
          {pagedLogs.length === 0 ? (
            <div className="py-12 text-center font-sans text-[12.5px] text-[var(--text-secondary)]">
              {dict.monitor.emptyLogs}
            </div>
          ) : (
            <div className="space-y-1.5">
              {pagedLogs.map(({ entry, displayMessage }, idx) => {
                const upper = entry.level.toUpperCase();
                const badgeStyle =
                  upper === "ERROR"
                    ? {
                        color: "var(--danger-text-on-bg)",
                        backgroundColor: "var(--danger-bg)",
                      }
                    : upper === "WARN"
                      ? {
                          color: "var(--warning-text)",
                          backgroundColor: "var(--warning-bg)",
                        }
                      : {
                          color: "var(--text-secondary)",
                          backgroundColor: "var(--bg-hover)",
                        };
                return (
                  <div
                    key={`${entry.timestamp}-${idx}`}
                    className="flex items-start gap-2.5 leading-relaxed"
                  >
                    <span className="shrink-0 num-tabular text-[var(--text-tertiary)]">
                      {entry.timestamp}
                    </span>
                    <span
                      className="w-12 shrink-0 rounded-[4px] px-1 py-0.5 text-center text-[11.5px] font-semibold leading-tight"
                      style={badgeStyle}
                    >
                      {upper}
                    </span>
                    <span
                      className="min-w-0 break-all text-[var(--text-primary)]"
                      title={entry.message !== displayMessage ? entry.message : undefined}
                    >
                      {displayMessage}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Unified Pagination Footer */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-4 py-2 text-[11.5px] text-[var(--text-secondary)] lg:px-5">
        <div className="flex items-center gap-3">
          <span className="font-mono num-tabular">{totalCountLabel}</span>
          <div className="inline-flex items-center gap-1 rounded-[7px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5">
            {[25, 50, 100].map((sz) => (
              <button
                key={sz}
                type="button"
                onClick={() => setPageSize(sz)}
                className={`rounded-[5px] px-1.5 py-0.5 font-mono text-[11.5px] num-tabular cursor-pointer ${
                  pageSize === sz
                    ? "bg-[var(--bg-surface)] font-medium text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                {sz}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            disabled={safePage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            className="ui-btn-secondary h-7 px-2 text-[11.5px]"
          >
            <ChevronLeft className="h-3.5 w-3.5" strokeWidth={1.5} />
            {dict.monitor.pagePrev}
          </button>
          <span className="min-w-[88px] text-center font-mono text-[11.5px] num-tabular text-[var(--text-primary)]">
            {pageLabel}
          </span>
          <button
            type="button"
            disabled={safePage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            className="ui-btn-secondary h-7 px-2 text-[11.5px]"
          >
            {dict.monitor.pageNext}
            <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.5} />
          </button>
        </div>
      </div>
    </section>
  );
}
