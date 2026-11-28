import { useEffect, useState } from "react";
import {
  Activity,
  AppWindow,
  Code2,
  GitBranch,
  Globe,
  Play,
  Server,
  Settings,
  ShieldCheck,
  Square,
  Waypoints,
} from "lucide-react";
import type { Dict } from "../i18n";
import type { CoreInfo, NavTab, NodeIR, ProxyChain } from "../types";
import { delayColorVar, formatLatency, PROTO_BADGES } from "../utils/nodes";
import { NodeLabel } from "./RegionFlag";
import { SignalBars } from "./SignalBars";

interface SidebarProps {
  dict: Dict;
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  nodeCount: number;
  chainCount: number;
  enabledAppCount: number;
  hasRecoveryFault: boolean;
  activeRuleCount: number;
  connectionCount: number;
  dnsFakeIp: boolean;
  hasAppUpdate: boolean;
  takeoverSummary: string;
  mainNode: NodeIR | null;
  mainChain: ProxyChain | null;
  mainNodeTesting: boolean;
  onRetestMainNode: () => void;
  mixedPort: number;
  coreInfo: CoreInfo;
  coreBusy: boolean;
  onToggleCore: () => void;
}

type SidebarMode = "full" | "compact" | "rail";

function computeSidebarMode(): SidebarMode {
  if (typeof window === "undefined") return "full";
  if (window.innerWidth >= 1200) return "full";
  if (window.innerWidth >= 1000) return "compact";
  return "rail";
}

interface NavItemDef {
  id: NavTab;
  label: string;
  icon: typeof Server;
  badge?: string;
  dotColor?: string;
}

export function Sidebar({
  dict,
  activeTab,
  onSelectTab,
  nodeCount,
  chainCount,
  enabledAppCount,
  hasRecoveryFault,
  activeRuleCount,
  connectionCount,
  dnsFakeIp,
  hasAppUpdate,
  takeoverSummary,
  mainNode,
  mainChain,
  mainNodeTesting,
  onRetestMainNode,
  mixedPort,
  coreInfo,
  coreBusy,
  onToggleCore,
}: SidebarProps) {
  const [mode, setMode] = useState<SidebarMode>(computeSidebarMode);

  useEffect(() => {
    const onResize = () => setMode(computeSidebarMode());
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const navGroups: NavItemDef[][] = [
    [
      { id: "nodes", label: dict.nav.nodes, icon: Server, badge: String(nodeCount) },
      { id: "chains", label: dict.nav.chains, icon: Waypoints, badge: String(chainCount) },
      {
        id: "apps",
        label: dict.nav.apps,
        icon: AppWindow,
        badge: String(enabledAppCount),
        dotColor: hasRecoveryFault ? "var(--warning-dot)" : undefined,
      },
      {
        id: "routing",
        label: dict.nav.routing,
        icon: GitBranch,
        badge: String(activeRuleCount),
      },
      {
        id: "dns",
        label: dict.nav.dns,
        icon: Globe,
        badge: dnsFakeIp ? "FakeIP" : undefined,
      },
    ],
    [
      {
        id: "monitor",
        label: dict.nav.monitor,
        icon: Activity,
        badge: String(connectionCount),
      },
    ],
    [
      {
        id: "core",
        label: dict.nav.core,
        icon: Code2,
        dotColor: coreInfo.installed
          ? coreInfo.running
            ? "var(--success-dot)"
            : "var(--warning-dot)"
          : "var(--text-secondary)",
      },
      {
        id: "settings",
        label: dict.nav.settings,
        icon: Settings,
        dotColor: hasAppUpdate ? "var(--accent-focus)" : undefined,
      },
    ],
  ];

  const hasActiveExit = Boolean(mainChain || mainNode);
  const activeExitName = mainChain ? mainChain.name : mainNode ? mainNode.remark : "";
  const delay = mainChain
    ? mainChain.realDelayMs ?? null
    : mainNode
      ? mainNode.realDelayMs ?? null
      : null;
  const beaconColorVar = mainNodeTesting
    ? "var(--accent-focus)"
    : delay != null
      ? delayColorVar(delay)
      : coreInfo.running
        ? "var(--danger-dot)"
        : "var(--text-tertiary)";
  const retestTitle = mainNodeTesting
    ? dict.nav.retestingMainDelay
    : dict.nav.retestMainDelay;
  const isRail = mode === "rail";
  const widthClass =
    mode === "full" ? "w-[212px]" : mode === "compact" ? "w-[188px]" : "w-[64px]";

  return (
    <aside
      className={`flex ${widthClass} shrink-0 flex-col justify-between gap-3 bg-[var(--bg-sidebar)] px-2.5 py-2.5 select-none`}
    >
      <nav aria-label="Main navigation" className="space-y-3">
        {navGroups.map((group, gi) => (
          <div
            key={gi}
            className={
              gi > 0
                ? "space-y-1 border-t border-[var(--border-hairline)] pt-3"
                : "space-y-1"
            }
          >
            {group.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  title={isRail ? `${item.label}${item.badge ? ` (${item.badge})` : ""}` : undefined}
                  aria-label={item.label}
                  aria-current={active ? "page" : undefined}
                  onClick={() => onSelectTab(item.id)}
                  className={`relative flex w-full items-center rounded-[10px] text-[12.5px] transition-colors cursor-pointer ${
                    isRail ? "justify-center px-0 py-2.5" : "justify-between px-3 py-2"
                  } ${
                    active
                      ? "border border-[var(--border-hairline)] bg-[var(--bg-surface)] font-medium text-[var(--text-primary)] shadow-[var(--shadow-card)]"
                      : "border border-transparent font-normal text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <Icon
                      className="h-4 w-4 shrink-0"
                      style={{
                        color: active ? "var(--text-primary)" : "var(--text-secondary)",
                      }}
                      strokeWidth={1.5}
                    />
                    {!isRail && <span className="truncate">{item.label}</span>}
                  </span>

                  {!isRail && (item.badge !== undefined || item.dotColor !== undefined) && (
                    <span className="flex shrink-0 items-center gap-1.5">
                      {item.dotColor && (
                        <span
                          aria-hidden="true"
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ backgroundColor: item.dotColor }}
                        />
                      )}
                      {item.badge !== undefined && (
                        <span className="font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                          {item.badge}
                        </span>
                      )}
                    </span>
                  )}

                  {isRail && item.dotColor && (
                    <span
                      aria-hidden="true"
                      className="absolute top-1.5 right-2 h-1.5 w-1.5 rounded-full"
                      style={{ backgroundColor: item.dotColor }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Bottom Active Exit & One-Line Takeover Summary Card */}
      {isRail ? (
        <div className="flex flex-col items-center gap-2 border-t border-[var(--border-hairline)] pt-2.5">
          {hasActiveExit ? (
            <button
              type="button"
              disabled={mainNodeTesting}
              onClick={onRetestMainNode}
              title={
                delay != null
                  ? `${activeExitName} (${formatLatency(delay)}) - ${retestTitle}`
                  : `${activeExitName} - ${retestTitle}`
              }
              aria-label={retestTitle}
              className="flex h-7 w-7 items-center justify-center rounded-full transition-colors hover:bg-[var(--bg-hover)] cursor-pointer disabled:cursor-wait"
            >
              <span
                aria-hidden="true"
                className={`signal-beacon ${mainNodeTesting ? "signal-beacon-probing" : ""}`}
                style={{ ["--beacon-color" as string]: beaconColorVar }}
              >
                <span className="signal-beacon-ring" />
                <span className="signal-beacon-core" />
              </span>
            </button>
          ) : (
            <span
              title={takeoverSummary}
              className="h-2.5 w-2.5 rounded-full"
              style={{
                backgroundColor: hasRecoveryFault
                  ? "var(--warning-dot)"
                  : coreInfo.running
                    ? "var(--success-dot)"
                    : "var(--text-secondary)",
              }}
            />
          )}
          <button
            type="button"
            disabled={coreBusy}
            onClick={onToggleCore}
            title={coreInfo.running ? dict.nav.stopCore : dict.nav.startCore}
            aria-label={coreInfo.running ? dict.nav.stopCore : dict.nav.startCore}
            className={`${coreInfo.running ? "ui-btn-secondary" : "ui-btn-primary"} h-8 w-8 p-0`}
          >
            {coreInfo.running ? (
              <Square className="h-3.5 w-3.5" strokeWidth={1.6} />
            ) : (
              <Play className="h-3.5 w-3.5" strokeWidth={1.6} />
            )}
          </button>
        </div>
      ) : (
        <div className="ui-card space-y-2.5 p-3">
          <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)]">
            <span className="inline-flex items-center gap-1.5 font-medium">
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: "var(--accent-focus)" }}
              />
              {dict.nav.mainNodeLabel}
            </span>
            <span className="font-mono num-tabular text-[var(--text-secondary)]">
              :{mixedPort}
            </span>
          </div>

          <div
            className="flex min-w-0 text-[12.5px] font-semibold text-[var(--text-primary)]"
            title={hasActiveExit ? activeExitName : dict.nav.noNodeSelected}
          >
            {mainChain ? (
              <span className="flex min-w-0 items-center gap-1.5">
                <Waypoints
                  className="h-3.5 w-3.5 shrink-0 text-[var(--accent-focus)]"
                  strokeWidth={1.6}
                />
                <span className="truncate">{mainChain.name}</span>
              </span>
            ) : mainNode ? (
              <NodeLabel
                remark={mainNode.remark}
                region={mainNode.region}
                size="sm"
                className="w-full"
              />
            ) : (
              <span className="truncate text-[var(--text-secondary)]">
                {dict.nav.noNodeSelected}
              </span>
            )}
          </div>

          {hasActiveExit && (
            <div className="flex items-center justify-between text-[11px]">
              <span className="rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[var(--text-secondary)]">
                {mainChain
                  ? `${mainChain.hops.length}H`
                  : mainNode
                    ? PROTO_BADGES[mainNode.protocol]
                    : ""}
              </span>
              <button
                type="button"
                disabled={mainNodeTesting}
                onClick={onRetestMainNode}
                title={retestTitle}
                aria-label={retestTitle}
                className="-mr-1.5 inline-flex items-center gap-1.5 rounded-[7px] px-1.5 py-0.5 transition-colors hover:bg-[var(--bg-hover)] active:scale-[0.97] cursor-pointer disabled:cursor-wait"
              >
                <span
                  aria-hidden="true"
                  className={`signal-beacon ${mainNodeTesting ? "signal-beacon-probing" : ""}`}
                  style={{ ["--beacon-color" as string]: beaconColorVar }}
                >
                  <span className="signal-beacon-ring" />
                  <span className="signal-beacon-core" />
                </span>
                <SignalBars ms={delay} />
                <span
                  className="font-mono font-medium num-tabular"
                  style={{
                    color: mainNodeTesting
                      ? "var(--text-secondary)"
                      : delayColorVar(delay),
                  }}
                >
                  {mainNodeTesting ? "..." : formatLatency(delay)}
                </span>
              </button>
            </div>
          )}

          {/* One-Line Takeover Summary (shared format with Tray & TitleBar) */}
          <div
            className="truncate rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-1 text-[11px] text-[var(--text-secondary)]"
            title={takeoverSummary}
          >
            {takeoverSummary}
          </div>

          <button
            type="button"
            disabled={coreBusy}
            onClick={onToggleCore}
            className={`w-full ${coreInfo.running ? "ui-btn-secondary" : "ui-btn-primary"} h-7 text-[12px]`}
          >
            {coreInfo.running ? (
              <>
                <Square className="h-3 w-3" strokeWidth={1.6} />
                {dict.nav.stopCore}
              </>
            ) : (
              <>
                <Play className="h-3 w-3" strokeWidth={1.6} />
                {dict.nav.startCore}
              </>
            )}
          </button>

          <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-2 text-[11px] text-[var(--text-secondary)]">
            <span className="inline-flex items-center gap-1">
              <ShieldCheck className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
              {dict.nav.netguard}
            </span>
            <span
              className="font-medium"
              style={{
                color: coreInfo.netguardArmed ? "var(--success-text)" : "var(--text-secondary)",
              }}
            >
              {coreInfo.netguardArmed ? dict.nav.netguardArmed : dict.nav.netguardReady}
            </span>
          </div>
        </div>
      )}
    </aside>
  );
}
