import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Ban,
  ChevronDown,
  ChevronRight,
  FlaskConical,
  FolderOpen,
  Globe,
  GripVertical,
  ListPlus,
  Loader2,
  MoreHorizontal,
  Pencil,
  Plus,
  ShieldAlert,
  Trash2,
  Waypoints,
  X,
} from "lucide-react";
import { CustomSelect, type SelectGroup } from "../../components/CustomSelect";
import { RegionFlag, parseFlagText } from "../../components/RegionFlag";
import type { Dict } from "../../i18n";
import type {
  AppPresetStatus,
  AppProxyRule,
  AppProxyStatusDto,
  AppRuleTestQuery,
  AppRuleTestTrace,
  CaptureMode,
  DomainOverride,
  DomainOverrideAction,
  DriverProbeDto,
  ExternalChildAlert,
  InstalledAppItem,
  MissingAppTargetWarning,
  NodeIR,
  PlatformKind,
  PrivilegedServiceStatus,
  ProcessInfoDto,
  ProxyChain,
  ServiceActionKind,
} from "../../types";
import {
  computeAvailableRegions,
  formatLatency,
  resolveActiveRecoveryFault,
} from "../../utils/nodes";
import { DryRunDrawer } from "./DryRunDrawer";
import { ProcessPickerModal } from "./ProcessPickerModal";

interface AppsViewProps {
  dict: Dict;
  platform: PlatformKind | string;
  captureMode: CaptureMode;
  captureSwitching: boolean;
  nodes: NodeIR[];
  chains: ProxyChain[];
  mainNodeId?: string | null;
  appRules: AppProxyRule[];
  appPresets: AppPresetStatus[];
  serviceStatus: PrivilegedServiceStatus;
  driverStatus: DriverProbeDto | null;
  appProxyStatus: AppProxyStatusDto | null;
  missingTargets: MissingAppTargetWarning[];
  externalChildren: ExternalChildAlert[];
  onSelectCapture: (mode: CaptureMode) => Promise<void>;
  onServiceAction: (action: ServiceActionKind) => Promise<void>;
  onFallbackToTun: () => Promise<void>;
  onOpenWindowsSecurity: () => Promise<void>;
  onPickWindivertDir: () => Promise<void>;
  onProbeDriver: () => Promise<void>;
  onOpenLogs: () => void;
  onOpenLogsDir: () => Promise<void>;
  onTogglePreset: (presetId: string, enabled: boolean, target?: string) => Promise<void>;
  onSaveRule: (rule: AppProxyRule) => Promise<void>;
  onDeleteRule: (id: string) => Promise<void>;
  onReorderRules: (ids: string[]) => Promise<void>;
  onRunDryRun: (query: AppRuleTestQuery) => Promise<AppRuleTestTrace | null>;
  onLoadProcesses: () => Promise<{
    processes: ProcessInfoDto[];
    installed: InstalledAppItem[];
  }>;
  onIncludeExternalChild: (ruleId: string, childPath: string) => Promise<void>;
  onIgnoreExternalChild: (ruleId: string, childPath: string) => Promise<void>;
  onTestInRouting: (host: string) => void;
}

const PRESET_ORDER = [
  "antigravity",
  "cursor",
  "vscode",
  "git-ssh",
  "discord",
  "telegram",
  "steam",
];

function presetMonogram(name: string): string {
  const words = name.replace(/[^a-zA-Z0-9\s]/g, " ").trim().split(/\s+/);
  if (words.length >= 2) {
    return `${words[0][0] ?? ""}${words[1][0] ?? ""}`.toUpperCase();
  }
  return name.slice(0, 2).toUpperCase();
}

interface RuleDraft {
  id: string;
  name: string;
  presetId?: string | null;
  processNames: string;
  pathContains: string;
  macBundlePaths: string;
  includeChildren: boolean;
  domains: DomainOverride[];
  dstPorts: string;
  protocols: Set<string>;
  dstCidrs: string;
  target: string;
  enabled: boolean;
  priority: number;
}

function ruleToDraft(rule: AppProxyRule): RuleDraft {
  return {
    id: rule.id,
    name: rule.name,
    presetId: rule.presetId ?? null,
    processNames: rule.processNames.join(", "),
    pathContains: rule.pathContains.join(", "),
    macBundlePaths: rule.macBundlePaths.join(", "),
    includeChildren: rule.includeChildren,
    domains: rule.domains.map((d) => ({ ...d })),
    dstPorts: rule.dstPorts.join(", "),
    protocols: new Set(rule.protocols.length > 0 ? rule.protocols : ["tcp", "udp"]),
    dstCidrs: rule.dstCidrs.join(", "),
    target: rule.target || "follow",
    enabled: rule.enabled,
    priority: rule.priority,
  };
}

export function AppsView({
  dict,
  platform,
  captureMode,
  captureSwitching,
  nodes,
  chains,
  mainNodeId,
  appRules,
  appPresets,
  serviceStatus,
  driverStatus,
  appProxyStatus,
  missingTargets,
  externalChildren,
  onSelectCapture,
  onServiceAction,
  onFallbackToTun,
  onOpenWindowsSecurity,
  onPickWindivertDir,
  onProbeDriver,
  onOpenLogs,
  onOpenLogsDir,
  onTogglePreset,
  onSaveRule,
  onDeleteRule,
  onReorderRules,
  onRunDryRun,
  onLoadProcesses,
  onIncludeExternalChild,
  onIgnoreExternalChild,
  onTestInRouting,
}: AppsViewProps) {
  const isMac = platform === "macos";

  const [menuOpen, setMenuOpen] = useState(false);
  const [dismissedFaultKey, setDismissedFaultKey] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [domainInput, setDomainInput] = useState("");
  const [validationErr, setValidationErr] = useState<string | null>(null);
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [compactMenuRuleId, setCompactMenuRuleId] = useState<string | null>(null);

  const [pickerOpen, setPickerOpen] = useState(false);
  const [pickerProcesses, setPickerProcesses] = useState<ProcessInfoDto[]>([]);
  const [pickerInstalled, setPickerInstalled] = useState<InstalledAppItem[]>([]);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerProcess, setDrawerProcess] = useState("node.exe");

  const menuRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<HTMLDivElement | null>(null);
  const editorNameRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editingId) {
      window.requestAnimationFrame(() => {
        editorRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        editorNameRef.current?.focus();
      });
    }
  }, [editingId]);

  useEffect(() => {
    const onPointer = (e: MouseEvent) => {
      if (menuOpen && menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
      if (compactMenuRuleId) {
        setCompactMenuRuleId(null);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMenuOpen(false);
        setCompactMenuRuleId(null);
      }
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [menuOpen, compactMenuRuleId]);

  const sortedPresets = useMemo(() => {
    return [...appPresets].sort((a, b) => {
      const ia = PRESET_ORDER.indexOf(a.id);
      const ib = PRESET_ORDER.indexOf(b.id);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });
  }, [appPresets]);

  const sortedRules = useMemo(
    () => [...appRules].sort((a, b) => a.priority - b.priority),
    [appRules],
  );

  const missingByRule = useMemo(
    () => new Map(missingTargets.map((m) => [m.ruleId, m])),
    [missingTargets],
  );

  const mainNode = useMemo(
    () => nodes.find((n) => n.id === mainNodeId) ?? nodes[0] ?? null,
    [nodes, mainNodeId],
  );

  const regionNames = dict.routing.regions as Record<string, string>;
  const availableRegions = useMemo(() => computeAvailableRegions(nodes), [nodes]);

  // Unified 6-option Target Selector groups (B1: button uses shortLabel only, menu shows full label + meta)
  const targetGroups = useMemo<SelectGroup[]>(() => {
    const mainMeta = mainNode ? parseFlagText(mainNode.remark, mainNode.region).cleanText : undefined;
    const primaryGroup: SelectGroup = {
      label: dict.routing.optActionsGroup,
      options: [
        {
          value: "follow",
          label: dict.apps.targetFollow,
          shortLabel: dict.apps.targetFollowShort,
          meta: mainMeta,
          title: mainMeta
            ? `${dict.apps.targetFollow} (${dict.apps.targetResolved.replace("{target}", mainMeta)})`
            : dict.apps.targetFollow,
        },
        {
          value: "main",
          label: dict.apps.targetMain,
          meta: mainMeta,
          title: mainMeta
            ? `${dict.apps.targetMain} (${dict.apps.targetResolved.replace("{target}", mainMeta)})`
            : dict.apps.targetMain,
          icon: mainNode?.region ? <RegionFlag code={mainNode.region} size="xs" /> : undefined,
        },
        {
          value: "direct",
          label: dict.apps.targetDirect,
        },
        {
          value: "reject",
          label: dict.apps.targetReject,
          tone: "danger",
          icon: <Ban className="h-3 w-3 shrink-0" style={{ color: "var(--danger-text)" }} strokeWidth={1.7} />,
        },
      ],
    };

    const autoGroup: SelectGroup = {
      label: dict.apps.targetAuto,
      options: [
        ...availableRegions.map((b) => ({
          value: `auto:${b.code}`,
          label: `${dict.routing.optAutoRegionPrefix} ${regionNames[b.code] ?? b.code}`,
          meta: String(b.count),
          icon: <RegionFlag code={b.code} size="xs" />,
        })),
        {
          value: "auto:ALL",
          label: dict.routing.optAutoAll,
          meta: String(nodes.length),
        },
      ],
    };

    const groups: SelectGroup[] = [primaryGroup, autoGroup];
    if (chains.length > 0) {
      groups.push({
        label: dict.apps.targetChain,
        options: chains.map((c) => ({
          value: `chain:${c.id}`,
          label: c.name,
          meta:
            c.realDelayMs != null
              ? `${c.hops.length}H \u00b7 ${formatLatency(c.realDelayMs)}`
              : `${c.hops.length}H`,
          icon: <Waypoints className="h-3 w-3 shrink-0 text-[var(--accent-focus)]" strokeWidth={1.6} />,
        })),
      });
    }
    if (nodes.length > 0) {
      groups.push({
        label: dict.apps.targetNode,
        options: nodes.map((n) => {
          const parsed = parseFlagText(n.remark, n.region);
          return {
            value: `node:${n.id}`,
            label: parsed.cleanText,
            meta: n.realDelayMs != null ? formatLatency(n.realDelayMs) : undefined,
            icon: parsed.isoCode ? <RegionFlag code={parsed.isoCode} size="xs" /> : undefined,
          };
        }),
      });
    }
    return groups;
  }, [availableRegions, chains, dict, mainNode, nodes, regionNames]);

  const resolvePresetTargetHint = (target: string): string | null => {
    if (target === "direct" || target === "reject") return null;
    if (target === "follow" || target === "main") {
      if (mainNodeId?.startsWith("chain:")) {
        return chains.find((c) => c.id === mainNodeId.slice(6))?.name ?? null;
      }
      if (!mainNode) return null;
      return parseFlagText(mainNode.remark, mainNode.region).cleanText;
    }
    if (target.startsWith("chain:")) {
      return chains.find((c) => c.id === target.slice(6))?.name ?? null;
    }
    if (target === "auto:ALL") {
      return mainNode ? parseFlagText(mainNode.remark, mainNode.region).cleanText : null;
    }
    if (target.startsWith("auto:")) {
      const code = target.slice(5).toUpperCase();
      const candidate = nodes.find((n) => n.region.toUpperCase() === code);
      return candidate ? parseFlagText(candidate.remark, candidate.region).cleanText : null;
    }
    if (target.startsWith("node:")) {
      const found = nodes.find((n) => n.id === target.slice(5));
      return found ? parseFlagText(found.remark, found.region).cleanText : null;
    }
    return null;
  };

  // Quiet Recovery Banner fault detection (shared single-source-of-truth with Sidebar/TitleBar/Tray)
  const activeFaultKind = useMemo(
    () =>
      resolveActiveRecoveryFault({
        captureMode,
        serviceStatus,
        appProxyStatus,
        driverStatus,
      }),
    [captureMode, serviceStatus, appProxyStatus, driverStatus],
  );

  const showRecoveryBanner =
    activeFaultKind !== null && activeFaultKind !== dismissedFaultKey;

  useEffect(() => {
    if (!activeFaultKind) {
      setDismissedFaultKey(null);
    }
  }, [activeFaultKind]);

  const enabledCount = sortedRules.filter((r) => r.enabled).length;
  const engineStatusLabel =
    captureMode === "tun"
      ? dict.apps.statusPausedTun
      : captureMode === "apps" && appProxyStatus?.running
        ? enabledCount === 1
          ? dict.apps.statusRunningOne
          : dict.apps.statusRunning.replace("{count}", String(enabledCount))
        : dict.apps.statusStandby;

  const openPicker = async () => {
    setPickerOpen(true);
    const { processes, installed } = await onLoadProcesses();
    setPickerProcesses(processes);
    setPickerInstalled(installed);
  };

  const openNewRuleEditor = () => {
    setEditingId("__new__");
    setAdvancedOpen(false);
    setDomainInput("");
    setValidationErr(null);
    setDraft({
      id: `app-custom-${Date.now()}`,
      name: "",
      presetId: null,
      processNames: "",
      pathContains: "",
      macBundlePaths: "",
      includeChildren: true,
      domains: [],
      dstPorts: "",
      protocols: new Set(["tcp", "udp"]),
      dstCidrs: "",
      target: "follow",
      enabled: true,
      priority: sortedRules.length + 1,
    });
  };

  const openEditRule = (rule: AppProxyRule) => {
    setEditingId(rule.id);
    setDraft(ruleToDraft(rule));
    setAdvancedOpen(
      rule.dstPorts.length > 0 || rule.dstCidrs.length > 0 || rule.protocols.length === 1,
    );
    setDomainInput("");
    setValidationErr(null);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setDraft(null);
    setValidationErr(null);
  };

  const addDomainChip = () => {
    if (!draft) return;
    const cleaned = domainInput.trim().toLowerCase();
    if (!cleaned) return;
    if (!draft.domains.some((d) => d.pattern === cleaned)) {
      setDraft({
        ...draft,
        domains: [...draft.domains, { pattern: cleaned, action: "proxy" }],
      });
    }
    setDomainInput("");
  };

  const cycleDomainAction = (pattern: string) => {
    if (!draft) return;
    const order: DomainOverrideAction[] = ["proxy", "direct", "reject"];
    setDraft({
      ...draft,
      domains: draft.domains.map((d) => {
        if (d.pattern !== pattern) return d;
        const next = order[(order.indexOf(d.action) + 1) % order.length];
        return { ...d, action: next };
      }),
    });
  };

  const removeDomainChip = (pattern: string) => {
    if (!draft) return;
    setDraft({
      ...draft,
      domains: draft.domains.filter((d) => d.pattern !== pattern),
    });
  };

  const saveDraft = async () => {
    if (!draft) return;
    const splitCsv = (s: string) =>
      s
        .split(/[,\n]+/)
        .map((x) => x.trim())
        .filter(Boolean);

    const name = draft.name.trim();
    const processNames = splitCsv(draft.processNames);
    const pathContains = splitCsv(draft.pathContains);
    const macBundlePaths = splitCsv(draft.macBundlePaths);

    if (!name) {
      setValidationErr(dict.apps.validationName);
      return;
    }
    if (
      processNames.length === 0 &&
      pathContains.length === 0 &&
      macBundlePaths.length === 0
    ) {
      setValidationErr(dict.apps.validationMatcher);
      return;
    }

    const dstPorts = splitCsv(draft.dstPorts)
      .map((s) => Number.parseInt(s, 10))
      .filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);

    const existing = sortedRules.find((r) => r.id === draft.id);
    const payload: AppProxyRule = {
      id: draft.id,
      name,
      enabled: draft.enabled,
      priority: draft.priority,
      presetId: draft.presetId ?? null,
      processNames,
      pathPrefixes: existing?.pathPrefixes ?? [],
      pathContains,
      macBundlePaths,
      ignoredExternalChildren: existing?.ignoredExternalChildren ?? [],
      includeChildren: draft.includeChildren,
      domains: draft.domains,
      dstCidrs: splitCsv(draft.dstCidrs),
      dstPorts,
      protocols: Array.from(draft.protocols),
      target: draft.target,
    };

    await onSaveRule(payload);
    cancelEdit();
  };

  const moveRule = async (index: number, delta: -1 | 1) => {
    const targetIdx = index + delta;
    if (targetIdx < 0 || targetIdx >= sortedRules.length) return;
    const ids = sortedRules.map((r) => r.id);
    const [moved] = ids.splice(index, 1);
    ids.splice(targetIdx, 0, moved);
    await onReorderRules(ids);
  };

  const shadowedRuleWarning = useMemo(() => {
    if (!draft) return null;
    const curIdx = sortedRules.findIndex((r) => r.id === draft.id);
    const limit = curIdx === -1 ? sortedRules.length : curIdx;
    const draftProcs = new Set(
      draft.processNames
        .split(/[,\n]+/)
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean),
    );
    if (draftProcs.size === 0) return null;
    for (let i = 0; i < limit; i++) {
      const earlier = sortedRules[i];
      if (!earlier.enabled) continue;
      if (earlier.processNames.some((p) => draftProcs.has(p.toLowerCase()))) {
        return dict.apps.shadowedWarn
          .replace("{index}", String(i + 1))
          .replace("{name}", earlier.name);
      }
    }
    return null;
  }, [draft, sortedRules, dict]);

  const renderInlineEditor = () => {
    if (!draft) return null;
    return (
      <div
        ref={editorRef}
        className="space-y-3 border-t border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-4"
      >
        {shadowedRuleWarning && (
          <div
            className="flex items-center gap-2 rounded-[9px] border px-3 py-1.5 text-[12px]"
            style={{
              borderColor: "var(--warning-border)",
              backgroundColor: "var(--warning-bg)",
              color: "var(--warning-text)",
            }}
          >
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
            <span>{shadowedRuleWarning}</span>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="block text-[12px] font-medium text-[var(--text-primary)]">
              {dict.apps.editorNameLabel}
            </label>
            <input
              ref={editorNameRef}
              type="text"
              value={draft.name}
              onChange={(e) => {
                setValidationErr(null);
                setDraft({ ...draft, name: e.target.value });
              }}
              placeholder={dict.apps.editorNamePh}
              className="ui-input h-8 w-full px-3 text-[12.5px]"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[12px] font-medium text-[var(--text-primary)]">
              {dict.apps.colTarget}
            </label>
            <CustomSelect
              value={draft.target}
              groups={targetGroups}
              onChange={(val) => setDraft({ ...draft, target: val })}
              className="w-full"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[12px] font-medium text-[var(--text-primary)]">
              {dict.apps.editorProcsLabel}
            </label>
            <input
              type="text"
              value={draft.processNames}
              onChange={(e) => {
                setValidationErr(null);
                setDraft({ ...draft, processNames: e.target.value });
              }}
              placeholder={dict.apps.editorProcsPh}
              className="ui-input h-8 w-full px-3 font-mono text-[12px]"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[12px] font-medium text-[var(--text-primary)]">
              {isMac ? dict.apps.editorMacBundleLabel : dict.apps.editorPathContainsLabel}
            </label>
            <input
              type="text"
              value={isMac ? draft.macBundlePaths : draft.pathContains}
              onChange={(e) => {
                setValidationErr(null);
                setDraft(
                  isMac
                    ? { ...draft, macBundlePaths: e.target.value }
                    : { ...draft, pathContains: e.target.value },
                );
              }}
              placeholder={isMac ? dict.apps.editorMacBundlePh : dict.apps.editorPathContainsPh}
              className="ui-input h-8 w-full px-3 font-mono text-[12px]"
            />
          </div>
        </div>

        <label className="inline-flex items-center gap-2 text-[12px] text-[var(--text-primary)] cursor-pointer">
          <input
            type="checkbox"
            checked={draft.includeChildren}
            onChange={(e) => setDraft({ ...draft, includeChildren: e.target.checked })}
            className="h-3.5 w-3.5 accent-[var(--accent-primary)]"
          />
          <span>{dict.apps.editorIncludeChildren}</span>
        </label>

        {/* L7 Domain Override Chips (3-state: icon + label + semantic color) */}
        <div className="space-y-2">
          <label className="block text-[12px] font-medium text-[var(--text-primary)]">
            {dict.apps.editorDomainsLabel}
          </label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addDomainChip();
                }
              }}
              placeholder={dict.apps.editorDomainPh}
              className="ui-input h-8 min-w-0 flex-1 px-3 font-mono text-[12px]"
            />
            <button type="button" onClick={addDomainChip} className="ui-btn-secondary h-8">
              <Plus className="h-3.5 w-3.5" strokeWidth={1.6} />
              {dict.apps.editorDomainAdd}
            </button>
          </div>
          {draft.domains.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {draft.domains.map((dom) => {
                const isReject = dom.action === "reject";
                const isDirect = dom.action === "direct";
                const style = isReject
                  ? {
                      borderColor: "var(--danger-border)",
                      backgroundColor: "var(--danger-bg)",
                      color: "var(--danger-text-on-bg)",
                    }
                  : isDirect
                    ? {
                        borderColor: "var(--success-border)",
                        backgroundColor: "var(--success-bg)",
                        color: "var(--success-text)",
                      }
                    : {
                        borderColor: "var(--border-strong)",
                        backgroundColor: "var(--bg-surface)",
                        color: "var(--text-primary)",
                      };
                const actionLabel = isReject
                  ? dict.apps.actionReject
                  : isDirect
                    ? dict.apps.actionDirect
                    : dict.apps.actionProxy;
                return (
                  <span
                    key={dom.pattern}
                    style={style}
                    className="inline-flex items-center gap-1.5 rounded-[6px] border px-2 py-1 text-[11.5px] font-medium"
                  >
                    <button
                      type="button"
                      onClick={() => cycleDomainAction(dom.pattern)}
                      className="inline-flex items-center gap-1 cursor-pointer"
                      title={`${dom.pattern} -> ${actionLabel}`}
                    >
                      {isReject ? (
                        <Ban className="h-3 w-3 shrink-0" strokeWidth={1.7} />
                      ) : isDirect ? (
                        <ArrowRight className="h-3 w-3 shrink-0" strokeWidth={1.7} />
                      ) : (
                        <Globe className="h-3 w-3 shrink-0" strokeWidth={1.6} />
                      )}
                      <span className="font-mono">{dom.pattern}</span>
                      <span className="opacity-75">[{actionLabel}]</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => removeDomainChip(dom.pattern)}
                      aria-label={`Remove ${dom.pattern}`}
                      className="ml-0.5 rounded p-0.5 hover:opacity-75 cursor-pointer"
                    >
                      <X className="h-3 w-3" strokeWidth={1.6} />
                    </button>
                  </span>
                );
              })}
            </div>
          )}
        </div>

        {/* Collapsible Advanced L4 Filters */}
        <div>
          <button
            type="button"
            onClick={() => setAdvancedOpen((v) => !v)}
            className="inline-flex items-center gap-1 text-[12px] font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
          >
            {advancedOpen ? (
              <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.5} />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.5} />
            )}
            {dict.apps.editorAdvancedToggle}
          </button>

          {advancedOpen && (
            <div className="mt-2.5 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)]">
                  {dict.apps.editorPortsLabel}
                </label>
                <input
                  type="text"
                  value={draft.dstPorts}
                  onChange={(e) => setDraft({ ...draft, dstPorts: e.target.value })}
                  placeholder={dict.apps.editorPortsPh}
                  className="ui-input h-8 w-full px-2.5 font-mono text-[12px]"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)]">
                  {dict.apps.editorProtocolsLabel}
                </label>
                <div className="flex items-center gap-1.5 pt-0.5">
                  {["tcp", "udp", "quic"].map((proto) => {
                    const active = draft.protocols.has(proto);
                    return (
                      <button
                        key={proto}
                        type="button"
                        onClick={() => {
                          const next = new Set(draft.protocols);
                          if (next.has(proto) && next.size > 1) next.delete(proto);
                          else next.add(proto);
                          setDraft({ ...draft, protocols: next });
                        }}
                        className={`rounded-[6px] border px-2 py-1 font-mono text-[11px] font-medium uppercase cursor-pointer ${
                          active
                            ? "border-[var(--accent-primary)] bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                            : "border-[var(--border-strong)] bg-[var(--bg-surface)] text-[var(--text-secondary)]"
                        }`}
                      >
                        {proto}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="space-y-1">
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)]">
                  {dict.apps.editorCidrsLabel}
                </label>
                <input
                  type="text"
                  value={draft.dstCidrs}
                  onChange={(e) => setDraft({ ...draft, dstCidrs: e.target.value })}
                  placeholder={dict.apps.editorCidrsPh}
                  className="ui-input h-8 w-full px-2.5 font-mono text-[12px]"
                />
              </div>
            </div>
          )}
        </div>

        {validationErr && (
          <div className="text-[12px] font-medium" style={{ color: "var(--danger-text)" }}>
            {validationErr}
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-1">
          <button type="button" onClick={cancelEdit} className="ui-btn-secondary h-8">
            {dict.nodes.cancel}
          </button>
          <button type="button" onClick={() => void saveDraft()} className="ui-btn-primary h-8">
            {dict.routing.btnSave}
          </button>
        </div>
      </div>
    );
  };

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Single-Row 40px Page Header */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <h1 className="text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
          {dict.apps.title}
        </h1>
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => {
              setDrawerProcess("node.exe");
              setDrawerOpen(true);
            }}
            className="ui-btn-secondary h-8"
          >
            <FlaskConical className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            {dict.apps.btnDryRun}
          </button>
          <button type="button" onClick={() => void openPicker()} className="ui-btn-secondary h-8">
            <ListPlus className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            {dict.apps.btnPickRunning}
          </button>
          <button type="button" onClick={openNewRuleEditor} className="ui-btn-primary h-8">
            <Plus className="h-3.5 w-3.5" strokeWidth={1.6} />
            {dict.apps.btnNewRule}
          </button>
        </div>
      </div>

      {/* Main Scrollable Content */}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4 lg:px-5">
        <div className="space-y-5">
          {/* 1. Single-Row 48px Engine & Service Strip */}
          <div className="ui-card flex min-h-[48px] flex-wrap items-center justify-between gap-3 px-4 py-2.5">
            <div className="flex min-w-0 items-center gap-2.5">
              <span
                className="h-2.5 w-2.5 shrink-0 rounded-full"
                style={{
                  backgroundColor: showRecoveryBanner
                    ? "var(--warning-dot)"
                    : captureMode === "apps" && appProxyStatus?.running
                      ? "var(--success-dot)"
                      : "var(--text-tertiary)",
                }}
              />
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">
                    {dict.apps.engineTitle}
                  </span>
                  <span
                    className="rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]"
                    title={isMac ? dict.apps.engineMac : dict.apps.engineWin}
                  >
                    {isMac ? dict.apps.engineTagMac : dict.apps.engineTagWin}
                  </span>
                  <span className="text-[12px] text-[var(--text-secondary)]">
                    {engineStatusLabel}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {isMac && !serviceStatus.installed ? (
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2.5 py-1 text-[11.5px] text-[var(--text-secondary)]">
                    <span className="font-mono">{dict.service.macLabel}:</span>
                    <span className="font-medium text-[var(--text-primary)]">
                      {dict.service.macNotInstalled}
                    </span>
                  </span>
                  <button
                    type="button"
                    title={dict.service.macInstallHint}
                    onClick={() => void onServiceAction("install")}
                    className="ui-btn-primary h-7 text-[11.5px]"
                  >
                    {dict.service.macInstall}
                  </button>
                </div>
              ) : captureMode === "tun" ? (
                <button
                  type="button"
                  disabled={captureSwitching}
                  onClick={() => void onSelectCapture("apps")}
                  className="ui-btn-secondary h-7 text-[11.5px]"
                >
                  {captureSwitching && (
                    <Loader2 className="h-3 w-3 animate-spin" strokeWidth={1.7} />
                  )}
                  {dict.apps.switchToApps}
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  {captureSwitching && (
                    <Loader2
                      className="h-3.5 w-3.5 animate-spin text-[var(--text-secondary)]"
                      strokeWidth={1.7}
                    />
                  )}
                  <button
                    type="button"
                    role="switch"
                    disabled={captureSwitching}
                    aria-checked={captureMode === "apps"}
                    aria-label={
                      captureMode === "apps" ? dict.apps.toggleDisable : dict.apps.toggleEnable
                    }
                    title={
                      captureMode === "apps" ? dict.apps.toggleDisable : dict.apps.toggleEnable
                    }
                    onClick={() =>
                      void onSelectCapture(captureMode === "apps" ? "off" : "apps")
                    }
                    className="ui-switch"
                  >
                    <span className="ui-switch-knob" />
                  </button>
                </div>
              )}

              {/* Overflow menu (...) */}
              <div ref={menuRef} className="relative">
                <button
                  type="button"
                  onClick={() => setMenuOpen((v) => !v)}
                  aria-label="Service actions"
                  aria-expanded={menuOpen}
                  className="ui-btn-ghost h-7 w-7 p-0"
                >
                  <MoreHorizontal className="h-4 w-4" strokeWidth={1.6} />
                </button>
                {menuOpen && (
                  <div className="ui-popover absolute top-full right-0 z-40 mt-1.5 min-w-[216px] w-max space-y-0.5 p-1.5 text-[12px]">
                    {!isMac ? (
                      <>
                        {serviceStatus.connected && (
                          <button
                            type="button"
                            onClick={() => {
                              setMenuOpen(false);
                              void onServiceAction("stop_worker");
                            }}
                            className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                          >
                            {dict.service.menuStopWorker}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => {
                            setMenuOpen(false);
                            void onServiceAction("cleanup_legacy");
                          }}
                          className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                        >
                          {dict.service.menuCleanupLegacy}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setMenuOpen(false);
                            void onProbeDriver();
                          }}
                          className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                        >
                          {dict.service.menuProbe}
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={() => {
                            setMenuOpen(false);
                            void onServiceAction("install");
                          }}
                          className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                        >
                          {dict.service.menuReinstall}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setMenuOpen(false);
                            void onServiceAction("uninstall");
                          }}
                          className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--danger-bg-hover)] hover:text-[var(--danger-text-on-bg)] cursor-pointer"
                        >
                          {dict.service.menuUninstall}
                        </button>
                      </>
                    )}
                    <div className="my-1 border-t border-[var(--border-hairline)]" />
                    <button
                      type="button"
                      onClick={() => {
                        setMenuOpen(false);
                        onOpenLogs();
                      }}
                      className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                    >
                      {dict.service.menuLogs}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setMenuOpen(false);
                        void onOpenLogsDir();
                      }}
                      className="flex w-full items-center whitespace-nowrap rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                    >
                      {dict.service.menuOpenLogsDir}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* 2. Quiet Recovery Banner (ONLY on real failure; NEVER on healthy standby) */}
          {showRecoveryBanner && (
            <div
              role="alert"
              className="flex flex-wrap items-center justify-between gap-3 rounded-[12px] border px-4 py-3"
              style={{
                borderColor: "var(--warning-border)",
                backgroundColor: "var(--warning-bg)",
                borderLeftWidth: "3px",
                borderLeftColor: "var(--warning-dot)",
              }}
            >
              <div className="flex min-w-0 flex-1 items-start gap-2.5">
                <ShieldAlert
                  className="mt-0.5 h-4 w-4 shrink-0"
                  style={{ color: "var(--warning-text)" }}
                  strokeWidth={1.7}
                />
                <div className="min-w-0">
                  <div
                    className="text-[13px] font-semibold"
                    style={{ color: "var(--warning-text)" }}
                  >
                    {activeFaultKind === "legacy_conflict"
                      ? dict.recovery.conflictTitle
                      : activeFaultKind === "hvci_blocked"
                        ? dict.recovery.blockedTitle
                        : activeFaultKind === "driver_missing"
                          ? dict.recovery.missingTitle
                          : activeFaultKind === "signature_failed"
                            ? dict.recovery.sigTitle
                            : activeFaultKind === "pipe_timeout"
                              ? dict.recovery.pipeTitle
                              : null}
                  </div>
                  <div className="text-[12px] text-[var(--text-secondary)]">
                    {activeFaultKind === "legacy_conflict"
                      ? serviceStatus.legacyServices && serviceStatus.legacyServices.length > 0
                        ? dict.recovery.conflictDescServices.replace(
                            "{services}",
                            serviceStatus.legacyServices.join(", "),
                          )
                        : dict.recovery.conflictDescGeneric
                      : activeFaultKind === "hvci_blocked"
                        ? dict.recovery.blockedDesc
                        : activeFaultKind === "driver_missing"
                          ? dict.recovery.missingDesc
                          : activeFaultKind === "signature_failed"
                            ? dict.recovery.sigDesc
                            : activeFaultKind === "pipe_timeout"
                              ? isMac
                                ? dict.recovery.pipeDesc
                                : dict.recovery.pipeDescWin
                              : null}
                  </div>
                  {activeFaultKind === "pipe_timeout" && serviceStatus.error && (
                    <div
                      className="mt-1 truncate font-mono text-[11px] text-[var(--text-secondary)] select-text"
                      title={serviceStatus.error}
                    >
                      {serviceStatus.error}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                {activeFaultKind === "legacy_conflict" && (
                  <>
                    <button
                      type="button"
                      onClick={() => void onServiceAction("cleanup_legacy")}
                      className="ui-btn-primary h-7 text-[11.5px]"
                    >
                      {dict.recovery.cleanupNow}
                    </button>
                    <button
                      type="button"
                      onClick={() => void onProbeDriver()}
                      className="ui-btn-secondary h-7 text-[11.5px]"
                    >
                      {dict.recovery.retry}
                    </button>
                  </>
                )}
                {activeFaultKind === "hvci_blocked" && (
                  <>
                    <button
                      type="button"
                      onClick={() => void onFallbackToTun()}
                      className="ui-btn-primary h-7 text-[11.5px]"
                    >
                      {dict.recovery.useTun}
                    </button>
                    <button
                      type="button"
                      onClick={() => void onOpenWindowsSecurity()}
                      className="ui-btn-secondary h-7 text-[11.5px]"
                    >
                      {dict.recovery.openSecurity}
                    </button>
                  </>
                )}
                {(activeFaultKind === "driver_missing" ||
                  activeFaultKind === "signature_failed") && (
                  <button
                    type="button"
                    onClick={() => void onPickWindivertDir()}
                    className="ui-btn-primary h-7 text-[11.5px]"
                  >
                    <FolderOpen className="h-3.5 w-3.5" strokeWidth={1.5} />
                    {activeFaultKind === "signature_failed"
                      ? dict.recovery.repickDir
                      : dict.recovery.pickDir}
                  </button>
                )}
                {activeFaultKind === "pipe_timeout" && (
                  <>
                    <button
                      type="button"
                      onClick={() => void onServiceAction(isMac ? "restart" : "start_worker")}
                      className="ui-btn-primary h-7 text-[11.5px]"
                    >
                      {isMac ? dict.recovery.restartService : dict.recovery.restartHelper}
                    </button>
                    {isMac ? (
                      <button
                        type="button"
                        onClick={onOpenLogs}
                        className="ui-btn-secondary h-7 text-[11.5px]"
                      >
                        {dict.service.menuLogs}
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void onProbeDriver()}
                        className="ui-btn-secondary h-7 text-[11.5px]"
                      >
                        {dict.recovery.retry}
                      </button>
                    )}
                  </>
                )}
                <button
                  type="button"
                  onClick={() => setDismissedFaultKey(activeFaultKind)}
                  aria-label={dict.recovery.dismiss}
                  className="ui-btn-ghost h-7 w-7 p-0"
                >
                  <X className="h-3.5 w-3.5" strokeWidth={1.6} />
                </button>
              </div>
            </div>
          )}

          {/* 3. 7-Card Preset App Wall (B10: items-start + full-width macOS external-child strip below) */}
          <div className="space-y-2.5">
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)]">
              {dict.apps.presetsTitle}
            </h2>
            <div
              className="grid items-start gap-2.5"
              style={{ gridTemplateColumns: "repeat(auto-fill, minmax(208px, 1fr))" }}
            >
              {sortedPresets.map((preset) => {
                const missingWarn = preset.ruleId ? missingByRule.get(preset.ruleId) : undefined;
                const statusLine =
                  preset.runningCount === 1
                    ? dict.apps.detectedRunningOne
                    : preset.runningCount > 1
                      ? dict.apps.detectedRunning.replace("{count}", String(preset.runningCount))
                      : preset.installed
                        ? dict.apps.installedIdle
                        : preset.enabled
                          ? dict.apps.notInstalledHint
                          : dict.apps.notInstalled;
                const resolvedHint = preset.enabled
                  ? resolvePresetTargetHint(missingWarn ? "follow" : preset.target)
                  : null;

                return (
                  <div
                    key={preset.id}
                    className="ui-card flex min-h-[104px] flex-col justify-between gap-2 p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] font-mono text-[11.5px] font-semibold text-[var(--text-primary)]">
                          {presetMonogram(preset.name)}
                        </span>
                        <span
                          className="truncate text-[13px] font-semibold text-[var(--text-primary)]"
                          title={preset.name}
                        >
                          {preset.name}
                        </span>
                      </div>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={preset.enabled}
                        aria-label={preset.name}
                        onClick={() =>
                          void onTogglePreset(preset.id, !preset.enabled, preset.target)
                        }
                        className="ui-switch"
                      >
                        <span className="ui-switch-knob" />
                      </button>
                    </div>

                    <div
                      className="truncate text-[11.5px] text-[var(--text-secondary)]"
                      title={statusLine}
                    >
                      {statusLine}
                    </div>

                    <div className="space-y-1">
                      <CustomSelect
                        value={missingWarn ? "follow" : preset.target}
                        groups={targetGroups}
                        disabled={!preset.enabled}
                        size="sm"
                        className="w-full"
                        onChange={(nextTarget) =>
                          void onTogglePreset(preset.id, true, nextTarget)
                        }
                      />
                      {resolvedHint && (
                        <div
                          className="truncate px-0.5 text-[11.5px] text-[var(--text-secondary)]"
                          title={dict.apps.targetResolved.replace("{target}", resolvedHint)}
                        >
                          {dict.apps.targetResolved.replace("{target}", resolvedHint)}
                        </div>
                      )}
                    </div>

                    {missingWarn && (
                      <div
                        className="flex items-center gap-1.5 rounded-[6px] border px-2 py-1 text-[11.5px]"
                        style={{
                          borderColor: "var(--warning-border)",
                          backgroundColor: "var(--warning-bg)",
                          color: "var(--warning-text)",
                        }}
                      >
                        <AlertTriangle className="h-3 w-3 shrink-0" strokeWidth={1.6} />
                        <span className="truncate" title={dict.apps.targetFallback}>
                          {dict.apps.targetFallback}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* B10: Full-width macOS external-child inline bar (never stretches sibling preset cards) */}
            {externalChildren.filter((a) => a.children.length > 0).length > 0 && (
              <div className="space-y-1.5">
                {externalChildren
                  .filter((a) => a.children.length > 0)
                  .map((extAlert) => (
                    <div
                      key={extAlert.ruleId}
                      className="flex flex-wrap items-center justify-between gap-2 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-subtle)] px-3.5 py-2 text-[12px] text-[var(--text-secondary)]"
                    >
                      <span className="min-w-0 flex-1">
                        {dict.apps.externalChild
                          .replace("{app}", extAlert.appName)
                          .replace("{count}", String(extAlert.children.length))
                          .replace(
                            "{names}",
                            extAlert.children.map((c) => c.name).join(", "),
                          )}
                      </span>
                      <div className="flex shrink-0 items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => {
                            for (const ch of extAlert.children) {
                              void onIncludeExternalChild(extAlert.ruleId, ch.exePath);
                            }
                          }}
                          className="ui-btn-primary h-7 px-2.5 text-[11.5px]"
                        >
                          {dict.apps.include}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            for (const ch of extAlert.children) {
                              void onIgnoreExternalChild(extAlert.ruleId, ch.exePath);
                            }
                          }}
                          className="ui-btn-ghost h-7 px-2.5 text-[11.5px]"
                        >
                          {dict.apps.ignore}
                        </button>
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </div>

          {/* 4. Custom Rules Table (@container P1-P4, Zero Fixed min-width) */}
          <div className="space-y-2">
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)]">
              {dict.apps.rulesTitle}
            </h2>

            <div className="apps-rules-container ui-card overflow-hidden">
              {editingId === "__new__" && renderInlineEditor()}

              {sortedRules.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-2.5 px-6 py-10 text-center">
                  <div className="text-[13.5px] font-medium text-[var(--text-primary)]">
                    {dict.apps.emptyRulesTitle}
                  </div>
                  <button
                    type="button"
                    onClick={() => void openPicker()}
                    className="ui-btn-secondary h-8"
                  >
                    <ListPlus className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    {dict.apps.btnPickRunning}
                  </button>
                </div>
              ) : (
                <>
                  {/* Header */}
                  <div className="apps-rules-grid border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
                    <div>{dict.apps.colOrder}</div>
                    <div>{dict.apps.colRule}</div>
                    <div className="apps-col-domains">{dict.apps.colDomains}</div>
                    <div>{dict.apps.colTarget}</div>
                    <div>{dict.apps.colEnabled}</div>
                    <div className="text-right">{dict.apps.colActions}</div>
                  </div>

                  {/* Rows */}
                  <div className="divide-y divide-[var(--border-hairline)]">
                    {sortedRules.map((rule, idx) => {
                      const isEditing = editingId === rule.id;
                      const missingWarn = missingByRule.get(rule.id);
                      const summaryChips = [
                        ...rule.processNames.slice(0, 2),
                        ...(isMac
                          ? rule.macBundlePaths.slice(0, 1)
                          : rule.pathContains.slice(0, 1).map((p) => `path: ${p}`)),
                      ];

                      return (
                        <div key={rule.id}>
                          <div
                            draggable
                            tabIndex={0}
                            onDragStart={() => setDraggedId(rule.id)}
                            onDragOver={(e) => e.preventDefault()}
                            onDrop={() => {
                              if (!draggedId || draggedId === rule.id) return;
                              const ids = sortedRules.map((r) => r.id);
                              const from = ids.indexOf(draggedId);
                              const to = ids.indexOf(rule.id);
                              if (from >= 0 && to >= 0) {
                                ids.splice(from, 1);
                                ids.splice(to, 0, draggedId);
                                void onReorderRules(ids);
                              }
                              setDraggedId(null);
                            }}
                            onKeyDown={(e) => {
                              if (e.altKey && e.key === "ArrowUp") {
                                e.preventDefault();
                                void moveRule(idx, -1);
                              } else if (e.altKey && e.key === "ArrowDown") {
                                e.preventDefault();
                                void moveRule(idx, 1);
                              }
                            }}
                            className="group apps-rules-grid min-h-[52px] px-4 py-2 text-[12.5px] transition-colors hover:bg-[var(--bg-hover)]"
                          >
                            {/* Order / Drag */}
                            <div className="flex items-center gap-1 font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
                              <GripVertical
                                className="h-3.5 w-3.5 shrink-0 text-[var(--text-tertiary)] opacity-50 group-hover:opacity-100 cursor-grab"
                                strokeWidth={1.5}
                              />
                              <span>#{idx + 1}</span>
                            </div>

                            {/* Name + Match Summary Subline */}
                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span
                                  className="truncate font-medium text-[var(--text-primary)]"
                                  title={rule.name}
                                >
                                  {rule.name}
                                </span>
                                {missingWarn && (
                                  <span
                                    title={dict.apps.targetFallback}
                                    className="shrink-0 rounded-[5px] border px-1.5 py-0.5 text-[11.5px] font-medium"
                                    style={{
                                      borderColor: "var(--warning-border)",
                                      backgroundColor: "var(--warning-bg)",
                                      color: "var(--warning-text)",
                                    }}
                                  >
                                    !
                                  </span>
                                )}
                              </div>
                              <div className="mt-0.5 flex flex-wrap items-center gap-1 text-[11.5px]">
                                {summaryChips.map((chip) => (
                                  <span
                                    key={chip}
                                    title={chip}
                                    className="max-w-[160px] truncate rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 font-mono text-[var(--text-secondary)]"
                                  >
                                    {chip}
                                  </span>
                                ))}
                                {rule.includeChildren && (
                                  <span className="rounded-[5px] bg-[var(--accent-soft)] px-1.5 py-0.5 font-mono text-[11.5px] text-[var(--text-secondary)]">
                                    {dict.apps.includeChildrenTag}
                                  </span>
                                )}
                                {rule.domains.length > 0 && (
                                  <span className="apps-col-domains-inline rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[11.5px] text-[var(--text-secondary)]">
                                    {rule.domains.length === 1
                                      ? dict.apps.domainCountOne
                                      : dict.apps.domainCount.replace(
                                          "{count}",
                                          String(rule.domains.length),
                                        )}
                                  </span>
                                )}
                              </div>
                            </div>

                            {/* Domain Overrides (P3) */}
                            <div className="apps-col-domains min-w-0">
                              {rule.domains.length > 0 ? (
                                <span
                                  title={rule.domains
                                    .map((d) => `${d.pattern} (${d.action})`)
                                    .join("\n")}
                                  className="inline-block max-w-full truncate rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 text-[11.5px] text-[var(--text-secondary)]"
                                >
                                  {rule.domains.length === 1
                                    ? dict.apps.domainCountOne
                                    : dict.apps.domainCount.replace(
                                        "{count}",
                                        String(rule.domains.length),
                                      )}
                                </span>
                              ) : (
                                <span className="text-[11.5px] text-[var(--text-tertiary)]">
                                  {dict.apps.noDomains}
                                </span>
                              )}
                            </div>

                            {/* Target Selector (P1) */}
                            <div className="min-w-0">
                              <CustomSelect
                                value={missingWarn ? "follow" : rule.target}
                                groups={targetGroups}
                                size="sm"
                                className="w-full"
                                onChange={(val) => void onSaveRule({ ...rule, target: val })}
                              />
                            </div>

                            {/* Enabled Switch (P1) */}
                            <div>
                              <button
                                type="button"
                                role="switch"
                                aria-checked={rule.enabled}
                                aria-label={rule.name}
                                onClick={() =>
                                  void onSaveRule({ ...rule, enabled: !rule.enabled })
                                }
                                className="ui-switch"
                              >
                                <span className="ui-switch-knob" />
                              </button>
                            </div>

                            {/* Actions (P2: Hover-reveal; compact menu < 640px) */}
                            <div className="relative flex items-center justify-end">
                              <div className="apps-actions-full row-actions flex items-center gap-0.5">
                                <button
                                  type="button"
                                  title={dict.apps.actMoveUp}
                                  disabled={idx === 0}
                                  onClick={() => void moveRule(idx, -1)}
                                  className="ui-btn-ghost h-6 w-6 p-0"
                                >
                                  <ArrowUp className="h-3 w-3" strokeWidth={1.6} />
                                </button>
                                <button
                                  type="button"
                                  title={dict.apps.actMoveDown}
                                  disabled={idx === sortedRules.length - 1}
                                  onClick={() => void moveRule(idx, 1)}
                                  className="ui-btn-ghost h-6 w-6 p-0"
                                >
                                  <ArrowDown className="h-3 w-3" strokeWidth={1.6} />
                                </button>
                                <button
                                  type="button"
                                  title={dict.apps.actTest}
                                  onClick={() => {
                                    setDrawerProcess(rule.processNames[0] ?? rule.name);
                                    setDrawerOpen(true);
                                  }}
                                  className="ui-btn-ghost h-6 w-6 p-0"
                                >
                                  <FlaskConical className="h-3.5 w-3.5" strokeWidth={1.5} />
                                </button>
                                <button
                                  type="button"
                                  title={dict.apps.actEdit}
                                  onClick={() =>
                                    isEditing ? cancelEdit() : openEditRule(rule)
                                  }
                                  className="ui-btn-ghost h-6 w-6 p-0"
                                >
                                  <Pencil className="h-3.5 w-3.5" strokeWidth={1.5} />
                                </button>
                                <button
                                  type="button"
                                  title={dict.apps.actDelete}
                                  onClick={() => void onDeleteRule(rule.id)}
                                  className="ui-btn-danger-ghost h-6 w-6 p-0"
                                >
                                  <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
                                </button>
                              </div>

                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setCompactMenuRuleId((cur) =>
                                    cur === rule.id ? null : rule.id,
                                  );
                                }}
                                aria-label={dict.apps.colActions}
                                className="apps-actions-compact ui-btn-ghost h-7 w-7 p-0"
                              >
                                <MoreHorizontal className="h-4 w-4" strokeWidth={1.6} />
                              </button>

                              {compactMenuRuleId === rule.id && (
                                <div
                                  onMouseDown={(e) => e.stopPropagation()}
                                  className="ui-popover absolute top-full right-0 z-40 mt-1 w-36 space-y-0.5 p-1 text-[12px]"
                                >
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setCompactMenuRuleId(null);
                                      setDrawerProcess(rule.processNames[0] ?? rule.name);
                                      setDrawerOpen(true);
                                    }}
                                    className="flex w-full items-center gap-2 rounded-[7px] px-2 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                                  >
                                    <FlaskConical className="h-3.5 w-3.5" strokeWidth={1.5} />
                                    {dict.apps.actTest}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setCompactMenuRuleId(null);
                                      openEditRule(rule);
                                    }}
                                    className="flex w-full items-center gap-2 rounded-[7px] px-2 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                                  >
                                    <Pencil className="h-3.5 w-3.5" strokeWidth={1.5} />
                                    {dict.apps.actEdit}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setCompactMenuRuleId(null);
                                      void onDeleteRule(rule.id);
                                    }}
                                    className="flex w-full items-center gap-2 rounded-[7px] px-2 py-1.5 hover:bg-[var(--danger-bg-hover)] hover:text-[var(--danger-text-on-bg)] cursor-pointer"
                                  >
                                    <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
                                    {dict.apps.actDelete}
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>

                          {isEditing && renderInlineEditor()}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Running Process / Installed App Picker Modal */}
      {pickerOpen && (
        <ProcessPickerModal
          dict={dict}
          processes={pickerProcesses}
          installedApps={pickerInstalled}
          targetGroups={targetGroups}
          onClose={() => setPickerOpen(false)}
          onAddRules={(items, incChildren, targetVal) => {
            for (const item of items) {
              void onSaveRule({
                id: `app-pick-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                name: item.name,
                enabled: true,
                priority: sortedRules.length + 1,
                presetId: null,
                processNames: [item.processName],
                pathPrefixes: [],
                pathContains: [],
                macBundlePaths: item.bundlePath ? [item.bundlePath] : [],
                ignoredExternalChildren: [],
                includeChildren: incChildren,
                domains: [],
                dstCidrs: [],
                dstPorts: [],
                protocols: ["tcp", "udp"],
                target: targetVal,
              });
            }
          }}
        />
      )}

      {/* Rule Match Tester Drawer */}
      {drawerOpen && (
        <DryRunDrawer
          dict={dict}
          appRules={sortedRules}
          nodes={nodes}
          mainNodeId={mainNodeId}
          initialProcess={drawerProcess}
          onRunTest={onRunDryRun}
          onTestInRouting={onTestInRouting}
          onClose={() => setDrawerOpen(false)}
        />
      )}
    </section>
  );
}
