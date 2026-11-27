import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  AppWindow,
  ArrowDown,
  ArrowUp,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Play,
  Power,
  ShieldCheck,
  Square,
} from "lucide-react";
import { api } from "../../api/client";
import { BrandLogo } from "../../components/BrandLogo";
import { NodeLabel } from "../../components/RegionFlag";
import { SegmentedControl } from "../../components/SegmentedControl";
import { SignalBars } from "../../components/SignalBars";
import {
  detectInitialLocale,
  getDict,
  LOCALE_STORAGE_KEY,
  THEME_STORAGE_KEY,
} from "../../i18n";
import type {
  AppProxyRule,
  AppProxyStatusDto,
  AppSettings,
  CaptureMode,
  CoreInfo,
  DriverProbeDto,
  Locale,
  NodeIR,
  PrivilegedServiceStatus,
  RouteMode,
  ThemeMode,
  TrafficSample,
} from "../../types";
import {
  buildTakeoverSummary,
  delayColorVar,
  formatSpeed,
  PROTO_BADGES,
  resolveActiveRecoveryFault,
} from "../../utils/nodes";

function applyTrayTheme(theme: ThemeMode) {
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  const root = document.documentElement;
  root.classList.add("tray-window");
  root.classList.toggle("dark", dark);
  root.style.removeProperty("background-color");
  root.style.colorScheme = dark ? "dark" : "light";
}

export function TrayPopup() {
  const [locale, setLocale] = useState<Locale>(detectInitialLocale);
  const [coreInfo, setCoreInfo] = useState<CoreInfo | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [nodes, setNodes] = useState<NodeIR[]>([]);
  const [appRules, setAppRules] = useState<AppProxyRule[]>([]);
  const [captureMode, setCaptureMode] = useState<CaptureMode>("off");
  const [serviceStatus, setServiceStatus] = useState<PrivilegedServiceStatus | null>(null);
  const [driverStatus, setDriverStatus] = useState<DriverProbeDto | null>(null);
  const [appProxyStatus, setAppProxyStatus] = useState<AppProxyStatusDto | null>(null);
  const [switchingCapture, setSwitchingCapture] = useState(false);
  const [pendingCapture, setPendingCapture] = useState<CaptureMode | null>(null);
  const [captureErr, setCaptureErr] = useState<string | null>(null);
  const [traffic, setTraffic] = useState<TrafficSample>({
    upBytesPerSec: 0,
    downBytesPerSec: 0,
    memoryBytes: 0,
    activeConnections: 0,
  });
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const dict = useMemo(() => getDict(locale), [locale]);

  const refreshAll = useCallback(async () => {
    try {
      const data = await api.getBootstrapState();
      setCoreInfo(data.coreInfo);
      setSettings(data.settings);
      setNodes(data.nodes);
      setAppRules(data.appRules ?? []);
      setCaptureMode(
        data.captureMode ??
          (data.settings.tunEnabled
            ? "tun"
            : data.settings.appProxyEnabled
              ? "apps"
              : "off"),
      );
      setServiceStatus(data.serviceStatus ?? null);
      setDriverStatus(data.driverStatus ?? null);
      setAppProxyStatus(data.appProxyStatus ?? null);
      if (api.isDesktop()) {
        const nextLoc: Locale = data.settings.locale === "en" ? "en" : "zh-CN";
        setLocale(nextLoc);
        applyTrayTheme((data.settings.theme as ThemeMode) || "system");
      }
    } catch {
      // ignore transient startup read
    }
  }, []);

  useEffect(() => {
    const syncThemeFromEnv = () => {
      const urlTheme = new URLSearchParams(window.location.search).get("theme");
      if (urlTheme === "light" || urlTheme === "dark") {
        applyTrayTheme(urlTheme);
        return;
      }
      try {
        const saved = window.localStorage.getItem(THEME_STORAGE_KEY) as ThemeMode | null;
        applyTrayTheme(saved ?? "system");
      } catch {
        applyTrayTheme("system");
      }
    };
    syncThemeFromEnv();
    void refreshAll();

    const onStorage = (e: StorageEvent) => {
      if (e.key === THEME_STORAGE_KEY && e.newValue) {
        applyTrayTheme(e.newValue as ThemeMode);
      }
      if (e.key === LOCALE_STORAGE_KEY && (e.newValue === "en" || e.newValue === "zh-CN")) {
        setLocale(e.newValue);
      }
    };
    window.addEventListener("storage", onStorage);

    let unlisten: (() => void) | undefined;
    void api.onStateSync(() => void refreshAll()).then((fn) => {
      unlisten = fn;
    });

    const loadTraffic = async () => {
      try {
        const snap = await api.getLiveMonitor();
        setTraffic(snap.traffic);
        setCoreInfo((prev) => (prev ? { ...prev, running: snap.coreRunning } : prev));
      } catch {
        // ignore
      }
    };
    void loadTraffic();
    const timer = window.setInterval(() => void loadTraffic(), 1500);

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.hideTrayPopup();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      if (unlisten) unlisten();
      window.clearInterval(timer);
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("storage", onStorage);
    };
  }, [refreshAll]);

  const mainNode = useMemo(() => {
    if (!settings) return nodes[0] ?? null;
    return nodes.find((n) => n.id === settings.mainNodeId) ?? nodes[0] ?? null;
  }, [nodes, settings]);

  const running = coreInfo?.running ?? false;
  const routeMode: RouteMode = settings?.routeMode ?? "rule";
  const sysProxy = settings?.systemProxyEnabled ?? false;
  const mixedPort = settings?.mixedPort ?? 10808;
  const enabledAppCount = appRules.filter((r) => r.enabled).length;
  const delay = mainNode ? (mainNode.realDelayMs ?? mainNode.tcpingMs ?? null) : null;
  const delayKind = mainNode?.realDelayMs != null ? "real" : "tcping";

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

  const trayFaultText =
    activeFaultKind === "legacy_conflict"
      ? dict.tray.warnConflict
      : activeFaultKind === "hvci_blocked"
        ? dict.tray.warnHvci
        : activeFaultKind === "driver_missing" || activeFaultKind === "signature_failed"
          ? dict.tray.warnDriver
          : activeFaultKind === "pipe_timeout"
            ? dict.tray.warnService
            : null;

  const takeoverSummary = useMemo(
    () =>
      buildTakeoverSummary(routeMode, sysProxy, captureMode, enabledAppCount, {
        modeRule: dict.summary.rule,
        modeGlobal: dict.summary.global,
        modeDirect: dict.summary.direct,
        sysProxy: dict.summary.sysProxy,
        apps: dict.summary.apps,
        appsOne: dict.summary.appsOne,
        noApps: dict.summary.noApps,
        tun: dict.summary.tun,
        none: dict.summary.none,
      }),
    [routeMode, sysProxy, captureMode, enabledAppCount, dict],
  );

  const handleToggleCore = async () => {
    if (busy || !coreInfo?.installed) return;
    setBusy(true);
    try {
      if (running) {
        const info = await api.stopCore();
        setCoreInfo(info);
      } else {
        const [info] = await api.startCore();
        setCoreInfo(info);
      }
    } finally {
      setBusy(false);
    }
  };

  const handleMode = async (m: RouteMode) => {
    setSettings((prev) => (prev ? { ...prev, routeMode: m } : prev));
    try {
      await api.setRouteMode(m);
    } catch {
      // ignore
    }
  };

  const handleSysProxy = async () => {
    const next = !sysProxy;
    setSettings((prev) => (prev ? { ...prev, systemProxyEnabled: next } : prev));
    try {
      const info = await api.toggleSystemProxy(next);
      setCoreInfo(info);
    } catch {
      // ignore
    }
  };

  const handleCapture = async (next: CaptureMode) => {
    setCaptureErr(null);
    if (next !== "off" && (!serviceStatus?.connected || serviceStatus.mode === "off")) {
      await api.showMainWindow();
      return;
    }
    setSwitchingCapture(true);
    setPendingCapture(next);
    try {
      const res = await api.setCaptureMode(next);
      setCaptureMode(res.captureMode);
      setCoreInfo(res.coreInfo);
      setServiceStatus(res.serviceStatus);
    } catch (err) {
      setCaptureErr(String(err));
    } finally {
      setSwitchingCapture(false);
      setPendingCapture(null);
    }
  };

  const handleCopyProxy = () => {
    const url = `http://127.0.0.1:${mixedPort}`;
    if (navigator.clipboard) {
      void navigator.clipboard.writeText(url).catch(() => {});
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const isDesktop = api.isDesktop();

  // Gate A A3: Root Tray Popover uses --bg-surface and inner cards use --bg-subtle.
  const card = (
    <div
      className={`flex flex-col justify-between overflow-hidden bg-[var(--bg-surface)] p-3 select-none ${
        isDesktop
          ? "h-screen w-screen border border-[var(--border-strong)]"
          : "h-[456px] w-[304px] rounded-[16px] border border-[var(--border-strong)] shadow-[var(--shadow-card-lg)]"
      }`}
    >
      <div className="space-y-2.5">
        {/* 1. Header: Monochrome Mark + Bypax + One-line Summary + Core Toggle */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-primary)]">
              <BrandLogo variant="monochrome" className="h-[18px] w-[18px]" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-[13px] font-semibold leading-tight text-[var(--text-primary)]">
                <span>{dict.appTitle}</span>
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{
                    backgroundColor: activeFaultKind
                      ? "var(--warning-dot)"
                      : running
                        ? "var(--success-dot)"
                        : "var(--text-secondary)",
                  }}
                />
              </div>
              <div
                className="truncate text-[11px] text-[var(--text-secondary)]"
                title={takeoverSummary}
              >
                {takeoverSummary}
              </div>
            </div>
          </div>

          <button
            type="button"
            disabled={busy || !coreInfo?.installed}
            onClick={() => void handleToggleCore()}
            className={`${
              running ? "ui-btn-secondary" : "ui-btn-primary"
            } h-7 shrink-0 px-2.5 text-[11.5px]`}
          >
            {running ? (
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
        </div>

        {/* 2. Main Exit Card (--bg-subtle) */}
        <div className="space-y-2 rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-2.5">
          <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)]">
            <span>{dict.tray.currentNode}</span>
            <span className="font-mono num-tabular text-[var(--text-secondary)]">
              :{mixedPort}
            </span>
          </div>

          <div className="flex items-center justify-between gap-2">
            <div
              className="min-w-0 flex-1 text-[12.5px] font-medium text-[var(--text-primary)]"
              title={mainNode ? mainNode.remark : dict.tray.noNode}
            >
              {mainNode ? (
                <NodeLabel remark={mainNode.remark} region={mainNode.region} size="sm" />
              ) : (
                <span className="text-[var(--text-secondary)]">{dict.tray.noNode}</span>
              )}
            </div>
            {mainNode && (
              <span className="inline-flex shrink-0 items-center gap-1.5">
                <SignalBars ms={delay} kind={delayKind} />
                <span
                  className="font-mono text-[11px] font-medium num-tabular"
                  style={{ color: delayColorVar(delay, delayKind) }}
                >
                  {delay != null ? `${delay} ms` : "--"}
                </span>
              </span>
            )}
          </div>

          <div className="flex items-center justify-between border-t border-[var(--border-hairline)] pt-2 font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
            <span className="inline-flex items-center gap-1">
              <ArrowDown
                className="h-3 w-3"
                style={{ color: "var(--success-text)" }}
                strokeWidth={1.6}
              />
              {formatSpeed(traffic.downBytesPerSec)}
            </span>
            <span className="inline-flex items-center gap-1">
              <ArrowUp className="h-3 w-3 text-[var(--text-secondary)]" strokeWidth={1.6} />
              {formatSpeed(traffic.upBytesPerSec)}
            </span>
            {mainNode && (
              <span className="rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-1.5 py-0.5 text-[11.5px] text-[var(--text-secondary)]">
                {PROTO_BADGES[mainNode.protocol]}
              </span>
            )}
          </div>
        </div>

        {/* 3. Mode Segmented */}
        <SegmentedControl
          value={routeMode}
          options={[
            { value: "rule" as RouteMode, label: dict.tray.modeRule },
            { value: "global" as RouteMode, label: dict.tray.modeGlobal },
            { value: "direct" as RouteMode, label: dict.tray.modeDirect },
          ]}
          onChange={(m) => void handleMode(m)}
          ariaLabel={dict.nav.routing}
          fullWidth
        />

        {/* 4. Takeover Block: System Proxy + Capture 3-Way Segmented */}
        <div className="space-y-2 rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-2.5">
          <div className="flex items-center justify-between text-[12px]">
            <span className="font-medium text-[var(--text-primary)]">
              {dict.tray.sysProxy}
            </span>
            <button
              type="button"
              role="switch"
              aria-checked={sysProxy}
              aria-label={dict.tray.sysProxy}
              onClick={() => void handleSysProxy()}
              className="ui-switch"
            >
              <span className="ui-switch-knob" />
            </button>
          </div>

          <div className="space-y-1 border-t border-[var(--border-hairline)] pt-2">
            <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)]">
              <span>{dict.capture.label}</span>
              {captureErr && (
                <span
                  className="max-w-[170px] truncate"
                  style={{ color: "var(--danger-text)" }}
                  title={captureErr}
                >
                  {captureErr}
                </span>
              )}
            </div>
            <SegmentedControl
              value={captureMode}
              options={[
                { value: "off" as CaptureMode, label: dict.capture.off },
                {
                  value: "apps" as CaptureMode,
                  label: dict.capture.apps,
                  dotColor:
                    activeFaultKind || (captureMode === "apps" && enabledAppCount === 0)
                      ? "var(--warning-dot)"
                      : undefined,
                },
                { value: "tun" as CaptureMode, label: dict.capture.tun },
              ]}
              onChange={(m) => void handleCapture(m)}
              ariaLabel={dict.capture.label}
              surface="chrome"
              fullWidth
              switching={switchingCapture}
              switchingTarget={pendingCapture}
            />
          </div>
        </div>

        {/* 5. Fault Warning Banner (B7) OR Active Apps Quick-Link Row */}
        {trayFaultText ? (
          <button
            type="button"
            onClick={() => void api.showMainWindow()}
            title={trayFaultText}
            className="flex w-full items-center justify-between gap-1.5 rounded-[10px] border px-2.5 py-1.5 text-left text-[11.5px] font-medium transition-opacity hover:opacity-90 cursor-pointer"
            style={{
              borderColor: "var(--warning-border)",
              backgroundColor: "var(--warning-bg)",
              color: "var(--warning-text)",
            }}
          >
            <span className="flex min-w-0 items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.7} />
              <span className="truncate">{trayFaultText}</span>
            </span>
            <ChevronRight className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
          </button>
        ) : captureMode === "apps" ? (
          <button
            type="button"
            onClick={() => void api.showMainWindow()}
            className="flex w-full items-center justify-between rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-3 py-1.5 text-[12px] text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
          >
            <span className="inline-flex items-center gap-2">
              <AppWindow className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
              <span>
                {enabledAppCount === 1
                  ? dict.tray.appsActiveLinkOne
                  : enabledAppCount > 0
                    ? dict.tray.appsActiveLink.replace("{count}", String(enabledAppCount))
                    : dict.tray.appsNoneLink}
              </span>
            </span>
            <ChevronRight className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
          </button>
        ) : null}
      </div>

      {/* 6. Footer Action Menu */}
      <div className="space-y-0.5 border-t border-[var(--border-hairline)] pt-2 text-[12px]">
        <button
          type="button"
          onClick={() => void api.showMainWindow()}
          className="flex w-full items-center justify-between rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
        >
          <span className="inline-flex items-center gap-2">
            <ExternalLink className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            {dict.tray.openMain}
          </span>
        </button>

        <button
          type="button"
          onClick={handleCopyProxy}
          className="flex w-full items-center justify-between rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
        >
          <span className="inline-flex items-center gap-2">
            {copied ? (
              <Check
                className="h-3.5 w-3.5"
                style={{ color: "var(--success-text)" }}
                strokeWidth={1.6}
              />
            ) : (
              <Copy className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
            )}
            {copied ? dict.tray.copied : dict.tray.copyProxy}
          </span>
          <span className="font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
            :{mixedPort}
          </span>
        </button>

        <button
          type="button"
          onClick={async () => {
            await api.restoreNetguardNow().catch(() => {});
            await refreshAll();
          }}
          className="flex w-full items-center gap-2 rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
        >
          <ShieldCheck className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
          {dict.tray.restoreNetguard}
        </button>

        <button
          type="button"
          onClick={() => void api.quitApp()}
          className="flex w-full items-center gap-2 rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] transition-colors hover:bg-[var(--danger-bg-hover)] hover:text-[var(--danger-text-on-bg)] cursor-pointer"
        >
          <Power className="h-3.5 w-3.5" strokeWidth={1.5} />
          {dict.tray.quit}
        </button>
      </div>
    </div>
  );

  if (isDesktop) return card;

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-[var(--bg-chrome)] p-4">
      {card}
    </div>
  );
}
