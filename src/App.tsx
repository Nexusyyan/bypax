import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api/client";
import { BootstrapScreen } from "./components/BootstrapScreen";
import { Sidebar } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { AppsView } from "./features/apps/AppsView";
import { ChainsView } from "./features/chains/ChainsView";
import { CoreView } from "./features/core/CoreView";
import { DnsView } from "./features/dns/DnsView";
import { MonitorView } from "./features/monitor/MonitorView";
import { NodesView } from "./features/nodes/NodesView";
import { RoutingView } from "./features/routing/RoutingView";
import { SettingsView } from "./features/settings/SettingsView";
import {
  detectInitialLocale,
  getDict,
  LAST_UPDATE_CHECK_KEY,
  LOCALE_STORAGE_KEY,
  persistLocale,
  THEME_STORAGE_KEY,
} from "./i18n";
import type {
  AppPresetStatus,
  AppProxyRule,
  AppProxyStatusDto,
  AppRuleTestQuery,
  AppSettings,
  AppUpdateCheckReport,
  AppUpdateState,
  CaptureMode,
  CliIntegrationInfo,
  CompileOutput,
  ConnectionItem,
  CoreDownloadProgressEvent,
  CoreInfo,
  CoreUpdateCheckReport,
  DriverProbeDto,
  ExternalChildAlert,
  InboundPort,
  LatencyProgressEvent,
  Locale,
  LogEntry,
  NavTab,
  NodeIR,
  PlatformKind,
  PreflightReport,
  PrivilegedServiceStatus,
  ProxyChain,
  RouteMode,
  RulePresetSpec,
  RuleSetStatus,
  ServiceActionKind,
  SimpleRoutingRule,
  SubscriptionGroup,
  ThemeMode,
  ToastMessage,
  TrafficSample,
} from "./types";
import { buildTakeoverSummary, resolveActiveRecoveryFault } from "./utils/nodes";

const AUTO_CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;

const DEFAULT_APP_UPDATE_STATE: AppUpdateState = {
  stage: "idle",
  downloadedBytes: 0,
};

const DEFAULT_CORE_INFO: CoreInfo = {
  installed: false,
  running: false,
  version: null,
  binaryPath: "",
  sha256: null,
  portableMode: false,
  dataDir: "",
  netguardArmed: false,
  netguardRecoveredFromCrash: false,
};

const DEFAULT_SERVICE_STATUS: PrivilegedServiceStatus = {
  platform: "windows",
  mode: "off",
  installed: false,
  running: false,
  connected: false,
  elevated: false,
  state: "stopped",
  servicePid: null,
  appProxyRunning: false,
  tunRunning: false,
  error: null,
  errorKind: null,
  legacyServices: [],
  conflictDetail: null,
};

const DEFAULT_SETTINGS: AppSettings = {
  locale: "zh-CN",
  theme: "system",
  routeMode: "rule",
  mainNodeId: null,
  mixedPort: 10808,
  controlPort: 9090,
  allowLan: false,
  systemProxyEnabled: false,
  tunEnabled: false,
  autoStartCore: true,
  launchAtLogin: false,
  minimizeToTray: true,
  autoCheckUpdates: true,
  dnsLocalServer: "223.5.5.5",
  dnsRemoteServer: "https://1.1.1.1/dns-query",
  dnsBootstrapServer: "223.5.5.5",
  dnsRemoteDetour: "main",
  dnsStrategy: "prefer_ipv4",
  dnsFakeIp: false,
  dnsFakeIpInet4: "198.18.0.0/15",
  dnsFakeIpInet6: "fc00::/18",
  dnsDisableCache: false,
  dnsDisableExpire: false,
  dnsReverseMapping: false,
  dnsCacheCapacity: 4096,
  dnsClientSubnet: null,
  dnsCustomRules: [],
  dnsHosts: [],
  logLevel: "info",
  sniffEnabled: true,
  sniffTimeout: "300ms",
  findProcess: true,
  autoDetectInterface: true,
  tunInterfaceName: "bypax-tun0",
  tunStack: "mixed",
  tunMtu: 9000,
  tunInet4Address: "172.19.0.1/30",
  tunAutoRoute: true,
  tunStrictRoute: true,
  urltestInterval: "3m",
  urltestTolerance: 50,
  cacheFileEnabled: true,
  cacheStoreFakeip: true,
  latencyStripHandshake: true,
  latencyTestUrl: "https://www.gstatic.com/generate_204",
  customJsonOverride: null,
  appProxyEnabled: false,
  appProxyPort: 10818,
  appProxyBypassLan: true,
  appProxyBlockQuicWhenNeeded: true,
  appProxyWindivertDir: null,
  serviceMode: "off",
  tunRouteExcludeCidrs: [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
  ],
};

const EMPTY_COMPILED: CompileOutput = {
  config: {},
  totalNodes: 0,
  reachableNodes: 0,
  reachableNodeIds: [],
  synthesizedGroups: [],
  controlSecret: "",
  missingAppRuleTargets: [],
};

const EMPTY_TRAFFIC: TrafficSample = {
  upBytesPerSec: 0,
  downBytesPerSec: 0,
  memoryBytes: 0,
  activeConnections: 0,
};

function readInitialTheme(): ThemeMode {
  if (typeof window !== "undefined") {
    const urlTheme = new URLSearchParams(window.location.search).get("theme");
    if (urlTheme === "light" || urlTheme === "dark") return urlTheme;
  }
  try {
    const v = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // ignore
  }
  return "system";
}

function readInitialTab(): NavTab {
  if (typeof window !== "undefined") {
    const raw = new URLSearchParams(window.location.search).get("tab");
    if (
      raw === "nodes" ||
      raw === "chains" ||
      raw === "apps" ||
      raw === "routing" ||
      raw === "dns" ||
      raw === "monitor" ||
      raw === "core" ||
      raw === "settings"
    ) {
      return raw;
    }
  }
  return "nodes";
}

function detectInitialPlatform(): PlatformKind {
  if (typeof navigator !== "undefined") {
    const ua = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`.toLowerCase();
    if (ua.includes("mac")) return "macos";
    if (ua.includes("linux") && !ua.includes("android")) return "linux";
  }
  return "windows";
}

function readPreviewBootMode(): "loading" | "error" | null {
  if (typeof window === "undefined" || api.isDesktop()) return null;
  const raw = new URLSearchParams(window.location.search).get("boot");
  if (raw === "loading" || raw === "error") return raw;
  return null;
}

export default function App() {
  const [locale, setLocale] = useState<Locale>(detectInitialLocale);
  const [theme, setTheme] = useState<ThemeMode>(readInitialTheme);
  const [activeTab, setActiveTab] = useState<NavTab>(readInitialTab);
  const [selectedChainEditId, setSelectedChainEditId] = useState<string | null>(null);
  const [routingTestHost, setRoutingTestHost] = useState<string | null>(null);
  const [monitorSubTabReq, setMonitorSubTabReq] = useState<{
    tab: "conns" | "history" | "platforms" | "logs";
    nonce: number;
  } | null>(null);

  const [appVersion, setAppVersion] = useState<string>("0.1.0");
  const [platform, setPlatform] = useState<PlatformKind | string>(detectInitialPlatform);
  const [captureMode, setCaptureMode] = useState<CaptureMode>("off");
  const [captureSwitching, setCaptureSwitching] = useState(false);
  const [capturePendingTarget, setCapturePendingTarget] = useState<CaptureMode | null>(null);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [authPromptTarget, setAuthPromptTarget] = useState<CaptureMode | null>(null);
  const [authBusyLabel, setAuthBusyLabel] = useState<string | null>(null);

  const [coreInfo, setCoreInfo] = useState<CoreInfo>(DEFAULT_CORE_INFO);
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [nodes, setNodes] = useState<NodeIR[]>([]);
  const [chains, setChains] = useState<ProxyChain[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionGroup[]>([]);
  const [rules, setRules] = useState<SimpleRoutingRule[]>([]);
  const [rulePresets, setRulePresets] = useState<RulePresetSpec[]>([]);
  const [ruleSets, setRuleSets] = useState<RuleSetStatus[]>([]);
  const [extraPorts, setExtraPorts] = useState<InboundPort[]>([]);
  const [compiled, setCompiled] = useState<CompileOutput>(EMPTY_COMPILED);
  const [preflight, setPreflight] = useState<PreflightReport | null>(null);

  const [appRules, setAppRules] = useState<AppProxyRule[]>([]);
  const [appPresets, setAppPresets] = useState<AppPresetStatus[]>([]);
  const [serviceStatus, setServiceStatus] =
    useState<PrivilegedServiceStatus>(DEFAULT_SERVICE_STATUS);
  const [driverStatus, setDriverStatus] = useState<DriverProbeDto | null>(null);
  const [appProxyStatus, setAppProxyStatus] = useState<AppProxyStatusDto | null>(null);
  const [externalChildren, setExternalChildren] = useState<ExternalChildAlert[]>([]);
  const [cliInfo, setCliInfo] = useState<CliIntegrationInfo | null>(null);

  const [connections, setConnections] = useState<ConnectionItem[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [traffic, setTraffic] = useState<TrafficSample>(EMPTY_TRAFFIC);
  const [localDirectBytes, setLocalDirectBytes] = useState<number>(0);
  const [localRejectCount, setLocalRejectCount] = useState<number>(0);
  const [downHistory, setDownHistory] = useState<number[]>(() => Array(40).fill(0));
  const [upHistory, setUpHistory] = useState<number[]>(() => Array(40).fill(0));

  const [testingLatency, setTestingLatency] = useState(false);
  const [testingChainId, setTestingChainId] = useState<string | null>(null);
  const [mainNodeTesting, setMainNodeTesting] = useState(false);
  const [testProgress, setTestProgress] = useState<LatencyProgressEvent | null>(null);
  const [testDelayStats, setTestDelayStats] = useState<{ sum: number; count: number }>({
    sum: 0,
    count: 0,
  });
  const [syncingRuleSets, setSyncingRuleSets] = useState(false);
  const [applyingStrategy, setApplyingStrategy] = useState(false);
  const [coreBusy, setCoreBusy] = useState(false);
  const [downloadingCore, setDownloadingCore] = useState(false);
  const [coreDownloadProgress, setCoreDownloadProgress] =
    useState<CoreDownloadProgressEvent | null>(null);
  const [coreUpdateReport, setCoreUpdateReport] = useState<CoreUpdateCheckReport | null>(null);
  const [checkingCoreUpdate, setCheckingCoreUpdate] = useState(false);

  const [appUpdateReport, setAppUpdateReport] = useState<AppUpdateCheckReport | null>(null);
  const [appUpdateState, setAppUpdateState] = useState<AppUpdateState>(DEFAULT_APP_UPDATE_STATE);
  const [checkingAppUpdate, setCheckingAppUpdate] = useState(false);
  const [appUpdateError, setAppUpdateError] = useState<string | null>(null);
  const [bootstrapped, setBootstrapped] = useState(false);
  const [bootstrapError, setBootstrapError] = useState<string | null>(() =>
    readPreviewBootMode() === "error" ? "Local workspace store unavailable (preview)" : null,
  );
  const [retryingBootstrap, setRetryingBootstrap] = useState(false);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const bootstrappedRef = useRef(false);
  const autoCheckTriggeredRef = useRef(false);
  const updateResultHandledRef = useRef(false);
  const batchTestingRef = useRef(false);
  const mainProbeSeqRef = useRef(0);

  const dict = useMemo(() => getDict(locale), [locale]);
  const instanceConflictTplRef = useRef(dict.toast.instanceConflict);
  instanceConflictTplRef.current = dict.toast.instanceConflict;

  const pushToast = useCallback(
    (text: string, tone: ToastMessage["tone"] = "ok", durationMs = 3200) => {
      const id = `${Date.now()}-${Math.random()}`;
      setToasts((prev) => [...prev.slice(-3), { id, text, tone }]);
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, durationMs);
    },
    [],
  );

  // Apply light/dark theme class immediately (R1 + J13); CSS --bg-chrome takes over after pre-paint
  useEffect(() => {
    const root = document.documentElement;
    const apply = () => {
      const dark =
        theme === "dark" ||
        (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
      root.classList.toggle("dark", dark);
      root.style.removeProperty("background-color");
      root.style.colorScheme = dark ? "dark" : "light";
    };
    apply();
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // ignore
    }
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [theme]);

  // Cross-window storage sync (Tray <-> Main Window)
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (
        e.key === THEME_STORAGE_KEY &&
        (e.newValue === "light" || e.newValue === "dark" || e.newValue === "system")
      ) {
        setTheme(e.newValue);
      }
      if (e.key === LOCALE_STORAGE_KEY && (e.newValue === "zh-CN" || e.newValue === "en")) {
        setLocale(e.newValue);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const reloadBootstrap = useCallback(async () => {
    try {
      const data = await api.getBootstrapState();
      setAppVersion(data.appVersion || "0.1.0");
      setPlatform(data.platform ?? "windows");
      setCoreInfo(data.coreInfo);
      setSettings({ ...DEFAULT_SETTINGS, ...data.settings });
      setNodes(data.nodes);
      setChains(data.chains ?? []);
      setSubscriptions(data.subscriptions);
      setRules(data.rules);
      setRuleSets(data.ruleSets);
      setExtraPorts(data.extraPorts);
      setCompiled(data.compiled);
      setLogs(data.logs);
      setAppRules(data.appRules ?? []);
      setAppPresets(data.appPresets ?? []);
      if (data.serviceStatus) setServiceStatus(data.serviceStatus);
      if (data.driverStatus !== undefined) setDriverStatus(data.driverStatus ?? null);
      if (data.appProxyStatus !== undefined) setAppProxyStatus(data.appProxyStatus ?? null);
      setExternalChildren(data.externalChildren ?? []);
      if (data.cliInfo !== undefined) setCliInfo(data.cliInfo ?? null);
      setCaptureMode(
        data.captureMode ??
          (data.settings.tunEnabled
            ? "tun"
            : data.settings.appProxyEnabled
              ? "apps"
              : "off"),
      );
      if (data.appUpdateState) setAppUpdateState(data.appUpdateState);
      bootstrappedRef.current = true;
      setBootstrapError(null);
      setBootstrapped(true);

      if (data.lastUpdateResult && !updateResultHandledRef.current) {
        updateResultHandledRef.current = true;
        const res = data.lastUpdateResult;
        void api.consumeUpdateResult().catch(() => {});
        if (res.success) {
          pushToast(dict.toast.updateApplied.replace("{version}", res.toVersion), "ok");
        } else {
          pushToast(
            dict.toast.updateRolledBack
              .replace("{tag}", res.toTag)
              .replace("{error}", res.error ?? "unknown error"),
            "err",
          );
        }
      }
    } catch (err) {
      const msg = String(err);
      if (!bootstrappedRef.current) {
        setBootstrapError(msg);
      } else {
        pushToast(msg, "err");
      }
    }
  }, [dict.toast.updateApplied, dict.toast.updateRolledBack, pushToast]);

  const handleRetryBootstrap = useCallback(async () => {
    setRetryingBootstrap(true);
    setBootstrapError(null);
    try {
      await reloadBootstrap();
    } finally {
      setRetryingBootstrap(false);
    }
  }, [reloadBootstrap]);

  useEffect(() => {
    if (readPreviewBootMode() !== null) return;
    void reloadBootstrap();
    void api.listRulePresets().then(setRulePresets).catch(() => {});
  }, [reloadBootstrap]);

  // Listen to state sync, instance conflict, app update progress, and core download progress events.
  useEffect(() => {
    if (!api.isDesktop()) return;
    let active = true;
    let unlistenSync: (() => void) | undefined;
    let unlistenConflict: (() => void) | undefined;
    let unlistenAppUpdate: (() => void) | undefined;
    let unlistenCoreProg: (() => void) | undefined;

    void api.onStateSync(() => void reloadBootstrap()).then((fn) => {
      if (!active) fn();
      else unlistenSync = fn;
    });
    void api
      .onInstanceConflict((ev) => {
        const runningPath = ev?.runningPath || ev?.attemptedCwd || "Bypax";
        pushToast(
          instanceConflictTplRef.current.replace("{runningPath}", runningPath),
          "warn",
          6500,
        );
      })
      .then((fn) => {
        if (!active) fn();
        else unlistenConflict = fn;
      });
    void api.onAppUpdateProgress((st) => {
      setAppUpdateState(st);
      if (st.error) setAppUpdateError(st.error);
    }).then((fn) => {
      if (!active) fn();
      else unlistenAppUpdate = fn;
    });
    void api.onCoreDownloadProgress((ev) => {
      setCoreDownloadProgress(ev);
    }).then((fn) => {
      if (!active) fn();
      else unlistenCoreProg = fn;
    });

    return () => {
      active = false;
      if (unlistenSync) unlistenSync();
      if (unlistenConflict) unlistenConflict();
      if (unlistenAppUpdate) unlistenAppUpdate();
      if (unlistenCoreProg) unlistenCoreProg();
    };
  }, [pushToast, reloadBootstrap]);

  // Listen to incremental latency test progress events.
  useEffect(() => {
    if (!api.isDesktop()) return;
    let unlistenProg: (() => void) | undefined;
    void api
      .onLatencyProgress((ev) => {
        if (batchTestingRef.current) {
          setTestProgress(ev);
        }
        const latest = ev.latest;
        if (latest) {
          if (batchTestingRef.current && latest.delayMs != null && latest.delayMs > 0) {
            const ms = latest.delayMs;
            setTestDelayStats((prev) => ({ sum: prev.sum + ms, count: prev.count + 1 }));
          }
          setNodes((prev) =>
            prev.map((n) => {
              if (n.id !== latest.nodeId) return n;
              return { ...n, realDelayMs: latest.delayMs ?? -1 };
            }),
          );
        }
      })
      .then((fn) => {
        unlistenProg = fn;
      });
    return () => {
      if (unlistenProg) unlistenProg();
    };
  }, []);

  // Periodic live monitor polling (starts only after initial bootstrap completes)
  useEffect(() => {
    if (!bootstrapped) return;
    const poll = async () => {
      try {
        const snap = await api.getLiveMonitor();
        setCoreInfo((prev) =>
          prev.running === snap.coreRunning ? prev : { ...prev, running: snap.coreRunning },
        );
        setConnections(snap.connections);
        setLogs(snap.logs);
        setTraffic(snap.traffic);
        if (snap.appProxyStatus !== undefined && snap.appProxyStatus !== null) {
          setAppProxyStatus(snap.appProxyStatus);
        }
        setLocalDirectBytes(snap.localDirectBytes ?? 0);
        setLocalRejectCount(snap.localRejectCount ?? 0);
        setDownHistory((prev) => [...prev.slice(1), snap.traffic.downBytesPerSec]);
        setUpHistory((prev) => [...prev.slice(1), snap.traffic.upBytesPerSec]);
      } catch {
        // ignore transient polling error
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1800);
    return () => window.clearInterval(timer);
  }, [bootstrapped]);

  const mainChain = useMemo(() => {
    const id = settings.mainNodeId;
    if (!id || !id.startsWith("chain:")) return null;
    return chains.find((c) => c.id === id.slice("chain:".length)) ?? null;
  }, [chains, settings.mainNodeId]);

  const mainNode = useMemo(() => {
    if (mainChain) return null;
    return nodes.find((n) => n.id === settings.mainNodeId) ?? nodes[0] ?? null;
  }, [mainChain, nodes, settings.mainNodeId]);

  const enabledAppCount = useMemo(
    () => appRules.filter((r) => r.enabled).length,
    [appRules],
  );

  const hasRecoveryFault = useMemo(
    () =>
      resolveActiveRecoveryFault({
        captureMode,
        serviceStatus,
        appProxyStatus,
        driverStatus,
      }) !== null,
    [captureMode, serviceStatus, appProxyStatus, driverStatus],
  );

  const takeoverSummary = useMemo(
    () =>
      buildTakeoverSummary(
        settings.routeMode,
        settings.systemProxyEnabled,
        captureMode,
        enabledAppCount,
        {
          modeRule: dict.summary.rule,
          modeGlobal: dict.summary.global,
          modeDirect: dict.summary.direct,
          sysProxy: dict.summary.sysProxy,
          apps: dict.summary.apps,
          appsOne: dict.summary.appsOne,
          noApps: dict.summary.noApps,
          tun: dict.summary.tun,
          none: dict.summary.none,
        },
      ),
    [settings.routeMode, settings.systemProxyEnabled, captureMode, enabledAppCount, dict],
  );

  const handleChangeLocale = (next: Locale) => {
    setLocale(next);
    persistLocale(next);
    const updated = { ...settings, locale: next };
    setSettings(updated);
    void api.updateSettings(updated).then(setCompiled).catch(() => {});
  };

  const handleToggleLocale = () => {
    handleChangeLocale(locale === "zh-CN" ? "en" : "zh-CN");
  };

  const handleChangeTheme = (next: ThemeMode) => {
    setTheme(next);
    const updated = { ...settings, theme: next };
    setSettings(updated);
    void api.updateSettings(updated).then(setCompiled).catch(() => {});
  };

  const handleCycleTheme = () => {
    const next: ThemeMode =
      theme === "system" ? "light" : theme === "light" ? "dark" : "system";
    handleChangeTheme(next);
  };

  const handleSelectMode = async (mode: RouteMode) => {
    setSettings((prev) => ({ ...prev, routeMode: mode }));
    try {
      const nextCompiled = await api.setRouteMode(mode);
      setCompiled(nextCompiled);
      const msg =
        mode === "direct"
          ? dict.toast.modeDirect
          : mode === "global"
            ? dict.toast.modeGlobal
            : dict.toast.modeRule;
      pushToast(msg, "ok");
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleToggleSysProxy = async () => {
    const next = !settings.systemProxyEnabled;
    try {
      const info = await api.toggleSystemProxy(next);
      setCoreInfo(info);
      setSettings((prev) => ({ ...prev, systemProxyEnabled: next }));
      pushToast(next ? dict.toast.sysProxyOn : dict.toast.sysProxyOff);
    } catch (err) {
      const msg = String(err);
      if (msg.includes("NO_NODES_CONFIGURED")) {
        pushToast(dict.toast.noNodesSysProxy, "warn", 4500);
        setActiveTab("nodes");
      } else if (msg.includes("CORE_NOT_INSTALLED")) {
        pushToast(dict.toast.coreMissingAction, "err");
      } else {
        pushToast(msg, "err");
      }
    }
  };

  const executeCaptureSwitch = async (next: CaptureMode) => {
    setCaptureError(null);
    setCaptureSwitching(true);
    setCapturePendingTarget(next);
    try {
      const res = await api.setCaptureMode(next);
      setCaptureMode(res.captureMode);
      setCoreInfo(res.coreInfo);
      setServiceStatus(res.serviceStatus);
      setAppProxyStatus(res.appProxyStatus);
      setCompiled(res.compiled);
      setSettings((prev) => ({
        ...prev,
        appProxyEnabled: res.captureMode === "apps",
        tunEnabled: res.captureMode === "tun",
      }));
      if (res.captureMode === "tun") {
        pushToast(dict.capture.toastToTun, "ok");
      } else if (res.captureMode === "apps") {
        pushToast(dict.capture.toastToApps, "ok");
      } else {
        pushToast(dict.capture.toastToOff, "neutral");
      }
    } catch (err) {
      const reason = String(err);
      setCaptureError(reason);
      pushToast(dict.capture.switchFailed.replace("{reason}", reason), "err");
      void reloadBootstrap();
    } finally {
      setCaptureSwitching(false);
      setCapturePendingTarget(null);
    }
  };

  const handleSelectCapture = async (next: CaptureMode) => {
    if (next === captureMode) return;
    setCaptureError(null);
    const needsAuth =
      platform === "macos"
        ? serviceStatus.mode === "off" || !serviceStatus.connected
        : !serviceStatus.connected;
    if (next !== "off" && needsAuth) {
      setAuthPromptTarget(next);
      return;
    }
    await executeCaptureSwitch(next);
  };

  const handleAuthAction = async (kind: "once" | "install") => {
    const target = authPromptTarget;
    if (!target) return;
    setAuthBusyLabel(kind === "once" ? dict.service.waitingUac : dict.service.installing);
    try {
      const nextSvc = await api.serviceAction(kind === "once" ? "start_worker" : "install");
      setServiceStatus(nextSvc);
      setAuthPromptTarget(null);
      setAuthBusyLabel(null);
      await executeCaptureSwitch(target);
    } catch (err) {
      const msg = String(err);
      setAuthBusyLabel(null);
      if (msg.includes("UAC_CANCELLED")) {
        setAuthPromptTarget(null);
        pushToast(dict.service.uacCancelled, "neutral");
      } else {
        setAuthPromptTarget(null);
        pushToast(msg, "err");
      }
    }
  };

  const handleOpenLogsDir = async () => {
    try {
      const path = await api.openLogsDir();
      if (!api.isDesktop()) {
        pushToast(path, "neutral");
      }
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleOpenLiveLogs = () => {
    setMonitorSubTabReq((prev) => ({ tab: "logs", nonce: (prev?.nonce ?? 0) + 1 }));
    setActiveTab("monitor");
  };

  const handleServiceAction = async (action: ServiceActionKind) => {
    try {
      if (action === "cleanup_legacy") {
        pushToast(dict.service.cleaningLegacy, "neutral");
      }
      const nextSvc = await api.serviceAction(action);
      setServiceStatus(nextSvc);
      if (action === "cleanup_legacy") {
        pushToast(dict.toast.legacyCleaned, "ok");
      }
      await reloadBootstrap();
    } catch (err) {
      const msg = String(err);
      if (msg.includes("UAC_CANCELLED")) {
        pushToast(dict.service.uacCancelled, "neutral");
      } else {
        pushToast(msg, "err");
      }
    }
  };

  const handleToggleCore = async () => {
    setCoreBusy(true);
    try {
      if (coreInfo.running) {
        const info = await api.stopCore();
        setCoreInfo(info);
        pushToast(dict.toast.coreStopped, "neutral");
      } else {
        const [info, report] = await api.startCore();
        setCoreInfo(info);
        setPreflight(report);
        pushToast(report.ok ? dict.toast.coreStarted : dict.toast.preflightBlocked, report.ok ? "ok" : "err");
      }
    } catch (err) {
      const msg = String(err);
      pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
    } finally {
      setCoreBusy(false);
    }
  };

  const handleProbeMainNode = useCallback(
    async (explicitNodeId?: string) => {
      const targetId = explicitNodeId ?? settings.mainNodeId ?? nodes[0]?.id ?? null;
      if (!targetId) return;
      if (!coreInfo.installed) return;
      const seq = ++mainProbeSeqRef.current;
      setMainNodeTesting(true);
      try {
        if (targetId.startsWith("chain:")) {
          const cid = targetId.slice("chain:".length);
          const res = await api.testProxyChainDelay(cid);
          setChains((prev) =>
            prev.map((c) => (c.id === cid ? { ...c, realDelayMs: res.delayMs ?? -1 } : c)),
          );
        } else {
          const results = await api.runBatchRealDelay([targetId]);
          const hit = results.find((r) => r.nodeId === targetId) ?? results[0];
          if (hit) {
            setNodes((prev) =>
              prev.map((n) => {
                if (n.id !== targetId) return n;
                return { ...n, realDelayMs: hit.delayMs ?? -1 };
              }),
            );
          }
        }
      } catch (err) {
        const msg = String(err);
        pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
      } finally {
        if (mainProbeSeqRef.current === seq) {
          setMainNodeTesting(false);
        }
      }
    },
    [coreInfo.installed, dict.toast.coreMissingAction, nodes, pushToast, settings.mainNodeId],
  );

  const handleSelectMainNode = async (id: string) => {
    setSettings((prev) => ({ ...prev, mainNodeId: id }));
    try {
      const res = await api.selectMainNode(id);
      setCompiled(res.compiled);
      pushToast(res.hotSwitched ? dict.toast.hotSwitched : dict.toast.nodeSelected);
      void handleProbeMainNode(id);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleDeleteNode = async (id: string) => {
    try {
      await api.deleteNode(id);
      await reloadBootstrap();
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleImportPayload = async (payload: string, groupName: string) => {
    try {
      const res = await api.importNodes(payload, groupName);
      await reloadBootstrap();
      pushToast(`${dict.toast.imported} (${res.nodes.length})`);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleImportSubscription = async (name: string, url: string) => {
    try {
      const sub = await api.importSubscription(name, url);
      await reloadBootstrap();
      pushToast(`${dict.toast.subSynced}: ${sub.name} (${sub.nodeCount})`);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleRefreshSubscription = async (id: string) => {
    const sub = await api.refreshSubscription(id);
    await reloadBootstrap();
    pushToast(`${dict.toast.subSynced}: ${sub.name} (${sub.nodeCount})`);
  };

  const handleDeleteSubscription = async (id: string) => {
    try {
      await api.deleteSubscription(id);
      await reloadBootstrap();
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleRunRealDelayTest = async (nodeIds: string[], chainIds: string[] = []) => {
    if (nodeIds.length > 0) {
      batchTestingRef.current = true;
      setTestingLatency(true);
      setTestDelayStats({ sum: 0, count: 0 });
      setTestProgress({
        kind: "real",
        phase: "starting",
        completed: 0,
        total: nodeIds.length,
        passed: 0,
        failed: 0,
        stripHandshake: settings.latencyStripHandshake,
      });
      try {
        await api.runBatchRealDelay(nodeIds);
        await reloadBootstrap();
      } catch (err) {
        const msg = String(err);
        pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
        return;
      } finally {
        batchTestingRef.current = false;
        setTestingLatency(false);
        setTestProgress(null);
        setTestDelayStats({ sum: 0, count: 0 });
      }
    }

    for (const cid of chainIds) {
      setTestingChainId(cid);
      try {
        const res = await api.testProxyChainDelay(cid);
        setChains((prev) =>
          prev.map((c) => (c.id === cid ? { ...c, realDelayMs: res.delayMs ?? -1 } : c)),
        );
      } catch (err) {
        const msg = String(err);
        pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
        if (msg.includes("CORE_NOT_INSTALLED")) {
          break;
        }
      } finally {
        setTestingChainId(null);
      }
    }
  };

  const handleSaveChain = async (chain: ProxyChain): Promise<ProxyChain | null> => {
    try {
      const res = await api.saveProxyChain(chain);
      setChains(res.chains);
      setCompiled(res.compiled);
      pushToast(dict.toast.chainSaved);
      const saved =
        res.chains.find((c) => c.id === chain.id) ??
        res.chains.find((c) => c.name === chain.name) ??
        res.chains[res.chains.length - 1] ??
        null;
      return saved;
    } catch (err) {
      pushToast(String(err), "err");
      return null;
    }
  };

  const handleDeleteChain = async (id: string) => {
    try {
      const res = await api.deleteProxyChain(id);
      setChains(res.chains);
      setCompiled(res.compiled);
      if (settings.mainNodeId === `chain:${id}`) {
        await reloadBootstrap();
      }
      pushToast(dict.toast.chainDeleted, "neutral");
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleTestChainDelay = async (chainId: string) => {
    setTestingChainId(chainId);
    try {
      const res = await api.testProxyChainDelay(chainId);
      setChains((prev) =>
        prev.map((c) => (c.id === chainId ? { ...c, realDelayMs: res.delayMs ?? -1 } : c)),
      );
    } catch (err) {
      const msg = String(err);
      pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
    } finally {
      setTestingChainId(null);
    }
  };

  const handleSaveRule = async (rule: SimpleRoutingRule) => {
    setRules((prev) => {
      const exists = prev.some((r) => r.id === rule.id);
      const next = exists ? prev.map((r) => (r.id === rule.id ? rule : r)) : [rule, ...prev];
      return next.slice().sort((a, b) => a.priority - b.priority);
    });
    try {
      const next = await api.saveRule(rule);
      setCompiled(next);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleDeleteRule = async (id: string) => {
    setRules((prev) => prev.filter((r) => r.id !== id));
    try {
      const next = await api.deleteRule(id);
      setCompiled(next);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleSyncRuleSets = async (tags: string[]) => {
    setSyncingRuleSets(true);
    try {
      const res = await api.syncRuleSets(tags);
      setRuleSets(res.statuses);
      setCompiled(res.compiled);
      pushToast(dict.toast.ruleSetsSynced);
    } catch (err) {
      pushToast(String(err), "err");
    } finally {
      setSyncingRuleSets(false);
    }
  };

  const handleApplyStrategy = async (strategyId: string) => {
    setApplyingStrategy(true);
    try {
      const res = await api.applyRoutingStrategy(strategyId);
      setRules(res.rules);
      setRuleSets(res.ruleSets);
      setCompiled(res.compiled);
      pushToast(dict.toast.strategyApplied);
    } catch (err) {
      pushToast(String(err), "err");
    } finally {
      setApplyingStrategy(false);
    }
  };

  const handleTestRoute = useCallback(async (input: string, processName?: string) => {
    try {
      return await api.testRouteTarget(input, processName);
    } catch {
      return null;
    }
  }, []);

  const handleFetchHistory = useCallback(async (q: string, p: number, sz: number) => {
    try {
      return await api.getConnectionHistory(q, p, sz);
    } catch {
      return null;
    }
  }, []);

  const handleFetchPlatforms = useCallback(async (range: string) => {
    try {
      return await api.getPlatformTraffic(range);
    } catch {
      return null;
    }
  }, []);

  const handleClearHistory = useCallback(async () => {
    try {
      await api.clearConnectionHistory();
      pushToast(dict.toast.historyCleared, "neutral");
    } catch (err) {
      pushToast(String(err), "err");
    }
  }, [dict.toast.historyCleared, pushToast]);

  const handleSavePort = async (port: InboundPort) => {
    setExtraPorts((prev) => {
      const exists = prev.some((p) => p.id === port.id);
      return exists ? prev.map((p) => (p.id === port.id ? port : p)) : [...prev, port];
    });
    try {
      const next = await api.saveInboundPort(port);
      setCompiled(next);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleDeletePort = async (id: string) => {
    setExtraPorts((prev) => prev.filter((p) => p.id !== id));
    try {
      const next = await api.deleteInboundPort(id);
      setCompiled(next);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleCopyText = (text: string) => {
    if (navigator.clipboard) {
      void navigator.clipboard.writeText(text).catch(() => {});
    }
    pushToast(dict.toast.copied);
  };

  const handleRunPreflight = async (simulateBad: boolean) => {
    try {
      const report = await api.runPreflightCheck(simulateBad);
      setPreflight(report);
      pushToast(
        report.ok ? dict.toast.preflightPass : dict.toast.preflightBlocked,
        report.ok ? "ok" : "err",
      );
    } catch (err) {
      const msg = String(err);
      pushToast(msg.includes("CORE_NOT_INSTALLED") ? dict.toast.coreMissingAction : msg, "err");
    }
  };

  const handleCheckAppUpdate = useCallback(
    async (silent = false) => {
      setCheckingAppUpdate(true);
      setAppUpdateError(null);
      try {
        const report = await api.checkAppUpdate();
        setAppUpdateReport(report);
        try {
          window.localStorage.setItem(LAST_UPDATE_CHECK_KEY, String(Date.now()));
        } catch {
          // ignore
        }
        if (report.updateAvailable) {
          pushToast(dict.toast.updateAvailable.replace("{tag}", report.latestTag), "ok");
        } else if (!silent) {
          pushToast(dict.toast.updateUpToDate.replace("{version}", report.currentVersion), "neutral");
        }
      } catch (err) {
        const msg = String(err);
        if (!silent) {
          setAppUpdateError(msg);
          pushToast(msg, "err");
        }
      } finally {
        setCheckingAppUpdate(false);
      }
    },
    [dict.toast.updateAvailable, dict.toast.updateUpToDate, pushToast],
  );

  // Silent startup update check (at most once every 12h in desktop mode)
  useEffect(() => {
    if (!api.isDesktop() || !bootstrapped || !settings.autoCheckUpdates) return;
    if (autoCheckTriggeredRef.current) return;
    autoCheckTriggeredRef.current = true;
    try {
      const last = Number(window.localStorage.getItem(LAST_UPDATE_CHECK_KEY) ?? "0");
      if (Number.isFinite(last) && Date.now() - last < AUTO_CHECK_INTERVAL_MS) return;
    } catch {
      // ignore
    }
    const timer = window.setTimeout(() => void handleCheckAppUpdate(true), 3000);
    return () => window.clearTimeout(timer);
  }, [bootstrapped, settings.autoCheckUpdates, handleCheckAppUpdate]);

  const handleDownloadAppUpdate = async () => {
    setAppUpdateError(null);
    try {
      const nextState = await api.downloadAppUpdate();
      setAppUpdateState(nextState);
      if (nextState.stage === "ready_to_restart") {
        pushToast(
          dict.toast.updateReady.replace(
            "{tag}",
            nextState.targetTag ?? appUpdateReport?.latestTag ?? "",
          ),
          "ok",
        );
      } else if (nextState.stage === "idle") {
        pushToast(dict.toast.updateCancelled, "neutral");
      }
    } catch (err) {
      const msg = String(err);
      setAppUpdateError(msg);
      pushToast(msg, "err");
    }
  };

  const handleCancelAppUpdate = async () => {
    await api.cancelAppUpdate().catch(() => {});
  };

  const handleRestartToUpdate = async () => {
    setAppUpdateError(null);
    try {
      await api.restartToUpdate();
    } catch (err) {
      const msg = String(err);
      setAppUpdateError(msg);
      pushToast(msg, "err");
    }
  };

  const handleOpenExternalUrl = async (url: string) => {
    try {
      await api.openExternalUrl(url);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleCheckCoreUpdate = async () => {
    setCheckingCoreUpdate(true);
    try {
      const report = await api.checkCoreUpdate();
      setCoreUpdateReport(report);
      if (report.updateAvailable) {
        pushToast(dict.toast.coreUpdateFound.replace("{tag}", report.latestTag), "ok");
      } else {
        pushToast(dict.toast.coreUpToDate.replace("{tag}", report.latestTag), "neutral");
      }
    } catch (err) {
      pushToast(String(err), "err");
    } finally {
      setCheckingCoreUpdate(false);
    }
  };

  const handleDownloadCore = async () => {
    setDownloadingCore(true);
    setCoreDownloadProgress({ phase: "checking", downloadedBytes: 0 });
    try {
      const info = await api.downloadOfficialCore();
      setCoreInfo(info);
      setCoreUpdateReport((prev) =>
        prev ? { ...prev, installedVersion: info.version ?? prev.installedVersion, updateAvailable: false } : null,
      );
      pushToast(dict.toast.coreDownloaded);
    } catch (err) {
      pushToast(String(err), "err");
    } finally {
      setDownloadingCore(false);
      setCoreDownloadProgress(null);
    }
  };

  const handleImportCoreBinary = async () => {
    try {
      const path = await api.pickBinaryFile();
      if (!path) return;
      const info = await api.importCoreBinary(path);
      setCoreInfo(info);
      pushToast(dict.toast.coreDownloaded);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleUpdateSettings = async (next: AppSettings) => {
    setSettings(next);
    try {
      const nextCompiled = await api.updateSettings(next);
      setCompiled(nextCompiled);
    } catch (err) {
      pushToast(String(err), "err");
      void reloadBootstrap();
    }
  };

  const handleRestoreNetguard = async () => {
    try {
      const info = await api.restoreNetguardNow();
      setCoreInfo(info);
      setCaptureMode("off");
      setSettings((prev) => ({
        ...prev,
        systemProxyEnabled: false,
        appProxyEnabled: false,
        tunEnabled: false,
      }));
      await reloadBootstrap();
      pushToast(dict.toast.netguardRestored);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleTogglePreset = async (presetId: string, enabled: boolean, target?: string) => {
    try {
      const res = await api.toggleAppPreset(presetId, enabled, target);
      setAppRules(res.rules);
      setCompiled(res.compiled);
      const nextPresets = await api.listAppPresets();
      setAppPresets(nextPresets);
      const presetName = nextPresets.find((p) => p.id === presetId)?.name ?? presetId;
      if (enabled && target) {
        const targetLabel =
          target === "follow"
            ? dict.apps.targetFollow
            : target === "main"
              ? dict.apps.targetMain
              : target === "direct"
                ? dict.apps.targetDirect
                : target === "reject"
                  ? dict.apps.targetReject
                  : target;
        pushToast(
          dict.apps.toastPresetUpdated
            .replace("{name}", presetName)
            .replace("{target}", targetLabel),
        );
      }
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleSaveAppRule = async (rule: AppProxyRule) => {
    try {
      const res = await api.saveAppProxyRule(rule);
      setAppRules(res.rules);
      setCompiled(res.compiled);
      setAppPresets(await api.listAppPresets());
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleDeleteAppRule = async (id: string) => {
    try {
      const res = await api.deleteAppProxyRule(id);
      setAppRules(res.rules);
      setCompiled(res.compiled);
      setAppPresets(await api.listAppPresets());
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleReorderAppRules = async (ids: string[]) => {
    try {
      const res = await api.reorderAppProxyRules(ids);
      setAppRules(res.rules);
      setCompiled(res.compiled);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handlePickWindivertDir = async () => {
    const dir = await api.pickDirectory();
    if (!dir) return;
    try {
      const probe = await api.setWindivertDir(dir);
      setDriverStatus(probe);
      await reloadBootstrap();
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleProbeDriver = async () => {
    try {
      const probe = await api.probeWindivertDriver();
      setDriverStatus(probe);
      pushToast(probe.driverOpened ? "WinDivert OK" : probe.error ?? "Driver probe failed", probe.driverOpened ? "ok" : "err");
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleIncludeExternalChild = async (ruleId: string, childPath: string) => {
    try {
      const res = await api.includeExternalChild(ruleId, childPath);
      setAppRules(res.rules);
      setCompiled(res.compiled);
      setExternalChildren(await api.detectExternalChildren());
      pushToast(dict.apps.toastChildIncluded);
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleIgnoreExternalChild = async (ruleId: string, childPath: string) => {
    try {
      const res = await api.ignoreExternalChild(ruleId, childPath);
      setAppRules(res.rules);
      setCompiled(res.compiled);
      setExternalChildren(await api.detectExternalChildren());
      pushToast(dict.apps.toastChildIgnored, "neutral");
    } catch (err) {
      pushToast(String(err), "err");
    }
  };

  const handleRunAppDryRun = async (query: AppRuleTestQuery) => {
    try {
      return await api.testAppProxyRule(query);
    } catch {
      return null;
    }
  };

  const handleLoadProcesses = async () => {
    const [processes, installed] = await Promise.all([
      api.listRunningProcesses().catch(() => []),
      api.listInstalledApps().catch(() => []),
    ]);
    return { processes, installed };
  };

  if (!bootstrapped) {
    return (
      <BootstrapScreen
        dict={dict}
        platform={platform}
        error={bootstrapError}
        retrying={retryingBootstrap}
        onRetry={() => void handleRetryBootstrap()}
      />
    );
  }

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[var(--bg-chrome)]">
      <TitleBar
        dict={dict}
        platform={platform}
        locale={locale}
        theme={theme}
        coreInfo={coreInfo}
        routeMode={settings.routeMode}
        sysProxyEnabled={settings.systemProxyEnabled}
        captureMode={captureMode}
        captureSwitching={captureSwitching}
        capturePendingTarget={capturePendingTarget}
        captureError={captureError}
        enabledAppCount={enabledAppCount}
        hasRecoveryFault={hasRecoveryFault}
        takeoverSummary={takeoverSummary}
        authPromptTarget={authPromptTarget}
        authBusyLabel={authBusyLabel}
        traffic={traffic}
        appUpdateReport={appUpdateReport}
        appUpdateState={appUpdateState}
        onSelectMode={(m) => void handleSelectMode(m)}
        onToggleSysProxy={() => void handleToggleSysProxy()}
        onSelectCapture={(m) => void handleSelectCapture(m)}
        onAuthOnce={() => void handleAuthAction("once")}
        onAuthInstall={() => void handleAuthAction("install")}
        onAuthCancel={() => {
          setAuthPromptTarget(null);
          setAuthBusyLabel(null);
        }}
        onOpenCore={() => setActiveTab("core")}
        onOpenApps={() => setActiveTab("apps")}
        onSeeCaptureError={() => {
          setCaptureError(null);
          if (activeTab === "apps") {
            handleOpenLiveLogs();
          } else {
            setActiveTab("apps");
          }
        }}
        onDismissCaptureError={() => setCaptureError(null)}
        onOpenUpdates={() => setActiveTab("settings")}
        onRestartToUpdate={() => void handleRestartToUpdate()}
        onToggleLocale={handleToggleLocale}
        onCycleTheme={handleCycleTheme}
      />

      <div className="flex min-h-0 flex-1 bg-[var(--bg-chrome)]">
        <Sidebar
          dict={dict}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          nodeCount={nodes.length}
          chainCount={chains.length}
          enabledAppCount={enabledAppCount}
          hasRecoveryFault={hasRecoveryFault}
          activeRuleCount={rules.filter((r) => r.enabled).length}
          connectionCount={connections.length}
          dnsFakeIp={settings.dnsFakeIp}
          hasAppUpdate={
            Boolean(appUpdateReport?.updateAvailable) ||
            appUpdateState.stage === "ready_to_restart"
          }
          takeoverSummary={takeoverSummary}
          mainNode={mainNode}
          mainChain={mainChain}
          mainNodeTesting={mainNodeTesting}
          onRetestMainNode={() => void handleProbeMainNode()}
          mixedPort={settings.mixedPort}
          coreInfo={coreInfo}
          coreBusy={coreBusy}
          onToggleCore={() => void handleToggleCore()}
        />

        {/* Mandatory 1px hairline border separating L-chrome (#0B1120/#F6F7F9) from inset canvas (#0D1117/#FFFFFF) */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-tl-[14px] border-t border-l border-[var(--border-hairline)] bg-[var(--bg-canvas)]">
          {activeTab === "nodes" && (
            <NodesView
              dict={dict}
              coreInfo={coreInfo}
              nodes={nodes}
              chains={chains}
              subscriptions={subscriptions}
              rules={rules}
              mainNodeId={settings.mainNodeId}
              testingLatency={testingLatency}
              testingChainId={testingChainId}
              testProgress={testProgress}
              testAvgMs={
                testDelayStats.count > 0
                  ? Math.round(testDelayStats.sum / testDelayStats.count)
                  : null
              }
              downloadingCore={downloadingCore}
              coreDownloadPercent={coreDownloadProgress?.percent ?? null}
              onDownloadCore={handleDownloadCore}
              onImportCoreBinary={handleImportCoreBinary}
              onSelectMainNode={(id) => void handleSelectMainNode(id)}
              onDeleteNode={(id) => void handleDeleteNode(id)}
              onDeleteChain={(id) => void handleDeleteChain(id)}
              onEditChain={(id) => {
                setSelectedChainEditId(id);
                setActiveTab("chains");
              }}
              onTestChainDelay={(id) => void handleTestChainDelay(id)}
              onCopyText={handleCopyText}
              onRunRealDelayTest={(ids, cids) => void handleRunRealDelayTest(ids, cids)}
              onImportPayload={handleImportPayload}
              onImportSubscription={handleImportSubscription}
              onRefreshSubscription={handleRefreshSubscription}
              onDeleteSubscription={handleDeleteSubscription}
            />
          )}

          {activeTab === "chains" && (
            <ChainsView
              dict={dict}
              nodes={nodes}
              chains={chains}
              mainNodeId={settings.mainNodeId}
              initialChainId={selectedChainEditId}
              testingChainId={testingChainId}
              onSaveChain={handleSaveChain}
              onDeleteChain={handleDeleteChain}
              onTestChainDelay={handleTestChainDelay}
              onSelectMainChain={(cid) => handleSelectMainNode(`chain:${cid}`)}
              onGoToNodes={() => setActiveTab("nodes")}
            />
          )}

          {activeTab === "apps" && (
            <AppsView
              dict={dict}
              platform={platform}
              captureMode={captureMode}
              captureSwitching={captureSwitching}
              nodes={nodes}
              chains={chains}
              mainNodeId={settings.mainNodeId}
              appRules={appRules}
              appPresets={appPresets}
              serviceStatus={serviceStatus}
              driverStatus={driverStatus}
              appProxyStatus={appProxyStatus}
              missingTargets={compiled.missingAppRuleTargets ?? []}
              externalChildren={externalChildren}
              onSelectCapture={handleSelectCapture}
              onServiceAction={handleServiceAction}
              onFallbackToTun={() => handleSelectCapture("tun")}
              onOpenWindowsSecurity={() => api.openWindowsSecurity()}
              onPickWindivertDir={handlePickWindivertDir}
              onProbeDriver={handleProbeDriver}
              onOpenLogs={handleOpenLiveLogs}
              onOpenLogsDir={handleOpenLogsDir}
              onTogglePreset={handleTogglePreset}
              onSaveRule={handleSaveAppRule}
              onDeleteRule={handleDeleteAppRule}
              onReorderRules={handleReorderAppRules}
              onRunDryRun={handleRunAppDryRun}
              onLoadProcesses={handleLoadProcesses}
              onIncludeExternalChild={handleIncludeExternalChild}
              onIgnoreExternalChild={handleIgnoreExternalChild}
              onTestInRouting={(host) => {
                setRoutingTestHost(host);
                setActiveTab("routing");
              }}
            />
          )}

          {activeTab === "routing" && (
            <RoutingView
              dict={dict}
              locale={locale}
              routeMode={settings.routeMode}
              nodes={nodes}
              chains={chains}
              rules={rules}
              rulePresets={rulePresets}
              ruleSets={ruleSets}
              extraPorts={extraPorts}
              mainNodeId={settings.mainNodeId}
              mixedPort={settings.mixedPort}
              initialTestHost={routingTestHost}
              syncingRuleSets={syncingRuleSets}
              applyingStrategy={applyingStrategy}
              onSaveRule={(r) => void handleSaveRule(r)}
              onDeleteRule={(id) => void handleDeleteRule(id)}
              onSyncRuleSets={handleSyncRuleSets}
              onApplyStrategy={handleApplyStrategy}
              onTestRoute={handleTestRoute}
              onSavePort={(p) => void handleSavePort(p)}
              onDeletePort={(id) => void handleDeletePort(id)}
              onGoToNodes={() => setActiveTab("nodes")}
              onOpenChains={(cid) => {
                if (cid) setSelectedChainEditId(cid);
                setActiveTab("chains");
              }}
              onCopyText={handleCopyText}
              onInvalidPort={() => pushToast(dict.toast.invalidPort, "err")}
            />
          )}

          {activeTab === "dns" && (
            <DnsView
              dict={dict}
              settings={settings}
              nodes={nodes}
              chains={chains}
              onUpdateSettings={(s) => void handleUpdateSettings(s)}
            />
          )}

          {activeTab === "monitor" && (
            <MonitorView
              dict={dict}
              locale={locale}
              coreRunning={coreInfo.running}
              nodes={nodes}
              chains={chains}
              rules={rules}
              extraPorts={extraPorts}
              connections={connections}
              logs={logs}
              traffic={traffic}
              localDirectBytes={localDirectBytes}
              localRejectCount={localRejectCount}
              downHistory={downHistory}
              upHistory={upHistory}
              onStartCore={() => void handleToggleCore()}
              onFetchHistory={handleFetchHistory}
              onFetchPlatforms={handleFetchPlatforms}
              onClearHistory={handleClearHistory}
              onCloseConnection={(id) => {
                if (api.isDesktop()) void api.closeConnection(id).catch(() => {});
              }}
              onCloseAllConnections={() => {
                if (api.isDesktop()) void api.closeAllConnections().catch(() => {});
              }}
              onClearLogs={() => {
                setLogs([]);
                if (api.isDesktop()) void api.clearLogs().catch(() => {});
              }}
              onOpenLogsDir={() => void handleOpenLogsDir()}
              requestedSubTab={monitorSubTabReq?.tab}
              requestedSubTabNonce={monitorSubTabReq?.nonce}
            />
          )}

          {activeTab === "core" && (
            <CoreView
              dict={dict}
              coreInfo={coreInfo}
              settings={settings}
              compiled={compiled}
              preflight={preflight}
              coreBusy={coreBusy}
              downloadingCore={downloadingCore}
              coreDownloadProgress={coreDownloadProgress}
              coreUpdateReport={coreUpdateReport}
              checkingCoreUpdate={checkingCoreUpdate}
              onUpdateSettings={(s) => void handleUpdateSettings(s)}
              onRunPreflight={handleRunPreflight}
              onCheckCoreUpdate={handleCheckCoreUpdate}
              onDownloadCore={handleDownloadCore}
              onImportCoreBinary={handleImportCoreBinary}
              onToggleCore={handleToggleCore}
              onCopyJson={handleCopyText}
            />
          )}

          {activeTab === "settings" && (
            <SettingsView
              dict={dict}
              platform={platform}
              locale={locale}
              theme={theme}
              appVersion={appVersion}
              settings={settings}
              coreInfo={coreInfo}
              cliInfo={cliInfo}
              appUpdateReport={appUpdateReport}
              appUpdateState={appUpdateState}
              checkingAppUpdate={checkingAppUpdate}
              appUpdateError={appUpdateError}
              onChangeLocale={handleChangeLocale}
              onChangeTheme={handleChangeTheme}
              onUpdateSettings={(s) => void handleUpdateSettings(s)}
              onRestoreNetguard={() => void handleRestoreNetguard()}
              onCleanupLegacy={() => handleServiceAction("cleanup_legacy")}
              onOpenLogsDir={() => void handleOpenLogsDir()}
              onGoToDns={() => setActiveTab("dns")}
              onCopyText={handleCopyText}
              onCheckAppUpdate={() => handleCheckAppUpdate(false)}
              onDownloadAppUpdate={handleDownloadAppUpdate}
              onCancelAppUpdate={handleCancelAppUpdate}
              onRestartToUpdate={handleRestartToUpdate}
              onOpenExternalUrl={handleOpenExternalUrl}
            />
          )}
        </main>
      </div>

      {/* Floating Toasts */}
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-none fixed right-4 bottom-4 z-50 space-y-2"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className="ui-toast pointer-events-auto flex max-w-md items-center gap-2 px-3 py-2 text-[12px] text-[var(--text-primary)]"
          >
            <span
              className="h-1.5 w-1.5 shrink-0 rounded-full"
              style={{
                backgroundColor:
                  t.tone === "err"
                    ? "var(--danger-dot)"
                    : t.tone === "warn"
                      ? "var(--warning-dot)"
                      : t.tone === "ok"
                        ? "var(--success-dot)"
                        : "var(--text-secondary)",
              }}
            />
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
