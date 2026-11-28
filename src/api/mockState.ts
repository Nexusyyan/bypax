/**
 * Stateful in-memory preview backend used when running in a browser (`vite preview`)
 * without `__TAURI_INTERNALS__`. Supports deterministic URL `?scenario=` switches so
 * automated Gate B visual & interactive audits can exercise every view, modal, drawer,
 * empty state, HVCI recovery banner, macOS external child prompt, and Tray Popover.
 */

import type {
  AppPresetStatus,
  AppProxyRule,
  AppProxyStatusDto,
  AppRulesMutationResult,
  AppRuleTestQuery,
  AppRuleTestTrace,
  AppSettings,
  AppUpdateCheckReport,
  AppUpdateState,
  ApplyStrategyResult,
  BootstrapPayload,
  CaptureMode,
  ChainMutationResult,
  CliIntegrationInfo,
  CompileOutput,
  ConnectionHistoryPage,
  ConnectionItem,
  CoreInfo,
  CoreUpdateCheckReport,
  DriverProbeDto,
  ExternalChildAlert,
  ImportSummary,
  InboundPort,
  InstalledAppItem,
  LatencyResult,
  LiveMonitorPayload,
  LogEntry,
  MissingAppTargetWarning,
  NodeIR,
  PlatformKind,
  PlatformTrafficPayload,
  PreflightReport,
  PrivilegedServiceStatus,
  ProcessInfoDto,
  ProxyChain,
  RouteMode,
  RouteTestResult,
  RulePresetSpec,
  RuleSetStatus,
  SelectNodeResult,
  ServiceActionKind,
  SetCaptureModeResult,
  SimpleRoutingRule,
  SubscriptionGroup,
  SyncRuleSetsResult,
} from "../types";

export type PreviewScenario =
  | "default"
  | "empty"
  | "hvci"
  | "missing-driver"
  | "legacy-conflict"
  | "service-off"
  | "uac-cancel"
  | "macos"
  | "deleted-node"
  | "update-ready";

function readScenario(): PreviewScenario {
  if (typeof window === "undefined") return "default";
  const raw = new URLSearchParams(window.location.search).get("scenario");
  if (
    raw === "empty" ||
    raw === "hvci" ||
    raw === "missing-driver" ||
    raw === "legacy-conflict" ||
    raw === "service-off" ||
    raw === "uac-cancel" ||
    raw === "macos" ||
    raw === "deleted-node" ||
    raw === "update-ready"
  ) {
    return raw;
  }
  return "default";
}

interface MockStore {
  initialized: boolean;
  scenario: PreviewScenario;
  platform: PlatformKind;
  captureMode: CaptureMode;
  coreInfo: CoreInfo;
  settings: AppSettings;
  nodes: NodeIR[];
  chains: ProxyChain[];
  subscriptions: SubscriptionGroup[];
  rules: SimpleRoutingRule[];
  ruleSets: RuleSetStatus[];
  extraPorts: InboundPort[];
  appRules: AppProxyRule[];
  serviceStatus: PrivilegedServiceStatus;
  driverStatus: DriverProbeDto;
  appProxyStatus: AppProxyStatusDto;
  externalChildren: ExternalChildAlert[];
  cliInfo: CliIntegrationInfo;
  connections: ConnectionItem[];
  logs: LogEntry[];
  appUpdateState: AppUpdateState;
  uacCancelOnce: boolean;
}

const PRESET_CATALOG: Array<{
  id: string;
  name: string;
  category: string;
  description: string;
  processNames: string[];
  pathContains: string[];
  macBundlePaths: string[];
  installed: boolean;
  runningCount: number;
  detectedPaths: string[];
}> = [
  {
    id: "antigravity",
    name: "Antigravity",
    category: "ai-ide",
    description: "AI IDE and language server child processes",
    processNames: ["Antigravity.exe", "language_server_windows_x64.exe"],
    pathContains: ["\\Programs\\Antigravity\\"],
    macBundlePaths: ["/Applications/Antigravity.app"],
    installed: true,
    runningCount: 3,
    detectedPaths: ["C:\\Users\\demo\\AppData\\Local\\Programs\\Antigravity\\Antigravity.exe"],
  },
  {
    id: "cursor",
    name: "Cursor",
    category: "ai-ide",
    description: "AI code editor with node/helper subprocesses",
    processNames: ["Cursor.exe"],
    pathContains: ["\\Programs\\cursor\\"],
    macBundlePaths: ["/Applications/Cursor.app"],
    installed: true,
    runningCount: 2,
    detectedPaths: ["C:\\Users\\demo\\AppData\\Local\\Programs\\cursor\\Cursor.exe"],
  },
  {
    id: "vscode",
    name: "VS Code",
    category: "dev",
    description: "Visual Studio Code and extension host",
    processNames: ["Code.exe"],
    pathContains: ["\\Programs\\Microsoft VS Code\\"],
    macBundlePaths: ["/Applications/Visual Studio Code.app"],
    installed: true,
    runningCount: 0,
    detectedPaths: ["C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"],
  },
  {
    id: "git-ssh",
    name: "Git & SSH",
    category: "dev",
    description: "Git CLI, OpenSSH client, and credential helpers",
    processNames: ["git.exe", "git-remote-https.exe", "ssh.exe"],
    pathContains: ["\\Git\\"],
    macBundlePaths: ["/usr/bin/git", "/usr/bin/ssh"],
    installed: true,
    runningCount: 1,
    detectedPaths: ["C:\\Program Files\\Git\\cmd\\git.exe"],
  },
  {
    id: "discord",
    name: "Discord",
    category: "social",
    description: "Voice and desktop chat client",
    processNames: ["Discord.exe"],
    pathContains: ["\\Discord\\"],
    macBundlePaths: ["/Applications/Discord.app"],
    installed: true,
    runningCount: 2,
    detectedPaths: ["C:\\Users\\demo\\AppData\\Local\\Discord\\app-1.0\\Discord.exe"],
  },
  {
    id: "telegram",
    name: "Telegram",
    category: "social",
    description: "Telegram Desktop native client",
    processNames: ["Telegram.exe"],
    pathContains: ["\\Telegram Desktop\\"],
    macBundlePaths: ["/Applications/Telegram.app"],
    installed: false,
    runningCount: 0,
    detectedPaths: [],
  },
  {
    id: "steam",
    name: "Steam",
    category: "gaming",
    description: "Steam client and store browser helpers",
    processNames: ["steam.exe", "steamwebhelper.exe"],
    pathContains: ["\\Steam\\"],
    macBundlePaths: ["/Applications/Steam.app"],
    installed: false,
    runningCount: 0,
    detectedPaths: [],
  },
];

const MOCK_NODES: NodeIR[] = [
  {
    id: "n-jp-02",
    protocol: "vless",
    remark: "JP Tokyo-02 Direct-IPLC",
    server: "tokyo02.edge-relay.example",
    port: 443,
    group: "Studio Sub",
    region: "JP",
    wgLocalAddress: [],
    realDelayMs: 64,
    rawUri: "vless://11111111-1111-1111-1111-111111111111@tokyo02.edge-relay.example:443?security=reality#JP%20Tokyo-02%20Direct-IPLC",
    createdAt: "2026-11-26T00:00:00Z",
  },
  {
    id: "n-hk-01",
    protocol: "hysteria2",
    remark: "HK Kowloon-01 Ultra-Low-Latency-Gateway",
    server: "hk01.edge-relay.example",
    port: 8443,
    group: "Studio Sub",
    region: "HK",
    wgLocalAddress: [],
    realDelayMs: 42,
    rawUri: "hysteria2://samplepass@hk01.edge-relay.example:8443?sni=hk01.edge-relay.example#HK%20Kowloon-01",
    createdAt: "2026-11-26T00:00:00Z",
  },
  {
    id: "n-sg-01",
    protocol: "trojan",
    remark: "SG Marina-01 Streaming",
    server: "sg01.edge-relay.example",
    port: 443,
    group: "Studio Sub",
    region: "SG",
    wgLocalAddress: [],
    realDelayMs: 118,
    createdAt: "2026-11-26T00:00:00Z",
  },
  {
    id: "n-us-01",
    protocol: "vless",
    remark: "US SanJose-01 AI-Residential",
    server: "us-sj01.edge-relay.example",
    port: 443,
    group: "Self-Hosted",
    region: "US",
    wgLocalAddress: [],
    realDelayMs: 214,
    createdAt: "2026-11-26T00:00:00Z",
  },
  {
    id: "n-de-01",
    protocol: "shadowsocks",
    remark: "DE Frankfurt-01 Europe",
    server: "de-fra01.edge-relay.example",
    port: 10443,
    group: "Self-Hosted",
    region: "DE",
    wgLocalAddress: [],
    realDelayMs: 342,
    createdAt: "2026-11-26T00:00:00Z",
  },
  {
    id: "n-uk-01",
    protocol: "tuic",
    remark: "UK London-01 Academic",
    server: "uk-lon01.edge-relay.example",
    port: 443,
    group: "Self-Hosted",
    region: "UK",
    wgLocalAddress: [],
    realDelayMs: -1,
    createdAt: "2026-11-26T00:00:00Z",
  },
];

const MOCK_CHAINS: ProxyChain[] = [
  {
    id: "c-hk-us",
    name: "HK IPLC -> US AI Residential",
    hops: ["n-hk-01", "n-us-01"],
    enabled: true,
    realDelayMs: 186,
    description: null,
    createdAt: "2026-11-27T10:00:00Z",
  },
  {
    id: "c-jp-sg-de",
    name: "JP -> SG -> DE Triple Relay",
    hops: ["n-jp-02", "n-sg-01", "n-de-01"],
    enabled: true,
    realDelayMs: 278,
    description: null,
    createdAt: "2026-11-27T10:05:00Z",
  },
];

const MOCK_ROUTING_RULES: SimpleRoutingRule[] = [
  {
    id: "classic-private",
    title: "Private & LAN",
    titleEn: "Private & LAN",
    description: "geosite-private",
    patterns: ["local", "lan"],
    processNames: [],
    ruleSet: "geosite-private",
    target: "direct",
    enabled: true,
    priority: 10,
  },
  {
    id: "classic-ai",
    title: "AI Platforms",
    titleEn: "AI Platforms",
    description: "openai.com, anthropic.com, claude.ai",
    patterns: ["openai.com", "chatgpt.com", "anthropic.com", "claude.ai"],
    processNames: [],
    ruleSet: "geosite-openai",
    target: "chain:c-hk-us",
    enabled: true,
    priority: 20,
  },
  {
    id: "r-dev",
    title: "GitHub",
    titleEn: "GitHub",
    description: "github.com, githubusercontent.com",
    patterns: ["github.com", "githubusercontent.com"],
    processNames: [],
    ruleSet: "geosite-github",
    target: "n-jp-02",
    enabled: true,
    priority: 30,
  },
  {
    id: "classic-geosite-cn",
    title: "China Mainland Domains",
    titleEn: "China Mainland Domains",
    description: "geosite-cn",
    patterns: ["cn", "bilibili.com", "zhihu.com"],
    processNames: [],
    ruleSet: "geosite-cn",
    target: "direct",
    enabled: true,
    priority: 40,
  },
];

const MOCK_PROCESSES: ProcessInfoDto[] = [
  {
    pid: 4120,
    parentPid: 1024,
    name: "Antigravity.exe",
    exePath: "C:\\Users\\demo\\AppData\\Local\\Programs\\Antigravity\\Antigravity.exe",
    ancestorChain: ["Antigravity.exe"],
    matchedRuleId: "app-antigravity",
    matchedRuleName: "Antigravity",
  },
  {
    pid: 5532,
    parentPid: 4120,
    name: "language_server_windows_x64.exe",
    exePath:
      "C:\\Users\\demo\\AppData\\Local\\Programs\\Antigravity\\resources\\bin\\language_server_windows_x64.exe",
    ancestorChain: ["Antigravity.exe", "language_server_windows_x64.exe"],
    matchedRuleId: "app-antigravity",
    matchedRuleName: "Antigravity",
  },
  {
    pid: 8810,
    parentPid: 5532,
    name: "node.exe",
    exePath: "C:\\Program Files\\nodejs\\node.exe",
    ancestorChain: ["Antigravity.exe", "language_server_windows_x64.exe", "node.exe"],
    matchedRuleId: "app-antigravity",
    matchedRuleName: "Antigravity",
  },
  {
    pid: 6204,
    parentPid: 1024,
    name: "Cursor.exe",
    exePath: "C:\\Users\\demo\\AppData\\Local\\Programs\\cursor\\Cursor.exe",
    ancestorChain: ["Cursor.exe"],
    matchedRuleId: "app-cursor",
    matchedRuleName: "Cursor",
  },
  {
    pid: 6490,
    parentPid: 6204,
    name: "uv.exe",
    exePath: "C:\\Users\\demo\\.local\\bin\\uv.exe",
    ancestorChain: ["Cursor.exe", "uv.exe"],
    matchedRuleId: "app-cursor",
    matchedRuleName: "Cursor",
  },
  {
    pid: 7112,
    parentPid: 1024,
    name: "Code.exe",
    exePath: "C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    ancestorChain: ["Code.exe"],
    matchedRuleId: null,
    matchedRuleName: null,
  },
  {
    pid: 9320,
    parentPid: 1024,
    name: "Discord.exe",
    exePath: "C:\\Users\\demo\\AppData\\Local\\Discord\\app-1.0\\Discord.exe",
    ancestorChain: ["Discord.exe"],
    matchedRuleId: "app-discord",
    matchedRuleName: "Discord",
  },
];

const MOCK_INSTALLED_APPS: InstalledAppItem[] = [
  {
    name: "Antigravity",
    path: "C:\\Users\\demo\\AppData\\Local\\Programs\\Antigravity\\Antigravity.exe",
    processName: "Antigravity.exe",
    bundlePath: "/Applications/Antigravity.app",
  },
  {
    name: "Cursor",
    path: "C:\\Users\\demo\\AppData\\Local\\Programs\\cursor\\Cursor.exe",
    processName: "Cursor.exe",
    bundlePath: "/Applications/Cursor.app",
  },
  {
    name: "Visual Studio Code",
    path: "C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    processName: "Code.exe",
    bundlePath: "/Applications/Visual Studio Code.app",
  },
  {
    name: "Discord",
    path: "C:\\Users\\demo\\AppData\\Local\\Discord\\app-1.0\\Discord.exe",
    processName: "Discord.exe",
    bundlePath: "/Applications/Discord.app",
  },
  {
    name: "Postman",
    path: "C:\\Users\\demo\\AppData\\Local\\Postman\\Postman.exe",
    processName: "Postman.exe",
    bundlePath: "/Applications/Postman.app",
  },
];

const store: MockStore = {
  initialized: false,
  scenario: "default",
  platform: "windows",
  captureMode: "apps",
  coreInfo: {
    installed: true,
    running: true,
    version: "1.14.4",
    binaryPath: "core/sing-box.exe",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    portableMode: true,
    dataDir: "C:\\Tools\\Bypax\\bypax-data",
    netguardArmed: true,
    netguardRecoveredFromCrash: false,
  },
  settings: {
    locale: "zh-CN",
    theme: "system",
    routeMode: "rule",
    mainNodeId: "n-jp-02",
    mixedPort: 10808,
    controlPort: 9090,
    allowLan: false,
    systemProxyEnabled: true,
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
    dnsReverseMapping: true,
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
    appProxyEnabled: true,
    appProxyPort: 10818,
    appProxyBypassLan: true,
    appProxyBlockQuicWhenNeeded: true,
    appProxyWindivertDir: "runtime\\windivert",
    serviceMode: "service",
    tunRouteExcludeCidrs: [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "100.64.0.0/10",
      "198.19.0.0/16",
    ],
  },
  nodes: [],
  chains: [],
  subscriptions: [],
  rules: [],
  ruleSets: [],
  extraPorts: [],
  appRules: [],
  serviceStatus: {
    platform: "windows",
    mode: "service",
    installed: true,
    running: true,
    connected: true,
    elevated: true,
    state: "running",
    servicePid: 3288,
    appProxyRunning: true,
    tunRunning: false,
    error: null,
    errorKind: null,
  },
  driverStatus: {
    platform: "windows",
    elevated: true,
    dllLoaded: true,
    dllPath: "runtime\\windivert\\WinDivert.dll",
    driverOpened: true,
    driverVersion: "2.2.2-A",
    error: null,
    errorKind: null,
  },
  appProxyStatus: {
    running: true,
    mode: "windivert_zero_tun",
    activeRules: 3,
    exemptPids: [3288, 4096],
    lastError: null,
    errorKind: null,
    stats: {
      localDirectBytesTx: 2_400_000,
      localDirectBytesRx: 10_600_000,
      localDirectConnections: 14,
      localRejectConnections: 3,
      proxiedConnections: 48,
      activeProxiedConnections: 4,
      localConnections: [],
    },
  },
  externalChildren: [],
  cliInfo: {
    ready: true,
    cliPath: "C:\\Tools\\Bypax\\bypax-cli.exe",
    mcpConfigJson: JSON.stringify(
      {
        mcpServers: {
          bypax: {
            command: "C:\\Tools\\Bypax\\bypax-cli.exe",
            args: ["mcp"],
          },
        },
      },
      null,
      2,
    ),
    cliExamples: [
      "bypax-cli ctl --json status",
      "bypax-cli ctl --json app list-rules",
      "bypax-cli doctor",
    ],
  },
  connections: [],
  logs: [],
  appUpdateState: { stage: "idle", downloadedBytes: 0 },
  uacCancelOnce: false,
};

function computeMissingTargets(): MissingAppTargetWarning[] {
  const nodeIds = new Set(store.nodes.map((n) => n.id));
  const missing: MissingAppTargetWarning[] = [];
  for (const r of store.appRules) {
    if (r.target.startsWith("node:")) {
      const id = r.target.slice("node:".length);
      if (!nodeIds.has(id)) {
        missing.push({
          ruleId: r.id,
          ruleName: r.name,
          originalTarget: r.target,
          fallbackTarget: "follow",
        });
      }
    }
  }
  return missing;
}

function buildCompiled(): CompileOutput {
  return {
    config: {
      log: { level: store.settings.logLevel, timestamp: true },
      inbounds: [
        { type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: store.settings.mixedPort },
        ...(store.captureMode === "apps" && store.platform === "windows"
          ? [
              {
                type: "socks",
                tag: "app-proxy-in",
                listen: "127.0.0.1",
                listen_port: store.settings.appProxyPort,
              },
            ]
          : []),
        ...(store.captureMode === "tun" ||
        (store.captureMode === "apps" && store.platform === "macos")
          ? [{ type: "tun", tag: "tun-in", interface_name: store.settings.tunInterfaceName }]
          : []),
      ],
      outbounds: [
        { type: "selector", tag: "main-exit", outbounds: store.nodes.map((n) => n.id) },
        { type: "direct", tag: "direct" },
      ],
    },
    totalNodes: store.nodes.length,
    reachableNodes: store.nodes.length,
    reachableNodeIds: store.nodes.map((n) => n.id),
    synthesizedGroups: ["main-exit", "auto-us"],
    controlSecret: "preview-secret",
    missingAppRuleTargets: computeMissingTargets(),
  };
}

function buildPresets(): AppPresetStatus[] {
  const emptyMode = store.scenario === "empty";
  return PRESET_CATALOG.map((p) => {
    const matched = store.appRules.find((r) => r.presetId === p.id);
    return {
      id: p.id,
      name: p.name,
      category: p.category,
      description: p.description,
      processNames: p.processNames,
      pathContains: p.pathContains,
      macBundlePaths: p.macBundlePaths,
      includeChildren: true,
      installed: emptyMode ? false : p.installed,
      runningCount: emptyMode ? 0 : p.runningCount,
      detectedPaths: emptyMode ? [] : p.detectedPaths,
      enabled: Boolean(matched?.enabled),
      ruleId: matched?.id ?? null,
      target: matched?.target ?? "follow",
    };
  });
}

function ensureInit(): void {
  const sc = readScenario();
  if (store.initialized && store.scenario === sc) return;
  store.initialized = true;
  store.scenario = sc;

  const isMac = sc === "macos";
  store.platform = isMac ? "macos" : "windows";
  store.nodes = sc === "empty" ? [] : MOCK_NODES.map((n) => ({ ...n }));
  store.chains = sc === "empty" ? [] : MOCK_CHAINS.map((c) => ({ ...c, hops: [...c.hops] }));
  store.subscriptions =
    sc === "empty"
      ? []
      : [
          {
            id: "sub-studio",
            name: "Studio Sub",
            url: "https://sub.example.com/bypax",
            autoUpdateHours: 24,
            lastUpdated: "2026-11-26T14:30:00Z",
            nodeCount: 3,
          },
        ];
  store.rules = sc === "empty" ? [] : MOCK_ROUTING_RULES.map((r) => ({ ...r }));
  store.ruleSets = [
    { tag: "geosite-private", cachedLocally: true, bytes: 18420, fallbackMode: false },
    { tag: "geosite-openai", cachedLocally: true, bytes: 6420, fallbackMode: false },
    { tag: "geosite-github", cachedLocally: true, bytes: 14200, fallbackMode: false },
    { tag: "geosite-cn", cachedLocally: true, bytes: 248120, fallbackMode: false },
  ];
  store.extraPorts = [];

  store.appRules =
    sc === "empty"
      ? []
      : [
          {
            id: "app-antigravity",
            name: "Antigravity",
            enabled: true,
            priority: 1,
            presetId: "antigravity",
            processNames: ["Antigravity.exe", "language_server_windows_x64.exe"],
            pathPrefixes: [],
            pathContains: ["\\Programs\\Antigravity\\"],
            macBundlePaths: ["/Applications/Antigravity.app"],
            ignoredExternalChildren: [],
            includeChildren: true,
            domains: [
              { pattern: "*.googleapis.com", action: "proxy" },
              { pattern: "localhost", action: "direct" },
              { pattern: "telemetry.example.com", action: "reject" },
            ],
            dstCidrs: [],
            dstPorts: [443],
            protocols: ["tcp", "udp"],
            target: "main",
          },
          {
            id: "app-cursor",
            name: "Cursor",
            enabled: true,
            priority: 2,
            presetId: "cursor",
            processNames: ["Cursor.exe"],
            pathPrefixes: [],
            pathContains: ["\\Programs\\cursor\\"],
            macBundlePaths: ["/Applications/Cursor.app"],
            ignoredExternalChildren: [],
            includeChildren: true,
            domains: [{ pattern: "*.openai.com", action: "proxy" }],
            dstCidrs: [],
            dstPorts: [],
            protocols: ["tcp"],
            target: sc === "deleted-node" ? "node:n-deleted-999" : "follow",
          },
          {
            id: "app-discord",
            name: "Discord",
            enabled: true,
            priority: 3,
            presetId: "discord",
            processNames: ["Discord.exe"],
            pathPrefixes: [],
            pathContains: ["\\Discord\\"],
            macBundlePaths: ["/Applications/Discord.app"],
            ignoredExternalChildren: [],
            includeChildren: true,
            domains: [],
            dstCidrs: [],
            dstPorts: [],
            protocols: ["tcp", "udp"],
            target: "auto:US",
          },
        ];

  store.coreInfo = {
    installed: sc !== "empty",
    running: sc !== "empty",
    version: sc === "empty" ? null : "1.14.4",
    binaryPath: isMac ? "/Applications/Bypax.app/Contents/MacOS/sing-box" : "core/sing-box.exe",
    sha256: sc === "empty" ? null : "a4d912f9b38c6e1189f4e2a177c2d091",
    portableMode: !isMac,
    dataDir: isMac ? "~/Library/Application Support/Bypax" : "C:\\Tools\\Bypax\\bypax-data",
    netguardArmed: sc !== "empty",
    netguardRecoveredFromCrash: false,
  };

  const legacyConflict = sc === "legacy-conflict";
  const serviceOff = sc === "service-off" || sc === "uac-cancel" || legacyConflict;
  store.captureMode = sc === "empty" || serviceOff ? "off" : "apps";
  store.settings.systemProxyEnabled = sc !== "empty";
  store.settings.appProxyEnabled = store.captureMode === "apps";
  store.settings.tunEnabled = false;
  store.settings.mainNodeId = sc === "empty" ? null : "n-jp-02";
  store.settings.serviceMode = serviceOff ? "off" : isMac ? "service" : "elevated_worker";

  const hvci = sc === "hvci";
  const missingDriver = sc === "missing-driver";
  store.serviceStatus = {
    platform: store.platform,
    mode: store.settings.serviceMode,
    installed: isMac ? !serviceOff : false,
    running: !serviceOff,
    connected: !serviceOff,
    elevated: !serviceOff,
    state: serviceOff ? "stopped" : "running",
    servicePid: serviceOff ? null : 3288,
    appProxyRunning: store.captureMode === "apps" && !hvci && !missingDriver,
    tunRunning: false,
    error: legacyConflict
      ? "Legacy background services detected: BypaxService"
      : hvci
        ? "Windows Security or Memory Integrity prevented WinDivert64.sys from loading."
        : missingDriver
          ? "WinDivert.dll or WinDivert64.sys is missing from runtime/windivert."
          : null,
    errorKind: legacyConflict
      ? "legacy_conflict"
      : hvci
        ? "hvci_blocked"
        : missingDriver
          ? "driver_missing"
          : null,
    legacyServices: legacyConflict ? ["BypaxService"] : [],
    conflictDetail: legacyConflict
      ? "Legacy background services detected: BypaxService"
      : null,
  };

  store.driverStatus = {
    platform: store.platform,
    elevated: !serviceOff,
    dllLoaded: !missingDriver,
    dllPath: missingDriver ? null : "runtime\\windivert\\WinDivert.dll",
    driverOpened: !hvci && !missingDriver,
    driverVersion: !hvci && !missingDriver ? "2.2.2-A" : null,
    error: store.serviceStatus.error,
    errorKind: store.serviceStatus.errorKind,
  };

  store.appProxyStatus = {
    running: store.serviceStatus.appProxyRunning,
    mode: isMac ? "macos_utun_path" : "windivert_zero_tun",
    activeRules: store.appRules.filter((r) => r.enabled).length,
    exemptPids: [3288, 4096],
    lastError: store.serviceStatus.error,
    errorKind: store.serviceStatus.errorKind,
    stats: {
      localDirectBytesTx: 2_100_000,
      localDirectBytesRx: 10_900_000,
      localDirectConnections: 14,
      localRejectConnections: 2,
      proxiedConnections: 42,
      activeProxiedConnections: 3,
      localConnections: [],
    },
  };

  store.externalChildren = isMac
    ? [
        {
          ruleId: "app-cursor",
          ruleName: "Cursor",
          appName: "Cursor",
          children: [
            { pid: 8810, name: "node", exePath: "/opt/homebrew/bin/node" },
            { pid: 8842, name: "uv", exePath: "/opt/homebrew/bin/uv" },
          ],
        },
      ]
    : [];

  store.cliInfo = isMac
    ? {
        ready: true,
        cliPath: "/Applications/Bypax.app/Contents/MacOS/bypax-cli",
        mcpConfigJson: JSON.stringify(
          {
            mcpServers: {
              bypax: {
                command: "/Applications/Bypax.app/Contents/MacOS/bypax-cli",
                args: ["mcp"],
              },
            },
          },
          null,
          2,
        ),
        cliExamples: [
          "bypax-cli ctl --json status",
          "bypax-cli ctl --json app list-rules",
          "bypax-cli doctor",
        ],
      }
    : store.cliInfo;

  store.connections =
    sc === "empty"
      ? []
      : [
          {
            id: "c-1",
            process: "node.exe",
            destination: "api.openai.com:443",
            inbound: "app-proxy-in",
            rule: "app_rule=Antigravity",
            chain: ["main-exit", "n-jp-02"],
            uploadBytes: 342_120,
            downloadBytes: 4_812_900,
            start: "2026-11-26T15:02:10Z",
            sourcePort: 54120,
            sourceKind: "app_proxy",
            ancestorApp: "Antigravity",
            ancestorChain: ["Antigravity.exe", "language_server_windows_x64.exe", "node.exe"],
            pid: 8810,
            appRuleName: "Antigravity",
            originExpired: false,
            localAction: null,
          },
          {
            id: "c-2",
            process: "chrome.exe",
            destination: "github.com:443",
            inbound: "mixed-in",
            rule: "rule_set=[geosite-github] => n-jp-02",
            chain: ["n-jp-02"],
            uploadBytes: 128_400,
            downloadBytes: 2_310_000,
            start: "2026-11-26T15:01:44Z",
            sourceKind: "sys_proxy",
            ancestorApp: null,
            ancestorChain: ["chrome.exe"],
            pid: 2110,
            appRuleName: null,
            originExpired: false,
            localAction: null,
          },
          {
            id: "c-3",
            process: "Discord.exe",
            destination: "gateway.discord.gg:443",
            inbound: "app-proxy-in",
            rule: "app_rule=Discord",
            chain: ["auto-us", "n-us-01"],
            uploadBytes: 86_200,
            downloadBytes: 912_000,
            start: "2026-11-26T15:00:12Z",
            sourcePort: 54198,
            sourceKind: "app_proxy",
            ancestorApp: "Discord",
            ancestorChain: ["Discord.exe"],
            pid: 9320,
            appRuleName: "Discord",
            originExpired: false,
            localAction: null,
          },
          {
            id: "c-4",
            process: "Antigravity.exe",
            destination: "127.0.0.1:5173",
            inbound: "app-proxy-local",
            rule: "app_rule=Antigravity",
            chain: ["direct"],
            uploadBytes: 42_000,
            downloadBytes: 184_000,
            start: "2026-11-26T15:03:05Z",
            sourceKind: "app_proxy",
            ancestorApp: "Antigravity",
            ancestorChain: ["Antigravity.exe"],
            pid: 4120,
            appRuleName: "Antigravity",
            originExpired: false,
            localAction: "local_direct",
          },
          {
            id: "c-5",
            process: "Antigravity.exe",
            destination: "telemetry.example.com:443",
            inbound: "app-proxy-local",
            rule: "app_rule=Antigravity",
            chain: ["reject"],
            uploadBytes: 0,
            downloadBytes: 0,
            start: "2026-11-26T15:03:18Z",
            sourceKind: "app_proxy",
            ancestorApp: "Antigravity",
            ancestorChain: ["Antigravity.exe"],
            pid: 4120,
            appRuleName: "Antigravity",
            originExpired: false,
            localAction: "local_reject",
          },
          {
            id: "c-6",
            process: "",
            destination: "cdn.jsdelivr.net:443",
            inbound: "app-proxy-in",
            rule: "final",
            chain: ["main-exit", "n-jp-02"],
            uploadBytes: 12_400,
            downloadBytes: 245_000,
            start: "2026-11-26T14:58:10Z",
            sourceKind: "app_proxy",
            originExpired: true,
            localAction: null,
          },
        ];

  store.logs = [
    { timestamp: "2026-11-26T15:00:01Z", level: "INFO", message: "Bypax runtime initialized (preview mode)" },
    { timestamp: "2026-11-26T15:00:02Z", level: "INFO", message: "App Proxy attached (3 active rules)" },
    { timestamp: "2026-11-26T15:01:44Z", level: "INFO", message: "inbound/mixed: github.com:443 -> n-jp-02" },
    { timestamp: "2026-11-26T15:02:10Z", level: "INFO", message: "app-proxy: Antigravity > node.exe api.openai.com:443 -> main-exit" },
  ];

  store.appUpdateState =
    sc === "update-ready"
      ? {
          stage: "ready_to_restart",
          targetVersion: "0.2.0",
          targetTag: "v0.2.0",
          assetName: "bypax-v0.2.0-x86_64-windows-portable.zip",
          assetKind: "portable_zip",
          downloadedBytes: 28_450_000,
          totalBytes: 28_450_000,
          percent: 100,
          via: "local_proxy",
          sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }
      : { stage: "idle", downloadedBytes: 0 };
}

export const mockBackend = {
  getBootstrapState(): BootstrapPayload {
    ensureInit();
    return {
      appVersion: "0.1.0",
      platform: store.platform,
      captureMode: store.captureMode,
      coreInfo: { ...store.coreInfo },
      settings: { ...store.settings },
      nodes: store.nodes.map((n) => ({ ...n })),
      chains: store.chains.map((c) => ({ ...c, hops: [...c.hops] })),
      subscriptions: store.subscriptions.map((s) => ({ ...s })),
      rules: store.rules.map((r) => ({ ...r })),
      extraPorts: store.extraPorts.map((p) => ({ ...p })),
      ruleSets: store.ruleSets.map((rs) => ({ ...rs })),
      compiled: buildCompiled(),
      logs: store.logs.map((l) => ({ ...l })),
      appUpdateState: { ...store.appUpdateState },
      lastUpdateResult: null,
      appRules: store.appRules.map((r) => ({ ...r, domains: r.domains.map((d) => ({ ...d })) })),
      appPresets: buildPresets(),
      serviceStatus: { ...store.serviceStatus },
      driverStatus: { ...store.driverStatus },
      appProxyStatus: { ...store.appProxyStatus, stats: { ...store.appProxyStatus.stats } },
      externalChildren: store.externalChildren.map((c) => ({ ...c, children: [...c.children] })),
      cliInfo: { ...store.cliInfo },
    };
  },

  listRulePresets(): RulePresetSpec[] {
    return [
      {
        id: "r-openai",
        category: "ai",
        title: "OpenAI / ChatGPT",
        titleEn: "OpenAI / ChatGPT",
        description: "openai.com, chatgpt.com",
        patterns: ["openai.com", "chatgpt.com"],
        processNames: [],
        ruleSet: "geosite-openai",
        defaultTarget: "auto:US",
        defaultPriority: 15,
      },
      {
        id: "r-anthropic",
        category: "ai",
        title: "Claude / Anthropic",
        titleEn: "Claude / Anthropic",
        description: "anthropic.com, claude.ai",
        patterns: ["anthropic.com", "claude.ai"],
        processNames: [],
        ruleSet: "geosite-anthropic",
        defaultTarget: "auto:US",
        defaultPriority: 16,
      },
      {
        id: "r-youtube",
        category: "media",
        title: "YouTube",
        titleEn: "YouTube",
        description: "youtube.com, googlevideo.com",
        patterns: ["youtube.com", "googlevideo.com"],
        processNames: [],
        ruleSet: "geosite-youtube",
        defaultTarget: "main",
        defaultPriority: 22,
      },
    ];
  },

  importNodes(payload: string, groupName = "Imported"): ImportSummary {
    ensureInit();
    const lines = payload
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.includes("://"));
    const added: NodeIR[] = lines.map((line, idx) => {
      const hashIdx = line.indexOf("#");
      const remark =
        hashIdx >= 0
          ? decodeURIComponent(line.slice(hashIdx + 1))
          : `Node-${store.nodes.length + idx + 1}`;
      return {
        id: `n-imp-${Date.now()}-${idx}`,
        protocol: line.startsWith("hysteria2") ? "hysteria2" : "vless",
        remark,
        server: `edge-${idx + 1}.example.com`,
        port: 443,
        group: groupName || "Imported",
        region: remark.includes("US") ? "US" : remark.includes("HK") ? "HK" : "JP",
        wgLocalAddress: [],
        realDelayMs: 65 + idx * 42,
        createdAt: new Date().toISOString(),
      };
    });
    store.nodes = [...store.nodes, ...added];
    if (!store.settings.mainNodeId && store.nodes.length > 0) {
      store.settings.mainNodeId = store.nodes[0].id;
    }
    return { nodes: added, skipped: 0 };
  },

  deleteNode(id: string): boolean {
    ensureInit();
    store.nodes = store.nodes.filter((n) => n.id !== id);
    if (store.settings.mainNodeId === id) {
      store.settings.mainNodeId = store.nodes[0]?.id ?? null;
    }
    return true;
  },

  selectMainNode(id: string): SelectNodeResult {
    ensureInit();
    store.settings.mainNodeId = id;
    return { hotSwitched: store.coreInfo.running, mainNodeId: id, compiled: buildCompiled() };
  },

  setRouteMode(mode: RouteMode): CompileOutput {
    ensureInit();
    store.settings.routeMode = mode;
    return buildCompiled();
  },

  toggleSystemProxy(enabled: boolean): CoreInfo {
    ensureInit();
    if (enabled && store.nodes.length === 0) {
      throw new Error("NO_NODES_CONFIGURED");
    }
    if (enabled && !store.coreInfo.installed) {
      throw new Error("CORE_NOT_INSTALLED");
    }
    store.settings.systemProxyEnabled = enabled;
    store.coreInfo.netguardArmed = enabled;
    return { ...store.coreInfo };
  },

  setCaptureMode(mode: CaptureMode): SetCaptureModeResult {
    ensureInit();
    if (mode !== "off" && (!store.serviceStatus.connected || store.serviceStatus.mode === "off")) {
      throw new Error("SERVICE_OFF");
    }
    store.captureMode = mode;
    store.settings.appProxyEnabled = mode === "apps";
    store.settings.tunEnabled = mode === "tun";
    store.serviceStatus.appProxyRunning = mode === "apps";
    store.serviceStatus.tunRunning = mode === "tun";
    if (mode === "tun") {
      // Clear HVCI fault when falling back to TUN
      store.serviceStatus.error = null;
      store.serviceStatus.errorKind = null;
      store.appProxyStatus.lastError = null;
      store.appProxyStatus.errorKind = null;
    }
    store.appProxyStatus.running = mode === "apps";
    store.appProxyStatus.activeRules = store.appRules.filter((r) => r.enabled).length;
    return {
      captureMode: store.captureMode,
      coreInfo: { ...store.coreInfo },
      serviceStatus: { ...store.serviceStatus },
      appProxyStatus: { ...store.appProxyStatus },
      compiled: buildCompiled(),
    };
  },

  serviceAction(action: ServiceActionKind): PrivilegedServiceStatus {
    ensureInit();
    // B8: service-off succeeds cleanly on both "Allow once" and "Install service";
    // use ?scenario=uac-cancel to test the UAC_CANCELLED rollback path deterministically.
    if (action === "start_worker" && store.scenario === "uac-cancel") {
      throw new Error("UAC_CANCELLED");
    }
    if (action === "install" || action === "start" || action === "restart") {
      store.settings.serviceMode = "service";
      store.serviceStatus = {
        ...store.serviceStatus,
        mode: "service",
        installed: true,
        running: true,
        connected: true,
        elevated: true,
        state: "running",
        servicePid: 3288,
        error: null,
        errorKind: null,
      };
    } else if (action === "start_worker") {
      store.settings.serviceMode = "elevated_worker";
      store.serviceStatus = {
        ...store.serviceStatus,
        mode: "elevated_worker",
        installed: false,
        running: true,
        connected: true,
        elevated: true,
        state: "running",
        servicePid: 7744,
        error: null,
        errorKind: null,
      };
    } else if (action === "cleanup_legacy") {
      store.settings.serviceMode = "off";
      store.captureMode = "off";
      store.settings.appProxyEnabled = false;
      store.settings.tunEnabled = false;
      store.serviceStatus = {
        ...store.serviceStatus,
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
      store.driverStatus.error = null;
      store.driverStatus.errorKind = null;
      store.appProxyStatus.running = false;
      store.appProxyStatus.lastError = null;
      store.appProxyStatus.errorKind = null;
    } else if (action === "stop" || action === "stop_worker" || action === "uninstall") {
      store.settings.serviceMode = "off";
      store.captureMode = "off";
      store.settings.appProxyEnabled = false;
      store.settings.tunEnabled = false;
      store.serviceStatus = {
        ...store.serviceStatus,
        mode: "off",
        installed: action === "uninstall" ? false : store.serviceStatus.installed,
        running: false,
        connected: false,
        elevated: false,
        state: "stopped",
        servicePid: null,
        appProxyRunning: false,
        tunRunning: false,
      };
      store.appProxyStatus.running = false;
    }
    return { ...store.serviceStatus };
  },

  saveAppRule(rule: AppProxyRule): AppRulesMutationResult {
    ensureInit();
    const exists = store.appRules.some((r) => r.id === rule.id);
    if (exists) {
      store.appRules = store.appRules.map((r) => (r.id === rule.id ? rule : r));
    } else {
      store.appRules = [...store.appRules, { ...rule, priority: store.appRules.length + 1 }];
    }
    store.appProxyStatus.activeRules = store.appRules.filter((r) => r.enabled).length;
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: store.captureMode === "apps",
    };
  },

  deleteAppRule(id: string): AppRulesMutationResult {
    ensureInit();
    store.appRules = store.appRules
      .filter((r) => r.id !== id)
      .map((r, idx) => ({ ...r, priority: idx + 1 }));
    store.appProxyStatus.activeRules = store.appRules.filter((r) => r.enabled).length;
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: store.captureMode === "apps",
    };
  },

  reorderAppRules(ids: string[]): AppRulesMutationResult {
    ensureInit();
    const byId = new Map(store.appRules.map((r) => [r.id, r]));
    const next: AppProxyRule[] = [];
    for (const id of ids) {
      const r = byId.get(id);
      if (r) {
        next.push({ ...r, priority: next.length + 1 });
        byId.delete(id);
      }
    }
    for (const leftover of byId.values()) {
      next.push({ ...leftover, priority: next.length + 1 });
    }
    store.appRules = next;
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: store.captureMode === "apps",
    };
  },

  toggleAppPreset(presetId: string, enabled: boolean, target?: string): AppRulesMutationResult {
    ensureInit();
    const preset = PRESET_CATALOG.find((p) => p.id === presetId);
    const existing = store.appRules.find((r) => r.presetId === presetId);
    if (existing) {
      store.appRules = store.appRules.map((r) =>
        r.id === existing.id
          ? { ...r, enabled, target: target ?? r.target }
          : r,
      );
    } else if (preset) {
      store.appRules = [
        ...store.appRules,
        {
          id: `app-${preset.id}`,
          name: preset.name,
          enabled,
          priority: store.appRules.length + 1,
          presetId: preset.id,
          processNames: preset.processNames,
          pathPrefixes: [],
          pathContains: preset.pathContains,
          macBundlePaths: preset.macBundlePaths,
          ignoredExternalChildren: [],
          includeChildren: true,
          domains: [],
          dstCidrs: [],
          dstPorts: [],
          protocols: ["tcp", "udp"],
          target: target ?? "follow",
        },
      ];
    }
    store.appProxyStatus.activeRules = store.appRules.filter((r) => r.enabled).length;
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: store.captureMode === "apps",
    };
  },

  listAppPresets(): AppPresetStatus[] {
    ensureInit();
    return buildPresets();
  },

  testAppRule(query: AppRuleTestQuery): AppRuleTestTrace {
    ensureInit();
    const proc = (query.processName || "").trim().toLowerCase();
    const exe = (query.exePath || "").trim().toLowerCase();
    const host = (query.host || "").trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];

    const matchedIdx = store.appRules.findIndex((r) => {
      if (!r.enabled) return false;
      const byProc = r.processNames.some((p) => {
        const lp = p.toLowerCase();
        return proc === lp || proc.includes(lp.replace(/\.exe$/, ""));
      });
      const pathMatched =
        exe.length > 0 &&
        (r.pathContains.some((c) => exe.includes(c.toLowerCase())) ||
          r.macBundlePaths.some((b) => exe.startsWith(b.toLowerCase())));
      const viaAncestor =
        r.includeChildren &&
        (proc === "node.exe" || proc === "node") &&
        (r.presetId === "antigravity" || r.presetId === "cursor");
      return byProc || pathMatched || viaAncestor;
    });

    if (matchedIdx < 0) {
      return {
        step1ProcessMatch: "No app rule matched this process",
        step2DomainOverride: "No override evaluated",
        step3FinalExit: "Bypassed to Routing / Direct",
        matchedRuleId: null,
        matchedRuleName: null,
        matchedViaAncestor: null,
        matchedDomainPattern: null,
        domainOverrideAction: null,
        finalAction: "bypass",
        finalTarget: "follow",
        resolvedLabel: "Routing / Direct",
        bypassedToRouting: true,
      };
    }

    const rule = store.appRules[matchedIdx];
    const viaAncestor =
      (proc === "node.exe" || proc === "node") && rule.includeChildren
        ? rule.processNames[0] ?? rule.name
        : null;
    const domHit = rule.domains.find((d) => {
      const needle = d.pattern.toLowerCase().replace(/^\*\./, "");
      return host === needle || host.endsWith(`.${needle}`);
    });
    const finalAction = domHit ? domHit.action : rule.target === "direct" ? "direct" : rule.target === "reject" ? "reject" : "proxy";
    const mainNode = store.nodes.find((n) => n.id === store.settings.mainNodeId) ?? store.nodes[0];
    const exitLabel =
      finalAction === "direct"
        ? "Direct"
        : finalAction === "reject"
          ? "Reject"
          : rule.target === "main" || rule.target === "follow"
            ? `Main Exit \u00b7 ${mainNode?.remark ?? "None"}`
            : rule.target;

    return {
      step1ProcessMatch: viaAncestor
        ? `Matched rule #${matchedIdx + 1} ${rule.name} (via parent ${viaAncestor})`
        : `Matched rule #${matchedIdx + 1} ${rule.name}`,
      step2DomainOverride: domHit
        ? `${host || "(host)"} matched override ${domHit.pattern} -> ${domHit.action}`
        : "No domain override",
      step3FinalExit: exitLabel,
      matchedRuleId: rule.id,
      matchedRuleName: rule.name,
      matchedViaAncestor: viaAncestor,
      matchedDomainPattern: domHit?.pattern ?? null,
      domainOverrideAction: domHit?.action ?? null,
      finalAction,
      finalTarget: rule.target,
      resolvedLabel: exitLabel,
      bypassedToRouting: false,
    };
  },

  listRunningProcesses(filter?: string): ProcessInfoDto[] {
    ensureInit();
    const q = (filter || "").trim().toLowerCase();
    if (!q) return MOCK_PROCESSES.map((p) => ({ ...p }));
    return MOCK_PROCESSES.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.exePath && p.exePath.toLowerCase().includes(q)) ||
        p.ancestorChain.some((a) => a.toLowerCase().includes(q)),
    );
  },

  listInstalledApps(): InstalledAppItem[] {
    ensureInit();
    return MOCK_INSTALLED_APPS.map((a) => ({ ...a }));
  },

  includeExternalChild(ruleId: string, childPath: string): AppRulesMutationResult {
    ensureInit();
    store.appRules = store.appRules.map((r) =>
      r.id === ruleId
        ? { ...r, pathPrefixes: Array.from(new Set([...r.pathPrefixes, childPath])) }
        : r,
    );
    store.externalChildren = store.externalChildren
      .map((a) =>
        a.ruleId === ruleId
          ? { ...a, children: a.children.filter((c) => c.exePath !== childPath) }
          : a,
      )
      .filter((a) => a.children.length > 0);
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: true,
    };
  },

  ignoreExternalChild(ruleId: string, childPath: string): AppRulesMutationResult {
    ensureInit();
    store.appRules = store.appRules.map((r) =>
      r.id === ruleId
        ? {
            ...r,
            ignoredExternalChildren: Array.from(
              new Set([...r.ignoredExternalChildren, childPath]),
            ),
          }
        : r,
    );
    store.externalChildren = store.externalChildren
      .map((a) =>
        a.ruleId === ruleId
          ? { ...a, children: a.children.filter((c) => c.exePath !== childPath) }
          : a,
      )
      .filter((a) => a.children.length > 0);
    return {
      rules: store.appRules.map((r) => ({ ...r })),
      compiled: buildCompiled(),
      reloaded: false,
    };
  },

  probeDriver(): DriverProbeDto {
    ensureInit();
    return { ...store.driverStatus };
  },

  setWindivertDir(dir: string): DriverProbeDto {
    ensureInit();
    store.settings.appProxyWindivertDir = dir;
    store.driverStatus = {
      ...store.driverStatus,
      dllLoaded: true,
      dllPath: `${dir}\\WinDivert.dll`,
      driverOpened: true,
      driverVersion: "2.2.2-A",
      error: null,
      errorKind: null,
    };
    store.serviceStatus.error = null;
    store.serviceStatus.errorKind = null;
    return { ...store.driverStatus };
  },

  getLiveMonitor(): LiveMonitorPayload {
    ensureInit();
    return {
      coreRunning: store.coreInfo.running,
      connections: store.connections.map((c) => ({ ...c })),
      traffic: {
        upBytesPerSec: store.coreInfo.running ? 86_400 : 0,
        downBytesPerSec: store.coreInfo.running ? 1_280_000 : 0,
        memoryBytes: store.coreInfo.running ? 38_400_000 : 0,
        activeConnections: store.connections.length,
      },
      logs: store.logs.map((l) => ({ ...l })),
      appProxyStatus: { ...store.appProxyStatus },
      localDirectBytes:
        store.appProxyStatus.stats.localDirectBytesTx +
        store.appProxyStatus.stats.localDirectBytesRx,
      localRejectCount: store.appProxyStatus.stats.localRejectConnections,
    };
  },

  getConnectionHistory(query: string, page: number, pageSize: number): ConnectionHistoryPage {
    ensureInit();
    const items = store.connections
      .filter((c) => !query || c.destination.toLowerCase().includes(query.toLowerCase()))
      .map((c) => ({
        id: `hist-${c.id}`,
        process: c.ancestorApp ? `${c.ancestorApp} > ${c.process}` : c.process || "App Proxy",
        destination: c.destination,
        host: c.destination.split(":")[0],
        platform: c.destination.includes("openai")
          ? "OpenAI"
          : c.destination.includes("github")
            ? "GitHub"
            : "Other",
        inbound: c.inbound,
        rule: c.rule,
        chain: c.chain,
        uploadBytes: c.uploadBytes,
        downloadBytes: c.downloadBytes,
        startedAt: c.start,
        closedAt: c.start,
      }));
    return { items, total: items.length, page, pageSize };
  },

  getPlatformTraffic(): PlatformTrafficPayload {
    ensureInit();
    return {
      items: [
        {
          platform: "OpenAI",
          uploadBytes: 342_120,
          downloadBytes: 4_812_900,
          totalBytes: 5_155_020,
          connectionCount: 18,
          activeCount: 1,
          topDomains: ["api.openai.com"],
        },
        {
          platform: "GitHub",
          uploadBytes: 128_400,
          downloadBytes: 2_310_000,
          totalBytes: 2_438_400,
          connectionCount: 12,
          activeCount: 1,
          topDomains: ["github.com"],
        },
      ],
      totalUpload: 470_520,
      totalDownload: 7_122_900,
      totalConnections: 30,
    };
  },

  saveRule(rule: SimpleRoutingRule): CompileOutput {
    ensureInit();
    const exists = store.rules.some((r) => r.id === rule.id);
    if (exists) {
      store.rules = store.rules.map((r) => (r.id === rule.id ? { ...rule } : r));
    } else {
      store.rules = [...store.rules, { ...rule }];
    }
    store.rules.sort((a, b) => a.priority - b.priority);
    return buildCompiled();
  },

  deleteRule(id: string): CompileOutput {
    ensureInit();
    store.rules = store.rules.filter((r) => r.id !== id);
    return buildCompiled();
  },

  saveInboundPort(port: InboundPort): CompileOutput {
    ensureInit();
    const exists = store.extraPorts.some((p) => p.id === port.id);
    if (exists) {
      store.extraPorts = store.extraPorts.map((p) => (p.id === port.id ? { ...port } : p));
    } else {
      store.extraPorts = [...store.extraPorts, { ...port }];
    }
    return buildCompiled();
  },

  deleteInboundPort(id: string): CompileOutput {
    ensureInit();
    store.extraPorts = store.extraPorts.filter((p) => p.id !== id);
    return buildCompiled();
  },

  saveProxyChain(chain: ProxyChain): ChainMutationResult {
    ensureInit();
    const trimmedName = chain.name.trim();
    if (!trimmedName) {
      throw new Error("Proxy chain name cannot be empty");
    }
    if (chain.hops.length < 2) {
      throw new Error("Proxy chain requires at least 2 hops");
    }
    const nextChain: ProxyChain = {
      ...chain,
      id: chain.id?.trim() || `chain-${Date.now()}`,
      name: trimmedName,
      hops: [...chain.hops],
      enabled: chain.enabled ?? true,
      createdAt: chain.createdAt || new Date().toISOString(),
    };
    const exists = store.chains.some((c) => c.id === nextChain.id);
    if (exists) {
      store.chains = store.chains.map((c) => (c.id === nextChain.id ? nextChain : c));
    } else {
      store.chains = [...store.chains, nextChain];
    }
    return {
      chains: store.chains.map((c) => ({ ...c, hops: [...c.hops] })),
      compiled: buildCompiled(),
    };
  },

  deleteProxyChain(id: string): ChainMutationResult {
    ensureInit();
    store.chains = store.chains.filter((c) => c.id !== id);
    if (store.settings.mainNodeId === `chain:${id}`) {
      store.settings.mainNodeId = store.nodes[0]?.id ?? null;
    }
    return {
      chains: store.chains.map((c) => ({ ...c, hops: [...c.hops] })),
      compiled: buildCompiled(),
    };
  },

  testProxyChainDelay(chainId: string): LatencyResult {
    ensureInit();
    const chain = store.chains.find((c) => c.id === chainId);
    if (!chain) {
      return { nodeId: `chain:${chainId}`, kind: "real", delayMs: -1, error: "Chain not found" };
    }
    const hopDelays = chain.hops.map(
      (hid) => store.nodes.find((n) => n.id === hid)?.realDelayMs ?? null,
    );
    const hasFailedHop = hopDelays.some((d) => d != null && d < 0);
    const ms = hasFailedHop
      ? -1
      : hopDelays.reduce<number>((sum, d) => sum + (d && d > 0 ? d : 90), 0);
    store.chains = store.chains.map((c) =>
      c.id === chainId ? { ...c, realDelayMs: ms } : c,
    );
    return {
      nodeId: `chain:${chainId}`,
      kind: "real",
      delayMs: ms,
      error: ms < 0 ? "Hop unreachable" : null,
    };
  },

  runBatchRealDelay(nodeIds: string[]): LatencyResult[] {
    ensureInit();
    const ids = nodeIds.length > 0 ? nodeIds : store.nodes.map((n) => n.id);
    return ids.map((id, idx) => {
      const ms = id === "n-uk-01" ? -1 : 54 + idx * 37;
      store.nodes = store.nodes.map((n) =>
        n.id === id ? { ...n, realDelayMs: ms } : n,
      );
      return {
        nodeId: id,
        kind: "real",
        delayMs: ms,
        error: ms < 0 ? "Probe timed out" : null,
      };
    });
  },

  startCore(): [CoreInfo, PreflightReport] {
    ensureInit();
    store.coreInfo.installed = true;
    store.coreInfo.running = true;
    return [
      { ...store.coreInfo },
      { ok: true, exitCode: 0, stdout: "preflight ok", stderr: "", deprecatedWarnings: [] },
    ];
  },

  stopCore(): CoreInfo {
    ensureInit();
    store.coreInfo.running = false;
    return { ...store.coreInfo };
  },

  downloadOfficialCore(): CoreInfo {
    ensureInit();
    store.coreInfo.installed = true;
    store.coreInfo.version = "1.14.4";
    return { ...store.coreInfo };
  },

  checkCoreUpdate(): CoreUpdateCheckReport {
    ensureInit();
    return {
      installedVersion: store.coreInfo.version,
      latestVersion: "1.14.4",
      latestTag: "v1.14.4",
      updateAvailable: false,
      assetName: "sing-box-1.14.4-windows-amd64.zip",
      downloadUrl: "https://github.com/SagerNet/sing-box/releases",
      checkedVia: "direct",
    };
  },

  checkAppUpdate(): AppUpdateCheckReport {
    ensureInit();
    return {
      currentVersion: "0.1.0",
      latestVersion: store.scenario === "update-ready" ? "0.2.0" : "0.1.0",
      latestTag: store.scenario === "update-ready" ? "v0.2.0" : "v0.1.0",
      updateAvailable: store.scenario === "update-ready",
      noReleaseYet: false,
      releaseName: "Bypax v0.2.0",
      releaseUrl: "https://github.com/Nexusyyan/bypax/releases",
      publishedAt: "2026-11-26T12:00:00Z",
      releaseNotes: "- Multi-binary self-updater\n- Windows Zero-TUN App Proxy\n- macOS launchd + utun path routing",
      installMode: "portable",
      inAppUpdateSupported: true,
      checkedVia: "local_proxy",
      checkedAtMs: Date.now(),
    };
  },

  runPreflight(simulateBad: boolean): PreflightReport {
    return simulateBad
      ? {
          ok: false,
          exitCode: 1,
          stdout: "",
          stderr: "FATAL[0000] decode config: invalid outbound tag",
          deprecatedWarnings: [],
        }
      : { ok: true, exitCode: 0, stdout: "ok", stderr: "", deprecatedWarnings: [] };
  },

  applyStrategy(strategyId: string): ApplyStrategyResult {
    ensureInit();
    void strategyId;
    return {
      rules: store.rules.map((r) => ({ ...r })),
      ruleSets: store.ruleSets.map((rs) => ({ ...rs })),
      compiled: buildCompiled(),
    };
  },

  syncRuleSets(): SyncRuleSetsResult {
    ensureInit();
    return { statuses: store.ruleSets.map((r) => ({ ...r })), compiled: buildCompiled() };
  },

  testRouteTarget(input: string): RouteTestResult {
    ensureInit();
    const host = input
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split(":")[0];
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    const isPrivateIp =
      host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("100.64.");
    if (isPrivateIp) {
      return {
        input,
        normalizedHost: host,
        isIp,
        isPrivateIp,
        routeMode: store.settings.routeMode,
        matchedRuleId: "classic-private",
        matchedRuleTitle: "Private & LAN",
        matchedBy: "ip_is_private",
        target: "direct",
        resolvedExitKind: "direct",
        resolvedExitLabel: "Direct",
        resolvedNodeId: null,
        resolvedNodeRegion: null,
        dnsServer: "dns-system",
        dnsReason: "Private LAN direct bypass",
      };
    }

    const matchedRule =
      store.settings.routeMode === "rule"
        ? store.rules.find((r) => {
            if (!r.enabled) return false;
            return r.patterns.some((p) => {
              const needle = p.trim().toLowerCase().replace(/^\./, "");
              return needle.length > 0 && (host === needle || host.endsWith(`.${needle}`));
            });
          }) ?? null
        : null;

    const target =
      store.settings.routeMode === "direct"
        ? "direct"
        : store.settings.routeMode === "global"
          ? "main"
          : matchedRule?.target ?? "main";

    let resolvedExitKind = "node";
    let resolvedExitLabel = "JP Tokyo-02 Direct-IPLC";
    let resolvedNodeId: string | null = store.settings.mainNodeId ?? "n-jp-02";
    let resolvedNodeRegion: string | null = "JP";

    if (target === "direct") {
      resolvedExitKind = "direct";
      resolvedExitLabel = "Direct";
      resolvedNodeId = null;
      resolvedNodeRegion = null;
    } else if (target === "reject") {
      resolvedExitKind = "reject";
      resolvedExitLabel = "Reject";
      resolvedNodeId = null;
      resolvedNodeRegion = null;
    } else if (target.startsWith("chain:")) {
      const cid = target.slice("chain:".length);
      const chain = store.chains.find((c) => c.id === cid);
      resolvedExitKind = "chain";
      resolvedExitLabel = chain ? chain.name : cid;
      resolvedNodeId = target;
      resolvedNodeRegion = null;
    } else if (target.startsWith("auto:")) {
      const region = target.slice("auto:".length).toUpperCase();
      const cand =
        store.nodes.find((n) => n.region.toUpperCase() === region) ?? store.nodes[0] ?? null;
      resolvedExitKind = "auto";
      resolvedExitLabel = cand ? cand.remark : target;
      resolvedNodeId = cand?.id ?? null;
      resolvedNodeRegion = cand?.region ?? region;
    } else {
      const lookupId = target === "main" ? store.settings.mainNodeId ?? "" : target;
      if (lookupId.startsWith("chain:")) {
        const cid = lookupId.slice("chain:".length);
        const chain = store.chains.find((c) => c.id === cid);
        resolvedExitKind = "chain";
        resolvedExitLabel = chain ? chain.name : cid;
        resolvedNodeId = lookupId;
        resolvedNodeRegion = null;
      } else {
        const node = store.nodes.find((n) => n.id === lookupId) ?? store.nodes[0] ?? null;
        resolvedExitKind = "node";
        resolvedExitLabel = node ? node.remark : "None";
        resolvedNodeId = node?.id ?? null;
        resolvedNodeRegion = node?.region ?? null;
      }
    }

    return {
      input,
      normalizedHost: host,
      isIp,
      isPrivateIp,
      routeMode: store.settings.routeMode,
      matchedRuleId: matchedRule?.id ?? null,
      matchedRuleTitle: matchedRule?.title ?? null,
      matchedBy: matchedRule
        ? matchedRule.ruleSet
          ? `rule_set:${matchedRule.ruleSet}`
          : "domain_suffix"
        : "final",
      target,
      resolvedExitKind,
      resolvedExitLabel,
      resolvedNodeId,
      resolvedNodeRegion,
      dnsServer: target === "direct" ? "dns-local" : "dns-remote",
      dnsReason: target === "direct" ? "Local China DNS" : "Remote encrypted DNS",
    };
  },

  updateSettings(next: AppSettings): CompileOutput {
    ensureInit();
    store.settings = { ...next };
    return buildCompiled();
  },

  restoreNetguardNow(): CoreInfo {
    ensureInit();
    store.captureMode = "off";
    store.settings.systemProxyEnabled = false;
    store.settings.appProxyEnabled = false;
    store.settings.tunEnabled = false;
    store.serviceStatus.appProxyRunning = false;
    store.serviceStatus.tunRunning = false;
    store.appProxyStatus.running = false;
    store.coreInfo.netguardArmed = false;
    return { ...store.coreInfo };
  },
};
