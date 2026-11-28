export type Protocol =
  | "vless"
  | "vmess"
  | "trojan"
  | "shadowsocks"
  | "hysteria2"
  | "tuic"
  | "anytls"
  | "wireguard"
  | "http"
  | "socks";

export type RouteMode = "rule" | "global" | "direct";
export type CaptureMode = "off" | "apps" | "tun";
export type ServiceMode = "off" | "auto" | "service" | "elevated_worker";
export type DomainOverrideAction = "proxy" | "direct" | "reject";
export type PlatformKind = "windows" | "macos" | "linux";
export type NavTab =
  | "nodes"
  | "chains"
  | "apps"
  | "routing"
  | "dns"
  | "monitor"
  | "core"
  | "settings";
export type Locale = "zh-CN" | "en";
export type ThemeMode = "system" | "light" | "dark";

export interface TlsConfig {
  enabled: boolean;
  serverName?: string;
  insecure: boolean;
  alpn: string[];
  fingerprint?: string;
  realityPublicKey?: string;
  realityShortId?: string;
}

export interface TransportConfig {
  transportType: string;
  path?: string;
  host?: string;
  serviceName?: string;
  headers: Record<string, string>;
}

export interface NodeIR {
  id: string;
  protocol: Protocol;
  remark: string;
  server: string;
  port: number;
  group: string;
  region: string;
  uuid?: string;
  username?: string;
  password?: string;
  socksVersion?: string;
  method?: string;
  flow?: string;
  alterId?: number;
  security?: string;
  congestionControl?: string;
  upMbps?: number;
  downMbps?: number;
  obfsType?: string;
  obfsPassword?: string;
  serverPorts?: string[];
  hopInterval?: string;
  wgPrivateKey?: string;
  wgPeerPublicKey?: string;
  wgPresharedKey?: string;
  wgLocalAddress: string[];
  wgMtu?: number;
  wgReserved?: number[];
  tls?: TlsConfig;
  transport?: TransportConfig;
  detour?: string;
  realDelayMs?: number | null;
  rawUri?: string;
  createdAt: string;
}

export interface ProxyChain {
  id: string;
  name: string;
  hops: string[];
  enabled: boolean;
  realDelayMs?: number | null;
  description?: string | null;
  createdAt: string;
}

export interface MissingChainWarning {
  chainId: string;
  chainName: string;
  missingHopIds: string[];
}

export interface ChainMutationResult {
  chains: ProxyChain[];
  compiled: CompileOutput;
}

export interface SubscriptionGroup {
  id: string;
  name: string;
  url: string;
  autoUpdateHours: number;
  lastUpdated?: string | null;
  nodeCount: number;
}

export interface InboundPort {
  id: string;
  port: number;
  note: string;
  noteEn: string;
  target: string;
  enabled: boolean;
  allowLan: boolean;
}

export interface SimpleRoutingRule {
  id: string;
  title: string;
  titleEn: string;
  description: string;
  patterns: string[];
  domainKeywords?: string[];
  ipCidrs?: string[];
  processNames: string[];
  ruleSet?: string | null;
  target: string;
  enabled: boolean;
  priority: number;
}

export interface RulePresetSpec {
  id: string;
  category: string;
  title: string;
  titleEn: string;
  description: string;
  patterns: string[];
  processNames: string[];
  ruleSet?: string | null;
  defaultTarget: string;
  defaultPriority: number;
}

export interface RuleSetStatus {
  tag: string;
  cachedLocally: boolean;
  bytes: number;
  fallbackMode: boolean;
}

export interface SyncRuleSetsResult {
  statuses: RuleSetStatus[];
  compiled: CompileOutput;
}

export interface ApplyStrategyResult {
  rules: SimpleRoutingRule[];
  ruleSets: RuleSetStatus[];
  compiled: CompileOutput;
}

export interface RouteTestResult {
  input: string;
  normalizedHost: string;
  isIp: boolean;
  isPrivateIp: boolean;
  routeMode: RouteMode;
  matchedRuleId?: string | null;
  matchedRuleTitle?: string | null;
  matchedBy: string;
  target: string;
  resolvedExitKind: string;
  resolvedExitLabel: string;
  resolvedNodeId?: string | null;
  resolvedNodeRegion?: string | null;
  dnsServer: string;
  dnsReason: string;
}

export interface DnsRuleItem {
  id: string;
  title: string;
  domains: string[];
  ruleSet?: string | null;
  server: string;
  enabled: boolean;
}

export interface DnsHostEntry {
  domain: string;
  ips: string[];
}

export interface DomainOverride {
  pattern: string;
  action: DomainOverrideAction;
}

export interface AppProxyRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  presetId?: string | null;
  processNames: string[];
  pathPrefixes: string[];
  pathContains: string[];
  macBundlePaths: string[];
  ignoredExternalChildren: string[];
  includeChildren: boolean;
  domains: DomainOverride[];
  dstCidrs: string[];
  dstPorts: number[];
  protocols: string[];
  target: string;
}

export interface MissingAppTargetWarning {
  ruleId: string;
  ruleName: string;
  originalTarget: string;
  fallbackTarget: string;
}

export interface AppPresetStatus {
  id: string;
  name: string;
  category: string;
  description: string;
  processNames: string[];
  pathContains: string[];
  macBundlePaths: string[];
  includeChildren: boolean;
  installed: boolean;
  runningCount: number;
  detectedPaths: string[];
  enabled: boolean;
  ruleId?: string | null;
  target: string;
}

export interface AppRuleTestQuery {
  processName?: string;
  exePath?: string;
  host?: string;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
}

export interface AppRuleTestTrace {
  step1ProcessMatch: string;
  step2DomainOverride: string;
  step3FinalExit: string;
  matchedRuleId?: string | null;
  matchedRuleName?: string | null;
  matchedViaAncestor?: string | null;
  matchedDomainPattern?: string | null;
  domainOverrideAction?: string | null;
  finalAction: string;
  finalTarget: string;
  resolvedLabel: string;
  bypassedToRouting: boolean;
}

export interface ProcessInfoDto {
  pid: number;
  parentPid: number;
  name: string;
  exePath?: string | null;
  ancestorChain: string[];
  matchedRuleId?: string | null;
  matchedRuleName?: string | null;
}

export interface InstalledAppItem {
  name: string;
  path: string;
  processName: string;
  bundlePath?: string | null;
}

export interface ExternalChildInfo {
  pid: number;
  name: string;
  exePath: string;
}

export interface ExternalChildAlert {
  ruleId: string;
  ruleName: string;
  appName: string;
  children: ExternalChildInfo[];
}

export interface PrivilegedServiceStatus {
  platform: PlatformKind | string;
  mode: ServiceMode | string;
  installed: boolean;
  running: boolean;
  connected: boolean;
  elevated: boolean;
  state: string;
  servicePid?: number | null;
  appProxyRunning: boolean;
  tunRunning: boolean;
  error?: string | null;
  errorKind?: string | null;
  legacyServices?: string[];
  conflictDetail?: string | null;
}

export interface DriverProbeDto {
  platform: string;
  elevated: boolean;
  dllLoaded: boolean;
  dllPath?: string | null;
  driverOpened: boolean;
  driverVersion?: string | null;
  error?: string | null;
  errorKind?: string | null;
}

export interface AppProxyLocalConnectionDto {
  id: string;
  pid?: number | null;
  processName: string;
  ancestorApp?: string | null;
  ancestorChain: string[];
  destination: string;
  ruleName: string;
  localAction: "local_direct" | "local_reject" | string;
  uploadBytes: number;
  downloadBytes: number;
  startedAt: string;
  active: boolean;
}

export interface AppProxyLocalStatsDto {
  localDirectBytesTx: number;
  localDirectBytesRx: number;
  localDirectConnections: number;
  localRejectConnections: number;
  proxiedConnections: number;
  activeProxiedConnections: number;
  localConnections: AppProxyLocalConnectionDto[];
}

export interface AppProxyStatusDto {
  running: boolean;
  mode: "windivert_zero_tun" | "macos_utun_path" | "inactive" | string;
  activeRules: number;
  exemptPids: number[];
  lastError?: string | null;
  errorKind?: string | null;
  stats: AppProxyLocalStatsDto;
}

export interface CliIntegrationInfo {
  ready: boolean;
  cliPath?: string | null;
  mcpConfigJson: string;
  cliExamples: string[];
}

export interface SetCaptureModeResult {
  captureMode: CaptureMode;
  coreInfo: CoreInfo;
  serviceStatus: PrivilegedServiceStatus;
  appProxyStatus: AppProxyStatusDto;
  compiled: CompileOutput;
}

export interface AppRulesMutationResult {
  rules: AppProxyRule[];
  compiled: CompileOutput;
  reloaded: boolean;
}

export type ServiceActionKind =
  | "install"
  | "uninstall"
  | "start"
  | "stop"
  | "restart"
  | "start_worker"
  | "stop_worker"
  | "cleanup_legacy";

export interface AppSettings {
  locale: string;
  theme: string;
  routeMode: RouteMode;
  mainNodeId?: string | null;
  mixedPort: number;
  controlPort: number;
  allowLan: boolean;
  systemProxyEnabled: boolean;
  tunEnabled: boolean;
  autoStartCore: boolean;
  launchAtLogin: boolean;
  minimizeToTray: boolean;
  autoCheckUpdates: boolean;
  dnsLocalServer: string;
  dnsRemoteServer: string;
  dnsBootstrapServer: string;
  dnsRemoteDetour: string;
  dnsStrategy: string;
  dnsFakeIp: boolean;
  dnsFakeIpInet4: string;
  dnsFakeIpInet6: string;
  dnsDisableCache: boolean;
  dnsDisableExpire: boolean;
  dnsReverseMapping: boolean;
  dnsCacheCapacity: number;
  dnsClientSubnet?: string | null;
  dnsCustomRules: DnsRuleItem[];
  dnsHosts: DnsHostEntry[];
  logLevel: string;
  sniffEnabled: boolean;
  sniffTimeout: string;
  findProcess: boolean;
  autoDetectInterface: boolean;
  tunInterfaceName: string;
  tunStack: string;
  tunMtu: number;
  tunInet4Address: string;
  tunAutoRoute: boolean;
  tunStrictRoute: boolean;
  urltestInterval: string;
  urltestTolerance: number;
  cacheFileEnabled: boolean;
  cacheStoreFakeip: boolean;
  latencyStripHandshake: boolean;
  latencyTestUrl: string;
  customJsonOverride?: string | null;
  appProxyEnabled: boolean;
  appProxyPort: number;
  appProxyBypassLan: boolean;
  appProxyBlockQuicWhenNeeded: boolean;
  appProxyWindivertDir?: string | null;
  serviceMode: ServiceMode | string;
  tunRouteExcludeCidrs: string[];
}

export interface CoreInfo {
  installed: boolean;
  running: boolean;
  version?: string | null;
  binaryPath: string;
  sha256?: string | null;
  portableMode: boolean;
  dataDir: string;
  netguardArmed: boolean;
  netguardRecoveredFromCrash: boolean;
}

export interface CompileOutput {
  config: Record<string, unknown>;
  totalNodes: number;
  reachableNodes: number;
  reachableNodeIds: string[];
  synthesizedGroups: string[];
  controlSecret: string;
  missingAppRuleTargets?: MissingAppTargetWarning[];
  missingChainWarnings?: MissingChainWarning[];
}

export interface PreflightReport {
  ok: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  deprecatedWarnings: string[];
}

export interface LatencyResult {
  nodeId: string;
  kind: string;
  delayMs?: number | null;
  error?: string | null;
}

export interface LatencyProgressEvent {
  kind: "real";
  phase: "starting" | "testing" | "done";
  completed: number;
  total: number;
  passed: number;
  failed: number;
  stripHandshake?: boolean;
  latest?: LatencyResult | null;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
}

export type ConnectionSourceKind =
  | "sys_proxy"
  | "app_proxy"
  | "tun"
  | "dedicated_port";

export interface ConnectionItem {
  id: string;
  process: string;
  destination: string;
  inbound: string;
  rule: string;
  chain: string[];
  uploadBytes: number;
  downloadBytes: number;
  start: string;
  sourcePort?: number | null;
  sourceKind?: ConnectionSourceKind | string;
  ancestorApp?: string | null;
  ancestorChain?: string[];
  pid?: number | null;
  appRuleName?: string | null;
  originExpired?: boolean;
  localAction?: "local_direct" | "local_reject" | string | null;
}

export interface ConnectionHistoryRecord {
  id: string;
  process: string;
  destination: string;
  host: string;
  platform: string;
  inbound: string;
  rule: string;
  chain: string[];
  uploadBytes: number;
  downloadBytes: number;
  startedAt: string;
  closedAt: string;
}

export interface ConnectionHistoryPage {
  items: ConnectionHistoryRecord[];
  total: number;
  page: number;
  pageSize: number;
}

export interface PlatformTrafficStat {
  platform: string;
  uploadBytes: number;
  downloadBytes: number;
  totalBytes: number;
  connectionCount: number;
  activeCount: number;
  topDomains: string[];
}

export interface PlatformTrafficPayload {
  items: PlatformTrafficStat[];
  totalUpload: number;
  totalDownload: number;
  totalConnections: number;
}

export interface TrafficSample {
  upBytesPerSec: number;
  downBytesPerSec: number;
  memoryBytes: number;
  activeConnections: number;
}

export type AppUpdateStage =
  | "idle"
  | "checking"
  | "downloading"
  | "verifying"
  | "extracting"
  | "ready_to_restart"
  | "restarting"
  | "failed";

export interface AppUpdateCheckReport {
  currentVersion: string;
  latestVersion: string;
  latestTag: string;
  updateAvailable: boolean;
  noReleaseYet: boolean;
  releaseName: string;
  releaseUrl: string;
  publishedAt?: string | null;
  releaseNotes?: string | null;
  selectedAssetName?: string | null;
  selectedAssetUrl?: string | null;
  selectedAssetSize?: number | null;
  selectedAssetKind?: string | null;
  checksumsUrl?: string | null;
  installMode: string;
  inAppUpdateSupported: boolean;
  checkedVia: string;
  checkedAtMs: number;
}

export interface AppUpdateState {
  stage: AppUpdateStage;
  targetVersion?: string | null;
  targetTag?: string | null;
  assetName?: string | null;
  assetKind?: string | null;
  downloadedBytes: number;
  totalBytes?: number | null;
  percent?: number | null;
  via?: string | null;
  stagedDir?: string | null;
  stagedExePath?: string | null;
  stagedAppBundlePath?: string | null;
  stagedCoreExePath?: string | null;
  sha256?: string | null;
  error?: string | null;
}

export interface UpdateApplyResult {
  success: boolean;
  fromVersion: string;
  toVersion: string;
  toTag: string;
  error?: string | null;
  appliedAt: string;
}

export interface CoreUpdateCheckReport {
  installedVersion?: string | null;
  latestVersion: string;
  latestTag: string;
  updateAvailable: boolean;
  assetName: string;
  downloadUrl: string;
  assetSize?: number | null;
  checkedVia: string;
}

export interface CoreDownloadProgressEvent {
  phase:
    | "checking"
    | "downloading"
    | "verifying"
    | "extracting"
    | "restarting"
    | "done";
  downloadedBytes: number;
  totalBytes?: number | null;
  percent?: number | null;
  targetVersion?: string | null;
  via?: string | null;
}

export interface BootstrapPayload {
  appVersion: string;
  platform?: PlatformKind | string;
  captureMode?: CaptureMode;
  coreInfo: CoreInfo;
  settings: AppSettings;
  nodes: NodeIR[];
  chains: ProxyChain[];
  subscriptions: SubscriptionGroup[];
  rules: SimpleRoutingRule[];
  extraPorts: InboundPort[];
  ruleSets: RuleSetStatus[];
  compiled: CompileOutput;
  logs: LogEntry[];
  appUpdateState: AppUpdateState;
  lastUpdateResult?: UpdateApplyResult | null;
  appRules?: AppProxyRule[];
  appPresets?: AppPresetStatus[];
  serviceStatus?: PrivilegedServiceStatus;
  driverStatus?: DriverProbeDto;
  appProxyStatus?: AppProxyStatusDto;
  externalChildren?: ExternalChildAlert[];
  cliInfo?: CliIntegrationInfo;
}

export interface LiveMonitorPayload {
  coreRunning: boolean;
  connections: ConnectionItem[];
  traffic: TrafficSample;
  logs: LogEntry[];
  appProxyStatus?: AppProxyStatusDto | null;
  localDirectBytes?: number;
  localRejectCount?: number;
}

export interface ImportSummary {
  nodes: NodeIR[];
  skipped: number;
}

export interface SelectNodeResult {
  hotSwitched: boolean;
  mainNodeId: string;
  compiled: CompileOutput;
}

export interface InstanceConflictEvent {
  runningPath: string;
  attemptedCwd: string;
}

export interface ToastMessage {
  id: string;
  text: string;
  tone: "ok" | "warn" | "err" | "neutral";
}
