import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open } from "@tauri-apps/plugin-dialog";
import type {
  AppPresetStatus,
  AppProxyRule,
  AppRulesMutationResult,
  AppRuleTestQuery,
  AppRuleTestTrace,
  AppSettings,
  AppUpdateCheckReport,
  AppUpdateState,
  ApplyStrategyResult,
  BootstrapPayload,
  CaptureMode,
  CliIntegrationInfo,
  CompileOutput,
  ConnectionHistoryPage,
  CoreDownloadProgressEvent,
  CoreInfo,
  CoreUpdateCheckReport,
  DriverProbeDto,
  ExternalChildAlert,
  ImportSummary,
  InboundPort,
  InstalledAppItem,
  LatencyProgressEvent,
  LatencyResult,
  LiveMonitorPayload,
  NodeIR,
  PlatformTrafficPayload,
  PreflightReport,
  PrivilegedServiceStatus,
  ProcessInfoDto,
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
  UpdateApplyResult,
} from "../types";
import { mockBackend } from "./mockState";

function isTauriEnv(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export const api = {
  isDesktop: isTauriEnv,

  async getBootstrapState(): Promise<BootstrapPayload> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState();
    return invoke<BootstrapPayload>("get_bootstrap_state");
  },

  async importNodes(payload: string, groupName?: string): Promise<ImportSummary> {
    if (!isTauriEnv()) return mockBackend.importNodes(payload, groupName);
    return invoke<ImportSummary>("import_nodes", { payload, groupName });
  },

  async importSubscription(name: string, url: string): Promise<SubscriptionGroup> {
    if (!isTauriEnv()) {
      return {
        id: `sub-${Date.now()}`,
        name: name || "Subscription",
        url,
        autoUpdateHours: 24,
        lastUpdated: new Date().toISOString(),
        nodeCount: 3,
      };
    }
    return invoke<SubscriptionGroup>("import_subscription", { name, url });
  },

  async refreshSubscription(id: string): Promise<SubscriptionGroup> {
    if (!isTauriEnv()) {
      return {
        id,
        name: "Studio Sub",
        url: "https://sub.example.com/bypax",
        autoUpdateHours: 24,
        lastUpdated: new Date().toISOString(),
        nodeCount: 3,
      };
    }
    return invoke<SubscriptionGroup>("refresh_subscription", { id });
  },

  async deleteSubscription(id: string): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("delete_subscription", { id });
  },

  async saveNode(node: NodeIR): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("save_node", { node });
  },

  async deleteNode(id: string): Promise<boolean> {
    if (!isTauriEnv()) return mockBackend.deleteNode(id);
    return invoke<boolean>("delete_node", { id });
  },

  async selectMainNode(id: string): Promise<SelectNodeResult> {
    if (!isTauriEnv()) return mockBackend.selectMainNode(id);
    return invoke<SelectNodeResult>("select_main_node", { id });
  },

  async setRouteMode(mode: RouteMode): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.setRouteMode(mode);
    return invoke<CompileOutput>("set_route_mode", { mode });
  },

  async toggleSystemProxy(enabled: boolean): Promise<CoreInfo> {
    if (!isTauriEnv()) return mockBackend.toggleSystemProxy(enabled);
    return invoke<CoreInfo>("toggle_system_proxy", { enabled });
  },

  async toggleTun(enabled: boolean): Promise<CompileOutput> {
    if (!isTauriEnv()) {
      const res = mockBackend.setCaptureMode(enabled ? "tun" : "off");
      return res.compiled;
    }
    return invoke<CompileOutput>("toggle_tun", { enabled });
  },

  async setCaptureMode(mode: CaptureMode): Promise<SetCaptureModeResult> {
    if (!isTauriEnv()) {
      await new Promise((r) => setTimeout(r, 120));
      return mockBackend.setCaptureMode(mode);
    }
    return invoke<SetCaptureModeResult>("set_capture_mode", { mode });
  },

  // --- App Proxy & Privileged Service Commands (#19) ---

  async listAppProxyRules(): Promise<AppProxyRule[]> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().appRules ?? [];
    return invoke<AppProxyRule[]>("list_app_proxy_rules");
  },

  async saveAppProxyRule(rule: AppProxyRule): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.saveAppRule(rule);
    return invoke<AppRulesMutationResult>("save_app_proxy_rule", { rule });
  },

  async deleteAppProxyRule(id: string): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.deleteAppRule(id);
    return invoke<AppRulesMutationResult>("delete_app_proxy_rule", { id });
  },

  async reorderAppProxyRules(ids: string[]): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.reorderAppRules(ids);
    return invoke<AppRulesMutationResult>("reorder_app_proxy_rules", { ids });
  },

  async listAppPresets(): Promise<AppPresetStatus[]> {
    if (!isTauriEnv()) return mockBackend.listAppPresets();
    return invoke<AppPresetStatus[]>("list_app_presets");
  },

  async toggleAppPreset(
    presetId: string,
    enabled: boolean,
    target?: string,
  ): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.toggleAppPreset(presetId, enabled, target);
    return invoke<AppRulesMutationResult>("toggle_app_preset", {
      presetId,
      enabled,
      target: target ?? null,
    });
  },

  async testAppProxyRule(query: AppRuleTestQuery): Promise<AppRuleTestTrace> {
    if (!isTauriEnv()) return mockBackend.testAppRule(query);
    return invoke<AppRuleTestTrace>("test_app_proxy_rule", { query });
  },

  async listRunningProcesses(filter?: string): Promise<ProcessInfoDto[]> {
    if (!isTauriEnv()) return mockBackend.listRunningProcesses(filter);
    return invoke<ProcessInfoDto[]>("list_running_processes", {
      filter: filter || null,
    });
  },

  async listInstalledApps(): Promise<InstalledAppItem[]> {
    if (!isTauriEnv()) return mockBackend.listInstalledApps();
    return invoke<InstalledAppItem[]>("list_installed_apps");
  },

  async detectExternalChildren(): Promise<ExternalChildAlert[]> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().externalChildren ?? [];
    return invoke<ExternalChildAlert[]>("detect_external_children");
  },

  async includeExternalChild(
    ruleId: string,
    childPath: string,
  ): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.includeExternalChild(ruleId, childPath);
    return invoke<AppRulesMutationResult>("include_external_child", {
      ruleId,
      childPath,
    });
  },

  async ignoreExternalChild(
    ruleId: string,
    childPath: string,
  ): Promise<AppRulesMutationResult> {
    if (!isTauriEnv()) return mockBackend.ignoreExternalChild(ruleId, childPath);
    return invoke<AppRulesMutationResult>("ignore_external_child", {
      ruleId,
      childPath,
    });
  },

  async getServiceStatus(): Promise<PrivilegedServiceStatus> {
    if (!isTauriEnv()) {
      return mockBackend.getBootstrapState().serviceStatus as PrivilegedServiceStatus;
    }
    return invoke<PrivilegedServiceStatus>("get_service_status");
  },

  async probeWindivertDriver(customDir?: string): Promise<DriverProbeDto> {
    if (!isTauriEnv()) return mockBackend.probeDriver();
    return invoke<DriverProbeDto>("probe_windivert_driver", {
      customDir: customDir ?? null,
    });
  },

  async setWindivertDir(dir: string): Promise<DriverProbeDto> {
    if (!isTauriEnv()) return mockBackend.setWindivertDir(dir);
    return invoke<DriverProbeDto>("set_windivert_dir", { dir });
  },

  async serviceAction(action: ServiceActionKind): Promise<PrivilegedServiceStatus> {
    if (!isTauriEnv()) {
      await new Promise((r) => setTimeout(r, 140));
      return mockBackend.serviceAction(action);
    }
    return invoke<PrivilegedServiceStatus>("service_action", { action });
  },

  async openWindowsSecurity(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("open_windows_security");
  },

  async getCliIntegrationInfo(): Promise<CliIntegrationInfo> {
    if (!isTauriEnv()) {
      return mockBackend.getBootstrapState().cliInfo as CliIntegrationInfo;
    }
    return invoke<CliIntegrationInfo>("get_cli_integration_info");
  },

  // --- Routing, DNS, Core & Updates ---

  async saveRule(rule: SimpleRoutingRule): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().compiled;
    return invoke<CompileOutput>("save_rule", { rule });
  },

  async deleteRule(id: string): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().compiled;
    return invoke<CompileOutput>("delete_rule", { id });
  },

  async listRulePresets(): Promise<RulePresetSpec[]> {
    if (!isTauriEnv()) return mockBackend.listRulePresets();
    return invoke<RulePresetSpec[]>("list_rule_presets");
  },

  async listRuleSets(): Promise<RuleSetStatus[]> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().ruleSets;
    return invoke<RuleSetStatus[]>("list_rule_sets");
  },

  async applyRoutingStrategy(strategyId: string): Promise<ApplyStrategyResult> {
    if (!isTauriEnv()) return mockBackend.applyStrategy(strategyId);
    return invoke<ApplyStrategyResult>("apply_routing_strategy", { strategyId });
  },

  async syncRuleSets(tags: string[]): Promise<SyncRuleSetsResult> {
    if (!isTauriEnv()) return mockBackend.syncRuleSets();
    return invoke<SyncRuleSetsResult>("sync_rule_sets", { tags });
  },

  async testRouteTarget(input: string, processName?: string): Promise<RouteTestResult> {
    if (!isTauriEnv()) return mockBackend.testRouteTarget(input);
    return invoke<RouteTestResult>("test_route_target", {
      input,
      processName: processName || null,
    });
  },

  async saveInboundPort(port: InboundPort): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().compiled;
    return invoke<CompileOutput>("save_inbound_port", { port });
  },

  async deleteInboundPort(id: string): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().compiled;
    return invoke<CompileOutput>("delete_inbound_port", { id });
  },

  async updateSettings(settings: AppSettings): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.updateSettings(settings);
    return invoke<CompileOutput>("update_settings", { settings });
  },

  async compilePreview(): Promise<CompileOutput> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().compiled;
    return invoke<CompileOutput>("compile_preview");
  },

  async runPreflightCheck(simulateBad: boolean): Promise<PreflightReport> {
    if (!isTauriEnv()) return mockBackend.runPreflight(simulateBad);
    return invoke<PreflightReport>("run_preflight_check", { simulateBad });
  },

  async startCore(): Promise<[CoreInfo, PreflightReport]> {
    if (!isTauriEnv()) return mockBackend.startCore();
    return invoke<[CoreInfo, PreflightReport]>("start_core");
  },

  async stopCore(): Promise<CoreInfo> {
    if (!isTauriEnv()) return mockBackend.stopCore();
    return invoke<CoreInfo>("stop_core");
  },

  async checkCoreUpdate(): Promise<CoreUpdateCheckReport> {
    if (!isTauriEnv()) return mockBackend.checkCoreUpdate();
    return invoke<CoreUpdateCheckReport>("check_core_update");
  },

  async downloadOfficialCore(): Promise<CoreInfo> {
    if (!isTauriEnv()) return mockBackend.downloadOfficialCore();
    return invoke<CoreInfo>("download_official_core");
  },

  async importCoreBinary(path: string): Promise<CoreInfo> {
    if (!isTauriEnv()) return mockBackend.downloadOfficialCore();
    return invoke<CoreInfo>("import_core_binary", { path });
  },

  async checkAppUpdate(): Promise<AppUpdateCheckReport> {
    if (!isTauriEnv()) return mockBackend.checkAppUpdate();
    return invoke<AppUpdateCheckReport>("check_app_update");
  },

  async downloadAppUpdate(): Promise<AppUpdateState> {
    if (!isTauriEnv()) {
      return {
        stage: "ready_to_restart",
        targetVersion: "0.2.0",
        targetTag: "v0.2.0",
        downloadedBytes: 28_450_000,
        totalBytes: 28_450_000,
        percent: 100,
        via: "local_proxy",
      };
    }
    return invoke<AppUpdateState>("download_app_update");
  },

  async cancelAppUpdate(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("cancel_app_update");
  },

  async restartToUpdate(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("restart_to_update");
  },

  async getAppUpdateState(): Promise<AppUpdateState> {
    if (!isTauriEnv()) return mockBackend.getBootstrapState().appUpdateState;
    return invoke<AppUpdateState>("get_app_update_state");
  },

  async consumeUpdateResult(): Promise<UpdateApplyResult | null> {
    if (!isTauriEnv()) return null;
    return invoke<UpdateApplyResult | null>("consume_update_result");
  },

  async openExternalUrl(url: string): Promise<void> {
    if (!isTauriEnv()) {
      window.open(url, "_blank", "noopener,noreferrer");
      return;
    }
    return invoke("open_external_url", { url });
  },

  async pickBinaryFile(): Promise<string | null> {
    if (!isTauriEnv()) return null;
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Executable", extensions: ["exe", "bin", "*"] }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async pickDirectory(): Promise<string | null> {
    if (!isTauriEnv()) return "C:\\Tools\\Bypax\\runtime\\windivert";
    const selected = await open({
      multiple: false,
      directory: true,
    });
    return typeof selected === "string" ? selected : null;
  },

  async runBatchTcping(nodeIds: string[]): Promise<LatencyResult[]> {
    if (!isTauriEnv()) {
      await new Promise((r) => setTimeout(r, 180));
      return mockBackend.runBatchLatency("tcping", nodeIds);
    }
    return invoke<LatencyResult[]>("run_batch_tcping", { nodeIds });
  },

  async runBatchRealDelay(nodeIds: string[]): Promise<LatencyResult[]> {
    if (!isTauriEnv()) {
      await new Promise((r) => setTimeout(r, 240));
      return mockBackend.runBatchLatency("real", nodeIds);
    }
    return invoke<LatencyResult[]>("run_batch_real_delay", { nodeIds });
  },

  async onLatencyProgress(
    cb: (ev: LatencyProgressEvent) => void,
  ): Promise<() => void> {
    if (!isTauriEnv()) return () => {};
    return listen<LatencyProgressEvent>("bypax-latency-progress", (e) => cb(e.payload));
  },

  async onStateSync(cb: () => void): Promise<() => void> {
    if (!isTauriEnv()) return () => {};
    return listen("bypax-state-sync", () => cb());
  },

  async onAppUpdateProgress(
    cb: (state: AppUpdateState) => void,
  ): Promise<() => void> {
    if (!isTauriEnv()) return () => {};
    return listen<AppUpdateState>("bypax-update-progress", (e) => cb(e.payload));
  },

  async onCoreDownloadProgress(
    cb: (ev: CoreDownloadProgressEvent) => void,
  ): Promise<() => void> {
    if (!isTauriEnv()) return () => {};
    return listen<CoreDownloadProgressEvent>("bypax-core-download-progress", (e) =>
      cb(e.payload),
    );
  },

  async getLiveMonitor(): Promise<LiveMonitorPayload> {
    if (!isTauriEnv()) return mockBackend.getLiveMonitor();
    return invoke<LiveMonitorPayload>("get_live_monitor");
  },

  async getConnectionHistory(
    query: string,
    page: number,
    pageSize: number,
  ): Promise<ConnectionHistoryPage> {
    if (!isTauriEnv()) return mockBackend.getConnectionHistory(query, page, pageSize);
    return invoke<ConnectionHistoryPage>("get_connection_history", {
      query,
      page,
      pageSize,
    });
  },

  async getPlatformTraffic(range: string): Promise<PlatformTrafficPayload> {
    if (!isTauriEnv()) return mockBackend.getPlatformTraffic();
    return invoke<PlatformTrafficPayload>("get_platform_traffic", { range });
  },

  async clearConnectionHistory(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("clear_connection_history");
  },

  async closeConnection(id: string): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("close_connection", { id });
  },

  async closeAllConnections(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("close_all_connections");
  },

  async openLogsDir(): Promise<string> {
    if (!isTauriEnv()) return "C:\\Tools\\Bypax\\bypax-data\\logs";
    return invoke<string>("open_logs_dir");
  },

  async clearLogs(): Promise<void> {
    if (!isTauriEnv()) return;
    return invoke("clear_logs");
  },

  async restoreNetguardNow(): Promise<CoreInfo> {
    if (!isTauriEnv()) return mockBackend.restoreNetguardNow();
    return invoke<CoreInfo>("restore_netguard_now");
  },

  async hideToTray(): Promise<void> {
    if (isTauriEnv()) await invoke("hide_to_tray");
  },

  async showMainWindow(): Promise<void> {
    if (isTauriEnv()) await invoke("show_main_window");
  },

  async hideTrayPopup(): Promise<void> {
    if (isTauriEnv()) await invoke("hide_tray_popup");
  },

  async quitApp(): Promise<void> {
    if (isTauriEnv()) await invoke("quit_app");
  },

  windowControls: {
    async minimize(): Promise<void> {
      if (isTauriEnv()) await getCurrentWindow().minimize();
    },
    async toggleMaximize(): Promise<void> {
      if (isTauriEnv()) await getCurrentWindow().toggleMaximize();
    },
    async isMaximized(): Promise<boolean> {
      if (!isTauriEnv()) return false;
      return getCurrentWindow().isMaximized();
    },
    async close(): Promise<void> {
      if (isTauriEnv()) await getCurrentWindow().close();
    },
    async onResized(cb: () => void): Promise<() => void> {
      if (!isTauriEnv()) return () => {};
      return getCurrentWindow().onResized(() => cb());
    },
  },
};
