import { useEffect, useState } from "react";
import {
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  Download,
  ExternalLink,
  Globe,
  HardDrive,
  RefreshCw,
  RotateCw,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { BrandLogo } from "../../components/BrandLogo";
import { SegmentedControl } from "../../components/SegmentedControl";
import type { Dict } from "../../i18n";
import type {
  AppSettings,
  AppUpdateCheckReport,
  AppUpdateState,
  CliIntegrationInfo,
  CoreInfo,
  Locale,
  PlatformKind,
  ThemeMode,
} from "../../types";
import { formatBytes } from "../../utils/nodes";

interface SettingsViewProps {
  dict: Dict;
  platform: PlatformKind | string;
  locale: Locale;
  theme: ThemeMode;
  appVersion: string;
  settings: AppSettings;
  coreInfo: CoreInfo;
  cliInfo: CliIntegrationInfo | null;
  appUpdateReport: AppUpdateCheckReport | null;
  appUpdateState: AppUpdateState;
  checkingAppUpdate: boolean;
  appUpdateError: string | null;
  onChangeLocale: (locale: Locale) => void;
  onChangeTheme: (theme: ThemeMode) => void;
  onUpdateSettings: (next: AppSettings) => void;
  onRestoreNetguard: () => void;
  onCleanupLegacy: () => Promise<void>;
  onGoToDns: () => void;
  onCopyText: (text: string) => void;
  onCheckAppUpdate: () => Promise<void>;
  onDownloadAppUpdate: () => Promise<void>;
  onCancelAppUpdate: () => Promise<void>;
  onRestartToUpdate: () => Promise<void>;
  onOpenExternalUrl: (url: string) => Promise<void>;
}

const RELEASES_FALLBACK_URL = "https://github.com/Nexusyyan/bypax/releases";

const TEST_URL_PRESETS = [
  { label: "gstatic HTTPS", value: "https://www.gstatic.com/generate_204" },
  { label: "gstatic HTTP", value: "http://www.gstatic.com/generate_204" },
  { label: "Cloudflare HTTP", value: "http://cp.cloudflare.com/generate_204" },
];

export function SettingsView({
  dict,
  platform,
  locale,
  theme,
  appVersion,
  settings,
  coreInfo,
  cliInfo,
  appUpdateReport,
  appUpdateState,
  checkingAppUpdate,
  appUpdateError,
  onChangeLocale,
  onChangeTheme,
  onUpdateSettings,
  onRestoreNetguard,
  onCleanupLegacy,
  onGoToDns,
  onCopyText,
  onCheckAppUpdate,
  onDownloadAppUpdate,
  onCancelAppUpdate,
  onRestartToUpdate,
  onOpenExternalUrl,
}: SettingsViewProps) {
  const [savedTick, setSavedTick] = useState(false);
  const [showNotes, setShowNotes] = useState(false);
  const [agentTab, setAgentTab] = useState<"mcp" | "cli">("mcp");
  const [agentCopied, setAgentCopied] = useState(false);

  const [mixedPortDraft, setMixedPortDraft] = useState(String(settings.mixedPort));
  const [controlPortDraft, setControlPortDraft] = useState(String(settings.controlPort));
  const [testUrlDraft, setTestUrlDraft] = useState(settings.latencyTestUrl);
  const [overrideDraft, setOverrideDraft] = useState(settings.customJsonOverride ?? "");

  useEffect(() => setMixedPortDraft(String(settings.mixedPort)), [settings.mixedPort]);
  useEffect(() => setControlPortDraft(String(settings.controlPort)), [settings.controlPort]);
  useEffect(() => setTestUrlDraft(settings.latencyTestUrl), [settings.latencyTestUrl]);
  useEffect(() => setOverrideDraft(settings.customJsonOverride ?? ""), [settings.customJsonOverride]);

  const commit = (patch: Partial<AppSettings>) => {
    onUpdateSettings({ ...settings, ...patch });
    setSavedTick(true);
    window.setTimeout(() => setSavedTick(false), 1600);
  };

  const mixedPortNum = Number.parseInt(mixedPortDraft, 10);
  const mixedPortValid =
    mixedPortDraft.length > 0 &&
    Number.isFinite(mixedPortNum) &&
    mixedPortNum >= 1024 &&
    mixedPortNum <= 65535;

  const controlPortNum = Number.parseInt(controlPortDraft, 10);
  const controlPortValid =
    controlPortDraft.length > 0 &&
    Number.isFinite(controlPortNum) &&
    controlPortNum >= 1024 &&
    controlPortNum <= 65535;

  const commitMixedPort = () => {
    if (mixedPortValid) {
      if (mixedPortNum !== settings.mixedPort) commit({ mixedPort: mixedPortNum });
    } else {
      setMixedPortDraft(String(settings.mixedPort));
    }
  };

  const commitControlPort = () => {
    if (controlPortValid) {
      if (controlPortNum !== settings.controlPort) commit({ controlPort: controlPortNum });
    } else {
      setControlPortDraft(String(settings.controlPort));
    }
  };

  const fallbackCliPath = cliInfo?.cliPath || "bypax-cli";
  const mcpSnippet =
    cliInfo?.mcpConfigJson ||
    JSON.stringify(
      {
        mcpServers: {
          bypax: {
            command: fallbackCliPath,
            args: ["mcp"],
          },
        },
      },
      null,
      2,
    );
  const cliSnippet = (
    cliInfo?.cliExamples ?? [
      "bypax-cli ctl --json status",
      "bypax-cli ctl --json app list-rules",
      "bypax-cli doctor",
    ]
  ).join("\n");

  const activeAgentCode = agentTab === "mcp" ? mcpSnippet : cliSnippet;

  const handleCopyAgentSnippet = () => {
    onCopyText(activeAgentCode);
    setAgentCopied(true);
    window.setTimeout(() => setAgentCopied(false), 1500);
  };

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Unified Single-Row 40px Page Header */}
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <h1 className="text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
          {dict.settings.title}
        </h1>
        <span
          className={`inline-flex items-center gap-1 text-[11.5px] transition-opacity ${
            savedTick ? "opacity-100" : "opacity-65"
          }`}
          style={{ color: "var(--success-text)" }}
        >
          <Check className="h-3.5 w-3.5" strokeWidth={1.6} />
          {dict.settings.autoSaved}
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
        <div className="mx-auto w-full max-w-3xl space-y-5 px-4 py-4 lg:px-6 lg:py-5">

        {/* General */}
        <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
          <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
            {dict.settings.secGeneral}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
            <div>
              <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                {dict.settings.langLabel}
              </div>
              <div className="text-[11.5px] text-[var(--text-secondary)]">
                {dict.settings.langDesc}
              </div>
            </div>
            <SegmentedControl
              value={locale}
              options={[
                { value: "zh-CN" as Locale, label: "ZH" },
                { value: "en" as Locale, label: "EN" },
              ]}
              onChange={onChangeLocale}
              ariaLabel={dict.settings.langLabel}
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
            <div>
              <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                {dict.settings.themeLabel}
              </div>
              <div className="text-[11.5px] text-[var(--text-secondary)]">
                {dict.settings.themeDesc}
              </div>
            </div>
            <SegmentedControl
              value={theme}
              options={[
                { value: "system" as ThemeMode, label: dict.settings.themeSystem },
                { value: "light" as ThemeMode, label: dict.settings.themeLight },
                { value: "dark" as ThemeMode, label: dict.settings.themeDark },
              ]}
              onChange={onChangeTheme}
              ariaLabel={dict.settings.themeLabel}
            />
          </div>

          {(
            [
              ["launchAtLogin", dict.settings.autostartLabel, dict.settings.autostartDesc],
              ["minimizeToTray", dict.settings.trayLabel, dict.settings.trayDesc],
              ["autoCheckUpdates", dict.settings.autoUpdateLabel, dict.settings.autoUpdateDesc],
            ] as const
          ).map(([field, label, desc]) => (
            <div key={field} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <div className="text-[12.5px] font-medium text-[var(--text-primary)]">{label}</div>
                <div className="text-[11.5px] text-[var(--text-secondary)]">{desc}</div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={settings[field]}
                aria-label={label}
                onClick={() => commit({ [field]: !settings[field] })}
                className="ui-switch"
              >
                <span className="ui-switch-knob" />
              </button>
            </div>
          ))}
        </div>

        {/* Network & Ports */}
        <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
          <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
            {dict.settings.secNetwork}
          </div>

          <div className="grid grid-cols-1 gap-4 px-4 py-3 sm:grid-cols-2">
            <div className="space-y-1">
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.settings.mixedPortLabel}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={mixedPortDraft}
                onChange={(e) =>
                  setMixedPortDraft(e.target.value.replace(/[^0-9]/g, "").slice(0, 5))
                }
                onBlur={commitMixedPort}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    commitMixedPort();
                    e.currentTarget.blur();
                  }
                }}
                className="ui-input h-8 w-full px-3 font-mono text-[12px] num-tabular"
              />
              {!mixedPortValid && (
                <div className="text-[11px]" style={{ color: "var(--danger-text)" }}>
                  {dict.settings.portRangeHint}
                </div>
              )}
            </div>

            <div className="space-y-1">
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.settings.controlPortLabel}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={controlPortDraft}
                onChange={(e) =>
                  setControlPortDraft(e.target.value.replace(/[^0-9]/g, "").slice(0, 5))
                }
                onBlur={commitControlPort}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    commitControlPort();
                    e.currentTarget.blur();
                  }
                }}
                className="ui-input h-8 w-full px-3 font-mono text-[12px] num-tabular"
              />
              {!controlPortValid && (
                <div className="text-[11px]" style={{ color: "var(--danger-text)" }}>
                  {dict.settings.portRangeHint}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                {dict.settings.allowLanLabel}
              </div>
              <div className="text-[11.5px] text-[var(--text-secondary)]">
                {dict.settings.allowLanDesc}
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={settings.allowLan}
              aria-label={dict.settings.allowLanLabel}
              onClick={() => commit({ allowLan: !settings.allowLan })}
              className="ui-switch"
            >
              <span className="ui-switch-knob" />
            </button>
          </div>

          <div className="space-y-2 px-4 py-3">
            <div>
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.settings.testUrlLabel}
              </label>
              <div className="text-[11px] text-[var(--text-secondary)]">
                {dict.settings.testUrlHint}
              </div>
            </div>
            <input
              type="text"
              value={testUrlDraft}
              onChange={(e) => setTestUrlDraft(e.target.value)}
              onBlur={() => {
                const v = testUrlDraft.trim();
                if (v && v !== settings.latencyTestUrl) commit({ latencyTestUrl: v });
                else if (!v) setTestUrlDraft(settings.latencyTestUrl);
              }}
              className="ui-input h-8 w-full px-3 font-mono text-[12px]"
            />
            <div className="flex flex-wrap gap-1.5">
              {TEST_URL_PRESETS.map((p) => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => {
                    setTestUrlDraft(p.value);
                    commit({ latencyTestUrl: p.value });
                  }}
                  className={`rounded-[6px] border px-2 py-0.5 font-mono text-[11px] transition-colors cursor-pointer ${
                    testUrlDraft === p.value
                      ? "border-[var(--border-strong)] bg-[var(--bg-selected)] text-[var(--text-primary)]"
                      : "border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                {dict.settings.stripHandshakeLabel}
              </div>
              <div className="text-[11.5px] text-[var(--text-secondary)]">
                {dict.settings.stripHandshakeDesc}
              </div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={settings.latencyStripHandshake}
              aria-label={dict.settings.stripHandshakeLabel}
              onClick={() =>
                commit({ latencyStripHandshake: !settings.latencyStripHandshake })
              }
              className="ui-switch"
            >
              <span className="ui-switch-knob" />
            </button>
          </div>

          <div className="flex items-center justify-between gap-4 bg-[var(--bg-subtle)] px-4 py-2.5 text-[12px]">
            <span className="inline-flex items-center gap-2 text-[var(--text-secondary)]">
              <Globe className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
              {dict.settings.dnsShortcutLabel}
            </span>
            <button type="button" onClick={onGoToDns} className="ui-btn-secondary h-7 text-[11.5px]">
              {dict.settings.dnsShortcutBtn}
              <ArrowRight className="h-3 w-3" strokeWidth={1.5} />
            </button>
          </div>
        </div>

        {/* AI Agent Integration Card (bypax-ux-spec.md Section 3.7) */}
        <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
            <span className="inline-flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5" strokeWidth={1.5} />
              {dict.agent.title}
            </span>
            <SegmentedControl
              value={agentTab}
              options={[
                { value: "mcp", label: dict.agent.tabMcp },
                { value: "cli", label: dict.agent.tabCli },
              ]}
              onChange={setAgentTab}
              ariaLabel={dict.agent.title}
            />
          </div>

          <div className="space-y-3 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[12px]">
              <div className="flex min-w-0 items-center gap-2">
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{
                    backgroundColor: cliInfo?.ready
                      ? "var(--success-dot)"
                      : "var(--text-tertiary)",
                  }}
                />
                <span className="font-medium text-[var(--text-primary)]">
                  {cliInfo?.ready ? dict.agent.ready : dict.agent.missing}
                </span>
                {cliInfo?.cliPath && (
                  <span
                    className="truncate font-mono text-[11px] text-[var(--text-secondary)]"
                    title={cliInfo.cliPath}
                  >
                    {"\u00b7"} {cliInfo.cliPath}
                  </span>
                )}
              </div>

              {!cliInfo?.ready && (
                <button
                  type="button"
                  onClick={() => void onOpenExternalUrl(RELEASES_FALLBACK_URL)}
                  className="ui-btn-secondary h-7 text-[11.5px]"
                >
                  {dict.agent.howToGet}
                  <ExternalLink className="h-3 w-3" strokeWidth={1.5} />
                </button>
              )}
            </div>

            <div className="relative rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)]">
              <button
                type="button"
                onClick={handleCopyAgentSnippet}
                className="ui-btn-secondary absolute top-2 right-2 h-7 px-2.5 text-[11.5px]"
              >
                {agentCopied ? (
                  <>
                    <Check
                      className="h-3 w-3"
                      style={{ color: "var(--success-text)" }}
                      strokeWidth={1.7}
                    />
                    {dict.agent.copied}
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    {dict.agent.copy}
                  </>
                )}
              </button>
              <pre className="overflow-x-auto p-3.5 pr-24 font-mono text-[11.5px] leading-relaxed text-[var(--text-primary)] select-text">
                {activeAgentCode}
              </pre>
            </div>

            <div className="text-[11.5px] text-[var(--text-secondary)]">
              {dict.agent.offlineNote}
            </div>
          </div>
        </div>

        {/* NetGuard & Storage */}
        <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
          <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
            {dict.settings.secNetGuard}
          </div>
          <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 flex-1 items-start gap-2.5">
              <ShieldCheck
                className="mt-0.5 h-4 w-4 shrink-0 text-[var(--text-secondary)]"
                strokeWidth={1.5}
              />
              <p className="text-[12px] text-[var(--text-secondary)]">
                {dict.settings.netguardDesc}
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={onRestoreNetguard}
                className="ui-btn-secondary h-8 shrink-0"
              >
                {dict.settings.restoreNow}
              </button>
              {platform !== "macos" && (
                <button
                  type="button"
                  onClick={() => void onCleanupLegacy()}
                  className="ui-btn-secondary h-8 shrink-0"
                >
                  {dict.settings.cleanupLegacyBtn}
                </button>
              )}
            </div>
          </div>

          <div className="space-y-1 px-4 py-3 text-[12px]">
            <div className="flex items-center gap-2">
              <HardDrive
                className="h-4 w-4 shrink-0 text-[var(--text-secondary)]"
                strokeWidth={1.5}
              />
              <span className="font-medium text-[var(--text-primary)]">
                {coreInfo.portableMode
                  ? dict.settings.portableActive
                  : dict.settings.portableStandard}
              </span>
            </div>
            <div className="break-all pl-6 font-mono text-[11px] text-[var(--text-secondary)]">
              {coreInfo.dataDir}
            </div>
          </div>
        </div>

        {/* Advanced JSON Override */}
        <div className="ui-card overflow-hidden">
          <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
            {dict.settings.secOverride}
          </div>
          <div className="space-y-2 p-4">
            <p className="text-[11.5px] text-[var(--text-secondary)]">
              {dict.settings.overrideDesc}
            </p>
            <textarea
              rows={3}
              value={overrideDraft}
              onChange={(e) => setOverrideDraft(e.target.value)}
              onBlur={() =>
                commit({ customJsonOverride: overrideDraft.trim() || null })
              }
              placeholder={dict.settings.overridePlaceholder}
              className="ui-input w-full p-2.5 font-mono text-[11.5px]"
            />
          </div>
        </div>

        {/* About Bypax (>= 48px Full-Color Rainbow Squircle) & In-App Self-Update */}
        {(() => {
          const stage = appUpdateState.stage;
          const isBusyDownload =
            stage === "downloading" || stage === "verifying" || stage === "extracting";
          const isReady = stage === "ready_to_restart";
          const isRestarting = stage === "restarting";
          const targetTag =
            appUpdateState.targetTag ?? appUpdateReport?.latestTag ?? `v${appVersion}`;
          const pct = appUpdateState.percent ?? 0;
          const displayErr = appUpdateState.error ?? appUpdateError;

          const statusText = isReady
            ? dict.settings.updateReady.replace("{tag}", targetTag)
            : stage === "downloading"
              ? dict.settings.updateDownloading.replace("{tag}", targetTag)
              : stage === "verifying"
                ? dict.settings.updateVerifying.replace("{tag}", targetTag)
                : stage === "extracting"
                  ? dict.settings.updateExtracting.replace("{tag}", targetTag)
                  : appUpdateReport
                    ? appUpdateReport.updateAvailable
                      ? dict.settings.updateFound
                          .replace("{tag}", appUpdateReport.latestTag)
                          .replace("{via}", appUpdateReport.checkedVia)
                      : appUpdateReport.noReleaseYet
                        ? dict.settings.updateNoReleaseYet.replace(
                            "{via}",
                            appUpdateReport.checkedVia,
                          )
                        : dict.settings.updateUpToDate
                            .replace("{version}", appUpdateReport.currentVersion)
                            .replace("{via}", appUpdateReport.checkedVia)
                    : dict.settings.updateIdle;

          return (
            <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
              <div className="flex items-center justify-between bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
                <span>{dict.settings.secUpdates}</span>
                <button
                  type="button"
                  onClick={() =>
                    void onOpenExternalUrl(
                      appUpdateReport?.releaseUrl ?? RELEASES_FALLBACK_URL,
                    )
                  }
                  className="inline-flex items-center gap-1 text-[11px] text-[var(--text-secondary)] transition-colors hover:text-[var(--text-primary)] cursor-pointer"
                >
                  <span>{dict.settings.openReleases}</span>
                  <ExternalLink className="h-3 w-3" strokeWidth={1.5} />
                </button>
              </div>

              <div className="space-y-3 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <BrandLogo variant="color" className="h-12 w-12 shrink-0" />
                    <div>
                      <div className="flex flex-wrap items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
                        <span>{dict.appTitle}</span>
                        <span className="font-mono text-[12px] font-medium num-tabular text-[var(--text-secondary)]">
                          v{appVersion}
                        </span>
                        <span className="rounded-full border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-mono text-[11.5px] font-normal text-[var(--text-secondary)]">
                          {coreInfo.portableMode
                            ? dict.settings.installModePortable
                            : dict.settings.installModeStandalone}
                        </span>
                        <span className="rounded-full border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-mono text-[11.5px] font-normal text-[var(--text-secondary)]">
                          MIT
                        </span>
                      </div>
                      <div className="text-[12px] text-[var(--text-secondary)]">
                        {dict.settings.aboutDesc}
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {isReady ? (
                      <button
                        type="button"
                        onClick={() => void onRestartToUpdate()}
                        className="ui-btn-primary h-8"
                      >
                        <RotateCw className="h-3.5 w-3.5" strokeWidth={1.6} />
                        {dict.settings.restartToUpdate}
                      </button>
                    ) : isRestarting ? (
                      <button type="button" disabled className="ui-btn-primary h-8">
                        <RotateCw className="h-3.5 w-3.5 animate-spin" strokeWidth={1.6} />
                        {dict.settings.restartingUpdate}
                      </button>
                    ) : isBusyDownload ? (
                      <button
                        type="button"
                        onClick={() => void onCancelAppUpdate()}
                        className="ui-btn-secondary h-8"
                      >
                        <X className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                        {dict.settings.cancelUpdate}
                      </button>
                    ) : appUpdateReport?.updateAvailable &&
                      appUpdateReport.inAppUpdateSupported ? (
                      <>
                        <button
                          type="button"
                          onClick={() => void onDownloadAppUpdate()}
                          className="ui-btn-primary h-8"
                        >
                          <Download className="h-3.5 w-3.5" strokeWidth={1.5} />
                          {stage === "failed"
                            ? dict.settings.retryUpdate
                            : dict.settings.updateNow}
                        </button>
                        <button
                          type="button"
                          disabled={checkingAppUpdate}
                          onClick={() => void onCheckAppUpdate()}
                          className="ui-btn-secondary h-8"
                        >
                          <RefreshCw
                            className={`h-3.5 w-3.5 text-[var(--text-secondary)] ${
                              checkingAppUpdate ? "animate-spin" : ""
                            }`}
                            strokeWidth={1.5}
                          />
                          {checkingAppUpdate
                            ? dict.settings.checkingUpdates
                            : dict.settings.checkUpdates}
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        disabled={checkingAppUpdate}
                        onClick={() => void onCheckAppUpdate()}
                        className="ui-btn-secondary h-8"
                      >
                        <RefreshCw
                          className={`h-3.5 w-3.5 text-[var(--text-secondary)] ${
                            checkingAppUpdate ? "animate-spin" : ""
                          }`}
                          strokeWidth={1.5}
                        />
                        {checkingAppUpdate
                          ? dict.settings.checkingUpdates
                          : dict.settings.checkUpdates}
                      </button>
                    )}
                  </div>
                </div>

                {/* Status line */}
                <div
                  className="flex flex-wrap items-center justify-between gap-2 rounded-[10px] border px-3 py-2 text-[12px]"
                  style={
                    isReady
                      ? {
                          borderColor: "var(--success-border)",
                          backgroundColor: "var(--success-bg)",
                          color: "var(--success-text)",
                        }
                      : {
                          borderColor: "var(--border-hairline)",
                          backgroundColor: "var(--bg-subtle)",
                          color: "var(--text-secondary)",
                        }
                  }
                >
                  <span className="min-w-0 flex-1">{statusText}</span>
                  {appUpdateReport?.releaseNotes && (
                    <button
                      type="button"
                      onClick={() => setShowNotes((v) => !v)}
                      className="inline-flex shrink-0 items-center gap-1 text-[11.5px] font-medium text-[var(--text-primary)] cursor-pointer"
                    >
                      <span>{dict.settings.releaseNotesToggle}</span>
                      <ChevronDown
                        className={`h-3.5 w-3.5 transition-transform ${
                          showNotes ? "rotate-180" : ""
                        }`}
                        strokeWidth={1.5}
                      />
                    </button>
                  )}
                </div>

                {appUpdateReport?.updateAvailable && !appUpdateReport.inAppUpdateSupported && (
                  <div className="flex items-center justify-between gap-2 text-[11.5px] text-[var(--text-secondary)]">
                    <span>{dict.settings.updateUnsupportedPlatform}</span>
                    <button
                      type="button"
                      onClick={() => void onOpenExternalUrl(appUpdateReport.releaseUrl)}
                      className="ui-btn-secondary h-7 shrink-0 text-[11.5px]"
                    >
                      {dict.settings.openReleases}
                      <ExternalLink className="h-3 w-3" strokeWidth={1.5} />
                    </button>
                  </div>
                )}

                {isBusyDownload && (
                  <div className="space-y-1.5">
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-track)]">
                      <div
                        className="h-full rounded-full transition-all duration-150"
                        style={{
                          width: `${Math.max(4, pct)}%`,
                          backgroundColor: "var(--success-dot)",
                        }}
                      />
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                      <span>
                        {formatBytes(appUpdateState.downloadedBytes)}
                        {appUpdateState.totalBytes
                          ? ` / ${formatBytes(appUpdateState.totalBytes)}`
                          : ""}
                        {appUpdateState.via ? ` (${appUpdateState.via})` : ""}
                      </span>
                      <span>{pct}%</span>
                    </div>
                  </div>
                )}

                {isReady && appUpdateState.sha256 && (
                  <div className="font-mono text-[11px] num-tabular text-[var(--text-tertiary)]">
                    SHA-256: {appUpdateState.sha256.slice(0, 24)}...
                  </div>
                )}

                {displayErr && !isReady && !isBusyDownload && (
                  <div className="text-[11.5px]" style={{ color: "var(--danger-text)" }}>
                    {displayErr}
                  </div>
                )}
              </div>

              {showNotes && appUpdateReport?.releaseNotes && (
                <pre className="max-h-48 overflow-auto bg-[var(--bg-subtle)] px-4 py-3 font-mono text-[11.5px] whitespace-pre-wrap text-[var(--text-secondary)]">
                  {appUpdateReport.releaseNotes}
                </pre>
              )}
            </div>
          );
        })()}
        </div>
      </div>
    </section>
  );
}
