import { useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  Copy,
  Download,
  FolderOpen,
  Play,
  RefreshCw,
  ShieldAlert,
  Square,
} from "lucide-react";
import { CustomSelect, type SelectGroup } from "../../components/CustomSelect";
import type { Dict } from "../../i18n";
import type {
  AppSettings,
  CompileOutput,
  CoreDownloadProgressEvent,
  CoreInfo,
  CoreUpdateCheckReport,
  PreflightReport,
} from "../../types";
import { formatBytes } from "../../utils/nodes";

interface CoreViewProps {
  dict: Dict;
  coreInfo: CoreInfo;
  settings: AppSettings;
  compiled: CompileOutput;
  preflight: PreflightReport | null;
  coreBusy: boolean;
  downloadingCore: boolean;
  coreDownloadProgress: CoreDownloadProgressEvent | null;
  coreUpdateReport: CoreUpdateCheckReport | null;
  checkingCoreUpdate: boolean;
  onUpdateSettings: (next: AppSettings) => void;
  onRunPreflight: (simulateBad: boolean) => Promise<void>;
  onCheckCoreUpdate: () => Promise<void>;
  onDownloadCore: () => Promise<void>;
  onImportCoreBinary: () => Promise<void>;
  onToggleCore: () => Promise<void>;
  onCopyJson: (text: string) => void;
}

export function CoreView({
  dict,
  coreInfo,
  settings,
  compiled,
  preflight,
  coreBusy,
  downloadingCore,
  coreDownloadProgress,
  coreUpdateReport,
  checkingCoreUpdate,
  onUpdateSettings,
  onRunPreflight,
  onCheckCoreUpdate,
  onDownloadCore,
  onImportCoreBinary,
  onToggleCore,
  onCopyJson,
}: CoreViewProps) {
  const [viewMode, setViewMode] = useState<"visual" | "json">("visual");

  const [sniffTimeoutDraft, setSniffTimeoutDraft] = useState(settings.sniffTimeout);
  const [tunIfaceDraft, setTunIfaceDraft] = useState(settings.tunInterfaceName);
  const [tunMtuDraft, setTunMtuDraft] = useState(String(settings.tunMtu));
  const [tunAddrDraft, setTunAddrDraft] = useState(settings.tunInet4Address);
  const [intervalDraft, setIntervalDraft] = useState(settings.urltestInterval);
  const [toleranceDraft, setToleranceDraft] = useState(String(settings.urltestTolerance));

  useEffect(() => setSniffTimeoutDraft(settings.sniffTimeout), [settings.sniffTimeout]);
  useEffect(() => setTunIfaceDraft(settings.tunInterfaceName), [settings.tunInterfaceName]);
  useEffect(() => setTunMtuDraft(String(settings.tunMtu)), [settings.tunMtu]);
  useEffect(() => setTunAddrDraft(settings.tunInet4Address), [settings.tunInet4Address]);
  useEffect(() => setIntervalDraft(settings.urltestInterval), [settings.urltestInterval]);
  useEffect(() => setToleranceDraft(String(settings.urltestTolerance)), [settings.urltestTolerance]);

  const commit = (patch: Partial<AppSettings>) => {
    onUpdateSettings({ ...settings, ...patch });
  };

  const prettyJson = useMemo(
    () => JSON.stringify(compiled.config, null, 2),
    [compiled]
  );

  const logLevelGroups: SelectGroup[] = useMemo(
    () => [
      {
        label: dict.core.logLevelLabel,
        options: [
          { value: "trace", label: "trace" },
          { value: "debug", label: "debug" },
          { value: "info", label: "info" },
          { value: "warn", label: "warn" },
          { value: "error", label: "error" },
        ],
      },
    ],
    [dict]
  );

  const tunStackGroups: SelectGroup[] = useMemo(
    () => [
      {
        label: dict.core.tunStackLabel,
        options: [
          { value: "mixed", label: "mixed" },
          { value: "system", label: "system" },
          { value: "gvisor", label: "gvisor" },
        ],
      },
    ],
    [dict]
  );

  const corePhaseLabel = useMemo(() => {
    const p = coreDownloadProgress?.phase;
    if (p === "checking") return dict.core.phaseChecking;
    if (p === "downloading") return dict.core.phaseDownloading;
    if (p === "verifying") return dict.core.phaseVerifying;
    if (p === "extracting") return dict.core.phaseExtracting;
    if (p === "restarting") return dict.core.phaseRestarting;
    return dict.core.downloading;
  }, [coreDownloadProgress?.phase, dict]);

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Unified Single-Row 40px Page Header */}
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <h1 className="text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
          {dict.core.title}
        </h1>
        <span className="font-mono text-[11.5px] text-[var(--text-secondary)]">
          {dict.core.schemaBadge}
        </span>
      </div>

      {/* Binary Runtime Manager Banner */}
      <div className="shrink-0 space-y-2.5 border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-4 py-3 lg:px-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] font-semibold text-[var(--text-primary)]">
                {dict.core.binaryTitle}
              </span>
              <span
                className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2 py-0.5 font-mono text-[11px]"
                style={{
                  color: coreInfo.installed
                    ? "var(--success-text)"
                    : "var(--warning-text)",
                }}
              >
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{
                    backgroundColor: coreInfo.installed
                      ? "var(--success-dot)"
                      : "var(--warning-dot)",
                  }}
                />
                {coreInfo.installed
                  ? `${dict.core.binaryInstalled} (${coreInfo.version ?? "v1.14+"})`
                  : dict.core.binaryMissing}
              </span>
              {coreUpdateReport && (
                <span
                  className="inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[11.5px] num-tabular"
                  style={
                    coreUpdateReport.updateAvailable
                      ? {
                          borderColor: "var(--success-border)",
                          backgroundColor: "var(--success-bg)",
                          color: "var(--success-text)",
                        }
                      : {
                          borderColor: "var(--border-hairline)",
                          backgroundColor: "var(--bg-surface)",
                          color: "var(--text-secondary)",
                        }
                  }
                >
                  {coreUpdateReport.updateAvailable
                    ? dict.core.coreUpdateFound.replace("{tag}", coreUpdateReport.latestTag)
                    : dict.core.coreUpToDate.replace("{tag}", coreUpdateReport.latestTag)}
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
              <span className="truncate">
                {dict.core.pathLabel}: {coreInfo.binaryPath}
              </span>
              {coreInfo.sha256 && (
                <span>
                  {dict.core.shaLabel}: {coreInfo.sha256.slice(0, 16)}...
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={checkingCoreUpdate || downloadingCore}
              onClick={() => void onCheckCoreUpdate()}
              className="ui-btn-secondary h-8"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 text-[var(--text-tertiary)] ${
                  checkingCoreUpdate ? "animate-spin" : ""
                }`}
                strokeWidth={1.5}
              />
              {checkingCoreUpdate ? dict.core.checkingUpdate : dict.core.checkUpdate}
            </button>
            <button
              type="button"
              disabled={downloadingCore}
              onClick={() => void onDownloadCore()}
              className={
                coreUpdateReport?.updateAvailable ? "ui-btn-primary h-8" : "ui-btn-secondary h-8"
              }
            >
              <Download
                className={`h-3.5 w-3.5 ${
                  coreUpdateReport?.updateAvailable ? "" : "text-[var(--text-tertiary)]"
                }`}
                strokeWidth={1.5}
              />
              {downloadingCore
                ? coreDownloadProgress?.percent != null
                  ? `${dict.core.downloading} ${coreDownloadProgress.percent}%`
                  : dict.core.downloading
                : coreUpdateReport?.updateAvailable
                  ? dict.core.updateCoreTo.replace("{tag}", coreUpdateReport.latestTag)
                  : dict.core.downloadOfficial}
            </button>
            <button
              type="button"
              disabled={downloadingCore}
              onClick={() => void onImportCoreBinary()}
              className="ui-btn-secondary h-8"
            >
              <FolderOpen className="h-3.5 w-3.5 text-[var(--text-tertiary)]" strokeWidth={1.5} />
              {dict.core.importBinary}
            </button>
            <button
              type="button"
              disabled={coreBusy || downloadingCore || !coreInfo.installed}
              onClick={() => void onToggleCore()}
              className={coreInfo.running ? "ui-btn-secondary h-8" : "ui-btn-primary h-8"}
            >
              {coreInfo.running ? (
                <>
                  <Square className="h-3.5 w-3.5" strokeWidth={1.5} />
                  {dict.nav.stopCore}
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" strokeWidth={1.5} />
                  {dict.nav.startCore}
                </>
              )}
            </button>
          </div>
        </div>

        {downloadingCore && coreDownloadProgress && (
          <div className="space-y-1.5 rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-3 py-2">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[11.5px]">
              <span className="font-medium text-[var(--text-primary)]">
                {corePhaseLabel}
                {coreDownloadProgress.targetVersion
                  ? ` (${coreDownloadProgress.targetVersion})`
                  : ""}
              </span>
              <span className="font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                {coreDownloadProgress.downloadedBytes > 0
                  ? `${formatBytes(coreDownloadProgress.downloadedBytes)}${
                      coreDownloadProgress.totalBytes
                        ? ` / ${formatBytes(coreDownloadProgress.totalBytes)}`
                        : ""
                    }`
                  : ""}
                {coreDownloadProgress.via ? ` (${coreDownloadProgress.via})` : ""}
                {coreDownloadProgress.percent != null
                  ? ` ${coreDownloadProgress.percent}%`
                  : ""}
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-track)]">
              <div
                className="h-full rounded-full transition-all duration-150"
                style={{
                  width: `${Math.max(5, coreDownloadProgress.percent ?? 15)}%`,
                  backgroundColor: "var(--success-dot)",
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Config Header + Visual/JSON Switcher + Actions */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2.5 border-b border-[var(--border-hairline)] px-5 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[12px]">
            <button
              type="button"
              onClick={() => setViewMode("visual")}
              className={`rounded-[6px] px-3 py-1 font-medium cursor-pointer ${
                viewMode === "visual"
                  ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {dict.core.tabVisual}
            </button>
            <button
              type="button"
              onClick={() => setViewMode("json")}
              className={`rounded-[6px] px-3 py-1 font-medium cursor-pointer ${
                viewMode === "json"
                  ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {dict.core.tabJson}
            </button>
          </div>

          <span className="rounded-full border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
            {dict.core.treeShake}: {compiled.totalNodes} -&gt; {compiled.reachableNodes}{" "}
            {dict.core.nodesActive}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void onRunPreflight(false)}
            className="ui-btn-primary h-8"
          >
            <CheckCircle2 className="h-3.5 w-3.5" strokeWidth={1.5} />
            {dict.core.runPreflight}
          </button>
          <button
            type="button"
            onClick={() => void onRunPreflight(true)}
            className="ui-btn-danger-subtle h-8"
          >
            <ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.5} />
            {dict.core.testBadBlock}
          </button>
          <button
            type="button"
            onClick={() => onCopyJson(prettyJson)}
            className="ui-btn-secondary h-8"
          >
            <Copy className="h-3.5 w-3.5 text-[var(--text-tertiary)]" strokeWidth={1.5} />
            {dict.core.copyJson}
          </button>
        </div>
      </div>

      {/* Preflight Status Strip */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-5 py-2 text-[11.5px]">
        <div className="flex items-center gap-2">
          <span
            className="h-2 w-2 shrink-0 rounded-full"
            style={{
              backgroundColor:
                preflight == null
                  ? "var(--text-tertiary)"
                  : preflight.ok
                    ? "var(--success-dot)"
                    : "var(--danger-dot)",
            }}
          />
          <span className="font-mono text-[var(--text-primary)]">
            {preflight == null
              ? dict.core.preflightIdle
              : preflight.ok
                ? dict.core.preflightPass
                : `${dict.core.preflightFail}${preflight.stderr ? ` (${preflight.stderr.split("\n")[0]})` : ""}`}
          </span>
        </div>
        <span className="font-mono text-[var(--text-secondary)]">{dict.core.schemaBadge}</span>
      </div>

      {/* Body: Visual Config Editor OR Compiled JSON */}
      {viewMode === "visual" ? (
        <div className="min-h-0 flex-1 overflow-auto">
          <div className="mx-auto w-full max-w-4xl space-y-5 px-6 py-5">
            {/* Logging & Route Engine */}
            <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
              <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
                {dict.core.secLogRoute}
              </div>

              <div className="flex items-center justify-between gap-4 px-4 py-3">
                <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                  {dict.core.logLevelLabel}
                </div>
                <CustomSelect
                  value={settings.logLevel}
                  groups={logLevelGroups}
                  onChange={(val) => commit({ logLevel: val })}
                  className="w-36"
                />
              </div>

              <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3">
                <div>
                  <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                    {dict.core.sniffLabel}
                  </div>
                  <div className="text-[11.5px] text-[var(--text-secondary)]">
                    {dict.core.sniffDesc}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {settings.sniffEnabled && (
                    <div className="flex items-center gap-1.5 text-[11.5px] text-[var(--text-secondary)]">
                      <span>{dict.core.sniffTimeoutLabel}</span>
                      <input
                        type="text"
                        value={sniffTimeoutDraft}
                        onChange={(e) => setSniffTimeoutDraft(e.target.value)}
                        onBlur={() => {
                          const v = sniffTimeoutDraft.trim();
                          if (v && v !== settings.sniffTimeout) commit({ sniffTimeout: v });
                          else if (!v) setSniffTimeoutDraft(settings.sniffTimeout);
                        }}
                        className="ui-input h-7 w-20 px-2 font-mono text-[11.5px]"
                      />
                    </div>
                  )}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={settings.sniffEnabled}
                    aria-label={dict.core.sniffLabel}
                    onClick={() => commit({ sniffEnabled: !settings.sniffEnabled })}
                    className="ui-switch shrink-0"
                  >
                    <span className="ui-switch-knob" />
                  </button>
                </div>
              </div>

              {(
                [
                  ["findProcess", dict.core.findProcessLabel, dict.core.findProcessDesc],
                  [
                    "autoDetectInterface",
                    dict.core.autoDetectLabel,
                    dict.core.autoDetectDesc,
                  ],
                ] as const
              ).map(([field, label, desc]) => {
                const checked = settings[field];
                return (
                  <div key={field} className="flex items-center justify-between gap-4 px-4 py-3">
                    <div>
                      <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                        {label}
                      </div>
                      <div className="text-[11.5px] text-[var(--text-secondary)]">{desc}</div>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={checked}
                      aria-label={label}
                      onClick={() => commit({ [field]: !checked })}
                      className="ui-switch shrink-0"
                    >
                      <span className="ui-switch-knob" />
                    </button>
                  </div>
                );
              })}
            </div>

            {/* TUN Interface Parameters */}
            <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
              <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
                {dict.core.secTun}
              </div>

              <div className="grid grid-cols-1 gap-4 px-4 py-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.tunIfaceLabel}
                  </label>
                  <input
                    type="text"
                    value={tunIfaceDraft}
                    onChange={(e) => setTunIfaceDraft(e.target.value)}
                    onBlur={() => {
                      const v = tunIfaceDraft.trim();
                      if (v && v !== settings.tunInterfaceName) {
                        commit({ tunInterfaceName: v });
                      } else if (!v) {
                        setTunIfaceDraft(settings.tunInterfaceName);
                      }
                    }}
                    className="ui-input h-8 w-full px-3 font-mono text-[12px]"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.tunStackLabel}
                  </label>
                  <CustomSelect
                    value={settings.tunStack}
                    groups={tunStackGroups}
                    onChange={(val) => commit({ tunStack: val })}
                    className="w-full"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.tunMtuLabel}
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={tunMtuDraft}
                    onChange={(e) =>
                      setTunMtuDraft(e.target.value.replace(/[^0-9]/g, "").slice(0, 5))
                    }
                    onBlur={() => {
                      const n = Number.parseInt(tunMtuDraft, 10);
                      if (Number.isFinite(n) && n >= 1280 && n <= 65535) {
                        if (n !== settings.tunMtu) commit({ tunMtu: n });
                      } else {
                        setTunMtuDraft(String(settings.tunMtu));
                      }
                    }}
                    className="ui-input h-8 w-full px-3 font-mono text-[12px] num-tabular"
                  />
                </div>

                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.tunAddrLabel}
                  </label>
                  <input
                    type="text"
                    value={tunAddrDraft}
                    onChange={(e) => setTunAddrDraft(e.target.value)}
                    onBlur={() => {
                      const v = tunAddrDraft.trim();
                      if (v && v !== settings.tunInet4Address) {
                        commit({ tunInet4Address: v });
                      } else if (!v) {
                        setTunAddrDraft(settings.tunInet4Address);
                      }
                    }}
                    className="ui-input h-8 w-full px-3 font-mono text-[12px]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 px-4 py-3 sm:grid-cols-2">
                {(
                  [
                    ["tunAutoRoute", dict.core.tunAutoRouteLabel],
                    ["tunStrictRoute", dict.core.tunStrictRouteLabel],
                  ] as const
                ).map(([field, label]) => {
                  const checked = settings[field];
                  return (
                    <div key={field} className="flex items-center justify-between gap-3">
                      <span className="text-[12.5px] font-medium text-[var(--text-primary)]">
                        {label}
                      </span>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={checked}
                        aria-label={label}
                        onClick={() => commit({ [field]: !checked })}
                        className="ui-switch shrink-0"
                      >
                        <span className="ui-switch-knob" />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Auto-Select (URLTest) & Cache File */}
            <div className="ui-card divide-y divide-[var(--border-hairline)] overflow-hidden">
              <div className="bg-[var(--bg-subtle)] px-4 py-2 text-[11.5px] font-medium text-[var(--text-secondary)]">
                {dict.core.secAutoCache}
              </div>

              <div className="grid grid-cols-1 gap-4 px-4 py-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.urltestIntervalLabel}
                  </label>
                  <input
                    type="text"
                    value={intervalDraft}
                    onChange={(e) => setIntervalDraft(e.target.value)}
                    onBlur={() => {
                      const v = intervalDraft.trim();
                      if (v && v !== settings.urltestInterval) {
                        commit({ urltestInterval: v });
                      } else if (!v) {
                        setIntervalDraft(settings.urltestInterval);
                      }
                    }}
                    className="ui-input h-8 w-full px-3 font-mono text-[12px]"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                    {dict.core.urltestToleranceLabel}
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    value={toleranceDraft}
                    onChange={(e) =>
                      setToleranceDraft(e.target.value.replace(/[^0-9]/g, "").slice(0, 4))
                    }
                    onBlur={() => {
                      const n = Number.parseInt(toleranceDraft, 10);
                      if (Number.isFinite(n) && n >= 10 && n <= 2000) {
                        if (n !== settings.urltestTolerance) commit({ urltestTolerance: n });
                      } else {
                        setToleranceDraft(String(settings.urltestTolerance));
                      }
                    }}
                    className="ui-input h-8 w-full px-3 font-mono text-[12px] num-tabular"
                  />
                </div>
              </div>

              {(
                [
                  ["cacheFileEnabled", dict.core.cacheEnabledLabel, dict.core.cacheEnabledDesc],
                  ["cacheStoreFakeip", dict.core.cacheFakeipLabel, dict.core.cacheFakeipDesc],
                ] as const
              ).map(([field, label, desc]) => {
                const checked = settings[field];
                return (
                  <div key={field} className="flex items-center justify-between gap-4 px-4 py-3">
                    <div>
                      <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                        {label}
                      </div>
                      <div className="text-[11.5px] text-[var(--text-secondary)]">{desc}</div>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={checked}
                      aria-label={label}
                      onClick={() => commit({ [field]: !checked })}
                      className="ui-switch shrink-0"
                    >
                      <span className="ui-switch-knob" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto bg-[var(--bg-subtle)] p-5">
          <pre className="select-text whitespace-pre font-mono text-[12px] leading-relaxed text-[var(--text-primary)]">
            {prettyJson}
          </pre>
        </div>
      )}
    </section>
  );
}
