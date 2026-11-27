import { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpCircle,
  ChevronDown,
  Globe,
  Languages,
  Maximize2,
  Minimize2,
  Minus,
  Monitor,
  Moon,
  RotateCw,
  Shield,
  SlidersHorizontal,
  Sun,
  X,
} from "lucide-react";
import { api } from "../api/client";
import type { Dict } from "../i18n";
import type {
  AppUpdateCheckReport,
  AppUpdateState,
  CaptureMode,
  CoreInfo,
  Locale,
  PlatformKind,
  RouteMode,
  ThemeMode,
  TrafficSample,
} from "../types";
import { formatSpeed } from "../utils/nodes";
import { AuthPopover } from "./AuthPopover";
import { BrandLogo } from "./BrandLogo";
import { SegmentedControl } from "./SegmentedControl";

interface TitleBarProps {
  dict: Dict;
  platform: PlatformKind | string;
  locale: Locale;
  theme: ThemeMode;
  coreInfo: CoreInfo;
  routeMode: RouteMode;
  sysProxyEnabled: boolean;
  captureMode: CaptureMode;
  captureSwitching: boolean;
  capturePendingTarget: CaptureMode | null;
  captureError: string | null;
  enabledAppCount: number;
  hasRecoveryFault: boolean;
  takeoverSummary: string;
  authPromptTarget: CaptureMode | null;
  authBusyLabel: string | null;
  traffic: TrafficSample;
  appUpdateReport: AppUpdateCheckReport | null;
  appUpdateState: AppUpdateState;
  onSelectMode: (mode: RouteMode) => void;
  onToggleSysProxy: () => void;
  onSelectCapture: (mode: CaptureMode) => void;
  onAuthOnce: () => void;
  onAuthInstall: () => void;
  onAuthCancel: () => void;
  onOpenCore: () => void;
  onOpenApps: () => void;
  onSeeCaptureError: () => void;
  onDismissCaptureError: () => void;
  onOpenUpdates: () => void;
  onRestartToUpdate: () => void;
  onToggleLocale: () => void;
  onCycleTheme: () => void;
}

type WidthTier = "wide" | "medium" | "compact";

function computeTier(): WidthTier {
  if (typeof window === "undefined") return "wide";
  if (window.innerWidth >= 1280) return "wide";
  if (window.innerWidth >= 1100) return "medium";
  return "compact";
}

export function TitleBar({
  dict,
  platform,
  locale,
  theme,
  coreInfo,
  routeMode,
  sysProxyEnabled,
  captureMode,
  captureSwitching,
  capturePendingTarget,
  captureError,
  enabledAppCount,
  hasRecoveryFault,
  takeoverSummary,
  authPromptTarget,
  authBusyLabel,
  traffic,
  appUpdateReport,
  appUpdateState,
  onSelectMode,
  onToggleSysProxy,
  onSelectCapture,
  onAuthOnce,
  onAuthInstall,
  onAuthCancel,
  onOpenCore,
  onOpenApps,
  onSeeCaptureError,
  onDismissCaptureError,
  onOpenUpdates,
  onRestartToUpdate,
  onToggleLocale,
  onCycleTheme,
}: TitleBarProps) {
  const [maximized, setMaximized] = useState(false);
  const [tier, setTier] = useState<WidthTier>(computeTier);
  const [takeoverOpen, setTakeoverOpen] = useState(false);
  const [appearanceOpen, setAppearanceOpen] = useState(false);

  const takeoverRef = useRef<HTMLDivElement | null>(null);
  const appearanceRef = useRef<HTMLDivElement | null>(null);
  const isMac = platform === "macos";

  useEffect(() => {
    const syncMax = () => {
      api.windowControls.isMaximized().then(setMaximized).catch(() => {});
    };
    const syncTier = () => setTier(computeTier());
    syncMax();
    syncTier();

    window.addEventListener("resize", syncTier);
    let unlisten: (() => void) | undefined;
    void api.windowControls.onResized(syncMax).then((fn) => {
      unlisten = fn;
    });
    return () => {
      window.removeEventListener("resize", syncTier);
      if (unlisten) unlisten();
    };
  }, []);

  useEffect(() => {
    const onPointer = (e: MouseEvent) => {
      const target = e.target as Node;
      if (takeoverOpen && takeoverRef.current && !takeoverRef.current.contains(target)) {
        setTakeoverOpen(false);
      }
      if (appearanceOpen && appearanceRef.current && !appearanceRef.current.contains(target)) {
        setAppearanceOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setTakeoverOpen(false);
        setAppearanceOpen(false);
      }
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [takeoverOpen, appearanceOpen]);

  const modeOptions = [
    { value: "rule" as RouteMode, label: dict.titlebar.modeRule },
    { value: "global" as RouteMode, label: dict.titlebar.modeGlobal },
    { value: "direct" as RouteMode, label: dict.titlebar.modeDirect },
  ];

  const appsNeedsHint =
    hasRecoveryFault || (captureMode === "apps" && enabledAppCount === 0);

  const captureOptions = [
    {
      value: "off" as CaptureMode,
      label: dict.capture.off,
      title: dict.capture.offHint,
    },
    {
      value: "apps" as CaptureMode,
      label: dict.capture.apps,
      title: isMac ? dict.apps.engineMac : dict.apps.engineWin,
      dotColor: appsNeedsHint ? "var(--warning-dot)" : undefined,
    },
    {
      value: "tun" as CaptureMode,
      label: dict.capture.tun,
      title: dict.capture.tunHint,
    },
  ];

  const activeTakeoverCount =
    (sysProxyEnabled ? 1 : 0) + (captureMode !== "off" ? 1 : 0);

  return (
    <header
      data-tauri-drag-region
      className={`relative z-30 flex h-11 shrink-0 items-center justify-between gap-2 bg-[var(--bg-chrome)] select-none ${
        isMac ? "pr-3 pl-[82px]" : "pr-0 pl-3"
      }`}
    >
      {/* Left: Brand Mark (non-macOS) + Core Status Pill + Update Pill */}
      <div data-tauri-drag-region className="flex min-w-0 items-center gap-2">
        {!isMac && (
          <>
            <span className="flex h-[26px] w-[26px] shrink-0 items-center justify-center rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]">
              <BrandLogo variant="monochrome" className="h-[18px] w-[18px]" />
            </span>

            {tier === "wide" && (
              <span
                data-tauri-drag-region
                className="text-[13px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]"
              >
                {dict.appTitle}
              </span>
            )}
          </>
        )}

        {!coreInfo.installed && (
          <button
            type="button"
            onClick={onOpenCore}
            title={`${dict.core.binaryTitle}: ${dict.titlebar.coreMissing}`}
            className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2 text-[11.5px] font-medium text-[var(--text-secondary)] shadow-[var(--shadow-sm)] transition-colors hover:border-[var(--border-strong)] hover:text-[var(--text-primary)] cursor-pointer"
          >
            <span
              className="h-2 w-2 shrink-0 rounded-full"
              style={{ backgroundColor: "var(--warning-dot)" }}
            />
            {tier !== "compact" && <span>{dict.titlebar.coreMissing}</span>}
          </button>
        )}

        {appUpdateState.stage === "ready_to_restart" ? (
          <button
            type="button"
            onClick={onRestartToUpdate}
            className="inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11.5px] font-medium transition-colors cursor-pointer"
            style={{
              borderColor: "var(--success-border)",
              backgroundColor: "var(--success-bg)",
              color: "var(--success-text)",
            }}
          >
            <RotateCw className="h-3 w-3 shrink-0" strokeWidth={1.6} />
            <span className="truncate">{dict.titlebar.restartToUpdate}</span>
          </button>
        ) : appUpdateState.stage === "downloading" ||
          appUpdateState.stage === "verifying" ||
          appUpdateState.stage === "extracting" ? (
          <button
            type="button"
            onClick={onOpenUpdates}
            className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[var(--border-strong)] bg-[var(--bg-surface)] px-2 text-[11.5px] font-mono num-tabular text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
          >
            <span
              className="h-1.5 w-1.5 rounded-full animate-pulse"
              style={{ backgroundColor: "var(--success-dot)" }}
            />
            <span>
              {dict.titlebar.updateDownloading.replace(
                "{pct}",
                String(appUpdateState.percent ?? 0),
              )}
            </span>
          </button>
        ) : appUpdateReport?.updateAvailable && tier === "wide" ? (
          <button
            type="button"
            onClick={onOpenUpdates}
            className="inline-flex h-7 items-center gap-1.5 rounded-full border border-[var(--border-strong)] bg-[var(--bg-surface)] px-2 text-[11.5px] font-medium text-[var(--text-primary)] transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
          >
            <ArrowUpCircle
              className="h-3.5 w-3.5 shrink-0"
              style={{ color: "var(--accent-focus)" }}
              strokeWidth={1.6}
            />
            <span className="font-mono num-tabular">
              {dict.titlebar.updateAvailable.replace("{tag}", appUpdateReport.latestTag)}
            </span>
          </button>
        ) : null}
      </div>

      {/* Center: Mode Segmented + Orthogonal Takeover Controls */}
      <div className="flex shrink-0 items-center gap-2">
        <SegmentedControl
          value={routeMode}
          options={modeOptions}
          onChange={onSelectMode}
          ariaLabel={dict.nav.routing}
          surface="chrome"
        />

        {tier !== "compact" ? (
          <div className="relative flex items-center gap-2">
            <div className="h-4 w-px bg-[var(--border-hairline)]" />

            {/* System Proxy switch pill (30px high, inner 32x18 switch) */}
            <div
              className="inline-flex h-[30px] items-center gap-2 rounded-[9px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-2.5 shadow-[var(--shadow-sm)]"
              title={dict.takeover.sysProxyHint}
            >
              <span className="text-[12px] font-medium text-[var(--text-primary)]">
                {dict.takeover.sysProxy}
              </span>
              <button
                type="button"
                role="switch"
                aria-checked={sysProxyEnabled}
                aria-label={dict.takeover.sysProxy}
                onClick={onToggleSysProxy}
                className="ui-switch"
              >
                <span className="ui-switch-knob" />
              </button>
            </div>

            {/* Transparent takeover 3-way segmented control: Off | App Proxy | TUN */}
            <div className="relative flex items-center">
              <SegmentedControl
                value={captureMode}
                options={captureOptions}
                onChange={onSelectCapture}
                ariaLabel={dict.capture.label}
                surface="chrome"
                switching={captureSwitching}
                switchingTarget={capturePendingTarget}
              />

              {authPromptTarget && (
                <AuthPopover
                  dict={dict}
                  platform={platform}
                  targetMode={authPromptTarget}
                  busyLabel={authBusyLabel}
                  onSelectOnce={onAuthOnce}
                  onSelectInstall={onAuthInstall}
                  onCancel={onAuthCancel}
                  align="center"
                />
              )}

              {captureError && !authPromptTarget && (
                <div
                  role="alert"
                  onMouseDown={(e) => e.stopPropagation()}
                  className="ui-popover absolute top-full right-0 z-50 mt-2 flex max-w-[360px] items-center gap-2 px-3 py-2 text-[11.5px]"
                  style={{
                    borderColor: "var(--danger-border)",
                    backgroundColor: "var(--danger-bg)",
                    color: "var(--danger-text-on-bg)",
                  }}
                >
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
                  <span className="min-w-0 flex-1 truncate" title={captureError}>
                    {captureError}
                  </span>
                  <button
                    type="button"
                    onClick={onSeeCaptureError}
                    className="shrink-0 font-semibold underline hover:opacity-80 cursor-pointer"
                  >
                    {dict.capture.seeWhy}
                  </button>
                  <button
                    type="button"
                    onClick={onDismissCaptureError}
                    aria-label={dict.recovery.dismiss}
                    className="shrink-0 rounded p-0.5 hover:opacity-75 cursor-pointer"
                  >
                    <X className="h-3 w-3" strokeWidth={1.7} />
                  </button>
                </div>
              )}
            </div>
          </div>
        ) : (
          /* 940-1099px Compact Tier: Single Collapsed Takeover Button */
          <div ref={takeoverRef} className="relative">
            <button
              type="button"
              aria-expanded={takeoverOpen}
              aria-label={`${dict.takeover.collapsed}: ${takeoverSummary}`}
              title={takeoverSummary}
              onClick={() => setTakeoverOpen((v) => !v)}
              className="inline-flex h-[30px] items-center gap-1.5 rounded-[9px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-2.5 text-[12px] font-medium text-[var(--text-primary)] shadow-[var(--shadow-sm)] transition-colors hover:bg-[var(--bg-subtle)] cursor-pointer"
            >
              <Shield className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.6} />
              <span>{dict.takeover.collapsed}</span>
              <span
                aria-hidden="true"
                className="h-2 w-2 rounded-full"
                style={{
                  backgroundColor: hasRecoveryFault
                    ? "var(--warning-dot)"
                    : activeTakeoverCount > 0
                      ? "var(--success-dot)"
                      : "var(--text-secondary)",
                }}
              />
              <ChevronDown className="h-3 w-3 text-[var(--text-secondary)]" strokeWidth={1.6} />
            </button>

            {takeoverOpen && (
              <div className="ui-popover absolute top-full right-0 z-50 mt-2 w-[304px] space-y-3 p-3.5">
                <div className="space-y-0.5">
                  <div className="text-[12.5px] font-semibold text-[var(--text-primary)]">
                    {dict.takeover.panelTitle}
                  </div>
                  <div
                    className="truncate text-[11.5px] text-[var(--text-secondary)]"
                    title={takeoverSummary}
                  >
                    {takeoverSummary}
                  </div>
                </div>

                <div className="flex items-center justify-between rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-3 py-2">
                  <div>
                    <div className="text-[12.5px] font-medium text-[var(--text-primary)]">
                      {dict.takeover.sysProxy}
                    </div>
                    <div className="text-[11px] text-[var(--text-secondary)]">
                      {dict.takeover.sysProxyHint}
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={sysProxyEnabled}
                    aria-label={dict.takeover.sysProxy}
                    onClick={onToggleSysProxy}
                    className="ui-switch"
                  >
                    <span className="ui-switch-knob" />
                  </button>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11.5px] text-[var(--text-secondary)]">
                    <span>{dict.capture.label}</span>
                    {captureMode === "apps" && enabledAppCount === 0 && (
                      <button
                        type="button"
                        onClick={() => {
                          setTakeoverOpen(false);
                          onOpenApps();
                        }}
                        className="font-medium underline cursor-pointer"
                        style={{ color: "var(--warning-text)" }}
                      >
                        {dict.capture.noAppsHint}
                      </button>
                    )}
                  </div>
                  <SegmentedControl
                    value={captureMode}
                    options={captureOptions}
                    onChange={onSelectCapture}
                    ariaLabel={dict.capture.label}
                    fullWidth
                    switching={captureSwitching}
                    switchingTarget={capturePendingTarget}
                  />
                </div>
              </div>
            )}

            {authPromptTarget && (
              <AuthPopover
                dict={dict}
                platform={platform}
                targetMode={authPromptTarget}
                busyLabel={authBusyLabel}
                onSelectOnce={onAuthOnce}
                onSelectInstall={onAuthInstall}
                onCancel={onAuthCancel}
                align="right"
              />
            )}
          </div>
        )}
      </div>

      {/* Right: Throughput (Down + Up) + Locale/Theme (or merged Appearance) + Native Window Controls */}
      <div className="flex shrink-0 items-center gap-0.5">
        <div className="mr-2 flex items-center gap-2.5 whitespace-nowrap font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
          <span
            className="inline-flex items-center gap-0.5"
            title={dict.monitor.downloadShort}
          >
            <ArrowDown
              className="h-3 w-3 shrink-0"
              style={{ color: "var(--success-text)" }}
              strokeWidth={1.6}
            />
            {formatSpeed(traffic.downBytesPerSec)}
          </span>
          <span
            className="inline-flex items-center gap-0.5"
            title={dict.monitor.uploadShort}
          >
            <ArrowUp
              className="h-3 w-3 shrink-0 text-[var(--text-secondary)]"
              strokeWidth={1.6}
            />
            {formatSpeed(traffic.upBytesPerSec)}
          </span>
        </div>

        {tier === "wide" ? (
          <>
            <button
              type="button"
              onClick={onToggleLocale}
              title={dict.titlebar.switchLang}
              className="ui-btn-ghost h-7 px-2 text-[11.5px] text-[var(--text-secondary)]"
            >
              <Languages className="h-3.5 w-3.5" strokeWidth={1.5} />
              <span className="font-mono num-tabular">{locale === "zh-CN" ? "ZH" : "EN"}</span>
            </button>

            <button
              type="button"
              onClick={onCycleTheme}
              title={dict.titlebar.switchTheme}
              aria-label={dict.titlebar.switchTheme}
              className="ui-btn-ghost h-7 w-7 rounded-full p-0 text-[var(--text-secondary)]"
            >
              {theme === "dark" ? (
                <Moon className="h-3.5 w-3.5" strokeWidth={1.5} />
              ) : theme === "light" ? (
                <Sun className="h-3.5 w-3.5" strokeWidth={1.5} />
              ) : (
                <Monitor className="h-3.5 w-3.5" strokeWidth={1.5} />
              )}
            </button>
          </>
        ) : (
          /* Medium & Compact Tiers: Combined Appearance (Locale + Theme) Popover */
          <div ref={appearanceRef} className="relative">
            <button
              type="button"
              onClick={() => setAppearanceOpen((v) => !v)}
              title={dict.titlebar.appearance}
              aria-label={dict.titlebar.appearance}
              aria-expanded={appearanceOpen}
              className="ui-btn-ghost h-7 w-7 rounded-[8px] p-0 text-[var(--text-secondary)]"
            >
              <SlidersHorizontal className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
            {appearanceOpen && (
              <div className="ui-popover absolute top-full right-0 z-50 mt-1.5 min-w-[232px] w-max max-w-[calc(100vw-24px)] space-y-1 p-1.5 text-[12px]">
                <button
                  type="button"
                  onClick={() => {
                    onToggleLocale();
                    setAppearanceOpen(false);
                  }}
                  className="flex w-full items-center justify-between gap-4 rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                >
                  <span className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap">
                    <Globe className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    <span>{dict.titlebar.switchLang}</span>
                  </span>
                  <span className="shrink-0 whitespace-nowrap font-mono text-[11px] text-[var(--text-secondary)]">
                    {locale === "zh-CN" ? "ZH" : "EN"}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    onCycleTheme();
                    setAppearanceOpen(false);
                  }}
                  className="flex w-full items-center justify-between gap-4 rounded-[8px] px-2.5 py-1.5 text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                >
                  <span className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap">
                    {theme === "dark" ? (
                      <Moon className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    ) : theme === "light" ? (
                      <Sun className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    ) : (
                      <Monitor className="h-3.5 w-3.5 shrink-0 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    )}
                    <span>{dict.titlebar.switchTheme}</span>
                  </span>
                  <span className="shrink-0 whitespace-nowrap font-mono text-[11px] text-[var(--text-secondary)]">
                    {theme === "dark"
                      ? dict.settings.themeDark
                      : theme === "light"
                        ? dict.settings.themeLight
                        : dict.settings.themeSystem}
                  </span>
                </button>
              </div>
            )}
          </div>
        )}

        {!isMac && (
          <>
            <div className="mx-1 h-3.5 w-px bg-[var(--border-hairline)]" />
            <button
              type="button"
              onClick={() => api.windowControls.minimize()}
              aria-label={dict.titlebar.minimize}
              className="inline-flex h-11 w-[46px] items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              <Minus className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
            <button
              type="button"
              onClick={async () => {
                await api.windowControls.toggleMaximize();
                setMaximized(await api.windowControls.isMaximized());
              }}
              aria-label={dict.titlebar.maximize}
              className="inline-flex h-11 w-[46px] items-center justify-center text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              {maximized ? (
                <Minimize2 className="h-3.5 w-3.5" strokeWidth={1.5} />
              ) : (
                <Maximize2 className="h-3.5 w-3.5" strokeWidth={1.5} />
              )}
            </button>
            <button
              type="button"
              onClick={() => api.windowControls.close()}
              aria-label={dict.titlebar.close}
              className="win-close-btn inline-flex h-11 w-[46px] items-center justify-center text-[var(--text-secondary)] transition-colors cursor-pointer"
            >
              <X className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
          </>
        )}
      </div>
    </header>
  );
}
