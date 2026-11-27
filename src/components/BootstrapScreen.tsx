import { useEffect, useState } from "react";
import { AlertCircle, Maximize2, Minimize2, Minus, RotateCw, X } from "lucide-react";
import { api } from "../api/client";
import type { Dict } from "../i18n";
import type { PlatformKind } from "../types";
import { BrandLogo } from "./BrandLogo";

interface BootstrapScreenProps {
  dict: Dict;
  platform: PlatformKind | string;
  error: string | null;
  retrying: boolean;
  onRetry: () => void;
}

export function BootstrapScreen({
  dict,
  platform,
  error,
  retrying,
  onRetry,
}: BootstrapScreenProps) {
  const [maximized, setMaximized] = useState(false);
  const isMac = platform === "macos";

  useEffect(() => {
    const syncMax = () => {
      api.windowControls.isMaximized().then(setMaximized).catch(() => {});
    };
    syncMax();
    let unlisten: (() => void) | undefined;
    void api.windowControls.onResized(syncMax).then((fn) => {
      unlisten = fn;
    });
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[var(--bg-chrome)] select-none">
      {/* Minimal frameless drag bar aligned with TitleBar chrome geometry */}
      <header
        data-tauri-drag-region
        className={`relative z-30 flex h-11 shrink-0 items-center justify-between gap-2 bg-[var(--bg-chrome)] ${
          isMac ? "pr-3 pl-[76px]" : "pr-0 pl-3"
        }`}
      >
        <div data-tauri-drag-region className="flex min-w-0 items-center gap-2">
          <span className="flex h-[26px] w-[26px] shrink-0 items-center justify-center rounded-[8px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]">
            <BrandLogo variant="monochrome" className="h-[18px] w-[18px]" />
          </span>
          <span
            data-tauri-drag-region
            className="text-[13px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]"
          >
            {dict.appTitle}
          </span>
        </div>

        <div data-tauri-drag-region className="flex-1 self-stretch" />

        {!isMac && (
          <div className="flex shrink-0 items-center">
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
          </div>
        )}
      </header>

      {/* Inset Studio Slate canvas with mandatory 1px hairline border */}
      <main
        role="status"
        aria-live="polite"
        aria-busy={!error}
        className="flex min-h-0 flex-1 flex-col items-center justify-center rounded-tl-[14px] rounded-tr-[14px] border-t border-x border-[var(--border-hairline)] bg-[var(--bg-canvas)] px-6"
      >
        <div className="flex w-full max-w-[360px] flex-col items-center text-center">
          <BrandLogo variant="color" className="h-[68px] w-[68px]" />

          <h1 className="mt-4 text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
            {dict.appTitle}
          </h1>

          {error ? (
            <div className="mt-4 w-full space-y-3">
              <div
                className="flex items-start gap-2.5 rounded-[12px] border px-3.5 py-3 text-left"
                style={{
                  backgroundColor: "var(--danger-bg)",
                  borderColor: "var(--danger-border)",
                  color: "var(--danger-text-on-bg)",
                }}
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.7} />
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px] font-semibold">{dict.bootstrap.errorTitle}</div>
                  <p
                    className="mt-1 break-words font-mono text-[11.5px] leading-relaxed opacity-90 select-text"
                    title={error}
                  >
                    {error}
                  </p>
                </div>
              </div>

              <button
                type="button"
                disabled={retrying}
                onClick={onRetry}
                className="ui-btn-primary h-8 px-4"
              >
                <RotateCw
                  className={`h-3.5 w-3.5 ${retrying ? "animate-spin" : ""}`}
                  strokeWidth={1.6}
                />
                <span>{retrying ? dict.bootstrap.retrying : dict.bootstrap.retry}</span>
              </button>
            </div>
          ) : (
            <>
              <p className="mt-1.5 text-[13px] text-[var(--text-secondary)]">
                {dict.bootstrap.loadingTitle}
              </p>

              <div className="boot-track mt-5 w-48" aria-hidden="true">
                <div className="boot-indeterminate" />
              </div>

              <p className="mt-3 text-[11.5px] text-[var(--text-tertiary)]">
                {dict.bootstrap.loadingHint}
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
