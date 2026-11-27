import { useEffect, useRef } from "react";
import { Loader2, ShieldCheck } from "lucide-react";
import type { Dict } from "../i18n";
import type { CaptureMode, PlatformKind } from "../types";

interface AuthPopoverProps {
  dict: Dict;
  platform: PlatformKind | string;
  targetMode: CaptureMode;
  busyLabel: string | null;
  onSelectOnce: () => void;
  onSelectInstall: () => void;
  onCancel: () => void;
  align?: "left" | "right" | "center";
}

export function AuthPopover({
  dict,
  platform,
  targetMode,
  busyLabel,
  onSelectOnce,
  onSelectInstall,
  onCancel,
  align = "center",
}: AuthPopoverProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const isMac = platform === "macos";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busyLabel) {
        onCancel();
      }
    };
    const onPointer = (e: MouseEvent) => {
      if (!busyLabel && ref.current && !ref.current.contains(e.target as Node)) {
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onPointer);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onPointer);
    };
  }, [busyLabel, onCancel]);

  const alignClass =
    align === "right"
      ? "right-0"
      : align === "left"
        ? "left-0"
        : "left-1/2 -translate-x-1/2";

  return (
    <div
      ref={ref}
      role="dialog"
      aria-label={targetMode === "tun" ? dict.authPopover.titleTun : dict.authPopover.title}
      className={`ui-popover absolute top-full ${alignClass} z-50 mt-2 w-[320px] max-w-[calc(100vw-24px)] p-3.5 text-left`}
    >
      <div className="mb-2.5 text-[13px] font-semibold text-[var(--text-primary)]">
        {targetMode === "tun" ? dict.authPopover.titleTun : dict.authPopover.title}
      </div>

      {busyLabel ? (
        <div className="flex items-center gap-2 rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-3 py-3 text-[12.5px] text-[var(--text-secondary)]">
          <Loader2 className="h-4 w-4 shrink-0 animate-spin text-[var(--accent-focus)]" strokeWidth={1.7} />
          <span>{busyLabel}</span>
        </div>
      ) : (
        <div className="space-y-2">
          {!isMac ? (
            <button
              type="button"
              onClick={onSelectOnce}
              className="flex w-full items-start gap-2.5 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-surface)] p-2.5 text-left transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
            >
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent-focus)]" strokeWidth={1.6} />
              <div className="min-w-0">
                <div className="text-[12.5px] font-semibold text-[var(--text-primary)]">
                  {dict.authPopover.once}
                </div>
                <div className="mt-0.5 text-[11.5px] leading-relaxed text-[var(--text-secondary)]">
                  {dict.authPopover.onceDesc}
                </div>
              </div>
            </button>
          ) : (
            <button
              type="button"
              onClick={onSelectInstall}
              className="flex w-full items-start gap-2.5 rounded-[10px] border border-[var(--border-strong)] bg-[var(--bg-surface)] p-2.5 text-left transition-colors hover:bg-[var(--bg-hover)] cursor-pointer"
            >
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent-focus)]" strokeWidth={1.6} />
              <div className="min-w-0">
                <div className="text-[12.5px] font-semibold text-[var(--text-primary)]">
                  {dict.service.macInstall}
                </div>
                <div className="mt-0.5 text-[11.5px] leading-relaxed text-[var(--text-secondary)]">
                  {dict.authPopover.macInstallDesc}
                </div>
              </div>
            </button>
          )}

          <div className="flex justify-end pt-1">
            <button
              type="button"
              onClick={onCancel}
              className="ui-btn-ghost h-7 px-2.5 text-[12px]"
            >
              {dict.authPopover.cancel}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
