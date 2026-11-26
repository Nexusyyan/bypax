import type { KeyboardEvent } from "react";
import { Loader2 } from "lucide-react";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  title?: string;
  disabled?: boolean;
  dotColor?: string;
}

interface SegmentedControlProps<T extends string> {
  value: T;
  options: ReadonlyArray<SegmentedOption<T>>;
  onChange: (next: T) => void;
  ariaLabel: string;
  surface?: "subtle" | "chrome";
  fullWidth?: boolean;
  switching?: boolean;
  switchingTarget?: T | null;
  className?: string;
}

export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  surface = "subtle",
  fullWidth = false,
  switching = false,
  switchingTarget = null,
  className = "",
}: SegmentedControlProps<T>) {
  const effectiveValue = switching && switchingTarget ? switchingTarget : value;
  const activeIdx = Math.max(
    0,
    options.findIndex((o) => o.value === effectiveValue),
  );
  const count = Math.max(1, options.length);

  const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (switching) return;
    let nextIdx = -1;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      nextIdx = (idx + 1) % count;
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      nextIdx = (idx - 1 + count) % count;
    } else if (e.key === "Home") {
      nextIdx = 0;
    } else if (e.key === "End") {
      nextIdx = count - 1;
    }
    if (nextIdx >= 0) {
      e.preventDefault();
      const target = options[nextIdx];
      if (target && !target.disabled && target.value !== value) {
        onChange(target.value);
      }
      const parent = e.currentTarget.parentElement;
      const buttons = parent?.querySelectorAll<HTMLButtonElement>('button[role="radio"]');
      buttons?.[nextIdx]?.focus();
    }
  };

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      style={{ gridTemplateColumns: `repeat(${count}, minmax(0, 1fr))` }}
      className={`ui-segmented ${surface === "chrome" ? "ui-segmented-chrome" : ""} ${
        fullWidth ? "grid w-full" : "inline-grid"
      } ${className}`}
    >
      <span
        aria-hidden="true"
        className="ui-seg-thumb"
        style={{
          width: `calc((100% - 4px) / ${count})`,
          transform: `translateX(${activeIdx * 100}%)`,
        }}
      />
      {options.map((opt, idx) => {
        const active = opt.value === effectiveValue;
        const isLoadingThis = switching && active;
        const isDisabled = Boolean(opt.disabled) || (switching && !active);
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            disabled={isDisabled}
            data-active={active ? "true" : "false"}
            title={opt.title}
            onClick={() => {
              if (!switching && !opt.disabled && opt.value !== value) {
                onChange(opt.value);
              }
            }}
            onKeyDown={(e) => handleKeyDown(e, idx)}
            className="ui-seg-item"
          >
            {isLoadingThis && (
              <Loader2 className="h-3 w-3 shrink-0 animate-spin" strokeWidth={2} />
            )}
            <span className="truncate">{opt.label}</span>
            {opt.dotColor && !isLoadingThis && (
              <span
                aria-hidden="true"
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{ backgroundColor: opt.dotColor }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
