interface SignalBarsProps {
  ms?: number | null;
  className?: string;
}

export function latencyTier(ms?: number | null): { bars: number; colorVar: string } {
  if (ms == null) {
    return { bars: 0, colorVar: "var(--latency-none)" };
  }
  if (ms < 0) {
    return { bars: 0, colorVar: "var(--latency-bad)" };
  }
  if (ms <= 120) return { bars: 4, colorVar: "var(--latency-fast)" };
  if (ms <= 260) return { bars: 3, colorVar: "var(--latency-ok)" };
  if (ms <= 500) return { bars: 2, colorVar: "var(--latency-slow)" };
  return { bars: 1, colorVar: "var(--latency-bad)" };
}

/**
 * Dual-encoded latency indicator (1-4 signal bars + semantic color) so speed
 * tiers and unreachable `-1ms` failures are immediately distinguishable without
 * relying on color alone.
 */
export function SignalBars({ ms, className = "" }: SignalBarsProps) {
  const { bars, colorVar } = latencyTier(ms);
  const failed = ms != null && ms < 0;
  const heights = [4, 6, 8, 10];
  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 items-end gap-[1.5px] ${className}`}
      style={{ height: "10px" }}
    >
      {heights.map((h, i) => {
        const lit = i < bars;
        return (
          <span
            key={h}
            style={{
              width: "2px",
              height: `${h}px`,
              borderRadius: "1px",
              backgroundColor: lit
                ? colorVar
                : failed
                  ? "var(--danger-border)"
                  : "var(--bg-track)",
            }}
          />
        );
      })}
    </span>
  );
}
