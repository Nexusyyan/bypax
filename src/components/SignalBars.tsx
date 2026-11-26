interface SignalBarsProps {
  ms?: number | null;
  kind?: "tcping" | "real";
  className?: string;
}

export function latencyTier(
  ms?: number | null,
  kind: "tcping" | "real" = "real",
): { bars: number; colorVar: string } {
  if (ms == null || ms <= 0) {
    return { bars: 0, colorVar: "var(--latency-none)" };
  }
  const t1 = kind === "real" ? 120 : 80;
  const t2 = kind === "real" ? 260 : 180;
  const t3 = kind === "real" ? 500 : 350;
  if (ms <= t1) return { bars: 4, colorVar: "var(--latency-fast)" };
  if (ms <= t2) return { bars: 3, colorVar: "var(--latency-ok)" };
  if (ms <= t3) return { bars: 2, colorVar: "var(--latency-slow)" };
  return { bars: 1, colorVar: "var(--latency-bad)" };
}

/**
 * Dual-encoded latency indicator (1-4 signal bars + semantic color) so speed
 * tiers are immediately distinguishable without relying on color alone.
 */
export function SignalBars({ ms, kind = "real", className = "" }: SignalBarsProps) {
  const { bars, colorVar } = latencyTier(ms, kind);
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
              backgroundColor: lit ? colorVar : "var(--bg-track)",
            }}
          />
        );
      })}
    </span>
  );
}
