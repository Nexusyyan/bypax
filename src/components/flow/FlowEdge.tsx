import { useState } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";
import { X } from "lucide-react";

export type FlowEdgeVariant =
  | "default"
  | "proxy"
  | "chain"
  | "direct"
  | "reject"
  | "hit"
  | "dimmed";

export interface BypaxFlowEdgeData extends Record<string, unknown> {
  variant?: FlowEdgeVariant;
  animated?: boolean;
  label?: string;
  removable?: boolean;
  removeLabel?: string;
  onRemove?: (edgeId: string) => void;
}

export type BypaxFlowEdge = Edge<BypaxFlowEdgeData, "bypaxEdge">;

function resolveEdgeVisual(variant: FlowEdgeVariant, selected: boolean, hovered: boolean) {
  if (variant === "dimmed") {
    return {
      stroke: "var(--border-strong)",
      strokeWidth: 1.35,
      opacity: 0.24,
      dasharray: undefined as string | undefined,
    };
  }
  if (variant === "hit") {
    return {
      stroke: "var(--accent-focus)",
      strokeWidth: 2.6,
      opacity: 1,
      dasharray: undefined as string | undefined,
    };
  }
  if (variant === "chain") {
    return {
      stroke: "var(--accent-focus)",
      strokeWidth: selected || hovered ? 2.5 : 2.1,
      opacity: 1,
      dasharray: undefined as string | undefined,
    };
  }
  if (variant === "direct") {
    return {
      stroke: "var(--success-dot)",
      strokeWidth: selected || hovered ? 2.35 : 1.85,
      opacity: 0.92,
      dasharray: undefined as string | undefined,
    };
  }
  if (variant === "reject") {
    return {
      stroke: "var(--danger-dot)",
      strokeWidth: selected || hovered ? 2.25 : 1.8,
      opacity: 0.9,
      dasharray: "5 4",
    };
  }
  if (variant === "proxy") {
    return {
      stroke: selected || hovered ? "var(--accent-focus)" : "var(--text-secondary)",
      strokeWidth: selected || hovered ? 2.35 : 1.8,
      opacity: selected || hovered ? 1 : 0.78,
      dasharray: undefined as string | undefined,
    };
  }
  return {
    stroke: selected || hovered ? "var(--accent-focus)" : "var(--border-strong)",
    strokeWidth: selected || hovered ? 2.1 : 1.55,
    opacity: selected || hovered ? 0.95 : 0.75,
    dasharray: undefined as string | undefined,
  };
}

export function FlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  selected,
  data,
  markerEnd,
}: EdgeProps<BypaxFlowEdge>) {
  const [hovered, setHovered] = useState(false);
  const variant: FlowEdgeVariant = data?.variant ?? "default";
  const animated = Boolean(data?.animated) && variant !== "dimmed";
  const removable = Boolean(data?.removable && data?.onRemove);
  const label = data?.label;

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature: 0.34,
  });

  const visual = resolveEdgeVisual(variant, Boolean(selected), hovered);
  const showRemove = removable && (hovered || Boolean(selected)) && variant !== "dimmed";
  const showLabel = Boolean(label) && variant !== "dimmed" && !showRemove;

  return (
    <g
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className="bypax-flow-edge-group"
    >
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        interactionWidth={22}
        className={animated ? "flow-edge-animated" : undefined}
        style={{
          stroke: visual.stroke,
          strokeWidth: visual.strokeWidth,
          opacity: visual.opacity,
          strokeDasharray: animated ? undefined : visual.dasharray,
          transition: "stroke 140ms ease, stroke-width 140ms ease, opacity 140ms ease",
        }}
      />

      {(showRemove || showLabel) && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: "all",
            }}
            className="nodrag nopan"
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
          >
            {showRemove ? (
              <button
                type="button"
                aria-label={data?.removeLabel ?? "Disconnect wire"}
                title={data?.removeLabel ?? "Disconnect wire"}
                onClick={(e) => {
                  e.stopPropagation();
                  data?.onRemove?.(id);
                }}
                className="flex h-6 w-6 items-center justify-center rounded-full border border-[var(--danger-border)] bg-[var(--bg-surface)] text-[var(--danger-text)] shadow-[var(--shadow-sm)] transition-colors hover:bg-[var(--danger-bg)] cursor-pointer"
              >
                <X className="h-3 w-3" strokeWidth={2} />
              </button>
            ) : (
              <span className="rounded-full border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2 py-0.5 font-mono text-[10.5px] font-medium text-[var(--text-secondary)] shadow-[var(--shadow-sm)]">
                {label}
              </span>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </g>
  );
}
