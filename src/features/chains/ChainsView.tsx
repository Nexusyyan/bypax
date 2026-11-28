import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
} from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Gauge,
  Globe,
  Laptop,
  LayoutGrid,
  Maximize2,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Save,
  Search,
  Trash2,
  Unlink,
  Waypoints,
  X,
} from "lucide-react";
import { FlowEdge, type BypaxFlowEdge } from "../../components/flow/FlowEdge";
import { NodeLabel, RegionFlag } from "../../components/RegionFlag";
import { SignalBars } from "../../components/SignalBars";
import type { Dict } from "../../i18n";
import type { NodeIR, ProxyChain } from "../../types";
import {
  delayColorVar,
  formatLatency,
  middleTruncate,
  PROTO_BADGES,
  validateChainHops,
} from "../../utils/nodes";

const SOURCE_ID = "chain-source";
const SINK_ID = "chain-sink";
const HOP_PREFIX = "hop:";

interface ChainsViewProps {
  dict: Dict;
  nodes: NodeIR[];
  chains: ProxyChain[];
  mainNodeId?: string | null;
  initialChainId?: string | null;
  testingChainId: string | null;
  onSaveChain: (chain: ProxyChain) => Promise<ProxyChain | null>;
  onDeleteChain: (id: string) => Promise<void>;
  onTestChainDelay: (chainId: string) => Promise<void>;
  onSelectMainChain: (chainId: string) => Promise<void>;
  onGoToNodes: () => void;
}

interface EndpointNodeData extends Record<string, unknown> {
  kind: "source" | "sink";
  title: string;
  subtitle: string;
  connected: boolean;
  wirePending?: boolean;
  onClickWire?: () => void;
}

interface HopNodeData extends Record<string, unknown> {
  nodeId: string;
  node: NodeIR | null;
  roleLabel: string;
  wireLabel: string;
  hopIndex: number | null;
  connectedIn: boolean;
  connectedOut: boolean;
  missing: boolean;
  wireSourceActive: boolean;
  wireTargetCandidate: boolean;
  onRemoveHop: (nodeId: string) => void;
  onStartWire: (canvasId: string) => void;
  onCompleteWire: (canvasId: string) => void;
}

type ChainCanvasNode =
  | Node<EndpointNodeData, "chainEndpoint">
  | Node<HopNodeData, "chainHop">;

function ChainEndpointCard({ data }: NodeProps<Node<EndpointNodeData, "chainEndpoint">>) {
  const isSource = data.kind === "source";
  return (
    <div
      onClick={data.wirePending && data.onClickWire ? data.onClickWire : undefined}
      className={`w-[184px] rounded-[14px] border bg-[var(--bg-surface)] px-3.5 py-3 shadow-[var(--shadow-card)] transition-colors ${
        data.wirePending
          ? "border-[var(--accent-focus)] hit-ring cursor-pointer"
          : "border-[var(--border-strong)]"
      }`}
    >
      <div className="flex items-center gap-2.5">
        <span
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)]"
          style={{
            color: isSource ? "var(--accent-focus)" : "var(--success-text)",
          }}
        >
          {isSource ? (
            <Laptop className="h-4 w-4" strokeWidth={1.6} />
          ) : (
            <Globe className="h-4 w-4" strokeWidth={1.6} />
          )}
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-semibold text-[var(--text-primary)]">
            {data.title}
          </div>
          <div className="truncate text-[11px] text-[var(--text-secondary)]">
            {data.subtitle}
          </div>
        </div>
      </div>

      {isSource ? (
        <Handle
          id="out"
          type="source"
          position={Position.Right}
          className={`bypax-flow-handle ${data.connected ? "bypax-flow-handle-connected" : ""}`}
        />
      ) : (
        <Handle
          id="in"
          type="target"
          position={Position.Left}
          className={`bypax-flow-handle ${data.connected ? "bypax-flow-handle-success" : ""}`}
        />
      )}
    </div>
  );
}

function ChainHopCard({ data, selected }: NodeProps<Node<HopNodeData, "chainHop">>) {
  const node = data.node;
  const isWired = data.hopIndex !== null;

  return (
    <div
      onClick={() => {
        if (data.wireTargetCandidate) {
          data.onCompleteWire(`${HOP_PREFIX}${data.nodeId}`);
        }
      }}
      className={`w-[228px] rounded-[14px] border bg-[var(--bg-surface)] shadow-[var(--shadow-card)] transition-all ${
        data.missing
          ? "border-[var(--danger-border)]"
          : data.wireTargetCandidate
            ? "border-[var(--accent-focus)] hit-ring cursor-pointer"
            : selected || data.wireSourceActive
              ? "border-[var(--accent-focus)]"
              : isWired
                ? "border-[var(--border-strong)]"
                : "border-dashed border-[var(--border-strong)] opacity-85"
      }`}
    >
      <Handle
        id="in"
        type="target"
        position={Position.Left}
        className={`bypax-flow-handle ${data.connectedIn ? "bypax-flow-handle-connected" : ""}`}
      />

      <div className="flex items-center justify-between gap-1.5 border-b border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-3 py-1.5 rounded-t-[13px]">
        <span
          className="inline-flex items-center gap-1.5 truncate text-[11px] font-semibold"
          style={{
            color: data.missing
              ? "var(--danger-text)"
              : isWired
                ? "var(--accent-focus)"
                : "var(--text-secondary)",
          }}
        >
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{
              backgroundColor: data.missing
                ? "var(--danger-dot)"
                : isWired
                  ? "var(--accent-focus)"
                  : "var(--text-tertiary)",
            }}
          />
          <span className="truncate">{data.roleLabel}</span>
        </span>

        <div className="flex shrink-0 items-center gap-1">
          {node && (
            <span className="rounded-[5px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-1.5 py-0.5 font-mono text-[10.5px] font-medium text-[var(--text-secondary)]">
              {PROTO_BADGES[node.protocol]}
            </span>
          )}
          <button
            type="button"
            aria-label="Remove hop"
            onClick={(e) => {
              e.stopPropagation();
              data.onRemoveHop(data.nodeId);
            }}
            className="nodrag nopan flex h-6 w-6 items-center justify-center rounded-[6px] text-[var(--text-secondary)] transition-colors hover:bg-[var(--danger-bg-hover)] hover:text-[var(--danger-text-on-bg)] cursor-pointer"
          >
            <X className="h-3 w-3" strokeWidth={1.8} />
          </button>
        </div>
      </div>

      <div className="space-y-1.5 px-3 py-2.5">
        {node ? (
          <>
            <div className="min-w-0 text-[12.5px] font-semibold text-[var(--text-primary)]">
              <NodeLabel remark={node.remark} region={node.region} size="sm" />
            </div>
            <div className="flex items-center justify-between gap-2 text-[11px]">
              <span
                className="truncate font-mono text-[var(--text-secondary)]"
                title={`${node.server}:${node.port}`}
              >
                {middleTruncate(`${node.server}:${node.port}`, 22)}
              </span>
              <span className="inline-flex shrink-0 items-center gap-1 font-mono font-medium num-tabular">
                <SignalBars ms={node.realDelayMs} />
                <span style={{ color: delayColorVar(node.realDelayMs) }}>
                  {formatLatency(node.realDelayMs)}
                </span>
              </span>
            </div>
          </>
        ) : (
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-[var(--danger-text)]">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
            <span className="truncate font-mono">{data.nodeId}</span>
          </div>
        )}

        <div className="flex items-center justify-end pt-0.5">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              data.onStartWire(`${HOP_PREFIX}${data.nodeId}`);
            }}
            className={`nodrag nopan inline-flex items-center gap-1 rounded-[6px] border px-1.5 py-0.5 text-[10.5px] font-medium transition-colors cursor-pointer ${
              data.wireSourceActive
                ? "border-[var(--accent-focus)] bg-[var(--accent-soft)] text-[var(--accent-focus)]"
                : "border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <ArrowRight className="h-2.5 w-2.5" strokeWidth={1.8} />
            <span>{data.wireSourceActive ? "..." : data.wireLabel}</span>
          </button>
        </div>
      </div>

      <Handle
        id="out"
        type="source"
        position={Position.Right}
        className={`bypax-flow-handle ${data.connectedOut ? "bypax-flow-handle-connected" : ""}`}
      />
    </div>
  );
}

const NODE_TYPES = {
  chainEndpoint: ChainEndpointCard,
  chainHop: ChainHopCard,
};

const EDGE_TYPES = {
  bypaxEdge: FlowEdge,
};

/**
 * Traverses directed edges starting from `chain-source` to extract the ordered hop node IDs
 * and the set of active edges forming the chain pipeline.
 */
function extractPipelineFromEdges(edges: Edge[]): {
  orderedHops: string[];
  reachesSink: boolean;
  activeEdgeIds: Set<string>;
} {
  const outBySource = new Map<string, Edge>();
  for (const e of edges) {
    if (!outBySource.has(e.source)) {
      outBySource.set(e.source, e);
    }
  }
  const orderedHops: string[] = [];
  const activeEdgeIds = new Set<string>();
  const visited = new Set<string>([SOURCE_ID]);
  let cursor = SOURCE_ID;
  let reachesSink = false;

  while (true) {
    const edge = outBySource.get(cursor);
    if (!edge) break;
    activeEdgeIds.add(edge.id);
    if (edge.target === SINK_ID) {
      reachesSink = true;
      break;
    }
    if (visited.has(edge.target)) break;
    visited.add(edge.target);
    if (edge.target.startsWith(HOP_PREFIX)) {
      orderedHops.push(edge.target.slice(HOP_PREFIX.length));
    }
    cursor = edge.target;
  }

  return { orderedHops, reachesSink, activeEdgeIds };
}

function wouldCreateCycle(edges: Edge[], source: string, target: string): boolean {
  if (source === target) return true;
  const visited = new Set<string>([target]);
  const queue = [target];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const e of edges) {
      if (e.source === cur) {
        if (e.target === source) return true;
        if (!visited.has(e.target)) {
          visited.add(e.target);
          queue.push(e.target);
        }
      }
    }
  }
  return false;
}

function buildChainLayout(hops: string[]): {
  positions: Map<string, { x: number; y: number }>;
  edges: BypaxFlowEdge[];
} {
  const positions = new Map<string, { x: number; y: number }>();
  const spacing = 278;
  const startX = 258;
  const baseY = 156;
  positions.set(SOURCE_ID, { x: 24, y: baseY + 26 });

  const count = hops.length;
  hops.forEach((hopId, idx) => {
    const offsetY = count >= 3 && idx % 2 === 1 ? -14 : 0;
    positions.set(`${HOP_PREFIX}${hopId}`, {
      x: startX + idx * spacing,
      y: baseY + offsetY,
    });
  });

  positions.set(SINK_ID, {
    x: Math.max(560, startX + Math.max(count, 1) * spacing + 12),
    y: baseY + 26,
  });

  const edges: BypaxFlowEdge[] = [];
  if (hops.length > 0) {
    edges.push({
      id: `e:${SOURCE_ID}->${HOP_PREFIX}${hops[0]}`,
      type: "bypaxEdge",
      source: SOURCE_ID,
      sourceHandle: "out",
      target: `${HOP_PREFIX}${hops[0]}`,
      targetHandle: "in",
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      data: { variant: "chain", animated: true, removable: true },
    });
    for (let i = 0; i + 1 < hops.length; i += 1) {
      const from = `${HOP_PREFIX}${hops[i]}`;
      const to = `${HOP_PREFIX}${hops[i + 1]}`;
      edges.push({
        id: `e:${from}->${to}`,
        type: "bypaxEdge",
        source: from,
        sourceHandle: "out",
        target: to,
        targetHandle: "in",
        markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
        data: { variant: "chain", animated: true, removable: true },
      });
    }
    const last = `${HOP_PREFIX}${hops[hops.length - 1]}`;
    edges.push({
      id: `e:${last}->${SINK_ID}`,
      type: "bypaxEdge",
      source: last,
      sourceHandle: "out",
      target: SINK_ID,
      targetHandle: "in",
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      data: { variant: "chain", animated: true, removable: true },
    });
  }

  return { positions, edges };
}

function buildInitialChainGraph(
  chain: ProxyChain | null,
  nodeById: Map<string, NodeIR>,
  dict: Dict,
): { nodes: ChainCanvasNode[]; edges: BypaxFlowEdge[]; hops: string[] } {
  const hops = chain ? [...chain.hops] : [];
  const { positions, edges } = buildChainLayout(hops);
  const canvasNodes: ChainCanvasNode[] = [
    {
      id: SOURCE_ID,
      type: "chainEndpoint",
      position: positions.get(SOURCE_ID) ?? { x: 24, y: 182 },
      draggable: true,
      selectable: false,
      data: {
        kind: "source",
        title: dict.chains.nodeLocal,
        subtitle: dict.chains.nodeLocalSub,
        connected: hops.length > 0,
      },
    },
    ...hops.map((hopId) => ({
      id: `${HOP_PREFIX}${hopId}`,
      type: "chainHop" as const,
      position: positions.get(`${HOP_PREFIX}${hopId}`) ?? { x: 258, y: 156 },
      data: {
        nodeId: hopId,
        node: nodeById.get(hopId) ?? null,
        roleLabel: "",
        wireLabel: dict.chains.wireBtn,
        hopIndex: null,
        connectedIn: false,
        connectedOut: false,
        missing: !nodeById.has(hopId),
        wireSourceActive: false,
        wireTargetCandidate: false,
        onRemoveHop: () => {},
        onStartWire: () => {},
        onCompleteWire: () => {},
      },
    })),
    {
      id: SINK_ID,
      type: "chainEndpoint",
      position: positions.get(SINK_ID) ?? { x: 826, y: 182 },
      draggable: true,
      selectable: false,
      data: {
        kind: "sink",
        title: dict.chains.nodeInternet,
        subtitle: dict.chains.nodeInternetSub,
        connected: hops.length > 0,
      },
    },
  ];
  return { nodes: canvasNodes, edges, hops };
}

function ChainsStudioInner({
  dict,
  nodes,
  chains,
  mainNodeId,
  initialChainId,
  testingChainId,
  onSaveChain,
  onDeleteChain,
  onTestChainDelay,
  onSelectMainChain,
  onGoToNodes,
}: ChainsViewProps) {
  const { fitView, screenToFlowPosition } = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const initialChain =
    (initialChainId ? chains.find((c) => c.id === initialChainId) : null) ??
    chains[0] ??
    null;

  const initialGraph = useMemo(
    () => buildInitialChainGraph(initialChain, nodeById, dict),
    // Computed once for synchronous first-frame hydration
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const [selectedChainId, setSelectedChainId] = useState<string | null>(
    () => initialChain?.id ?? null,
  );
  const [draftId, setDraftId] = useState<string>(() => initialChain?.id ?? "");
  const [draftName, setDraftName] = useState<string>(
    () => initialChain?.name ?? dict.chains.defaultNewName,
  );
  const [placedNodeIds, setPlacedNodeIds] = useState<string[]>(() => initialGraph.hops);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState<boolean>(() => !initialChain);
  const [paletteOpen, setPaletteOpen] = useState(true);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteGroup, setPaletteGroup] = useState("ALL");
  const [wireSourceId, setWireSourceId] = useState<string | null>(null);
  const [fitTrigger, setFitTrigger] = useState(0);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<ChainCanvasNode>(
    initialGraph.nodes,
  );
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<BypaxFlowEdge>(
    initialGraph.edges,
  );

  // Fit viewport reliably once ReactFlow finishes measuring node dimensions
  useEffect(() => {
    if (!nodesInitialized) return;
    const timer = window.setTimeout(() => {
      void fitView({ padding: 0.2, maxZoom: 1.0, duration: 160 });
    }, 30);
    return () => window.clearTimeout(timer);
  }, [nodesInitialized, fitTrigger, fitView]);

  const activeSavedChain = useMemo(
    () => chains.find((c) => c.id === selectedChainId) ?? null,
    [chains, selectedChainId],
  );

  // Sync external initialChainId jump (e.g. from RoutingFlowCanvas chain card)
  useEffect(() => {
    if (initialChainId && chains.some((c) => c.id === initialChainId)) {
      setSelectedChainId(initialChainId);
    }
  }, [initialChainId, chains]);

  // Select first chain automatically when chains list changes and current selection vanished
  useEffect(() => {
    if (selectedChainId && !chains.some((c) => c.id === selectedChainId)) {
      setSelectedChainId(chains[0]?.id ?? null);
    } else if (!selectedChainId && !draftId && chains.length > 0 && !dirty) {
      setSelectedChainId(chains[0].id);
    }
  }, [chains, selectedChainId, draftId, dirty]);

  const loadChainIntoCanvas = useCallback(
    (chain: ProxyChain | null, isNewDraft = false) => {
      const built = buildInitialChainGraph(chain, nodeById, dict);
      setDraftId(chain ? chain.id : "");
      setDraftName(chain ? chain.name : isNewDraft ? dict.chains.defaultNewName : "");
      setPlacedNodeIds(built.hops);
      setWireSourceId(null);
      setDirty(isNewDraft);
      setRfNodes(built.nodes);
      setRfEdges(built.edges);
      setFitTrigger((n) => n + 1);
    },
    [dict, nodeById, setRfEdges, setRfNodes],
  );

  // Reload canvas whenever user switches selectedChainId
  const lastLoadedKeyRef = useRef<string | null>(
    initialChain
      ? `${initialChain.id}:${initialChain.hops.join(",")}:${initialChain.name}`
      : null,
  );
  useEffect(() => {
    const key = activeSavedChain
      ? `${activeSavedChain.id}:${activeSavedChain.hops.join(",")}:${activeSavedChain.name}`
      : "__empty__";
    if (lastLoadedKeyRef.current === key) return;
    if (!dirty || lastLoadedKeyRef.current === null) {
      lastLoadedKeyRef.current = key;
      if (activeSavedChain) {
        loadChainIntoCanvas(activeSavedChain, false);
      } else if (chains.length === 0) {
        loadChainIntoCanvas(null, true);
      }
    }
  }, [activeSavedChain, chains.length, dirty, loadChainIntoCanvas]);

  const pipeline = useMemo(() => extractPipelineFromEdges(rfEdges), [rfEdges]);

  const validation = useMemo(
    () => validateChainHops(pipeline.orderedHops, nodeById),
    [pipeline.orderedHops, nodeById],
  );

  const handleRemoveEdge = useCallback(
    (edgeId: string) => {
      setRfEdges((prev) => prev.filter((e) => e.id !== edgeId));
      setDirty(true);
    },
    [setRfEdges],
  );

  const handleRemoveHop = useCallback(
    (nodeId: string) => {
      const canvasId = `${HOP_PREFIX}${nodeId}`;
      setPlacedNodeIds((prev) => prev.filter((id) => id !== nodeId));
      setRfNodes((prev) => prev.filter((n) => n.id !== canvasId));
      setRfEdges((prev) => {
        const incoming = prev.find((e) => e.target === canvasId);
        const outgoing = prev.find((e) => e.source === canvasId);
        const filtered = prev.filter((e) => e.source !== canvasId && e.target !== canvasId);
        // Splice neighbor wire cleanly if removing an interior hop
        if (
          incoming &&
          outgoing &&
          !(incoming.source === SOURCE_ID && outgoing.target === SINK_ID)
        ) {
          filtered.push({
            id: `e:${incoming.source}->${outgoing.target}`,
            type: "bypaxEdge",
            source: incoming.source,
            sourceHandle: "out",
            target: outgoing.target,
            targetHandle: "in",
            markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
            data: { variant: "chain", animated: true, removable: true },
          });
        }
        return filtered;
      });
      setWireSourceId((prev) => (prev === canvasId ? null : prev));
      setDirty(true);
    },
    [setRfEdges, setRfNodes],
  );

  const connectPair = useCallback(
    (source: string, target: string) => {
      if (source === target) return;
      if (source === SINK_ID || target === SOURCE_ID) return;
      if (source === SOURCE_ID && target === SINK_ID) return;
      setRfEdges((prev) => {
        const cleaned = prev.filter((e) => e.source !== source && e.target !== target);
        if (wouldCreateCycle(cleaned, source, target)) {
          return prev;
        }
        return [
          ...cleaned,
          {
            id: `e:${source}->${target}`,
            type: "bypaxEdge",
            source,
            sourceHandle: "out",
            target,
            targetHandle: "in",
            markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
            data: { variant: "chain", animated: true, removable: true },
          },
        ];
      });
      setWireSourceId(null);
      setDirty(true);
    },
    [setRfEdges],
  );

  const onConnect = useCallback(
    (conn: Connection) => {
      if (!conn.source || !conn.target) return;
      connectPair(conn.source, conn.target);
    },
    [connectPair],
  );

  const isValidConnection = useCallback(
    (conn: Edge | Connection) => {
      if (!conn.source || !conn.target) return false;
      if (conn.source === conn.target) return false;
      if (conn.source === SINK_ID || conn.target === SOURCE_ID) return false;
      if (conn.source === SOURCE_ID && conn.target === SINK_ID) return false;
      const cleaned = rfEdges.filter(
        (e) => e.source !== conn.source && e.target !== conn.target,
      );
      return !wouldCreateCycle(cleaned, conn.source, conn.target);
    },
    [rfEdges],
  );

  const appendHopToCanvas = useCallback(
    (nodeId: string, dropPos?: { x: number; y: number }) => {
      if (placedNodeIds.includes(nodeId)) return;
      const canvasId = `${HOP_PREFIX}${nodeId}`;
      const existingOrdered = pipeline.orderedHops;
      const nextIndex = placedNodeIds.length;
      const pos = dropPos ?? {
        x: 280 + nextIndex * 286,
        y: 160 + (nextIndex % 2 === 1 ? -16 : 0),
      };

      setPlacedNodeIds((prev) => [...prev, nodeId]);
      setRfNodes((prev) => {
        const nextNodes: ChainCanvasNode[] = prev.map((n) => {
          if (n.id === SINK_ID && !dropPos) {
            return {
              ...n,
              position: {
                x: Math.max(n.position.x, pos.x + 300),
                y: n.position.y,
              },
            };
          }
          return n;
        });
        nextNodes.push({
          id: canvasId,
          type: "chainHop",
          position: pos,
          data: {
            nodeId,
            node: nodeById.get(nodeId) ?? null,
            roleLabel: "",
            wireLabel: dict.chains.wireBtn,
            hopIndex: null,
            connectedIn: false,
            connectedOut: false,
            missing: !nodeById.has(nodeId),
            wireSourceActive: false,
            wireTargetCandidate: false,
            onRemoveHop: () => {},
            onStartWire: () => {},
            onCompleteWire: () => {},
          },
        });
        return nextNodes;
      });

      // Automatically wire in sequence before Internet Target so 1-click `+` and drag-drop work smoothly
      setRfEdges((prev) => {
        const prevTail =
          existingOrdered.length > 0
            ? `${HOP_PREFIX}${existingOrdered[existingOrdered.length - 1]}`
            : SOURCE_ID;
        const filtered = prev.filter(
          (e) => !(e.source === prevTail && e.target === SINK_ID),
        );
        filtered.push(
          {
            id: `e:${prevTail}->${canvasId}`,
            type: "bypaxEdge",
            source: prevTail,
            sourceHandle: "out",
            target: canvasId,
            targetHandle: "in",
            markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
            data: { variant: "chain", animated: true, removable: true },
          },
          {
            id: `e:${canvasId}->${SINK_ID}`,
            type: "bypaxEdge",
            source: canvasId,
            sourceHandle: "out",
            target: SINK_ID,
            targetHandle: "in",
            markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
            data: { variant: "chain", animated: true, removable: true },
          },
        );
        return filtered;
      });

      setDirty(true);
      setFitTrigger((n) => n + 1);
    },
    [dict.chains.wireBtn, nodeById, pipeline.orderedHops, placedNodeIds, setRfEdges, setRfNodes],
  );

  // Hydrate reactive node & edge display data (role labels, wire states, callbacks)
  const renderedNodes = useMemo<ChainCanvasNode[]>(() => {
    const hopIndexMap = new Map<string, number>();
    pipeline.orderedHops.forEach((id, idx) => hopIndexMap.set(id, idx));
    const totalWired = pipeline.orderedHops.length;
    const sourcesWithOut = new Set(rfEdges.map((e) => e.source));
    const targetsWithIn = new Set(rfEdges.map((e) => e.target));

    return rfNodes.map((n) => {
      if (n.type === "chainEndpoint") {
        const isSource = n.id === SOURCE_ID;
        return {
          ...n,
          data: {
            ...n.data,
            title: isSource ? dict.chains.nodeLocal : dict.chains.nodeInternet,
            subtitle: isSource ? dict.chains.nodeLocalSub : dict.chains.nodeInternetSub,
            connected: isSource ? sourcesWithOut.has(SOURCE_ID) : targetsWithIn.has(SINK_ID),
            wirePending: !isSource && wireSourceId !== null && wireSourceId !== SOURCE_ID,
            onClickWire: !isSource
              ? () => {
                  if (wireSourceId) connectPair(wireSourceId, SINK_ID);
                }
              : undefined,
          },
        };
      }

      const hopId = n.data.nodeId;
      const idx = hopIndexMap.get(hopId) ?? null;
      let roleLabel = dict.chains.roleUnwired;
      if (idx !== null) {
        if (idx === 0) {
          roleLabel = dict.chains.roleEntry.replace("{index}", "1");
        } else if (idx === totalWired - 1 && totalWired >= 2) {
          roleLabel = dict.chains.roleExit.replace("{index}", String(idx + 1));
        } else {
          roleLabel = dict.chains.roleRelay.replace("{index}", String(idx + 1));
        }
      }

      return {
        ...n,
        data: {
          ...n.data,
          node: nodeById.get(hopId) ?? null,
          missing: !nodeById.has(hopId),
          roleLabel,
          wireLabel: dict.chains.wireBtn,
          hopIndex: idx,
          connectedIn: targetsWithIn.has(n.id),
          connectedOut: sourcesWithOut.has(n.id),
          wireSourceActive: wireSourceId === n.id,
          wireTargetCandidate: wireSourceId !== null && wireSourceId !== n.id,
          onRemoveHop: handleRemoveHop,
          onStartWire: (cid: string) =>
            setWireSourceId((prev) => (prev === cid ? null : cid)),
          onCompleteWire: (targetCid: string) => {
            if (wireSourceId) connectPair(wireSourceId, targetCid);
          },
        },
      };
    });
  }, [
    connectPair,
    dict.chains,
    handleRemoveHop,
    nodeById,
    pipeline.orderedHops,
    rfEdges,
    rfNodes,
    wireSourceId,
  ]);

  const renderedEdges = useMemo<BypaxFlowEdge[]>(() => {
    return rfEdges.map((e) => {
      const isPipeline = pipeline.activeEdgeIds.has(e.id);
      const edgeLabel =
        e.source === SOURCE_ID
          ? dict.chains.edgeEntry
          : e.target === SINK_ID
            ? dict.chains.edgeExit
            : dict.chains.edgeDetour;
      return {
        ...e,
        type: "bypaxEdge",
        markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
        data: {
          variant: isPipeline ? "chain" : "default",
          animated: isPipeline,
          label: edgeLabel,
          removable: true,
          removeLabel: dict.chains.disconnectEdge,
          onRemove: handleRemoveEdge,
        },
      };
    });
  }, [dict.chains, handleRemoveEdge, pipeline.activeEdgeIds, rfEdges]);

  const handleAutoLayout = useCallback(() => {
    const wiredSet = new Set(pipeline.orderedHops);
    const unwired = placedNodeIds.filter((id) => !wiredSet.has(id));
    const orderedAll = [...pipeline.orderedHops, ...unwired];
    const { positions } = buildChainLayout(orderedAll);

    setRfNodes((prev) =>
      prev.map((n) => {
        const nextPos = positions.get(n.id);
        return nextPos ? { ...n, position: nextPos } : n;
      }),
    );
    window.requestAnimationFrame(() => {
      void fitView({ padding: 0.22, duration: 220 });
    });
  }, [fitView, pipeline.orderedHops, placedNodeIds, setRfNodes]);

  const handleClearWires = () => {
    setRfEdges([]);
    setWireSourceId(null);
    setDirty(true);
  };

  const handleNewChain = () => {
    setSelectedChainId(null);
    lastLoadedKeyRef.current = "__new__";
    loadChainIntoCanvas(null, true);
  };

  const handleSave = async () => {
    const cleanName = draftName.trim();
    if (!cleanName || !validation.valid) return;
    setSaving(true);
    try {
      const payload: ProxyChain = {
        id: draftId,
        name: cleanName,
        hops: pipeline.orderedHops,
        enabled: activeSavedChain?.enabled ?? true,
        realDelayMs: activeSavedChain?.realDelayMs ?? null,
        description: activeSavedChain?.description ?? null,
        createdAt: activeSavedChain?.createdAt ?? new Date().toISOString(),
      };
      const saved = await onSaveChain(payload);
      if (saved) {
        setDraftId(saved.id);
        setSelectedChainId(saved.id);
        lastLoadedKeyRef.current = `${saved.id}:${saved.hops.join(",")}:${saved.name}`;
        setDirty(false);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const nodeId =
      e.dataTransfer.getData("application/bypax-node-id") ||
      e.dataTransfer.getData("text/plain");
    if (!nodeId || !nodeById.has(nodeId)) return;
    const pos = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    appendHopToCanvas(nodeId, { x: pos.x - 114, y: pos.y - 44 });
  };

  const groups = useMemo(
    () => ["ALL", ...Array.from(new Set(nodes.map((n) => n.group)))],
    [nodes],
  );

  const filteredPaletteNodes = useMemo(() => {
    const q = paletteQuery.trim().toLowerCase();
    return nodes.filter((n) => {
      if (paletteGroup !== "ALL" && n.group !== paletteGroup) return false;
      if (!q) return true;
      return (
        n.remark.toLowerCase().includes(q) ||
        n.server.toLowerCase().includes(q) ||
        PROTO_BADGES[n.protocol].toLowerCase().includes(q) ||
        n.region.toLowerCase().includes(q)
      );
    });
  }, [nodes, paletteGroup, paletteQuery]);

  const activeChainTarget = draftId ? `chain:${draftId}` : null;
  const isMainExit = Boolean(activeChainTarget && mainNodeId === activeChainTarget);
  const canSave = Boolean(draftName.trim()) && validation.valid && !saving;
  const isTestingCurrent = Boolean(draftId && testingChainId === draftId);

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Unified Single-Row 40px Page Header */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-4 py-2.5 lg:px-5">
        <div className="flex min-w-0 items-center gap-2.5">
          <h1 className="shrink-0 text-[18px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
            {dict.chains.title}
          </h1>

          {/* Chain Switcher Pills */}
          <div className="flex min-w-0 items-center gap-1 overflow-x-auto">
            {chains.map((c) => {
              const active = selectedChainId === c.id && draftId === c.id;
              return (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => {
                    setDirty(false);
                    setSelectedChainId(c.id);
                  }}
                  className={`inline-flex shrink-0 items-center gap-1.5 rounded-[9px] px-2.5 py-1 text-[12px] font-medium transition-colors cursor-pointer ${
                    active
                      ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                      : "border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <Waypoints className="h-3 w-3 shrink-0" strokeWidth={1.6} />
                  <span className="max-w-[140px] truncate">{c.name}</span>
                  <span className="font-mono text-[11px] opacity-80 num-tabular">
                    {c.hops.length}H
                  </span>
                </button>
              );
            })}
            <button
              type="button"
              onClick={handleNewChain}
              className="ui-btn-secondary h-7 shrink-0 px-2.5 text-[11.5px]"
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={1.6} />
              {dict.chains.newChain}
            </button>
          </div>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {draftId && (
            <>
              <button
                type="button"
                disabled={isTestingCurrent || dirty}
                onClick={() => void onTestChainDelay(draftId)}
                className="ui-btn-secondary h-8"
              >
                <Gauge className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                <span>
                  {isTestingCurrent ? dict.chains.testing : dict.chains.testLatency}
                </span>
                {activeSavedChain?.realDelayMs != null && !isTestingCurrent && (
                  <span
                    className="font-mono text-[11.5px] font-semibold num-tabular"
                    style={{ color: delayColorVar(activeSavedChain.realDelayMs) }}
                  >
                    {formatLatency(activeSavedChain.realDelayMs)}
                  </span>
                )}
              </button>

              <button
                type="button"
                disabled={dirty || !validation.valid}
                onClick={() => void onSelectMainChain(draftId)}
                className={isMainExit ? "ui-btn-primary h-8" : "ui-btn-secondary h-8"}
              >
                <Check className="h-3.5 w-3.5" strokeWidth={1.6} />
                {isMainExit ? dict.chains.activeMain : dict.chains.useAsMain}
              </button>
            </>
          )}

          <button
            type="button"
            disabled={!canSave}
            onClick={() => void handleSave()}
            className="ui-btn-primary h-8"
          >
            <Save className="h-3.5 w-3.5" strokeWidth={1.5} />
            <span>{dict.chains.saveBtn}</span>
            {dirty && (
              <span
                aria-hidden="true"
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: "var(--warning-dot)" }}
              />
            )}
          </button>

          {draftId && (
            <button
              type="button"
              aria-label={dict.chains.deleteBtn}
              title={dict.chains.deleteBtn}
              onClick={() => void onDeleteChain(draftId)}
              className="ui-btn-danger-ghost h-8 w-8 p-0"
            >
              <Trash2 className="h-3.5 w-3.5" strokeWidth={1.5} />
            </button>
          )}
        </div>
      </div>

      {/* Empty Nodes Guard */}
      {nodes.length < 2 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-[14px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)]">
            <Waypoints className="h-6 w-6" strokeWidth={1.5} />
          </div>
          <div className="text-[15px] font-semibold text-[var(--text-primary)]">
            {dict.chains.needNodesTitle}
          </div>
          <p className="max-w-md text-[12.5px] text-[var(--text-secondary)]">
            {dict.chains.needNodesDesc}
          </p>
          <button
            type="button"
            onClick={onGoToNodes}
            className="ui-btn-primary mt-1 h-9 px-4"
          >
            {dict.chains.goToNodes}
          </button>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 overflow-hidden">
          {/* Left Node Palette */}
          {paletteOpen && (
            <aside className="flex w-[248px] shrink-0 flex-col border-r border-[var(--border-hairline)] bg-[var(--bg-canvas)]">
              <div className="space-y-2 border-b border-[var(--border-hairline)] p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12px] font-semibold text-[var(--text-primary)]">
                    {dict.chains.paletteTitle}
                  </span>
                  <span className="font-mono text-[11px] text-[var(--text-secondary)] num-tabular">
                    {filteredPaletteNodes.length}
                  </span>
                </div>
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]"
                    strokeWidth={1.5}
                  />
                  <input
                    type="text"
                    value={paletteQuery}
                    onChange={(e) => setPaletteQuery(e.target.value)}
                    placeholder={dict.chains.paletteSearchPh}
                    className="ui-input h-8 w-full pr-2.5 pl-8 text-[12px]"
                  />
                </div>
                {groups.length > 2 && (
                  <div className="flex flex-wrap gap-1">
                    {groups.map((g) => {
                      const active = paletteGroup === g;
                      return (
                        <button
                          key={g}
                          type="button"
                          onClick={() => setPaletteGroup(g)}
                          className={`rounded-[6px] px-2 py-0.5 text-[11px] font-medium transition-colors cursor-pointer ${
                            active
                              ? "bg-[var(--accent-primary)] text-[var(--accent-primary-fg)]"
                              : "border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                          }`}
                        >
                          {g === "ALL" ? dict.nodes.groupAll : g}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto p-2.5">
                {filteredPaletteNodes.map((n) => {
                  const placedIdx = pipeline.orderedHops.indexOf(n.id);
                  const isPlaced = placedNodeIds.includes(n.id);
                  return (
                    <div
                      key={n.id}
                      draggable={!isPlaced}
                      onDragStart={(e) => {
                        e.dataTransfer.setData("application/bypax-node-id", n.id);
                        e.dataTransfer.setData("text/plain", n.id);
                        e.dataTransfer.effectAllowed = "copy";
                      }}
                      className={`group flex items-center justify-between gap-2 rounded-[10px] border px-2.5 py-2 text-[12px] transition-colors ${
                        isPlaced
                          ? "border-[var(--accent-focus)] bg-[var(--accent-soft)]"
                          : "border-[var(--border-hairline)] bg-[var(--bg-surface)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-hover)] cursor-grab active:cursor-grabbing"
                      }`}
                    >
                      <div className="min-w-0 flex-1 space-y-0.5">
                        <div className="min-w-0 font-medium text-[var(--text-primary)]">
                          <NodeLabel remark={n.remark} region={n.region} size="xs" />
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-[var(--text-secondary)] num-tabular">
                          <span>{PROTO_BADGES[n.protocol]}</span>
                          <span>{"\u00b7"}</span>
                          <span style={{ color: delayColorVar(n.realDelayMs) }}>
                            {formatLatency(n.realDelayMs)}
                          </span>
                        </div>
                      </div>

                      {isPlaced ? (
                        <span className="shrink-0 rounded-[6px] border border-[var(--border-strong)] bg-[var(--bg-surface)] px-1.5 py-0.5 font-mono text-[10.5px] font-semibold text-[var(--accent-focus)]">
                          {placedIdx >= 0 ? `#${placedIdx + 1}` : dict.chains.inCanvas}
                        </span>
                      ) : (
                        <button
                          type="button"
                          aria-label={`${dict.chains.addHop} ${n.remark}`}
                          onClick={() => appendHopToCanvas(n.id)}
                          className="ui-btn-secondary h-7 w-7 shrink-0 p-0"
                        >
                          <Plus className="h-3.5 w-3.5" strokeWidth={1.6} />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>

              <div className="border-t border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-3 py-2 text-[11px] text-[var(--text-secondary)]">
                {dict.chains.paletteHint}
              </div>
            </aside>
          )}

          {/* Center DIY Visual Canvas */}
          <div
            ref={wrapperRef}
            onDragOver={(e) => {
              e.preventDefault();
              e.dataTransfer.dropEffect = "copy";
            }}
            onDrop={handleDrop}
            className="relative flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden"
          >
            <ReactFlow
              nodes={renderedNodes}
              edges={renderedEdges}
              nodeTypes={NODE_TYPES}
              edgeTypes={EDGE_TYPES}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              isValidConnection={isValidConnection}
              onPaneClick={() => setWireSourceId(null)}
              fitView
              fitViewOptions={{ padding: 0.22 }}
              minZoom={0.45}
              maxZoom={1.6}
              deleteKeyCode={["Backspace", "Delete"]}
              className="bypax-flow h-full w-full"
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={18}
                size={1.2}
                color="var(--border-strong)"
              />
              <Controls showInteractive={false} position="bottom-left" />

              {/* Top-Left: Chain Name Editor & Palette Toggle */}
              <Panel position="top-left" className="m-3 flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPaletteOpen((v) => !v)}
                  aria-label={dict.chains.togglePalette}
                  title={dict.chains.togglePalette}
                  className="ui-btn-secondary h-8 w-8 p-0 shadow-[var(--shadow-sm)]"
                >
                  {paletteOpen ? (
                    <PanelLeftClose className="h-3.5 w-3.5" strokeWidth={1.5} />
                  ) : (
                    <PanelLeftOpen className="h-3.5 w-3.5" strokeWidth={1.5} />
                  )}
                </button>

                <div className="flex items-center gap-2 rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2.5 py-1 shadow-[var(--shadow-sm)]">
                  <label htmlFor="bypax-chain-name" className="sr-only">
                    {dict.chains.nameLabel}
                  </label>
                  <Waypoints
                    className="h-3.5 w-3.5 shrink-0 text-[var(--accent-focus)]"
                    strokeWidth={1.6}
                  />
                  <input
                    id="bypax-chain-name"
                    type="text"
                    value={draftName}
                    onChange={(e) => {
                      setDraftName(e.target.value);
                      setDirty(true);
                    }}
                    onKeyDown={(e) => {
                      if (e.nativeEvent.isComposing || e.keyCode === 229) return;
                      if (e.key === "Enter" && canSave) {
                        void handleSave();
                      }
                    }}
                    placeholder={dict.chains.namePlaceholder}
                    className="w-64 bg-transparent text-[12.5px] font-semibold text-[var(--text-primary)] outline-none placeholder:font-normal placeholder:text-[var(--text-tertiary)]"
                  />
                </div>
              </Panel>

              {/* Top-Right: Canvas Studio Controls */}
              <Panel position="top-right" className="m-3 flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={handleAutoLayout}
                  className="ui-btn-secondary h-8 text-[11.5px] shadow-[var(--shadow-sm)]"
                >
                  <LayoutGrid className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                  {dict.chains.autoLayout}
                </button>
                <button
                  type="button"
                  onClick={() => void fitView({ padding: 0.22, duration: 220 })}
                  aria-label={dict.chains.fitView}
                  title={dict.chains.fitView}
                  className="ui-btn-secondary h-8 w-8 p-0 shadow-[var(--shadow-sm)]"
                >
                  <Maximize2 className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                </button>
                <button
                  type="button"
                  onClick={handleClearWires}
                  className="ui-btn-secondary h-8 text-[11.5px] shadow-[var(--shadow-sm)]"
                >
                  <Unlink className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                  {dict.chains.clearWires}
                </button>
              </Panel>

              {/* Bottom-Center: Live Path Breadcrumb & Protocol Guard HUD */}
              <Panel position="bottom-center" className="mb-3 max-w-[90%]">
                <div className="flex flex-col items-center gap-1.5">
                  {validation.httpOverUdpWarnings.length > 0 && (
                    <div
                      className="flex items-center gap-1.5 rounded-[10px] border px-3 py-1.5 text-[11.5px] font-medium shadow-[var(--shadow-sm)]"
                      style={{
                        borderColor: "var(--warning-border)",
                        backgroundColor: "var(--warning-bg)",
                        color: "var(--warning-text)",
                      }}
                    >
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
                      <span>
                        {dict.chains.warnHttpOverUdp
                          .replace("{relay}", validation.httpOverUdpWarnings[0].relayRemark)
                          .replace("{next}", validation.httpOverUdpWarnings[0].nextRemark)}
                      </span>
                    </div>
                  )}

                  {validation.missingHopIds.length > 0 && (
                    <div
                      className="flex items-center gap-1.5 rounded-[10px] border px-3 py-1.5 text-[11.5px] font-medium shadow-[var(--shadow-sm)]"
                      style={{
                        borderColor: "var(--danger-border)",
                        backgroundColor: "var(--danger-bg)",
                        color: "var(--danger-text-on-bg)",
                      }}
                    >
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
                      <span>{dict.chains.warnMissingHop}</span>
                    </div>
                  )}

                  <div className="flex max-w-full flex-nowrap items-center gap-1.5 overflow-x-auto rounded-[12px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-3.5 py-2 text-[11.5px] whitespace-nowrap shadow-[var(--shadow-card)]">
                    {wireSourceId ? (
                      <span className="font-medium text-[var(--accent-focus)]">
                        {dict.chains.clickToWireHint}
                      </span>
                    ) : pipeline.orderedHops.length >= 2 ? (
                      <>
                        <span className="font-medium text-[var(--text-secondary)]">
                          {dict.chains.nodeLocal}
                        </span>
                        {pipeline.orderedHops.map((hid) => {
                          const hop = nodeById.get(hid);
                          return (
                            <span key={hid} className="inline-flex items-center gap-1.5">
                              <ArrowRight
                                className="h-3 w-3 text-[var(--text-tertiary)]"
                                strokeWidth={1.6}
                              />
                              <span className="inline-flex items-center gap-1 rounded-[6px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2 py-0.5 font-medium text-[var(--text-primary)]">
                                {hop ? (
                                  <>
                                    <RegionFlag code={hop.region} size="xs" />
                                    <span className="max-w-[130px] truncate">{hop.remark}</span>
                                  </>
                                ) : (
                                  <span className="font-mono text-[var(--danger-text)]">{hid}</span>
                                )}
                              </span>
                            </span>
                          );
                        })}
                        <ArrowRight
                          className="h-3 w-3 text-[var(--text-tertiary)]"
                          strokeWidth={1.6}
                        />
                        <span className="font-medium text-[var(--success-text)]">
                          {dict.chains.nodeInternet}
                        </span>
                      </>
                    ) : (
                      <span className="text-[var(--text-secondary)]">
                        {dict.chains.minHopsHint}
                      </span>
                    )}
                  </div>
                </div>
              </Panel>
            </ReactFlow>
          </div>
        </div>
      )}
    </section>
  );
}

export function ChainsView(props: ChainsViewProps) {
  return (
    <ReactFlowProvider>
      <ChainsStudioInner {...props} />
    </ReactFlowProvider>
  );
}
