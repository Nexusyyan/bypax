import { useEffect, useMemo, useState } from "react";
import { ArrowRight, CheckCircle2, Play, Route, X } from "lucide-react";
import { parseFlagText } from "../../components/RegionFlag";
import { SegmentedControl } from "../../components/SegmentedControl";
import type { Dict } from "../../i18n";
import type {
  AppProxyRule,
  AppRuleTestQuery,
  AppRuleTestTrace,
  NodeIR,
} from "../../types";

interface DryRunDrawerProps {
  dict: Dict;
  appRules: AppProxyRule[];
  nodes: NodeIR[];
  mainNodeId?: string | null;
  initialProcess?: string;
  initialHost?: string;
  onRunTest: (query: AppRuleTestQuery) => Promise<AppRuleTestTrace | null>;
  onTestInRouting: (host: string) => void;
  onClose: () => void;
}

export function DryRunDrawer({
  dict,
  appRules,
  nodes,
  mainNodeId,
  initialProcess = "node.exe",
  initialHost = "api.openai.com",
  onRunTest,
  onTestInRouting,
  onClose,
}: DryRunDrawerProps) {
  const [processName, setProcessName] = useState(initialProcess);
  const [exePath, setExePath] = useState("");
  const [host, setHost] = useState(initialHost);
  const [port, setPort] = useState("443");
  const [protocol, setProtocol] = useState<"tcp" | "udp" | "quic">("tcp");
  const [busy, setBusy] = useState(false);
  const [trace, setTrace] = useState<AppRuleTestTrace | null>(null);

  useEffect(() => {
    setProcessName(initialProcess);
  }, [initialProcess]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const execute = async () => {
    setBusy(true);
    try {
      const parsedPort = Number.parseInt(port, 10);
      const res = await onRunTest({
        processName: processName.trim() || undefined,
        exePath: exePath.trim() || undefined,
        host: host.trim() || undefined,
        dstPort: Number.isFinite(parsedPort) ? parsedPort : undefined,
        protocol,
      });
      setTrace(res);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void execute();
    // Run initial trace on drawer open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // B2: Format all 3 dry-run trace steps and exit label via i18n templates from structured fields
  const localizedTrace = useMemo(() => {
    if (!trace) return null;

    const sortedRules = [...appRules].sort((a, b) => a.priority - b.priority);
    const matchedIdx = trace.matchedRuleId
      ? sortedRules.findIndex((r) => r.id === trace.matchedRuleId)
      : -1;
    const matchedRule = matchedIdx >= 0 ? sortedRules[matchedIdx] : null;
    const ruleIndex = matchedIdx >= 0 ? matchedIdx + 1 : 1;

    const step1 =
      trace.bypassedToRouting || !trace.matchedRuleName
        ? dict.tester.traceNoMatch
        : trace.matchedViaAncestor
          ? dict.tester.traceMatchedParent
              .replace("{index}", String(ruleIndex))
              .replace("{name}", trace.matchedRuleName)
              .replace("{parent}", trace.matchedViaAncestor)
          : dict.tester.traceMatchedRule
              .replace("{index}", String(ruleIndex))
              .replace("{name}", trace.matchedRuleName);

    const normalizedHost = host
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0];

    let matchedPattern = trace.matchedDomainPattern ?? null;
    let overrideAction = trace.domainOverrideAction ?? null;
    if (!matchedPattern && matchedRule && normalizedHost) {
      const domHit = matchedRule.domains.find((d) => {
        const needle = d.pattern.toLowerCase().replace(/^\*\./, "");
        return normalizedHost === needle || normalizedHost.endsWith(`.${needle}`);
      });
      if (domHit) {
        matchedPattern = domHit.pattern;
        overrideAction = domHit.action;
      }
    }

    const actionText = (act: string | null | undefined) => {
      if (act === "direct") return dict.apps.actionDirect;
      if (act === "reject") return dict.apps.actionReject;
      return dict.apps.actionProxy;
    };

    const step2 = trace.bypassedToRouting
      ? dict.tester.traceOverrideSkipped
      : matchedPattern
        ? dict.tester.traceOverrideHit
            .replace("{host}", normalizedHost || "*")
            .replace("{pattern}", matchedPattern)
            .replace("{action}", actionText(overrideAction))
        : dict.tester.traceOverrideNone;

    const regionNames = dict.routing.regions as Record<string, string>;
    const mainNode = nodes.find((n) => n.id === mainNodeId) ?? nodes[0] ?? null;
    const mainClean = mainNode
      ? parseFlagText(mainNode.remark, mainNode.region).cleanText
      : dict.nav.noNodeSelected;

    const formatTarget = (target: string, finalAct: string): string => {
      if (trace.bypassedToRouting || finalAct === "bypass") {
        return dict.tester.traceBypassed;
      }
      if (finalAct === "direct" || target === "direct") {
        return dict.apps.targetDirect;
      }
      if (finalAct === "reject" || target === "reject") {
        return dict.apps.targetReject;
      }
      if (target === "main") {
        return `${dict.apps.targetMain} \u00b7 ${mainClean}`;
      }
      if (target === "follow") {
        return `${dict.apps.targetFollowShort} \u00b7 ${mainClean}`;
      }
      if (target === "auto:ALL") {
        return dict.routing.optAutoAll;
      }
      if (target.startsWith("auto:")) {
        const code = target.slice(5).toUpperCase();
        return `${dict.routing.optAutoRegionPrefix} ${regionNames[code] ?? code}`;
      }
      if (target.startsWith("node:")) {
        const nid = target.slice(5);
        const found = nodes.find((n) => n.id === nid);
        return found
          ? parseFlagText(found.remark, found.region).cleanText
          : dict.apps.targetFallback;
      }
      const directNode = nodes.find((n) => n.id === target);
      if (directNode) {
        return parseFlagText(directNode.remark, directNode.region).cleanText;
      }
      return `${dict.apps.targetFollowShort} \u00b7 ${mainClean}`;
    };

    const step3 = formatTarget(trace.finalTarget, trace.finalAction);

    return { step1, step2, step3, badge: step3 };
  }, [trace, appRules, nodes, mainNodeId, host, dict]);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ backgroundColor: "var(--backdrop-scrim)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside
        role="dialog"
        aria-modal="true"
        aria-label={dict.tester.title}
        className="flex h-full w-full max-w-[400px] flex-col border-l border-[var(--border-strong)] bg-[var(--bg-surface)] shadow-[var(--shadow-card-lg)]"
      >
        <div className="flex shrink-0 items-center justify-between border-b border-[var(--border-hairline)] px-5 py-3.5">
          <h2 className="text-[16px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
            {dict.tester.title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label={dict.nodes.cancel}
            className="ui-btn-ghost h-7 w-7 p-0"
          >
            <X className="h-4 w-4" strokeWidth={1.5} />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
          <div className="space-y-3">
            <div className="space-y-1">
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.tester.processLabel}
              </label>
              <input
                type="text"
                value={processName}
                onChange={(e) => setProcessName(e.target.value)}
                placeholder={dict.tester.processPh}
                className="ui-input h-8 w-full px-3 font-mono text-[12px]"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.tester.pathLabel}
              </label>
              <input
                type="text"
                value={exePath}
                onChange={(e) => setExePath(e.target.value)}
                placeholder={dict.tester.pathPh}
                className="ui-input h-8 w-full px-3 font-mono text-[12px]"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                {dict.tester.hostLabel}
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder={dict.tester.hostPh}
                className="ui-input h-8 w-full px-3 font-mono text-[12px]"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                  {dict.tester.portLabel}
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  value={port}
                  onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, "").slice(0, 5))}
                  className="ui-input h-8 w-full px-3 font-mono text-[12px] num-tabular"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-[12px] font-medium text-[var(--text-primary)]">
                  {dict.tester.protocolLabel}
                </label>
                <SegmentedControl
                  value={protocol}
                  options={[
                    { value: "tcp", label: "TCP" },
                    { value: "udp", label: "UDP" },
                    { value: "quic", label: "QUIC" },
                  ]}
                  onChange={setProtocol}
                  ariaLabel={dict.tester.protocolLabel}
                  fullWidth
                />
              </div>
            </div>

            <button
              type="button"
              disabled={busy}
              onClick={() => void execute()}
              className="ui-btn-primary h-8 w-full"
            >
              <Play className="h-3.5 w-3.5" strokeWidth={1.6} />
              {dict.tester.runBtn}
            </button>
          </div>

          {/* 3-Step Vertical Routing Timeline (100% localized) */}
          {trace && localizedTrace && (
            <div className="space-y-3 rounded-[14px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-4">
              {(
                [
                  { step: 1, title: dict.tester.step1, body: localizedTrace.step1 },
                  { step: 2, title: dict.tester.step2, body: localizedTrace.step2 },
                  { step: 3, title: dict.tester.step3, body: localizedTrace.step3 },
                ] as const
              ).map((item, idx) => (
                <div key={item.step} className="relative flex gap-3">
                  <div className="flex flex-col items-center">
                    <span
                      className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full font-mono text-[11.5px] font-semibold num-tabular"
                      style={{
                        backgroundColor:
                          idx === 2 && !trace.bypassedToRouting
                            ? "var(--accent-primary)"
                            : "var(--bg-surface)",
                        color:
                          idx === 2 && !trace.bypassedToRouting
                            ? "var(--accent-primary-fg)"
                            : "var(--text-primary)",
                        border: "1px solid var(--border-strong)",
                      }}
                    >
                      {item.step}
                    </span>
                    {idx < 2 && (
                      <span className="my-1 w-px flex-1 bg-[var(--border-strong)]" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1 pb-2">
                    <div className="text-[11.5px] font-medium text-[var(--text-secondary)]">
                      {item.title}
                    </div>
                    <div className="mt-0.5 break-words text-[12.5px] font-medium text-[var(--text-primary)]">
                      {item.body}
                    </div>
                  </div>
                </div>
              ))}

              {trace.bypassedToRouting ? (
                <div className="space-y-2 border-t border-[var(--border-hairline)] pt-3 text-[12px] text-[var(--text-secondary)]">
                  <p>{dict.tester.noMatch}</p>
                  <button
                    type="button"
                    onClick={() => {
                      onTestInRouting(host.trim() || "api.openai.com");
                      onClose();
                    }}
                    className="ui-btn-secondary h-7 text-[11.5px]"
                  >
                    <Route className="h-3.5 w-3.5 text-[var(--text-secondary)]" strokeWidth={1.5} />
                    {dict.tester.testInRouting}
                    <ArrowRight className="h-3 w-3" strokeWidth={1.5} />
                  </button>
                </div>
              ) : (
                <div
                  className="flex items-center gap-2 rounded-[8px] border px-2.5 py-1.5 text-[12px] font-medium"
                  title={localizedTrace.badge}
                  style={{
                    borderColor:
                      trace.finalAction === "reject"
                        ? "var(--danger-border)"
                        : "var(--success-border)",
                    backgroundColor:
                      trace.finalAction === "reject"
                        ? "var(--danger-bg)"
                        : "var(--success-bg)",
                    color:
                      trace.finalAction === "reject"
                        ? "var(--danger-text-on-bg)"
                        : "var(--success-text)",
                  }}
                >
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" strokeWidth={1.6} />
                  <span className="truncate">{localizedTrace.badge}</span>
                </div>
              )}
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}
