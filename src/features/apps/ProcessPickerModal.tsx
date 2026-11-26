import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search, X } from "lucide-react";
import { CustomSelect, type SelectGroup } from "../../components/CustomSelect";
import type { Dict } from "../../i18n";
import type { InstalledAppItem, ProcessInfoDto } from "../../types";
import { middleTruncate } from "../../utils/nodes";

interface ProcessPickerModalProps {
  dict: Dict;
  processes: ProcessInfoDto[];
  installedApps: InstalledAppItem[];
  targetGroups: SelectGroup[];
  defaultTarget?: string;
  onAddRules: (
    items: Array<{
      name: string;
      processName: string;
      exePath?: string | null;
      bundlePath?: string | null;
    }>,
    includeChildren: boolean,
    target: string,
  ) => void;
  onClose: () => void;
}

interface ProcessGroupNode {
  root: ProcessInfoDto;
  children: ProcessInfoDto[];
}

export function ProcessPickerModal({
  dict,
  processes,
  installedApps,
  targetGroups,
  defaultTarget = "follow",
  onAddRules,
  onClose,
}: ProcessPickerModalProps) {
  const [tab, setTab] = useState<"running" | "installed">("running");
  const [query, setQuery] = useState("");
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [expandedRoots, setExpandedRoots] = useState<Set<number>>(new Set());
  const [includeChildren, setIncludeChildren] = useState(true);
  const [target, setTarget] = useState(defaultTarget);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const groupedRunning = useMemo<ProcessGroupNode[]>(() => {
    const q = query.trim().toLowerCase();
    const byPid = new Map<number, ProcessInfoDto>(processes.map((p) => [p.pid, p]));
    const roots = new Map<number, ProcessGroupNode>();

    const findRootPid = (p: ProcessInfoDto): number => {
      let cur = p;
      const seen = new Set<number>([cur.pid]);
      while (byPid.has(cur.parentPid) && !seen.has(cur.parentPid)) {
        cur = byPid.get(cur.parentPid) as ProcessInfoDto;
        seen.add(cur.pid);
      }
      return cur.pid;
    };

    for (const p of processes) {
      const rootPid = findRootPid(p);
      const root = byPid.get(rootPid) ?? p;
      if (!roots.has(rootPid)) {
        roots.set(rootPid, { root, children: [] });
      }
      if (p.pid !== rootPid) {
        roots.get(rootPid)?.children.push(p);
      }
    }

    const list = Array.from(roots.values());
    if (!q) return list;
    return list.filter((g) => {
      const matchProc = (x: ProcessInfoDto) =>
        x.name.toLowerCase().includes(q) ||
        (x.exePath && x.exePath.toLowerCase().includes(q)) ||
        x.ancestorChain.some((a) => a.toLowerCase().includes(q));
      return matchProc(g.root) || g.children.some(matchProc);
    });
  }, [processes, query]);

  // Auto-expand groups with children on initial load for clear ancestor lineage visibility
  useEffect(() => {
    setExpandedRoots(
      new Set(groupedRunning.filter((g) => g.children.length > 0).map((g) => g.root.pid)),
    );
  }, [groupedRunning.length]);

  const filteredInstalled = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return installedApps;
    return installedApps.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.processName.toLowerCase().includes(q) ||
        a.path.toLowerCase().includes(q),
    );
  }, [installedApps, query]);

  const toggleSelect = (key: string) => {
    setSelectedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleSubmit = () => {
    const picked: Array<{
      name: string;
      processName: string;
      exePath?: string | null;
      bundlePath?: string | null;
    }> = [];

    for (const key of selectedKeys) {
      if (key.startsWith("proc:")) {
        const pid = Number(key.slice(5));
        const found = processes.find((p) => p.pid === pid);
        if (found) {
          picked.push({
            name: found.name.replace(/\.exe$/i, ""),
            processName: found.name,
            exePath: found.exePath,
          });
        }
      } else if (key.startsWith("app:")) {
        const pathVal = key.slice(4);
        const found = installedApps.find((a) => a.path === pathVal);
        if (found) {
          picked.push({
            name: found.name,
            processName: found.processName,
            exePath: found.path,
            bundlePath: found.bundlePath,
          });
        }
      }
    }

    if (picked.length > 0) {
      onAddRules(picked, includeChildren, target);
      onClose();
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: "var(--backdrop-scrim)" }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={dict.apps.pickerTitle}
        className="ui-modal flex max-h-[82vh] w-full max-w-[640px] flex-col overflow-hidden"
      >
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between border-b border-[var(--border-hairline)] px-5 py-3.5">
          <h2 className="text-[16px] font-semibold tracking-[-0.015em] text-[var(--text-primary)]">
            {dict.apps.pickerTitle}
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

        {/* Tabs & Search */}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] px-5 py-3">
          <div className="inline-flex rounded-[9px] border border-[var(--border-hairline)] bg-[var(--bg-subtle)] p-0.5 text-[12px]">
            <button
              type="button"
              onClick={() => setTab("running")}
              className={`rounded-[7px] px-3 py-1 font-medium transition-colors cursor-pointer ${
                tab === "running"
                  ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {dict.apps.pickerTabRunning}
            </button>
            <button
              type="button"
              onClick={() => setTab("installed")}
              className={`rounded-[7px] px-3 py-1 font-medium transition-colors cursor-pointer ${
                tab === "installed"
                  ? "bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {dict.apps.pickerTabInstalled}
            </button>
          </div>

          <div className="relative min-w-0 flex-1 sm:max-w-[260px]">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]"
              strokeWidth={1.5}
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={dict.apps.pickerSearchPh}
              className="ui-input h-8 w-full pr-3 pl-8 text-[12px]"
            />
          </div>
        </div>

        {/* Process Tree / Installed Apps Body */}
        <div className="proc-picker-container min-h-0 flex-1 overflow-y-auto px-3 py-2">
          {tab === "running" ? (
            groupedRunning.length === 0 ? (
              <div className="py-12 text-center text-[12.5px] text-[var(--text-secondary)]">
                {dict.apps.pickerEmpty}
              </div>
            ) : (
              <div className="space-y-1">
                {groupedRunning.map((grp) => {
                  const key = `proc:${grp.root.pid}`;
                  const checked = selectedKeys.has(key);
                  const expanded = expandedRoots.has(grp.root.pid);
                  const hasChildren = grp.children.length > 0;
                  return (
                    <div
                      key={grp.root.pid}
                      className="rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-surface)]"
                    >
                      <div className="proc-picker-row px-2.5 py-2 text-[12.5px] hover:bg-[var(--bg-hover)]">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleSelect(key)}
                          aria-label={grp.root.name}
                          className="h-3.5 w-3.5 accent-[var(--accent-primary)] cursor-pointer"
                        />
                        <div className="flex min-w-0 items-center gap-1.5">
                          {hasChildren ? (
                            <button
                              type="button"
                              onClick={() =>
                                setExpandedRoots((prev) => {
                                  const next = new Set(prev);
                                  if (next.has(grp.root.pid)) next.delete(grp.root.pid);
                                  else next.add(grp.root.pid);
                                  return next;
                                })
                              }
                              aria-label={expanded ? "Collapse" : "Expand"}
                              className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-[5px] text-[var(--text-secondary)] hover:bg-[var(--bg-selected)] cursor-pointer"
                            >
                              {expanded ? (
                                <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.6} />
                              ) : (
                                <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.6} />
                              )}
                            </button>
                          ) : (
                            <span className="inline-block h-5 w-5 shrink-0" />
                          )}
                          <span
                            className="truncate font-mono font-medium text-[var(--text-primary)]"
                            title={grp.root.name}
                          >
                            {grp.root.name}
                          </span>
                        </div>
                        <span className="font-mono text-[11.5px] num-tabular text-[var(--text-secondary)]">
                          PID {grp.root.pid}
                        </span>
                        <span
                          className="proc-col-path truncate font-mono text-[11px] text-[var(--text-tertiary)]"
                          title={grp.root.exePath ?? ""}
                        >
                          {middleTruncate(grp.root.exePath ?? "--", 36)}
                        </span>
                      </div>

                      {hasChildren && expanded && (
                        <div className="space-y-0.5 border-t border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-2.5 py-1.5">
                          {grp.children.map((ch) => {
                            const depth = Math.max(1, ch.ancestorChain.length - 1);
                            const chKey = `proc:${ch.pid}`;
                            const chChecked = selectedKeys.has(chKey);
                            return (
                              <div
                                key={ch.pid}
                                className="proc-picker-row py-1 text-[12px]"
                              >
                                <input
                                  type="checkbox"
                                  checked={chChecked}
                                  disabled={checked && includeChildren}
                                  onChange={() => toggleSelect(chKey)}
                                  aria-label={ch.name}
                                  className="h-3.5 w-3.5 accent-[var(--accent-primary)] cursor-pointer disabled:opacity-40"
                                />
                                <div
                                  className="flex min-w-0 items-center gap-1.5"
                                  style={{ paddingLeft: `${Math.min(depth * 14, 34)}px` }}
                                >
                                  <span className="font-mono text-[11px] text-[var(--text-tertiary)]">
                                    |-
                                  </span>
                                  <span
                                    className="truncate font-mono text-[var(--text-primary)]"
                                    title={ch.name}
                                  >
                                    {ch.name}
                                  </span>
                                  {includeChildren && (
                                    <span className="shrink-0 text-[11.5px] text-[var(--text-secondary)]">
                                      {dict.apps.pickerChildHint}
                                    </span>
                                  )}
                                </div>
                                <span className="font-mono text-[11px] num-tabular text-[var(--text-secondary)]">
                                  PID {ch.pid}
                                </span>
                                <span
                                  className="proc-col-path truncate font-mono text-[11px] text-[var(--text-tertiary)]"
                                  title={ch.exePath ?? ""}
                                >
                                  {middleTruncate(ch.exePath ?? "--", 32)}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )
          ) : filteredInstalled.length === 0 ? (
            <div className="py-12 text-center text-[12.5px] text-[var(--text-secondary)]">
              {dict.apps.pickerEmpty}
            </div>
          ) : (
            <div className="space-y-1">
              {filteredInstalled.map((app) => {
                const key = `app:${app.path}`;
                const checked = selectedKeys.has(key);
                return (
                  <label
                    key={app.path}
                    className="proc-picker-row rounded-[10px] border border-[var(--border-hairline)] bg-[var(--bg-surface)] px-2.5 py-2 text-[12.5px] hover:bg-[var(--bg-hover)] cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleSelect(key)}
                      className="h-3.5 w-3.5 accent-[var(--accent-primary)]"
                    />
                    <span className="truncate font-medium text-[var(--text-primary)]" title={app.name}>
                      {app.name}
                    </span>
                    <span
                      className="truncate font-mono text-[11px] text-[var(--text-secondary)]"
                      title={app.processName}
                    >
                      {app.processName}
                    </span>
                    <span
                      className="proc-col-path truncate font-mono text-[11px] text-[var(--text-tertiary)]"
                      title={app.bundlePath ?? app.path}
                    >
                      {middleTruncate(app.bundlePath ?? app.path, 34)}
                    </span>
                  </label>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-[var(--border-hairline)] bg-[var(--bg-subtle)] px-5 py-3">
          <div className="flex flex-wrap items-center gap-3">
            <label className="inline-flex items-center gap-2 text-[12px] text-[var(--text-primary)] cursor-pointer">
              <input
                type="checkbox"
                checked={includeChildren}
                onChange={(e) => setIncludeChildren(e.target.checked)}
                className="h-3.5 w-3.5 accent-[var(--accent-primary)]"
              />
              <span>{dict.apps.pickerIncludeChildren}</span>
            </label>
            <CustomSelect
              value={target}
              groups={targetGroups}
              onChange={setTarget}
              size="sm"
              className="w-48"
            />
          </div>

          <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} className="ui-btn-secondary h-8">
              {dict.nodes.cancel}
            </button>
            <button
              type="button"
              disabled={selectedKeys.size === 0}
              onClick={handleSubmit}
              className="ui-btn-primary h-8"
            >
              {selectedKeys.size === 1
                ? dict.apps.pickerAddSelectedOne
                : dict.apps.pickerAddSelected.replace("{count}", String(selectedKeys.size))}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
