"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Database,
  Radar,
  RefreshCcw,
  Shield,
  Terminal,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type ModelInfo = {
  id: string;
  label: string;
  status: string;
};

type RawModelInfo = {
  id: number | string;
  model?: string;
  model_name?: string;
  base_url?: string;
};

type Overview = {
  metrics: {
    events: number;
    anomalies: number;
    audit_results: number;
    agents_observed: number;
  };
  severity_breakdown: Record<string, number>;
  top_rules: Array<{ rule: string; count: number }>;
  top_agents: Array<{ agent: string; count: number }>;
};

type EventItem = {
  id: number;
  timestamp_ns: number;
  event_type: number;
  pid: number;
  comm: string;
  agent_id?: string | null;
  object?: string | null;
  payload?: Record<string, unknown> | null;
};

type AnomalyItem = {
  id: number;
  anomaly_id: string;
  rule: string;
  severity: string;
  pid: number;
  comm: string;
  object?: string | null;
  reason?: string | null;
  details?: Record<string, unknown> | null;
};

type AuditItem = {
  id: number;
  rule: string;
  severity: string;
  pid: number;
  comm: string;
  request?: Record<string, unknown> | null;
  result?: Record<string, unknown> | null;
};

type Health = {
  status: string;
  monitor_root: string;
  sqlite_path: string;
  counts: Record<string, number>;
};

const modes = [
  { id: "baseline", label: "Rule Baseline" },
  { id: "correlation", label: "Correlation Only" },
  { id: "ours", label: "Ours" },
];

function fmtNs(ns: number) {
  return `${(ns / 1_000_000).toFixed(0)} ms`;
}

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

export function ShowcaseConsole() {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [selectedModel, setSelectedModel] = useState<string>("deepseek-chat");
  const [selectedMode, setSelectedMode] = useState<string>("ours");
  const [health, setHealth] = useState<Health | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyItem[]>([]);
  const [audits, setAudits] = useState<AuditItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchJson = async <T,>(path: string): Promise<T> => {
    const res = await fetch(path, { cache: "no-store" });
    if (!res.ok) {
      throw new Error(`${path} -> ${res.status}`);
    }
    return res.json();
  };

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthRes, modelsRes, overviewRes, eventsRes, anomaliesRes, auditsRes] = await Promise.all([
        fetchJson<Health>("/api/health"),
        fetchJson<{ models: RawModelInfo[] }>("/api/models"),
        fetchJson<Overview>("/api/overview"),
        fetchJson<{ events: EventItem[] }>("/api/events?limit=12"),
        fetchJson<{ anomalies: AnomalyItem[] }>("/api/anomalies?limit=8"),
        fetchJson<{ audit_results: AuditItem[] }>("/api/audit-results?limit=8"),
      ]);
      const normalizedModels = modelsRes.models.map((item) => ({
        id: String(item.model ?? item.id),
        label: item.model_name ?? item.model ?? String(item.id),
        status: item.base_url ? "configured" : "local",
      }));
      setHealth(healthRes);
      setModels(normalizedModels);
      setOverview(overviewRes);
      setEvents(eventsRes.events);
      setAnomalies(anomaliesRes.anomalies);
      setAudits(auditsRes.audit_results);
      if (normalizedModels.length && !normalizedModels.find((item) => item.id === selectedModel)) {
        setSelectedModel(normalizedModels[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const activeModel = useMemo(
    () => models.find((item) => item.id === selectedModel) ?? null,
    [models, selectedModel],
  );

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,rgba(43,95,255,0.16),transparent_32%),radial-gradient(circle_at_85%_18%,rgba(20,184,166,0.18),transparent_22%),linear-gradient(180deg,#07111f_0%,#0a1728_42%,#f4efe7_42%,#f7f3ec_100%)] text-slate-950">
      <section className="mx-auto flex min-h-screen w-full max-w-7xl flex-col px-6 pb-14 pt-8 sm:px-8 lg:px-10">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4 rounded-full border border-white/15 bg-white/8 px-5 py-3 text-sm text-white/82 shadow-[0_20px_60px_rgba(3,8,20,0.28)] backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-full bg-cyan-400/15 text-cyan-200 ring-1 ring-cyan-200/30">
              <Shield className="size-4" />
            </div>
            <div>
              <p className="font-semibold tracking-[0.18em] uppercase text-cyan-100/90">eBPF Multi-Agent Monitor</p>
              <p className="text-xs text-white/60">Read-only live showcase over real SQLite outputs</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="rounded-full border border-white/14 bg-white/10 px-3 py-1 text-xs text-white/70">
              {health?.status === "ok" ? "SQLite connected" : "Waiting for backend"}
            </div>
            <Button
              onClick={() => void load()}
              variant="outline"
              className="h-9 rounded-full border-white/20 bg-white/6 px-4 text-white hover:bg-white/12"
            >
              <RefreshCcw className="size-4" />
              Refresh
            </Button>
          </div>
        </div>

        <div className="grid gap-8 lg:grid-cols-[0.92fr_1.08fr]">
          <div className="space-y-6 text-white">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/25 bg-cyan-300/10 px-3 py-1 text-xs font-semibold tracking-[0.22em] uppercase text-cyan-100">
                <Activity className="size-3.5" />
                Real Monitor Data
              </div>
              <h1 className="max-w-4xl text-5xl font-semibold leading-[1.02] tracking-[-0.04em] sm:text-6xl">
                Frontend and backend isolated here. Data comes from the real monitor chain.
              </h1>
              <p className="max-w-2xl text-base leading-8 text-slate-200/88 sm:text-lg">
                This console reads actual anomalies, events, and audit results from the monitor project's SQLite output
                without modifying the main codebase.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-[1.75rem] border border-white/12 bg-white/8 p-5 backdrop-blur-xl">
                <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/72">Model View</p>
                <div className="mt-3">
                  <Select value={selectedModel} onValueChange={setSelectedModel}>
                    <SelectTrigger className="h-11 rounded-2xl border-white/10 bg-white/8 text-white">
                      <SelectValue placeholder="Select model" />
                    </SelectTrigger>
                    <SelectContent>
                      {models.map((model) => (
                        <SelectItem key={model.id} value={model.id}>
                          <span>{model.label}</span>
                          <span className="text-xs uppercase tracking-[0.2em] text-slate-400">{model.status}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <p className="mt-3 text-sm text-slate-300">
                  Active display model: <span className="font-semibold text-white">{activeModel?.label ?? "Unknown"}</span>
                </p>
              </div>

              <div className="rounded-[1.75rem] border border-white/12 bg-white/8 p-5 backdrop-blur-xl">
                <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/72">Analysis Mode</p>
                <div className="mt-3">
                  <Select value={selectedMode} onValueChange={setSelectedMode}>
                    <SelectTrigger className="h-11 rounded-2xl border-white/10 bg-white/8 text-white">
                      <SelectValue placeholder="Select mode" />
                    </SelectTrigger>
                    <SelectContent>
                      {modes.map((mode) => (
                        <SelectItem key={mode.id} value={mode.id}>
                          <span>{mode.label}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <p className="mt-3 text-sm text-slate-300">
                  This selector is for comparison view. It does not mutate the main monitor runtime.
                </p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {overview
                ? [
                    { label: "Events", value: overview.metrics.events, icon: Radar },
                    { label: "Anomalies", value: overview.metrics.anomalies, icon: AlertTriangle },
                    { label: "Audits", value: overview.metrics.audit_results, icon: BrainCircuit },
                    { label: "Agents", value: overview.metrics.agents_observed, icon: Database },
                  ].map((metric) => {
                    const Icon = metric.icon;
                    return (
                      <div key={metric.label} className="rounded-3xl border border-white/12 bg-white/8 p-5 backdrop-blur-xl">
                        <div className="flex items-center gap-2 text-cyan-100/78">
                          <Icon className="size-4" />
                          <p className="text-sm">{metric.label}</p>
                        </div>
                        <p className="mt-4 text-3xl font-semibold tracking-[-0.05em] text-white">{metric.value}</p>
                      </div>
                    );
                  })
                : null}
            </div>
          </div>

          <div className="rounded-[2rem] border border-white/12 bg-slate-950/72 p-5 text-white shadow-[0_30px_90px_rgba(2,6,23,0.44)] backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.22em] text-cyan-200/72">Backend Health</p>
                <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em]">Live data source status</h2>
              </div>
            </div>
            <div className="mt-5 space-y-4 text-sm text-slate-200/88">
              {error ? (
                <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 p-4 text-rose-100">{error}</div>
              ) : null}
              <div className="rounded-2xl border border-white/10 bg-white/6 p-4">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-400">Monitor root</p>
                <p className="mt-2 break-all text-slate-100">{health?.monitor_root ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/6 p-4">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-400">SQLite path</p>
                <p className="mt-2 break-all text-slate-100">{health?.sqlite_path ?? "-"}</p>
              </div>
              <div className="rounded-2xl border border-cyan-300/18 bg-cyan-300/10 p-4">
                <div className="flex items-center gap-2 font-medium text-cyan-50">
                  <Terminal className="size-4" />
                  Status payload
                </div>
                <pre className="mt-3 overflow-auto rounded-xl bg-slate-950/70 p-4 text-xs leading-6 text-cyan-100/90">
                  {loading ? "Loading..." : pretty(health)}
                </pre>
              </div>
            </div>
          </div>
        </div>

        <section className="mt-8 grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <div className="rounded-[2rem] border border-slate-200 bg-white/82 p-6 shadow-[0_24px_80px_rgba(15,23,42,0.08)]">
            <h3 className="text-2xl font-semibold tracking-[-0.04em] text-slate-950">Latest anomalies</h3>
            <div className="mt-5 space-y-3">
              {anomalies.map((item) => (
                <div key={item.id} className="rounded-2xl border border-slate-200 bg-slate-50/90 p-4">
                  <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.18em] text-slate-500">
                    <span>{item.rule}</span>
                    <span>{item.severity}</span>
                    <span>pid {item.pid}</span>
                  </div>
                  <p className="mt-2 text-sm font-semibold text-slate-950">{item.comm}</p>
                  <p className="mt-1 text-sm leading-6 text-slate-600">{item.reason}</p>
                  <p className="mt-2 text-xs text-slate-500">object: {item.object ?? "-"}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[2rem] border border-slate-200 bg-[#fff9f0] p-6 shadow-[0_24px_70px_rgba(148,100,23,0.08)]">
            <h3 className="text-2xl font-semibold tracking-[-0.04em] text-slate-950">Latest audit results</h3>
            <div className="mt-5 space-y-3">
              {audits.map((item) => (
                <div key={item.id} className="rounded-2xl border border-amber-100 bg-white/80 p-4">
                  <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.18em] text-amber-700/72">
                    <span>{item.rule}</span>
                    <span>{item.severity}</span>
                    <span>{item.comm}</span>
                  </div>
                  <p className="mt-3 text-sm text-slate-700">
                    decision: <span className="font-semibold text-slate-950">{String(item.result?.decision ?? "-")}</span>
                  </p>
                  <p className="mt-1 text-sm text-slate-700">
                    class: <span className="font-semibold text-slate-950">{String(item.result?.class ?? "-")}</span>
                  </p>
                  {item.result?.llm_review ? (
                    <pre className="mt-3 overflow-auto rounded-xl bg-slate-950 p-4 text-xs leading-6 text-cyan-100">
                      {pretty(item.result.llm_review)}
                    </pre>
                  ) : (
                    <p className="mt-3 text-sm text-slate-500">No llm_review payload on this record.</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mt-8 rounded-[2rem] border border-slate-200 bg-slate-950 p-6 text-white shadow-[0_28px_80px_rgba(2,6,23,0.34)]">
          <h3 className="text-2xl font-semibold tracking-[-0.04em]">Latest raw events</h3>
          <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {events.map((item) => (
              <div key={item.id} className="rounded-2xl border border-white/10 bg-white/6 p-4">
                <div className="flex items-center justify-between gap-3 text-xs uppercase tracking-[0.18em] text-slate-400">
                  <span>{item.comm}</span>
                  <span>{fmtNs(item.timestamp_ns)}</span>
                </div>
                <p className="mt-2 text-sm text-white">event_type {item.event_type} / pid {item.pid}</p>
                <p className="mt-1 text-sm text-slate-300">object: {item.object ?? "-"}</p>
                <pre className="mt-3 max-h-44 overflow-auto rounded-xl bg-slate-950/70 p-3 text-xs leading-5 text-cyan-100/88">
                  {pretty(item.payload)}
                </pre>
              </div>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
