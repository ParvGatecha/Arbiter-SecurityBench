import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Layers, Play } from "lucide-react";
import { arbiterApi, formatCategory } from "../api/client";
import { EmptyState, ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import { SeverityBadge } from "../components/StatusBadge";
import type {
  BenchmarkDetailResponse,
  BenchmarkSummary,
  SecurityCategory,
  TargetModality,
} from "../types/api";

export function BenchmarkExplorerPage() {
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [modalityFilter, setModalityFilter] = useState<string>("");
  const [selected, setSelected] = useState<BenchmarkDetailResponse | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const loadList = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await arbiterApi.listBenchmarks({
        category: categoryFilter || undefined,
        target_type: modalityFilter || undefined,
      });
      setBenchmarks(res.items);
      if (res.items.length > 0) {
        const first = res.items[0];
        setDetailLoading(true);
        const detail = await arbiterApi.getBenchmark(first.benchmark_id, first.version);
        setSelected(detail);
        setSelectedVersion(detail.version);
      } else {
        setSelected(null);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
      setDetailLoading(false);
    }
  }, [categoryFilter, modalityFilter]);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const inspectSuite = async (benchmarkId: string, version?: string) => {
    setDetailLoading(true);
    setError(null);
    try {
      const detail = await arbiterApi.getBenchmark(benchmarkId, version);
      setSelected(detail);
      setSelectedVersion(detail.version);
    } catch (err) {
      setError(err);
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Benchmark Explorer"
        subtitle="Browse registered benchmark suites, semantic versions, supported target modalities, and attack coverage."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter by category"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as SecurityCategory | "")}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              <option value="">All Categories</option>
              <option value="prompt_injection">Prompt Injection</option>
              <option value="jailbreak_resistance">Jailbreak Resistance</option>
              <option value="system_prompt_extraction">System Prompt Extraction</option>
              <option value="sensitive_data_leakage">Sensitive Data Leakage</option>
              <option value="instruction_hierarchy_manipulation">Instruction Hierarchy</option>
              <option value="rag_security">RAG Security</option>
              <option value="agent_tool_abuse">Agent Tool Abuse</option>
              <option value="data_exfiltration">Data Exfiltration</option>
            </select>

            <select
              aria-label="Filter by target modality"
              value={modalityFilter}
              onChange={(e) => setModalityFilter(e.target.value as TargetModality | "")}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              <option value="">All Modalities</option>
              <option value="llm">LLM</option>
              <option value="rag">RAG</option>
              <option value="agent">Agent</option>
            </select>
          </div>
        }
      />

      {error !== null && <ErrorPanel error={error} onRetry={loadList} />}

      {loading ? (
        <LoadingPanel />
      ) : benchmarks.length === 0 ? (
        <EmptyState
          title="No Matching Benchmarks Registered"
          description="No benchmark suites matched the active filters in BenchmarkCoreRegistry."
        />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="space-y-3 lg:col-span-5">
            {benchmarks.map((suite) => {
              const isSelected =
                selected?.benchmark_id === suite.benchmark_id && selected?.version === suite.version;
              return (
                <button
                  key={`${suite.benchmark_id}:${suite.version}`}
                  type="button"
                  onClick={() => void inspectSuite(suite.benchmark_id, suite.version)}
                  className={`w-full rounded-lg border p-4 text-left transition-colors ${
                    isSelected
                      ? "border-sky-500/60 bg-[#111827]"
                      : "border-slate-800/90 bg-[#0c1017] hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Layers className="h-4 w-4 text-sky-400" />
                      <span className="text-sm font-semibold text-slate-100">{suite.name}</span>
                    </div>
                    <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[11px] text-slate-300">
                      v{suite.version}
                    </span>
                  </div>
                  <p className="mt-2 line-clamp-2 text-xs text-slate-400">{suite.description}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                    <span className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-slate-300">
                      {suite.test_count} tests
                    </span>
                    <span className="rounded bg-slate-800/80 px-2 py-0.5 uppercase">
                      {suite.supported_target_types.join(", ")}
                    </span>
                    <span className="rounded bg-emerald-500/10 px-2 py-0.5 capitalize text-emerald-300">
                      {suite.lifecycle_state}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-7">
            {detailLoading ? (
              <LoadingPanel message="Loading suite specification..." />
            ) : selected ? (
              <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
                <div className="flex flex-col gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <div className="text-xs font-mono text-slate-400">{selected.benchmark_id}</div>
                    <h2 className="mt-0.5 text-lg font-semibold text-slate-100">{selected.name}</h2>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">
                      {selected.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <select
                      aria-label="Select benchmark version"
                      value={selectedVersion}
                      onChange={(e) => void inspectSuite(selected.benchmark_id, e.target.value)}
                      className="rounded border border-slate-700 bg-[#111620] px-2.5 py-1.5 font-mono text-xs text-slate-200"
                    >
                      {selected.available_versions.map((v) => (
                        <option key={v} value={v}>
                          v{v}
                        </option>
                      ))}
                    </select>
                    <Link
                      to={`/runs/new?benchmarkId=${encodeURIComponent(selected.benchmark_id)}&version=${encodeURIComponent(selected.version)}`}
                      className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
                    >
                      <Play className="h-3.5 w-3.5" />
                      Run Suite
                    </Link>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-1.5">
                  {selected.categories.map((cat) => (
                    <span
                      key={cat}
                      className="rounded border border-slate-700/80 bg-slate-900 px-2 py-0.5 text-[11px] text-slate-300"
                    >
                      {formatCategory(cat)}
                    </span>
                  ))}
                </div>

                <div className="mt-5">
                  <div className="mb-2.5 flex items-center justify-between">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Test Cases Preview ({selected.test_cases.length})
                    </h3>
                    <Link
                      to={`/datasets?benchmarkId=${encodeURIComponent(selected.benchmark_id)}&version=${encodeURIComponent(selected.version)}`}
                      className="text-xs text-sky-400 hover:text-sky-300"
                    >
                      Open in Dataset Explorer
                    </Link>
                  </div>
                  <div className="max-h-96 divide-y divide-slate-800/70 overflow-y-auto rounded-md border border-slate-800 bg-[#080b10]">
                    {selected.test_cases.slice(0, 20).map((tc) => (
                      <div key={tc.test_id} className="flex items-start justify-between gap-3 p-3 text-xs">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-slate-400">{tc.test_id}</span>
                            <span className="font-medium text-slate-200">{tc.name}</span>
                          </div>
                          <p className="mt-1 line-clamp-1 text-slate-400">{tc.description}</p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] capitalize text-slate-300">
                            {tc.difficulty}
                          </span>
                          <SeverityBadge severity={tc.severity} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
