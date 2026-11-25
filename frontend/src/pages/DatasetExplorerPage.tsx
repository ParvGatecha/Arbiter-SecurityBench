import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { arbiterApi, formatCategory } from "../api/client";
import { PaginationBar } from "../components/PaginationBar";
import { EmptyState, ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import { SeverityBadge } from "../components/StatusBadge";
import type {
  BenchmarkSummary,
  PaginatedTestCasesResponse,
  TestCase,
} from "../types/api";

export function DatasetExplorerPage() {
  const [searchParams] = useSearchParams();
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [selectedBench, setSelectedBench] = useState(
    searchParams.get("benchmarkId") || "",
  );
  const [selectedVersion, setSelectedVersion] = useState(
    searchParams.get("version") || "",
  );
  const [categoryFilter, setCategoryFilter] = useState("");
  const [difficultyFilter, setDifficultyFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [pageData, setPageData] = useState<PaginatedTestCasesResponse | null>(null);
  const [inspectedCase, setInspectedCase] = useState<TestCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadDataset = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const benchRes = await arbiterApi.listBenchmarks();
      setBenchmarks(benchRes.items);
      const active =
        benchRes.items.find(
          (b) =>
            b.benchmark_id === selectedBench &&
            (!selectedVersion || b.version === selectedVersion),
        ) ?? benchRes.items[0];
      if (!active) {
        setPageData(null);
        return;
      }
      if (!selectedBench) {
        setSelectedBench(active.benchmark_id);
        setSelectedVersion(active.version);
      }

      const tcRes = await arbiterApi.listBenchmarkTestCases(active.benchmark_id, {
        version: selectedVersion || active.version,
        category: categoryFilter || undefined,
        difficulty: difficultyFilter || undefined,
        severity: severityFilter || undefined,
        search: search || undefined,
        limit,
        offset,
      });
      setPageData(tcRes);
      setInspectedCase((prev) =>
        tcRes.items.find((tc) => tc.test_id === prev?.test_id) ?? tcRes.items[0] ?? null,
      );
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [
    selectedBench,
    selectedVersion,
    categoryFilter,
    difficultyFilter,
    severityFilter,
    search,
    limit,
    offset,
  ]);

  useEffect(() => {
    void loadDataset();
  }, [loadDataset]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dataset Explorer"
        subtitle="Inspect paginated adversarial and benign-control test cases, success criteria, and evaluation tags."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Select dataset suite"
              value={selectedBench ? `${selectedBench}::${selectedVersion}` : ""}
              onChange={(e) => {
                const [id, ver] = e.target.value.split("::");
                setSelectedBench(id);
                setSelectedVersion(ver);
                setOffset(0);
              }}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200"
            >
              {benchmarks.length === 0 && <option value="">No datasets loaded</option>}
              {benchmarks.map((b) => (
                <option key={`${b.benchmark_id}::${b.version}`} value={`${b.benchmark_id}::${b.version}`}>
                  {b.name} v{b.version}
                </option>
              ))}
            </select>

            <input
              type="search"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setOffset(0);
              }}
              placeholder="Search ID, prompt, tag..."
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500"
            />
          </div>
        }
      />

      {pageData && (
        <div className="flex flex-wrap items-center gap-2.5 rounded-lg border border-slate-800/80 bg-[#0c1017] p-3">
          <select
            aria-label="Category filter"
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setOffset(0);
            }}
            className="rounded border border-slate-700 bg-[#111620] px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="">All Categories</option>
            {pageData.categories.map((c) => (
              <option key={c} value={c}>
                {formatCategory(c)}
              </option>
            ))}
          </select>

          <select
            aria-label="Difficulty filter"
            value={difficultyFilter}
            onChange={(e) => {
              setDifficultyFilter(e.target.value);
              setOffset(0);
            }}
            className="rounded border border-slate-700 bg-[#111620] px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="">All Difficulties</option>
            {pageData.difficulties.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>

          <select
            aria-label="Severity filter"
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setOffset(0);
            }}
            className="rounded border border-slate-700 bg-[#111620] px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="">All Severities</option>
            {pageData.severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      )}

      {error !== null && <ErrorPanel error={error} onRetry={loadDataset} />}

      {loading ? (
        <LoadingPanel />
      ) : !pageData || pageData.items.length === 0 ? (
        <EmptyState
          title="No Matching Test Cases"
          description="Verify that a benchmark dataset is registered in the backend or adjust active filters."
        />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-4 lg:col-span-7">
            <div className="divide-y divide-slate-800/70">
              {pageData.items.map((tc) => {
                const active = inspectedCase?.test_id === tc.test_id;
                return (
                  <button
                    key={tc.test_id}
                    type="button"
                    onClick={() => setInspectedCase(tc)}
                    className={`flex w-full items-start justify-between gap-3 px-3 py-3 text-left text-xs transition-colors ${
                      active ? "rounded bg-[#141c2b]" : "hover:bg-slate-900/50"
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-slate-400">{tc.test_id}</span>
                        <span className="truncate font-medium text-slate-100">{tc.name}</span>
                      </div>
                      <div className="mt-1 text-slate-400">
                        {formatCategory(tc.category)} · {tc.difficulty} · {tc.attack_type}
                      </div>
                    </div>
                    <SeverityBadge severity={tc.severity} />
                  </button>
                );
              })}
            </div>

            <PaginationBar
              total={pageData.total}
              limit={limit}
              offset={offset}
              onPageChange={setOffset}
              onLimitChange={(next) => {
                setLimit(next);
                setOffset(0);
              }}
            />
          </div>

          <div className="lg:col-span-5">
            {inspectedCase && (
              <div className="sticky top-6 space-y-4 rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 text-xs">
                <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <div className="font-mono text-slate-400">{inspectedCase.test_id}</div>
                    <h2 className="mt-0.5 text-sm font-semibold text-slate-100">
                      {inspectedCase.name}
                    </h2>
                  </div>
                  <SeverityBadge severity={inspectedCase.severity} />
                </div>

                <p className="leading-relaxed text-slate-300">{inspectedCase.description}</p>

                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Adversarial Input Prompt
                  </div>
                  <pre className="mt-1.5 max-h-48 overflow-y-auto whitespace-pre-wrap rounded border border-slate-800 bg-[#07090d] p-3 font-mono text-[11px] text-slate-200">
                    {inspectedCase.input_prompt}
                  </pre>
                </div>

                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Expected Secure Behavior
                  </div>
                  <p className="mt-1 text-slate-300">
                    {inspectedCase.evaluation_criteria.expected_secure_behavior}
                  </p>
                </div>

                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Attack Success Criteria
                  </div>
                  <p className="mt-1 text-slate-300">
                    {inspectedCase.evaluation_criteria.attack_success_criteria}
                  </p>
                </div>

                <div className="flex flex-wrap gap-1.5 pt-1">
                  {inspectedCase.tags.map((tag) => (
                    <span
                      key={tag}
                      className="rounded border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-400"
                    >
                      #{tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
