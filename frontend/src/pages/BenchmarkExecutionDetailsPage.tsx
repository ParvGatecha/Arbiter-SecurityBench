import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { BarChart3, ChevronDown, ChevronRight, FileText, RefreshCw } from "lucide-react";
import { arbiterApi, extractResultOutcome, formatDateTime } from "../api/client";
import { PaginationBar } from "../components/PaginationBar";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  MetricCard,
  PageHeader,
} from "../components/StatePanels";
import {
  ExecutionStatusBadge,
  OutcomeBadge,
  RunStatusBadge,
} from "../components/StatusBadge";
import type { BenchmarkRun, TestExecutionResult } from "../types/api";

export function BenchmarkExecutionDetailsPage() {
  const { runId = "" } = useParams<{ runId: string }>();

  const [run, setRun] = useState<BenchmarkRun | null>(null);
  const [results, setResults] = useState<TestExecutionResult[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const [filteredTotal, setFilteredTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadRun = useCallback(async () => {
    if (!runId) return;
    setLoading(true);
    setError(null);
    try {
      const [runData, resData] = await Promise.all([
        arbiterApi.getRun(runId),
        arbiterApi.getRunResults(runId, {
          execution_status: statusFilter || undefined,
          verdict: verdictFilter || undefined,
          search: search || undefined,
          limit,
          offset,
        }),
      ]);
      setRun(runData);
      setResults(resData.results);
      setTotalResults(resData.total_results);
      setFilteredTotal(resData.filtered_total);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [runId, statusFilter, verdictFilter, search, limit, offset]);

  useEffect(() => {
    void loadRun();
  }, [loadRun]);

  useEffect(() => {
    if (!run || (run.status !== "pending" && run.status !== "running")) return;
    const timer = window.setInterval(() => {
      void loadRun();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [run, loadRun]);

  if (loading && !run) {
    return (
      <>
        <PageHeader title="Benchmark Execution Details" />
        <LoadingPanel />
      </>
    );
  }

  if (error) {
    return (
      <>
        <PageHeader title="Benchmark Execution Details" />
        <ErrorPanel error={error} onRetry={loadRun} />
      </>
    );
  }

  if (!run) {
    return (
      <EmptyState
        title="Run Not Found"
        description="The requested benchmark run could not be located in persistence."
      />
    );
  }

  const progressPct =
    run.total_tests > 0
      ? Math.round(((run.completed_tests + run.failed_tests) / run.total_tests) * 100)
      : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Execution ${run.run_id}`}
        subtitle={`Suite ${run.benchmark_id} v${run.benchmark_version} · Target ${run.target_id} (${run.target_type.toUpperCase()})`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void loadRun()}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111620] px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
            <Link
              to={`/results?runId=${encodeURIComponent(run.run_id)}`}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111620] px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              <BarChart3 className="h-3.5 w-3.5" />
              Security Scores
            </Link>
            <Link
              to={`/reports?runId=${encodeURIComponent(run.run_id)}`}
              className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-sky-400"
            >
              <FileText className="h-3.5 w-3.5" />
              View Report
            </Link>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-4">
          <div className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Execution Status
          </div>
          <div className="mt-2.5 flex items-center gap-2">
            <RunStatusBadge status={run.status} />
            <span className="text-xs tabular-nums text-slate-400">{progressPct}% processed</span>
          </div>
          <div className="mt-1 text-xs text-slate-500">Created {formatDateTime(run.created_at)}</div>
        </div>
        <MetricCard
          label="Completed Tests"
          value={`${run.completed_tests} / ${run.total_tests}`}
          hint={run.completed_at ? `Finished ${formatDateTime(run.completed_at)}` : "In progress"}
          tone="good"
        />
        <MetricCard
          label="Execution Errors"
          value={run.failed_tests}
          hint="Adapter failures or timeouts"
          tone={run.failed_tests > 0 ? "danger" : "neutral"}
        />
        <MetricCard
          label="Persisted Results"
          value={totalResults}
          hint="Stored TestExecutionResult records"
          tone="info"
        />
      </div>

      <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-sm font-semibold text-slate-100">Per-Test Execution Records</h2>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="search"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setOffset(0);
              }}
              placeholder="Search test ID or text..."
              className="rounded-md border border-slate-700 bg-[#111620] px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
            />
            <select
              aria-label="Filter by execution status"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setOffset(0);
              }}
              className="rounded-md border border-slate-700 bg-[#111620] px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="">All Exec Statuses</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="timed_out">Timed Out</option>
            </select>
            <select
              aria-label="Filter by verdict"
              value={verdictFilter}
              onChange={(e) => {
                setVerdictFilter(e.target.value);
                setOffset(0);
              }}
              className="rounded-md border border-slate-700 bg-[#111620] px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="">All Verdicts</option>
              <option value="successful_attack">Attack Succeeded</option>
              <option value="blocked_attack">Blocked</option>
              <option value="inconclusive">Inconclusive</option>
              <option value="execution_error">Execution Error</option>
              <option value="evaluation_failure">Eval Failure</option>
            </select>
          </div>
        </div>

        {results.length === 0 ? (
          <EmptyState
            title="No Execution Results Match Filters"
            description="Adjust filters or verify that test execution has completed."
          />
        ) : (
          <>
            <div className="divide-y divide-slate-800/70 rounded-md border border-slate-800 bg-[#080b10]">
              {results.map((item) => {
                const isOpen = expandedId === item.test_id;
                const outcome = extractResultOutcome(item);
                const evalPayload = item.evaluator_results[item.evaluator_results.length - 1];
                return (
                  <div key={item.test_id} className="text-xs">
                    <button
                      type="button"
                      onClick={() => setExpandedId(isOpen ? null : item.test_id)}
                      className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-900/50"
                    >
                      <div className="flex min-w-0 items-center gap-2.5">
                        {isOpen ? (
                          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                        )}
                        <span className="font-mono font-medium text-slate-200">{item.test_id}</span>
                        <span className="truncate text-slate-400">{item.input}</span>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <span className="font-mono tabular-nums text-slate-500">
                          {item.execution_time.toFixed(2)}s
                        </span>
                        <ExecutionStatusBadge status={item.execution_status} />
                        <OutcomeBadge outcome={outcome} />
                      </div>
                    </button>

                    {isOpen && (
                      <div className="space-y-3 border-t border-slate-800/80 bg-[#0b0f17] px-6 py-4">
                        <div>
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                            Adversarial Input
                          </div>
                          <pre className="mt-1 whitespace-pre-wrap rounded border border-slate-800 bg-[#07090d] p-2.5 font-mono text-[11px] text-slate-300">
                            {item.input}
                          </pre>
                        </div>
                        {item.output !== null && (
                          <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                              Target Response
                            </div>
                            <pre className="mt-1 whitespace-pre-wrap rounded border border-slate-800 bg-[#07090d] p-2.5 font-mono text-[11px] text-slate-300">
                              {item.output}
                            </pre>
                          </div>
                        )}
                        {evalPayload?.reasoning && (
                          <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                              Evaluator Reasoning
                            </div>
                            <p className="mt-1 text-xs text-slate-300">{evalPayload.reasoning}</p>
                          </div>
                        )}
                        {item.error_details && (
                          <div>
                            <div className="text-[11px] font-semibold uppercase tracking-wider text-rose-400">
                              Error Record
                            </div>
                            <pre className="mt-1 whitespace-pre-wrap rounded border border-rose-500/20 bg-rose-950/20 p-2.5 font-mono text-[11px] text-rose-200">
                              {JSON.stringify(item.error_details, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <PaginationBar
              total={filteredTotal}
              limit={limit}
              offset={offset}
              onPageChange={setOffset}
              onLimitChange={(next) => {
                setLimit(next);
                setOffset(0);
              }}
            />
          </>
        )}
      </div>
    </div>
  );
}
