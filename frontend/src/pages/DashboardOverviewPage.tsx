import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, Play, ShieldAlert } from "lucide-react";
import {
  arbiterApi,
  formatDateTime,
  formatPercent,
  formatScore,
} from "../api/client";
import { CategoryRateBarChart, SampleOutcomePieChart } from "../components/Charts";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  MetricCard,
  PageHeader,
} from "../components/StatePanels";
import { RunStatusBadge } from "../components/StatusBadge";
import type {
  BenchmarkRun,
  BenchmarkSummary,
  RunScoreReport,
  TargetSummary,
} from "../types/api";

export function DashboardOverviewPage() {
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [totalRuns, setTotalRuns] = useState(0);
  const [latestScore, setLatestScore] = useState<RunScoreReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [benchRes, targetRes, runsRes] = await Promise.all([
        arbiterApi.listBenchmarks(),
        arbiterApi.listTargets(),
        arbiterApi.listRuns({ limit: 10, offset: 0 }),
      ]);
      setBenchmarks(benchRes.items);
      setTargets(targetRes.items);
      setRuns(runsRes.items);
      setTotalRuns(runsRes.total_count);

      const latestScoredCandidate = runsRes.items.find(
        (r) => r.completed_tests > 0 || r.failed_tests > 0,
      );
      if (latestScoredCandidate) {
        try {
          const score = await arbiterApi.getRunScores(latestScoredCandidate.run_id);
          setLatestScore(score);
        } catch {
          setLatestScore(null);
        }
      } else {
        setLatestScore(null);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) {
    return (
      <>
        <PageHeader
          title="Security Posture Overview"
          subtitle="Live execution telemetry, category resistance rates, and registered assets."
        />
        <LoadingPanel />
      </>
    );
  }

  if (error) {
    return (
      <>
        <PageHeader title="Security Posture Overview" />
        <ErrorPanel error={error} onRetry={load} />
      </>
    );
  }

  const latestMetrics = latestScore?.overall_metrics;
  const totalTestCases = benchmarks.reduce((acc, b) => acc + b.test_count, 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Posture Overview"
        subtitle="Real-time telemetry from FastAPI benchmark runs, registered suites, and target adapters."
        actions={
          <Link
            to="/runs/new"
            className="inline-flex items-center gap-2 rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
          >
            <Play className="h-3.5 w-3.5" />
            New Benchmark Run
          </Link>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Registered Benchmarks"
          value={benchmarks.length}
          hint={`${totalTestCases} total test cases loaded`}
          tone="info"
        />
        <MetricCard
          label="Configured Targets"
          value={targets.length}
          hint="Adapters in TargetAdapterRegistry"
        />
        <MetricCard
          label="Executed Runs"
          value={totalRuns}
          hint={latestScore ? `Latest scored: ${latestScore.target_id}` : "No completed runs yet"}
        />
        <MetricCard
          label="Latest Security Score"
          value={latestMetrics ? formatScore(latestMetrics.security_score) : "N/A"}
          hint={
            latestMetrics
              ? `ASR ${formatPercent(latestMetrics.attack_success_rate)} · Coverage ${formatPercent(latestMetrics.evaluation_coverage)}`
              : "Execute a benchmark run to compute scores"
          }
          tone={
            latestMetrics?.security_score !== null && latestMetrics?.security_score !== undefined
              ? latestMetrics.security_score >= 80
                ? "good"
                : latestMetrics.security_score >= 50
                  ? "warn"
                  : "danger"
              : "neutral"
          }
        />
      </div>

      {latestScore ? (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 lg:col-span-2">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">
                  Category Resistance vs Attack Success
                </h2>
                <p className="text-xs text-slate-400">
                  Run <span className="font-mono text-slate-300">{latestScore.run_id}</span> · Target{" "}
                  <span className="font-mono text-slate-300">{latestScore.target_id}</span>
                </p>
              </div>
              <Link
                to={`/results?runId=${encodeURIComponent(latestScore.run_id)}`}
                className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300"
              >
                Full Analysis <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
            <CategoryRateBarChart categories={Object.values(latestScore.category_metrics)} />
          </div>

          <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
            <h2 className="text-sm font-semibold text-slate-100">Outcome Accounting</h2>
            <p className="mb-3 text-xs text-slate-400">
              {latestMetrics?.sample_counts.total_samples ?? 0} total samples in denominator
            </p>
            <SampleOutcomePieChart counts={latestMetrics?.sample_counts} />
            {latestMetrics?.score_capped_by_critical_policy && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" />
                Score capped by critical vulnerability safeguard.
              </div>
            )}
          </div>
        </div>
      ) : (
        <EmptyState
          title="No Benchmark Runs Executed Yet"
          description="Charts and security scores appear automatically once a real benchmark run executes against a registered target adapter."
          action={
            <Link
              to="/runs/new"
              className="inline-flex items-center gap-1.5 rounded-md border border-sky-500/40 bg-sky-500/15 px-3.5 py-2 text-xs font-medium text-sky-200 hover:bg-sky-500/25"
            >
              Launch Benchmark Run
            </Link>
          }
        />
      )}

      <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">Recent Benchmark Runs</h2>
          <Link to="/results" className="text-xs font-medium text-sky-400 hover:text-sky-300">
            Explore all scores
          </Link>
        </div>

        {runs.length === 0 ? (
          <EmptyState
            title="No Run History"
            description="Persisted benchmark runs from FastAPI will be listed here with execution progress and quick inspection links."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Run ID</th>
                  <th className="py-2.5 pr-4 font-medium">Benchmark</th>
                  <th className="py-2.5 pr-4 font-medium">Target</th>
                  <th className="py-2.5 pr-4 font-medium">Status</th>
                  <th className="py-2.5 pr-4 font-medium">Progress</th>
                  <th className="py-2.5 pr-4 font-medium">Created</th>
                  <th className="py-2.5 text-right font-medium">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {runs.map((run) => (
                  <tr key={run.run_id} className="hover:bg-slate-900/40">
                    <td className="py-2.5 pr-4 font-mono text-slate-200">{run.run_id}</td>
                    <td className="py-2.5 pr-4 text-slate-300">
                      {run.benchmark_id} <span className="text-slate-500">v{run.benchmark_version}</span>
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-slate-300">{run.target_id}</td>
                    <td className="py-2.5 pr-4">
                      <RunStatusBadge status={run.status} />
                    </td>
                    <td className="py-2.5 pr-4 tabular-nums text-slate-300">
                      {run.completed_tests}/{run.total_tests}
                      {run.failed_tests > 0 && (
                        <span className="ml-1.5 text-rose-400">({run.failed_tests} err)</span>
                      )}
                    </td>
                    <td className="py-2.5 pr-4 text-slate-400">{formatDateTime(run.created_at)}</td>
                    <td className="py-2.5 text-right">
                      <Link
                        to={`/runs/${encodeURIComponent(run.run_id)}`}
                        className="font-medium text-sky-400 hover:text-sky-300"
                      >
                        Details
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
