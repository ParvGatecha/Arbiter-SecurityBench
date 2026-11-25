import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, Play } from "lucide-react";
import {
  arbiterApi,
  formatCategory,
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
import type { BenchmarkRun, RunScoreReport } from "../types/api";

export function SecurityResultsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState(searchParams.get("runId") || "");
  const [profile, setProfile] = useState<"default" | "weighted">("default");
  const [scoreReport, setScoreReport] = useState<RunScoreReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadRunsAndScore = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const runsRes = await arbiterApi.listRuns({ limit: 50, offset: 0 });
      setRuns(runsRes.items);
      const activeId = selectedRunId || runsRes.items[0]?.run_id || "";
      if (activeId) {
        if (!selectedRunId) setSelectedRunId(activeId);
        const report = await arbiterApi.getRunScores(activeId, profile);
        setScoreReport(report);
      } else {
        setScoreReport(null);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [selectedRunId, profile]);

  useEffect(() => {
    void loadRunsAndScore();
  }, [loadRunsAndScore]);

  const handleRunChange = (nextId: string) => {
    setSelectedRunId(nextId);
    setSearchParams({ runId: nextId });
  };

  const overall = scoreReport?.overall_metrics;
  const categories = scoreReport ? Object.values(scoreReport.category_metrics) : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Results"
        subtitle="Statistically grounded attack success rates, Wilson/Bootstrap confidence intervals, and category breakdowns."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Select benchmark run"
              value={selectedRunId}
              onChange={(e) => handleRunChange(e.target.value)}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              {runs.length === 0 && <option value="">No runs recorded</option>}
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.target_id} · {r.benchmark_id} v{r.benchmark_version} ({r.run_id.slice(0, 12)})
                </option>
              ))}
            </select>

            <select
              aria-label="Scoring profile"
              value={profile}
              onChange={(e) => setProfile(e.target.value as "default" | "weighted")}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
            >
              <option value="default">Strict Critical Guard (Default)</option>
              <option value="weighted">Weighted Uncapped</option>
            </select>
          </div>
        }
      />

      {error !== null && <ErrorPanel error={error} onRetry={loadRunsAndScore} />}

      {loading ? (
        <LoadingPanel />
      ) : !scoreReport || !overall ? (
        <EmptyState
          title="No Scored Runs Available"
          description="Execute a benchmark run against a registered target to inspect statistical security metrics and confidence intervals."
          action={
            <Link
              to="/runs/new"
              className="inline-flex items-center gap-1.5 rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
            >
              <Play className="h-3.5 w-3.5" />
              New Benchmark Run
            </Link>
          }
        />
      ) : (
        <>
          {scoreReport.warnings.length > 0 && (
            <div className="space-y-1.5 rounded-lg border border-amber-500/30 bg-amber-950/20 p-4 text-xs text-amber-200">
              {scoreReport.warnings.map((w) => (
                <div key={w} className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Composite Security Score"
              value={formatScore(overall.security_score)}
              hint={
                overall.score_capped_by_critical_policy
                  ? "Capped by critical/high vulnerability policy"
                  : `Profile: ${scoreReport.profile_id}`
              }
              tone={
                overall.security_score !== null
                  ? overall.security_score >= 80
                    ? "good"
                    : overall.security_score >= 50
                      ? "warn"
                      : "danger"
                  : "neutral"
              }
            />
            <MetricCard
              label="Attack Success Rate (ASR)"
              value={formatPercent(overall.attack_success_rate)}
              hint={
                overall.asr_wilson_ci
                  ? `95% Wilson CI [${formatPercent(overall.asr_wilson_ci.lower)}, ${formatPercent(overall.asr_wilson_ci.upper)}]`
                  : undefined
              }
              tone={overall.attack_success_rate && overall.attack_success_rate > 0 ? "danger" : "good"}
            />
            <MetricCard
              label="Attack Block Rate"
              value={formatPercent(overall.attack_block_rate)}
              hint={`${overall.sample_counts.blocked_attacks}/${overall.sample_counts.total_samples} blocked`}
              tone="good"
            />
            <MetricCard
              label="Evaluation Coverage"
              value={formatPercent(overall.evaluation_coverage)}
              hint={`Inconclusive ${formatPercent(overall.inconclusive_rate)} · Exec Err ${formatPercent(overall.execution_error_rate)}`}
              tone={overall.evaluation_coverage === 1 ? "info" : "warn"}
            />
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 lg:col-span-2">
              <h2 className="mb-3 text-sm font-semibold text-slate-100">
                Per-Category Block Rate &amp; Attack Success Rate
              </h2>
              <CategoryRateBarChart categories={categories} />
            </div>

            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h2 className="mb-3 text-sm font-semibold text-slate-100">Sample Denominator Breakdown</h2>
              <SampleOutcomePieChart counts={overall.sample_counts} />
            </div>
          </div>

          <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
            <h2 className="mb-4 text-sm font-semibold text-slate-100">Category Security Matrix</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                    <th className="py-2.5 pr-4 font-medium">Category</th>
                    <th className="py-2.5 pr-4 font-medium">Samples</th>
                    <th className="py-2.5 pr-4 font-medium">Score</th>
                    <th className="py-2.5 pr-4 font-medium">ASR</th>
                    <th className="py-2.5 pr-4 font-medium">Block Rate</th>
                    <th className="py-2.5 pr-4 font-medium">Severity-Wtd ASR</th>
                    <th className="py-2.5 pr-4 font-medium">95% Wilson CI</th>
                    <th className="py-2.5 font-medium">Critical / High</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {categories.map(({ category, metrics }) => (
                    <tr key={category} className="hover:bg-slate-900/40">
                      <td className="py-2.5 pr-4 font-medium text-slate-200">
                        {formatCategory(category)}
                      </td>
                      <td className="py-2.5 pr-4 tabular-nums text-slate-300">
                        {metrics.sample_counts.total_samples}
                      </td>
                      <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-200">
                        {formatScore(metrics.security_score)}
                      </td>
                      <td className="py-2.5 pr-4 tabular-nums text-rose-300">
                        {formatPercent(metrics.attack_success_rate)}
                      </td>
                      <td className="py-2.5 pr-4 tabular-nums text-emerald-300">
                        {formatPercent(metrics.attack_block_rate)}
                      </td>
                      <td className="py-2.5 pr-4 tabular-nums text-slate-300">
                        {formatPercent(metrics.severity_weighted_asr)}
                      </td>
                      <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-400">
                        {metrics.asr_wilson_ci
                          ? `[${formatPercent(metrics.asr_wilson_ci.lower)}, ${formatPercent(metrics.asr_wilson_ci.upper)}]`
                          : "N/A"}
                      </td>
                      <td className="py-2.5 tabular-nums text-slate-300">
                        {metrics.critical_compromises} crit / {metrics.high_compromises} high
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
