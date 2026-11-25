import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, GitCompare } from "lucide-react";
import { arbiterApi, formatCategory, formatPercent, formatScore } from "../api/client";
import { ComparisonBarChart } from "../components/Charts";
import {
  EmptyState,
  ErrorPanel,
  LoadingPanel,
  MetricCard,
  PageHeader,
} from "../components/StatePanels";
import type { BenchmarkComparisonReport, BenchmarkRun } from "../types/api";

function formatDeltaPct(delta: number | null): string {
  if (delta === null || Number.isNaN(delta)) return "N/A";
  const sign = delta > 0 ? "+" : "";
  return `${sign}${(delta * 100).toFixed(1)}%`;
}

function formatDeltaScore(delta: number | null): string {
  if (delta === null || Number.isNaN(delta)) return "N/A";
  const sign = delta > 0 ? "+" : "";
  return `${sign}${delta.toFixed(1)}`;
}

export function ModelComparisonPage() {
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [baselineId, setBaselineId] = useState("");
  const [candidateId, setCandidateId] = useState("");
  const [profile, setProfile] = useState<"default" | "weighted">("default");
  const [comparison, setComparison] = useState<BenchmarkComparisonReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const loadRuns = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await arbiterApi.listRuns({ limit: 50, offset: 0 });
      setRuns(res.items);
      if (res.items.length >= 2) {
        setBaselineId((prev) => prev || res.items[1].run_id);
        setCandidateId((prev) => prev || res.items[0].run_id);
      } else if (res.items.length === 1) {
        setBaselineId(res.items[0].run_id);
        setCandidateId(res.items[0].run_id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  const runComparison = useCallback(async () => {
    if (!baselineId || !candidateId) return;
    setComparing(true);
    setError(null);
    try {
      const report = await arbiterApi.compareRuns({
        baseline_run_id: baselineId,
        candidate_run_id: candidateId,
        profile,
      });
      setComparison(report);
    } catch (err) {
      setComparison(null);
      setError(err);
    } finally {
      setComparing(false);
    }
  }, [baselineId, candidateId, profile]);

  useEffect(() => {
    if (baselineId && candidateId && runs.length >= 2 && baselineId !== candidateId) {
      void runComparison();
    }
  }, [baselineId, candidateId, runs.length, runComparison]);

  const deltas = comparison ? Object.values(comparison.category_comparisons) : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Model Comparison"
        subtitle="McNemar / Fisher statistical significance testing and Holm-Bonferroni regression detection across runs."
      />

      {loading ? (
        <LoadingPanel />
      ) : runs.length < 2 ? (
        <EmptyState
          title="At Least Two Runs Required"
          description="Execute at least two benchmark runs against compatible suite versions to run statistical model comparisons."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 sm:grid-cols-4">
            <div>
              <label
                htmlFor="baseline-run-select"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                Baseline Run
              </label>
              <select
                id="baseline-run-select"
                value={baselineId}
                onChange={(e) => setBaselineId(e.target.value)}
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-2.5 py-2 text-xs text-slate-100"
              >
                {runs.map((r) => (
                  <option key={r.run_id} value={r.run_id}>
                    {r.target_id} ({r.benchmark_id} v{r.benchmark_version}) · {r.run_id.slice(0, 10)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="candidate-run-select"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                Candidate Run
              </label>
              <select
                id="candidate-run-select"
                value={candidateId}
                onChange={(e) => setCandidateId(e.target.value)}
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-2.5 py-2 text-xs text-slate-100"
              >
                {runs.map((r) => (
                  <option key={r.run_id} value={r.run_id}>
                    {r.target_id} ({r.benchmark_id} v{r.benchmark_version}) · {r.run_id.slice(0, 10)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="compare-profile-select"
                className="block text-[11px] font-medium uppercase tracking-wider text-slate-400"
              >
                Scoring Profile
              </label>
              <select
                id="compare-profile-select"
                value={profile}
                onChange={(e) => setProfile(e.target.value as "default" | "weighted")}
                className="mt-1.5 w-full rounded-md border border-slate-700 bg-[#111620] px-2.5 py-2 text-xs text-slate-100"
              >
                <option value="default">Strict Critical Guard</option>
                <option value="weighted">Weighted Uncapped</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                type="button"
                disabled={comparing || !baselineId || !candidateId}
                onClick={() => void runComparison()}
                className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-sky-500 px-3 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:opacity-40"
              >
                <GitCompare className="h-3.5 w-3.5" />
                {comparing ? "Comparing..." : "Compare Runs"}
              </button>
            </div>
          </div>

          {error !== null && <ErrorPanel error={error} title="Comparison cannot be computed" />}

          {comparison && (
            <>
              <div
                className={`flex items-start gap-3 rounded-lg border p-4 text-xs ${
                  comparison.regression_detected
                    ? "border-rose-500/35 bg-rose-950/20 text-rose-200"
                    : "border-emerald-500/30 bg-emerald-950/15 text-emerald-200"
                }`}
              >
                {comparison.regression_detected ? (
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
                ) : (
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                )}
                <div>
                  <div className="font-semibold">
                    {comparison.regression_detected
                      ? "Security Regression Detected"
                      : "No Statistically Significant Regression Detected"}
                  </div>
                  {comparison.regression_warnings.length > 0 && (
                    <ul className="mt-1 list-disc space-y-0.5 pl-4 text-rose-200/90">
                      {comparison.regression_warnings.map((w) => (
                        <li key={w}>{w}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <MetricCard
                  label="Security Score Delta"
                  value={formatDeltaScore(comparison.security_score_delta)}
                  tone={
                    comparison.security_score_delta !== null
                      ? comparison.security_score_delta >= 0
                        ? "good"
                        : "danger"
                      : "neutral"
                  }
                />
                <MetricCard
                  label="ASR Delta"
                  value={formatDeltaPct(comparison.asr_delta)}
                  hint="Negative is safer"
                  tone={
                    comparison.asr_delta !== null
                      ? comparison.asr_delta <= 0
                        ? "good"
                        : "danger"
                      : "neutral"
                  }
                />
                <MetricCard
                  label="Block Rate Delta"
                  value={formatDeltaPct(comparison.block_rate_delta)}
                  tone={
                    comparison.block_rate_delta !== null
                      ? comparison.block_rate_delta >= 0
                        ? "good"
                        : "warn"
                      : "neutral"
                  }
                />
                <MetricCard
                  label="Overall p-value"
                  value={
                    comparison.overall_significance
                      ? comparison.overall_significance.p_value.toFixed(4)
                      : "N/A"
                  }
                  hint={comparison.overall_significance?.test_name}
                  tone="info"
                />
              </div>

              <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
                <h2 className="mb-3 text-sm font-semibold text-slate-100">
                  Category ASR Comparison ({comparison.baseline_target_id} vs{" "}
                  {comparison.candidate_target_id})
                </h2>
                <ComparisonBarChart
                  deltas={deltas}
                  baselineLabel={comparison.baseline_target_id}
                  candidateLabel={comparison.candidate_target_id}
                />
              </div>

              <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
                <h2 className="mb-4 text-sm font-semibold text-slate-100">
                  Category Statistical Comparison
                </h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                        <th className="py-2.5 pr-4 font-medium">Category</th>
                        <th className="py-2.5 pr-4 font-medium">Baseline ASR</th>
                        <th className="py-2.5 pr-4 font-medium">Candidate ASR</th>
                        <th className="py-2.5 pr-4 font-medium">ASR Delta</th>
                        <th className="py-2.5 pr-4 font-medium">Adj. p-value</th>
                        <th className="py-2.5 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {deltas.map((row) => (
                        <tr key={row.category} className="hover:bg-slate-900/40">
                          <td className="py-2.5 pr-4 font-medium text-slate-200">
                            {formatCategory(row.category)}
                          </td>
                          <td className="py-2.5 pr-4 tabular-nums text-slate-300">
                            {formatPercent(row.baseline_asr)}
                          </td>
                          <td className="py-2.5 pr-4 tabular-nums text-slate-300">
                            {formatPercent(row.candidate_asr)}
                          </td>
                          <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-200">
                            {formatDeltaPct(row.asr_delta)}
                          </td>
                          <td className="py-2.5 pr-4 font-mono tabular-nums text-slate-400">
                            {row.significance?.adjusted_p_value !== null &&
                            row.significance?.adjusted_p_value !== undefined
                              ? row.significance.adjusted_p_value.toFixed(4)
                              : formatScore(row.significance?.p_value ?? null, 4)}
                          </td>
                          <td className="py-2.5 capitalize text-slate-300">
                            {row.status.replace(/_/g, " ")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
