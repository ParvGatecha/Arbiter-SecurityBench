import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle, Download } from "lucide-react";
import { arbiterApi, formatCategory, formatPercent, formatScore } from "../api/client";
import { EmptyState, ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import { RunStatusBadge, SeverityBadge } from "../components/StatusBadge";
import type { BenchmarkRun, ReportDocument } from "../types/api";

export function ReportsPage() {
  const [searchParams] = useSearchParams();
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState(searchParams.get("runId") || "");
  const [baselineRunId, setBaselineRunId] = useState("");
  const [report, setReport] = useState<ReportDocument | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloadingFmt, setDownloadingFmt] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const runsRes = await arbiterApi.listRuns({ limit: 50, offset: 0 });
      setRuns(runsRes.items);
      const activeId = selectedRunId || runsRes.items[0]?.run_id || "";
      if (activeId) {
        if (!selectedRunId) setSelectedRunId(activeId);
        const doc = await arbiterApi.getReportDocument(activeId, {
          baseline_run_id: baselineRunId || undefined,
        });
        setReport(doc);
      } else {
        setReport(null);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [selectedRunId, baselineRunId]);

  useEffect(() => {
    void loadReport();
  }, [loadReport]);

  const handleDownload = async (fmt: "json" | "html" | "pdf" | "markdown") => {
    if (!selectedRunId) return;
    setDownloadingFmt(fmt);
    setError(null);
    try {
      await arbiterApi.downloadReport(selectedRunId, fmt, {
        baseline_run_id: baselineRunId || undefined,
      });
    } catch (err) {
      setError(err);
    } finally {
      setDownloadingFmt(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Reports"
        subtitle="Inspect reproducible 13-section audit reports and export JSON, HTML, PDF, or Markdown artifacts."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Select run for report"
              value={selectedRunId}
              onChange={(e) => setSelectedRunId(e.target.value)}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200"
            >
              {runs.length === 0 && <option value="">No runs available</option>}
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.target_id} · {r.run_id.slice(0, 12)}
                </option>
              ))}
            </select>

            <select
              aria-label="Optional baseline run"
              value={baselineRunId}
              onChange={(e) => setBaselineRunId(e.target.value)}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="">No Baseline Comparison</option>
              {runs
                .filter((r) => r.run_id !== selectedRunId)
                .map((r) => (
                  <option key={r.run_id} value={r.run_id}>
                    Baseline: {r.target_id} ({r.run_id.slice(0, 10)})
                  </option>
                ))}
            </select>
          </div>
        }
      />

      {error !== null && <ErrorPanel error={error} onRetry={loadReport} />}

      {loading ? (
        <LoadingPanel />
      ) : !report ? (
        <EmptyState
          title="No Reports Available"
          description="Execute a benchmark run to generate downloadable HTML, PDF, JSON, and Markdown security reports."
        />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-col justify-between gap-4 rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 sm:flex-row sm:items-center">
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-xs text-slate-400">
                  Schema v{report.report_schema_version}
                </span>
                <RunStatusBadge status={report.executive_summary.run_status} />
                {!report.executive_summary.is_complete_run && (
                  <span className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300">
                    <AlertTriangle className="h-3 w-3" />
                    Incomplete Run
                  </span>
                )}
              </div>
              <h2 className="mt-2 text-base font-semibold text-slate-100">
                {report.executive_summary.headline}
              </h2>
              {report.executive_summary.incomplete_run_reason && (
                <p className="mt-1 text-xs text-amber-300">
                  {report.executive_summary.incomplete_run_reason}
                </p>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {(["html", "pdf", "json", "markdown"] as const).map((fmt) => (
                <button
                  key={fmt}
                  type="button"
                  disabled={downloadingFmt !== null}
                  onClick={() => void handleDownload(fmt)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111620] px-3 py-1.5 text-xs font-medium uppercase text-slate-200 hover:border-sky-500/50 hover:bg-slate-800 disabled:opacity-50"
                >
                  <Download className="h-3.5 w-3.5 text-sky-400" />
                  {downloadingFmt === fmt ? "Exporting..." : fmt}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h3 className="text-sm font-semibold text-slate-100">
                Provenance &amp; Verification Split
              </h3>
              <dl className="mt-3 grid grid-cols-2 gap-3 text-xs">
                <div>
                  <dt className="text-slate-400">Target ID</dt>
                  <dd className="mt-0.5 font-mono text-slate-200">
                    {report.target_information.target_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Benchmark Version</dt>
                  <dd className="mt-0.5 font-mono text-slate-200">
                    {report.benchmark_version.benchmark_id} v
                    {report.benchmark_version.benchmark_version}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Verified Compromises</dt>
                  <dd className="mt-0.5 font-mono text-rose-300">
                    {report.executive_summary.deterministic_verified_compromises}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Evaluator Judgments</dt>
                  <dd className="mt-0.5 font-mono text-amber-300">
                    {report.executive_summary.evaluator_judgment_compromises}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Suite Digest</dt>
                  <dd className="mt-0.5 truncate font-mono text-[11px] text-slate-400">
                    {report.benchmark_version.suite_content_digest || "N/A"}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Scoring Profile</dt>
                  <dd className="mt-0.5 font-mono text-slate-300">
                    {report.benchmark_configuration.scoring_profile_id}
                  </dd>
                </div>
              </dl>
            </div>

            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h3 className="text-sm font-semibold text-slate-100">
                Category Summary ({report.category_results.length})
              </h3>
              <div className="mt-3 space-y-2 text-xs">
                {report.category_results.map((row) => (
                  <div
                    key={row.category}
                    className="flex items-center justify-between rounded border border-slate-800/70 bg-[#080b10] px-3 py-2"
                  >
                    <span className="font-medium text-slate-200">
                      {formatCategory(row.category)}
                    </span>
                    <div className="flex items-center gap-4 font-mono tabular-nums">
                      <span className="text-rose-300">
                        ASR {formatPercent(row.metrics.attack_success_rate)}
                      </span>
                      <span className="text-sky-300">
                        Score {formatScore(row.metrics.security_score)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {report.successful_attack_analysis.length > 0 && (
            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h3 className="mb-3 text-sm font-semibold text-slate-100">
                Successful Attack Findings ({report.successful_attack_analysis.length})
              </h3>
              <div className="space-y-2.5 text-xs">
                {report.successful_attack_analysis.slice(0, 10).map((finding) => (
                  <div
                    key={finding.test_id}
                    className="rounded border border-slate-800 bg-[#080b10] p-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono font-medium text-slate-200">
                        {finding.test_id} — {finding.test_name}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300">
                          {finding.verification_classification.replace(/_/g, " ")}
                        </span>
                        <SeverityBadge severity={finding.severity} />
                      </div>
                    </div>
                    <p className="mt-1.5 text-slate-400">{finding.reasoning}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h3 className="text-sm font-semibold text-slate-100">Recommendations</h3>
              <ul className="mt-3 list-disc space-y-1.5 pl-4 text-xs text-slate-300">
                {report.recommendations.map((rec) => (
                  <li key={rec}>{rec}</li>
                ))}
              </ul>
            </div>

            <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
              <h3 className="text-sm font-semibold text-slate-100">Methodology &amp; Limitations</h3>
              <p className="mt-2 text-xs text-slate-400">
                {report.limitations.methodology_summary}
              </p>
              <ul className="mt-3 list-disc space-y-1.5 pl-4 text-xs text-slate-400">
                {report.limitations.limitations.map((lim) => (
                  <li key={lim}>{lim}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
