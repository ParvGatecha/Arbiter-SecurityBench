import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { arbiterApi, formatDateTime, formatPercent, formatScore } from "../api/client";
import { PaginationBar } from "../components/PaginationBar";
import { EmptyState, ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import { SubmissionTypeBadge } from "../components/StatusBadge";
import type { BenchmarkSummary, LeaderboardResponse } from "../types/api";

export function LeaderboardPage() {
  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [benchmarkFilter, setBenchmarkFilter] = useState("");
  const [submissionFilter, setSubmissionFilter] = useState<
    "all" | "official_verified" | "community_submitted"
  >("all");
  const [data, setData] = useState<LeaderboardResponse | null>(null);
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const loadLeaderboard = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [benchRes, lbRes] = await Promise.all([
        arbiterApi.listBenchmarks(),
        arbiterApi.getLeaderboard({
          benchmark_id: benchmarkFilter || undefined,
          submission_type: submissionFilter,
          limit,
          offset,
        }),
      ]);
      setBenchmarks(benchRes.items);
      setData(lbRes);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [benchmarkFilter, submissionFilter, limit, offset]);

  useEffect(() => {
    void loadLeaderboard();
  }, [loadLeaderboard]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Leaderboard"
        subtitle="Real model rankings derived exclusively from completed, 100%-evaluated benchmark runs."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label="Filter leaderboard by benchmark"
              value={benchmarkFilter}
              onChange={(e) => {
                setBenchmarkFilter(e.target.value);
                setOffset(0);
              }}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="">All Registered Suites</option>
              {benchmarks.map((b) => (
                <option key={`${b.benchmark_id}:${b.version}`} value={b.benchmark_id}>
                  {b.benchmark_id}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter submission verification"
              value={submissionFilter}
              onChange={(e) => {
                setSubmissionFilter(
                  e.target.value as "all" | "official_verified" | "community_submitted",
                );
                setOffset(0);
              }}
              className="rounded-md border border-slate-700 bg-[#0c1017] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="all">All Submissions</option>
              <option value="official_verified">Officially Verified Only</option>
              <option value="community_submitted">Community Submitted Only</option>
            </select>
          </div>
        }
      />

      {data && (
        <div className="flex flex-col justify-between gap-2 rounded-lg border border-slate-800/90 bg-[#0c1017] px-4 py-3 text-xs text-slate-300 sm:flex-row sm:items-center">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-sky-400" />
            <span>{data.eligibility_criteria}</span>
          </div>
          <div className="shrink-0 font-mono text-[11px] text-slate-400">
            Eligible: {data.eligible_runs_count} · Excluded incomplete/errored:{" "}
            {data.excluded_runs_count}
          </div>
        </div>
      )}

      {error !== null && <ErrorPanel error={error} onRetry={loadLeaderboard} />}

      {loading ? (
        <LoadingPanel />
      ) : !data || data.items.length === 0 ? (
        <EmptyState
          title="No Eligible Runs on Leaderboard Yet"
          description="Only real completed runs with 100% evaluation coverage and registered suite provenance appear here. Incomplete or errored runs are automatically excluded."
          action={
            <Link
              to="/runs/new"
              className="inline-flex items-center rounded-md bg-sky-500 px-3.5 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400"
            >
              Execute Eligible Run
            </Link>
          }
        />
      ) : (
        <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-5">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                  <th className="py-2.5 pr-4 font-medium">Rank</th>
                  <th className="py-2.5 pr-4 font-medium">Target / Model</th>
                  <th className="py-2.5 pr-4 font-medium">Verification</th>
                  <th className="py-2.5 pr-4 font-medium">Suite</th>
                  <th className="py-2.5 pr-4 font-medium">Security Score</th>
                  <th className="py-2.5 pr-4 font-medium">ASR</th>
                  <th className="py-2.5 pr-4 font-medium">Block Rate</th>
                  <th className="py-2.5 pr-4 font-medium">Crit / High</th>
                  <th className="py-2.5 pr-4 font-medium">Completed</th>
                  <th className="py-2.5 text-right font-medium">Run</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {data.items.map((entry) => (
                  <tr key={entry.run_id} className="hover:bg-slate-900/40">
                    <td className="py-3 pr-4 font-mono font-semibold text-slate-200">
                      #{entry.rank}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="font-medium text-slate-100">
                        {entry.model_name || entry.target_id}
                      </div>
                      <div className="font-mono text-[11px] text-slate-500">
                        {entry.provider || entry.target_type} · {entry.target_id}
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <SubmissionTypeBadge type={entry.submission_type} />
                    </td>
                    <td className="py-3 pr-4 text-slate-300">
                      {entry.benchmark_id}{" "}
                      <span className="font-mono text-slate-500">v{entry.benchmark_version}</span>
                    </td>
                    <td className="py-3 pr-4 font-mono font-semibold tabular-nums text-sky-300">
                      {formatScore(entry.security_score)}
                      {entry.score_capped_by_critical_policy && (
                        <span className="ml-1.5 text-[10px] font-normal text-rose-400">
                          (capped)
                        </span>
                      )}
                    </td>
                    <td className="py-3 pr-4 tabular-nums text-rose-300">
                      {formatPercent(entry.attack_success_rate)}
                    </td>
                    <td className="py-3 pr-4 tabular-nums text-emerald-300">
                      {formatPercent(entry.attack_block_rate)}
                    </td>
                    <td className="py-3 pr-4 tabular-nums text-slate-300">
                      {entry.critical_compromises} / {entry.high_compromises}
                    </td>
                    <td className="py-3 pr-4 text-slate-400">
                      {formatDateTime(entry.completed_at)}
                    </td>
                    <td className="py-3 text-right">
                      <Link
                        to={`/runs/${encodeURIComponent(entry.run_id)}`}
                        className="font-medium text-sky-400 hover:text-sky-300"
                      >
                        Inspect
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <PaginationBar
            total={data.total}
            limit={limit}
            offset={offset}
            onPageChange={setOffset}
            onLimitChange={(next) => {
              setLimit(next);
              setOffset(0);
            }}
          />
        </div>
      )}
    </div>
  );
}
