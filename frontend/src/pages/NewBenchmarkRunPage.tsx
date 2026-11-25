import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Play, PlusCircle } from "lucide-react";
import { arbiterApi } from "../api/client";
import { ErrorPanel, LoadingPanel, PageHeader } from "../components/StatePanels";
import type { BenchmarkSummary, TargetSummary } from "../types/api";

export function NewBenchmarkRunPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [benchmarks, setBenchmarks] = useState<BenchmarkSummary[]>([]);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [benchmarkKey, setBenchmarkKey] = useState("");
  const [targetId, setTargetId] = useState("");
  const [targetConfigJson, setTargetConfigJson] = useState('{\n  "temperature": 0\n}');
  const [submissionType, setSubmissionType] = useState<"community_submitted" | "official_verified">(
    "community_submitted",
  );
  const [runNote, setRunNote] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const loadOptions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [benchRes, targetRes] = await Promise.all([
        arbiterApi.listBenchmarks(),
        arbiterApi.listTargets(),
      ]);
      setBenchmarks(benchRes.items);
      setTargets(targetRes.items);

      const paramBench = searchParams.get("benchmarkId");
      const paramVer = searchParams.get("version");
      if (benchRes.items.length > 0) {
        const matched =
          benchRes.items.find(
            (b) => b.benchmark_id === paramBench && (!paramVer || b.version === paramVer),
          ) ?? benchRes.items[0];
        setBenchmarkKey(`${matched.benchmark_id}::${matched.version}`);
      }
      if (targetRes.items.length > 0) {
        setTargetId(targetRes.items[0].target_id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [searchParams]);

  useEffect(() => {
    void loadOptions();
  }, [loadOptions]);

  const selectedSuite = benchmarks.find(
    (b) => `${b.benchmark_id}::${b.version}` === benchmarkKey,
  );
  const selectedTarget = targets.find((t) => t.target_id === targetId);
  const incompatibleModality =
    selectedSuite &&
    selectedTarget &&
    !selectedSuite.supported_target_types.includes(selectedTarget.target_type);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedSuite || !targetId) return;

    setSubmitting(true);
    setError(null);
    try {
      const parsedConfig = targetConfigJson.trim()
        ? (JSON.parse(targetConfigJson) as Record<string, unknown>)
        : {};
      const run = await arbiterApi.createRun({
        benchmark_id: selectedSuite.benchmark_id,
        version: selectedSuite.version,
        target_id: targetId,
        target_config: parsedConfig,
        metadata: {
          submission_type: submissionType,
          ...(runNote.trim() ? { notes: runNote.trim() } : {}),
        },
      });
      navigate(`/runs/${encodeURIComponent(run.run_id)}`);
    } catch (err) {
      setError(err);
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="New Benchmark Run"
        subtitle="Execute a registered security benchmark suite against a configured target adapter."
        actions={
          <Link
            to="/settings"
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-[#111620] px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
          >
            <PlusCircle className="h-3.5 w-3.5" />
            Manage Targets
          </Link>
        }
      />

      {error !== null && <ErrorPanel error={error} title="Failed to launch benchmark run" />}

      {loading ? (
        <LoadingPanel />
      ) : (
        <form
          onSubmit={handleSubmit}
          className="grid grid-cols-1 gap-6 lg:grid-cols-12"
        >
          <div className="space-y-5 rounded-lg border border-slate-800/90 bg-[#0c1017] p-6 lg:col-span-8">
            <div>
              <label
                htmlFor="benchmark-select"
                className="block text-xs font-medium uppercase tracking-wider text-slate-400"
              >
                Benchmark Suite &amp; Version
              </label>
              <select
                id="benchmark-select"
                value={benchmarkKey}
                onChange={(e) => setBenchmarkKey(e.target.value)}
                required
                className="mt-2 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              >
                {benchmarks.length === 0 && <option value="">No benchmarks registered</option>}
                {benchmarks.map((b) => (
                  <option key={`${b.benchmark_id}::${b.version}`} value={`${b.benchmark_id}::${b.version}`}>
                    {b.name} ({b.benchmark_id} v{b.version} — {b.test_count} tests)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor="target-select"
                className="block text-xs font-medium uppercase tracking-wider text-slate-400"
              >
                Target Adapter
              </label>
              <select
                id="target-select"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                required
                className="mt-2 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              >
                {targets.length === 0 && (
                  <option value="">No targets registered — configure one in Settings</option>
                )}
                {targets.map((t) => (
                  <option key={t.target_id} value={t.target_id}>
                    {t.target_id} ({t.provider} / {t.model_name} · {t.target_type.toUpperCase()})
                  </option>
                ))}
              </select>
              {incompatibleModality && (
                <p className="mt-2 text-xs text-rose-400">
                  Target modality ({selectedTarget.target_type}) is not supported by this suite (
                  {selectedSuite.supported_target_types.join(", ")}).
                </p>
              )}
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="submission-type"
                  className="block text-xs font-medium uppercase tracking-wider text-slate-400"
                >
                  Submission Classification
                </label>
                <select
                  id="submission-type"
                  value={submissionType}
                  onChange={(e) =>
                    setSubmissionType(e.target.value as "community_submitted" | "official_verified")
                  }
                  className="mt-2 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                >
                  <option value="community_submitted">Community Submitted</option>
                  <option value="official_verified">Officially Verified</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="run-notes"
                  className="block text-xs font-medium uppercase tracking-wider text-slate-400"
                >
                  Execution Notes (Optional)
                </label>
                <input
                  id="run-notes"
                  type="text"
                  value={runNote}
                  onChange={(e) => setRunNote(e.target.value)}
                  placeholder="e.g. guardrail-v2 baseline check"
                  className="mt-2 w-full rounded-md border border-slate-700 bg-[#111620] px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="target-config-json"
                className="block text-xs font-medium uppercase tracking-wider text-slate-400"
              >
                Target Execution Parameters (JSON)
              </label>
              <textarea
                id="target-config-json"
                rows={4}
                value={targetConfigJson}
                onChange={(e) => setTargetConfigJson(e.target.value)}
                className="mt-2 w-full rounded-md border border-slate-700 bg-[#080b10] p-3 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="submit"
                disabled={submitting || !selectedSuite || !targetId || Boolean(incompatibleModality)}
                className="inline-flex items-center gap-2 rounded-md bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {submitting ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Executing Benchmark...
                  </>
                ) : (
                  <>
                    <Play className="h-3.5 w-3.5" />
                    Execute Benchmark Run
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="space-y-4 rounded-lg border border-slate-800/90 bg-[#0c1017] p-5 lg:col-span-4">
            <h2 className="text-sm font-semibold text-slate-100">Execution Safeguards</h2>
            <ul className="space-y-2.5 text-xs leading-relaxed text-slate-400">
              <li>
                • Prompts are dispatched sequentially via <span className="font-mono text-slate-300">POST /api/v1/benchmarks/runs</span>.
              </li>
              <li>
                • Completed responses are evaluated through Rule-Based, Sensitive Info, and Semantic evaluators.
              </li>
              <li>
                • Execution errors remain separated from security findings in denominator accounting.
              </li>
              <li>
                • Credentials are read strictly from backend environment variables, never stored in run configs.
              </li>
            </ul>
          </div>
        </form>
      )}
    </div>
  );
}
