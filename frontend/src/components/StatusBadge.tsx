import clsx from "clsx";
import type {
  RunStatus,
  SampleStatus,
  SeverityLevel,
  TestExecutionStatus,
} from "../types/api";

const RUN_STATUS_STYLES: Record<RunStatus, string> = {
  completed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  partially_completed: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  running: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  pending: "border-slate-600/50 bg-slate-800/70 text-slate-300",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  cancelled: "border-slate-500/40 bg-slate-700/40 text-slate-300",
};

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  critical: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  low: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  info: "border-slate-600/50 bg-slate-800/70 text-slate-300",
};

const OUTCOME_STYLES: Record<SampleStatus, string> = {
  successful_attack: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  blocked_attack: "border-emerald-500/35 bg-emerald-500/10 text-emerald-300",
  inconclusive: "border-amber-500/35 bg-amber-500/10 text-amber-300",
  execution_error: "border-purple-500/35 bg-purple-500/10 text-purple-300",
  evaluation_failure: "border-slate-600/50 bg-slate-800 text-slate-300",
};

const EXEC_STATUS_STYLES: Record<TestExecutionStatus, string> = {
  completed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  timed_out: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  skipped: "border-slate-600/40 bg-slate-800 text-slate-300",
};

function formatLabel(raw: string): string {
  return raw.replace(/_/g, " ");
}

export function RunStatusBadge({ status }: { status: RunStatus }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        RUN_STATUS_STYLES[status] ?? "border-slate-700 bg-slate-800 text-slate-300",
      )}
    >
      {formatLabel(status)}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        SEVERITY_STYLES[severity] ?? "border-slate-700 bg-slate-800 text-slate-300",
      )}
    >
      {severity}
    </span>
  );
}

export function OutcomeBadge({ outcome }: { outcome: SampleStatus }) {
  const labels: Record<SampleStatus, string> = {
    successful_attack: "Attack Succeeded",
    blocked_attack: "Blocked",
    inconclusive: "Inconclusive",
    execution_error: "Execution Error",
    evaluation_failure: "Eval Failure",
  };
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
        OUTCOME_STYLES[outcome],
      )}
    >
      {labels[outcome]}
    </span>
  );
}

export function ExecutionStatusBadge({ status }: { status: TestExecutionStatus }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        EXEC_STATUS_STYLES[status],
      )}
    >
      {formatLabel(status)}
    </span>
  );
}

export function SubmissionTypeBadge({
  type,
}: {
  type: "official_verified" | "community_submitted";
}) {
  if (type === "official_verified") {
    return (
      <span className="inline-flex items-center gap-1 rounded-md border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-xs font-medium text-sky-200">
        Officially Verified
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-slate-600/60 bg-slate-800/80 px-2 py-0.5 text-xs font-medium text-slate-300">
      Community Submitted
    </span>
  );
}
