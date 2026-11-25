import type { ReactNode } from "react";
import { AlertTriangle, Inbox, Loader2, RefreshCw } from "lucide-react";
import { ApiClientError } from "../api/client";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 border-b border-slate-800/80 pb-5 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-100 sm:text-2xl">
          {title}
        </h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "neutral" | "good" | "warn" | "danger" | "info";
}) {
  const accentMap: Record<typeof tone, string> = {
    neutral: "text-slate-100",
    good: "text-emerald-300",
    warn: "text-amber-300",
    danger: "text-rose-300",
    info: "text-sky-300",
  };

  return (
    <div className="rounded-lg border border-slate-800/90 bg-[#0c1017] p-4">
      <div className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</div>
      <div className={`mt-2 text-2xl font-semibold tabular-nums ${accentMap[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function LoadingPanel({ message = "Loading live telemetry from backend..." }: { message?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center rounded-lg border border-slate-800/80 bg-[#0c1017] px-6 py-14 text-center"
    >
      <Loader2 className="h-6 w-6 animate-spin text-sky-400" />
      <p className="mt-3 text-sm text-slate-300">{message}</p>
    </div>
  );
}

export function ErrorPanel({
  error,
  onRetry,
  title = "Backend request failed",
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
}) {
  const message =
    error instanceof Error ? error.message : "An unexpected error occurred communicating with the API.";
  const code = error instanceof ApiClientError ? error.errorCode : undefined;

  return (
    <div
      role="alert"
      className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-5 text-rose-100"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-rose-200">{title}</h3>
              {code && (
                <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[11px] text-rose-300">
                  {code}
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-rose-200/80">{message}</p>
          </div>
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-rose-400/30 bg-rose-500/15 px-3 py-1.5 text-xs font-medium text-rose-100 hover:bg-rose-500/25"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        )}
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 bg-[#0c1017]/70 px-6 py-12 text-center">
      <Inbox className="h-7 w-7 text-slate-500" />
      <h3 className="mt-3 text-sm font-semibold text-slate-200">{title}</h3>
      <p className="mt-1 max-w-md text-xs leading-relaxed text-slate-400">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
