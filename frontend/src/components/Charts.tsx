import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { formatCategory } from "../api/client";
import type { CategoryDeltaReport, CategoryScoreReport, SampleSizeReport } from "../types/api";

const TOOLTIP_STYLE = {
  backgroundColor: "#0c1017",
  borderColor: "#1f293b",
  borderRadius: "8px",
  fontSize: "12px",
  color: "#e2e8f0",
};

export function CategoryRateBarChart({
  categories,
}: {
  categories: CategoryScoreReport[];
}) {
  if (!categories.length) {
    return (
      <div className="flex h-64 items-center justify-center text-xs text-slate-500">
        No category metrics computed yet.
      </div>
    );
  }

  const data = categories.map((item) => ({
    category: formatCategory(item.category),
    asrPct:
      item.metrics.attack_success_rate !== null
        ? Number((item.metrics.attack_success_rate * 100).toFixed(1))
        : 0,
    blockPct:
      item.metrics.attack_block_rate !== null
        ? Number((item.metrics.attack_block_rate * 100).toFixed(1))
        : 0,
  }));

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 20 }}>
          <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="category"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
            axisLine={{ stroke: "#1e293b" }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            unit="%"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: "12px", color: "#cbd5e1" }} />
          <Bar dataKey="blockPct" name="Block Rate (%)" fill="#34d399" radius={[4, 4, 0, 0]} />
          <Bar dataKey="asrPct" name="Attack Success Rate (%)" fill="#fb7185" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SampleOutcomePieChart({ counts }: { counts: SampleSizeReport | null | undefined }) {
  if (!counts || counts.total_samples === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-xs text-slate-500">
        No evaluated sample counts available.
      </div>
    );
  }

  const raw = [
    { name: "Blocked", value: counts.blocked_attacks, color: "#34d399" },
    { name: "Attack Succeeded", value: counts.successful_attacks, color: "#fb7185" },
    { name: "Inconclusive", value: counts.inconclusive_samples, color: "#fbbf24" },
    { name: "Exec Errors", value: counts.execution_error_samples, color: "#a78bfa" },
    { name: "Eval Failures", value: counts.evaluation_failure_samples, color: "#64748b" },
  ].filter((d) => d.value > 0);

  if (!raw.length) {
    return (
      <div className="flex h-64 items-center justify-center text-xs text-slate-500">
        No outcome distribution recorded.
      </div>
    );
  }

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={raw}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={56}
            outerRadius={88}
            paddingAngle={2}
          >
            {raw.map((entry) => (
              <Cell key={entry.name} fill={entry.color} stroke="#07090d" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: "12px", color: "#cbd5e1" }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ComparisonBarChart({
  deltas,
  baselineLabel,
  candidateLabel,
}: {
  deltas: CategoryDeltaReport[];
  baselineLabel: string;
  candidateLabel: string;
}) {
  if (!deltas.length) {
    return (
      <div className="flex h-64 items-center justify-center text-xs text-slate-500">
        Select two compatible runs to view category deltas.
      </div>
    );
  }

  const data = deltas.map((d) => ({
    category: formatCategory(d.category),
    baselineAsr: d.baseline_asr !== null ? Number((d.baseline_asr * 100).toFixed(1)) : 0,
    candidateAsr: d.candidate_asr !== null ? Number((d.candidate_asr * 100).toFixed(1)) : 0,
  }));

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 16, left: -12, bottom: 20 }}>
          <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="category"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
            axisLine={{ stroke: "#1e293b" }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            unit="%"
            tick={{ fill: "#94a3b8", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: "12px", color: "#cbd5e1" }} />
          <Bar dataKey="baselineAsr" name={`Baseline ASR (${baselineLabel})`} fill="#38bdf8" radius={[4, 4, 0, 0]} />
          <Bar dataKey="candidateAsr" name={`Candidate ASR (${candidateLabel})`} fill="#fb7185" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
