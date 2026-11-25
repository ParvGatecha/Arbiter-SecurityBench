import type {
  ApiErrorPayload,
  BenchmarkComparisonReport,
  BenchmarkDetailResponse,
  BenchmarkListResponse,
  BenchmarkRun,
  CreateBenchmarkRunRequest,
  CreateTargetRequest,
  HealthResponse,
  LeaderboardResponse,
  PaginatedTestCasesResponse,
  PlatformSettingsResponse,
  ReportDocument,
  RunListResponse,
  RunResultsResponse,
  RunScoreReport,
  SampleStatus,
  TargetHealthResponse,
  TargetListResponse,
  TargetSummary,
  TestExecutionResult,
} from "../types/api";

export class ApiClientError extends Error {
  readonly status: number;
  readonly errorCode: string;
  readonly category: string;
  readonly details: Record<string, unknown>;

  constructor(
    message: string,
    status: number,
    errorCode = "HTTP_ERROR",
    category = "api",
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.errorCode = errorCode;
    this.category = category;
    this.details = details;
  }
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined | null>): string {
  const url = `${API_BASE}${path}`;
  if (!params) return url;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `${url}?${qs}` : url;
}

async function requestJson<T>(
  path: string,
  options?: RequestInit & { params?: Record<string, string | number | boolean | undefined | null> },
): Promise<T> {
  const { params, headers, ...init } = options ?? {};
  const response = await fetch(buildUrl(path, params), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });

  if (!response.ok) {
    let payload: Partial<ApiErrorPayload> | null = null;
    try {
      payload = (await response.json()) as Partial<ApiErrorPayload>;
    } catch {
      payload = null;
    }
    throw new ApiClientError(
      payload?.message || `Request failed with status ${response.status}`,
      response.status,
      payload?.error_code || `HTTP_${response.status}`,
      payload?.category || "api",
      payload?.details || {},
    );
  }

  return (await response.json()) as T;
}

export const arbiterApi = {
  getHealth(): Promise<HealthResponse> {
    return requestJson<HealthResponse>("/health");
  },

  getPlatformSettings(): Promise<PlatformSettingsResponse> {
    return requestJson<PlatformSettingsResponse>("/api/v1/platform/settings");
  },

  listBenchmarks(filters?: { category?: string; target_type?: string }): Promise<BenchmarkListResponse> {
    return requestJson<BenchmarkListResponse>("/api/v1/benchmarks", { params: filters });
  },

  getBenchmark(benchmarkId: string, version?: string): Promise<BenchmarkDetailResponse> {
    return requestJson<BenchmarkDetailResponse>(
      `/api/v1/benchmarks/${encodeURIComponent(benchmarkId)}`,
      { params: { version } },
    );
  },

  listBenchmarkTestCases(
    benchmarkId: string,
    params?: {
      version?: string;
      category?: string;
      difficulty?: string;
      severity?: string;
      search?: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<PaginatedTestCasesResponse> {
    return requestJson<PaginatedTestCasesResponse>(
      `/api/v1/benchmarks/${encodeURIComponent(benchmarkId)}/test-cases`,
      { params },
    );
  },

  listTargets(): Promise<TargetListResponse> {
    return requestJson<TargetListResponse>("/api/v1/targets");
  },

  registerTarget(payload: CreateTargetRequest): Promise<TargetSummary> {
    return requestJson<TargetSummary>("/api/v1/targets", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  checkTargetHealth(targetId: string): Promise<TargetHealthResponse> {
    return requestJson<TargetHealthResponse>(
      `/api/v1/targets/${encodeURIComponent(targetId)}/health`,
      { method: "POST" },
    );
  },

  createRun(payload: CreateBenchmarkRunRequest): Promise<BenchmarkRun> {
    return requestJson<BenchmarkRun>("/api/v1/benchmarks/runs", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  listRuns(params?: {
    benchmark_id?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<RunListResponse> {
    return requestJson<RunListResponse>("/api/v1/runs", { params });
  },

  getRun(runId: string): Promise<BenchmarkRun> {
    return requestJson<BenchmarkRun>(`/api/v1/runs/${encodeURIComponent(runId)}`);
  },

  getRunResults(
    runId: string,
    params?: {
      execution_status?: string;
      verdict?: string;
      search?: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<RunResultsResponse> {
    return requestJson<RunResultsResponse>(
      `/api/v1/runs/${encodeURIComponent(runId)}/results`,
      { params },
    );
  },

  getRunScores(runId: string, profile: "default" | "weighted" = "default"): Promise<RunScoreReport> {
    return requestJson<RunScoreReport>(
      `/api/v1/runs/${encodeURIComponent(runId)}/scores`,
      { params: { profile } },
    );
  },

  compareRuns(payload: {
    baseline_run_id: string;
    candidate_run_id: string;
    profile?: "default" | "weighted";
  }): Promise<BenchmarkComparisonReport> {
    return requestJson<BenchmarkComparisonReport>("/api/v1/runs/compare", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  getReportDocument(
    runId: string,
    params?: { baseline_run_id?: string; profile?: "default" | "weighted" },
  ): Promise<ReportDocument> {
    return requestJson<ReportDocument>(
      `/api/v1/runs/${encodeURIComponent(runId)}/report`,
      { params: { format: "json", ...params } },
    );
  },

  async downloadReport(
    runId: string,
    format: "json" | "html" | "pdf" | "markdown",
    options?: { baseline_run_id?: string; profile?: "default" | "weighted" },
  ): Promise<void> {
    const url = buildUrl(`/api/v1/runs/${encodeURIComponent(runId)}/report`, {
      format,
      download: true,
      baseline_run_id: options?.baseline_run_id,
      profile: options?.profile,
    });
    const response = await fetch(url);
    if (!response.ok) {
      throw new ApiClientError(
        `Report download failed with status ${response.status}`,
        response.status,
      );
    }
    const blob = await response.blob();
    const ext = format === "markdown" ? "md" : format;
    const objectUrl = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `report_${runId}.${ext}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(objectUrl);
  },

  getLeaderboard(params?: {
    benchmark_id?: string;
    version?: string;
    submission_type?: "all" | "official_verified" | "community_submitted";
    limit?: number;
    offset?: number;
  }): Promise<LeaderboardResponse> {
    return requestJson<LeaderboardResponse>("/api/v1/leaderboard", { params });
  },
};

export function formatCategory(category: string): string {
  return category
    .split("_")
    .map((part) => (part === "rag" ? "RAG" : part.charAt(0).toUpperCase() + part.slice(1)))
    .join(" ");
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "N/A";
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatScore(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "N/A";
  return `${value.toFixed(digits)}`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function extractResultOutcome(result: TestExecutionResult): SampleStatus {
  if (result.execution_status !== "completed") {
    return "execution_error";
  }
  const lastEval = result.evaluator_results[result.evaluator_results.length - 1];
  if (!lastEval) return "evaluation_failure";
  const raw = (lastEval.consensus_status || lastEval.evaluation_status || "").toLowerCase();
  if (raw === "successful_attack") return "successful_attack";
  if (raw === "blocked_attack") return "blocked_attack";
  if (raw === "inconclusive") return "inconclusive";
  return "evaluation_failure";
}
