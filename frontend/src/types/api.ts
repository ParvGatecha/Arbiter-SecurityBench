export type SecurityCategory =
  | "prompt_injection"
  | "jailbreak_resistance"
  | "system_prompt_extraction"
  | "sensitive_data_leakage"
  | "instruction_hierarchy_manipulation"
  | "rag_security"
  | "agent_tool_abuse"
  | "data_exfiltration";

export type SeverityLevel = "info" | "low" | "medium" | "high" | "critical";

export type DifficultyLevel = "easy" | "medium" | "hard" | "expert";

export type TargetModality = "llm" | "rag" | "agent";

export type RunStatus =
  | "pending"
  | "running"
  | "completed"
  | "partially_completed"
  | "failed"
  | "cancelled";

export type TestExecutionStatus = "completed" | "failed" | "timed_out" | "skipped";

export type BenchmarkLifecycleState = "draft" | "published" | "deprecated" | "archived";

export type AttackType =
  | "direct_override"
  | "indirect_context_poisoning"
  | "roleplay_jailbreak"
  | "policy_bypass"
  | "delimiter_confusion"
  | "encoding_obfuscation"
  | "tool_privilege_escalation"
  | "canary_exfiltration"
  | "multi_turn_crescendo"
  | "rag_document_injection";

export type SampleStatus =
  | "successful_attack"
  | "blocked_attack"
  | "inconclusive"
  | "execution_error"
  | "evaluation_failure";

export interface ApiErrorPayload {
  error_code: string;
  category: string;
  message: string;
  details: Record<string, unknown>;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface EvaluationCriteria {
  expected_secure_behavior: string;
  attack_success_criteria: string;
  failure_indicators: string[];
  evaluator_strategy: string;
  severity_weight: number;
}

export interface TestCase {
  schema_version: string;
  test_id: string;
  name: string;
  description: string;
  category: SecurityCategory;
  attack_type: AttackType;
  target_type: TargetModality;
  input_prompt: string;
  evaluation_criteria: EvaluationCriteria;
  severity: SeverityLevel;
  difficulty: DifficultyLevel;
  benchmark_version: string;
  tags: string[];
  lifecycle_state: BenchmarkLifecycleState;
  metadata: Record<string, unknown>;
}

export interface BenchmarkSummary {
  benchmark_id: string;
  suite_id: string;
  name: string;
  description: string;
  version: string;
  categories: SecurityCategory[];
  supported_target_types: TargetModality[];
  test_count: number;
  lifecycle_state: BenchmarkLifecycleState;
}

export interface BenchmarkListResponse {
  items: BenchmarkSummary[];
  total: number;
}

export interface BenchmarkDetailResponse extends BenchmarkSummary {
  available_versions: string[];
  test_cases: TestCase[];
  metadata: Record<string, unknown>;
}

export interface PaginatedTestCasesResponse {
  benchmark_id: string;
  suite_id: string;
  version: string;
  items: TestCase[];
  total: number;
  limit: number;
  offset: number;
  categories: SecurityCategory[];
  difficulties: DifficultyLevel[];
  severities: SeverityLevel[];
}

export interface BenchmarkRun {
  schema_version: string;
  run_id: string;
  benchmark_id: string;
  suite_id: string;
  benchmark_version: string;
  target_id: string;
  target_type: TargetModality;
  target_config: Record<string, unknown>;
  status: RunStatus;
  total_tests: number;
  completed_tests: number;
  failed_tests: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  metadata: Record<string, unknown>;
}

export interface RunListResponse {
  items: BenchmarkRun[];
  total: number;
  total_count: number;
  limit: number;
  offset: number;
}

export interface EvaluatorEvidenceItem {
  indicator: string;
  matched: boolean;
  source: string;
  excerpt?: string | null;
  details?: Record<string, unknown>;
}

export interface EvaluatorOutputRecord {
  evaluator_id: string;
  evaluation_status: "successful_attack" | "blocked_attack" | "inconclusive";
  attack_success: boolean | null;
  confidence: number;
  severity: SeverityLevel;
  evidence: EvaluatorEvidenceItem[];
  reasoning: string;
  metadata?: Record<string, unknown>;
}

export interface AggregatedEvaluationPayload {
  test_id?: string;
  consensus_status?: "successful_attack" | "blocked_attack" | "inconclusive";
  evaluation_status?: "successful_attack" | "blocked_attack" | "inconclusive";
  attack_success?: boolean | null;
  confidence?: number;
  severity?: SeverityLevel;
  individual_results?: EvaluatorOutputRecord[];
  has_disagreement?: boolean;
  agreement_ratio?: number;
  requires_human_review?: boolean;
  reasoning?: string;
  metadata?: Record<string, unknown>;
}

export interface ErrorRecord {
  error_code: string;
  category: string;
  severity: string;
  retryability: string;
  message: string;
  details: Record<string, unknown>;
  component: string | null;
}

export interface TestExecutionResult {
  schema_version: string;
  run_id: string;
  test_id: string;
  target_id: string;
  input: string;
  output: string | null;
  execution_status: TestExecutionStatus;
  execution_time: number;
  raw_response: Record<string, unknown> | null;
  evaluator_results: AggregatedEvaluationPayload[];
  error_details: ErrorRecord | Record<string, unknown> | null;
  timestamp: string;
}

export interface RunResultsResponse {
  run_id: string;
  benchmark_id: string;
  benchmark_version: string;
  target_id: string;
  status: RunStatus;
  total_results: number;
  filtered_total: number;
  limit: number;
  offset: number;
  results: TestExecutionResult[];
}

export interface CreateBenchmarkRunRequest {
  benchmark_id: string;
  version?: string | null;
  target_id: string;
  target_config?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface TargetSummary {
  target_id: string;
  target_type: TargetModality;
  adapter_type: string;
  provider: string;
  model_name: string;
  endpoint: string | null;
  capabilities: string[];
  is_connected: boolean;
  metadata: Record<string, unknown>;
}

export interface TargetListResponse {
  items: TargetSummary[];
  available_adapter_types: string[];
  total: number;
}

export interface CreateTargetRequest {
  adapter_type: "openai" | "anthropic" | "gemini" | "ollama" | "http";
  target_id: string;
  target_type: TargetModality;
  model?: string;
  base_url?: string;
  endpoint_url?: string;
  api_key_env_var?: string;
  allow_unauthenticated?: boolean;
  timeout_seconds?: number;
  prompt_field?: string;
  response_text_path?: string;
  metadata?: Record<string, unknown>;
}

export interface TargetHealthResponse {
  target_id: string;
  healthy: boolean;
  latency_ms: number | null;
  detail: string;
}

export interface ProportionCI {
  estimate: number;
  lower: number;
  upper: number;
  confidence_level: number;
  method: string;
  sample_size: number;
}

export interface SampleSizeReport {
  total_samples: number;
  successful_attacks: number;
  blocked_attacks: number;
  inconclusive_samples: number;
  execution_error_samples: number;
  evaluation_failure_samples: number;
  evaluated_samples: number;
  decisive_samples: number;
  ground_truth_samples: number;
  is_small_sample: boolean;
}

export interface SecurityMetrics {
  sample_counts: SampleSizeReport;
  attack_success_rate: number | null;
  attack_block_rate: number | null;
  inconclusive_rate: number | null;
  execution_error_rate: number | null;
  evaluation_failure_rate: number | null;
  evaluation_coverage: number | null;
  decisive_attack_success_rate: number | null;
  severity_weighted_asr: number | null;
  false_positive_rate: number | null;
  false_negative_rate: number | null;
  asr_wilson_ci: ProportionCI | null;
  asr_bootstrap_ci: ProportionCI | null;
  severity_weighted_asr_bootstrap_ci: ProportionCI | null;
  security_score: number | null;
  score_capped_by_critical_policy: boolean;
  critical_compromises: number;
  high_compromises: number;
}

export interface CategoryScoreReport {
  category: SecurityCategory;
  metrics: SecurityMetrics;
}

export interface RunScoreReport {
  run_id: string;
  benchmark_id: string;
  benchmark_version: string;
  target_id: string;
  target_type: TargetModality;
  execution_config: Record<string, unknown>;
  profile_id: string;
  overall_metrics: SecurityMetrics;
  category_metrics: Record<SecurityCategory, CategoryScoreReport>;
  warnings: string[];
  timestamp: string;
}

export interface SignificanceTestOutput {
  test_name: string;
  comparison_label: string;
  statistic: number | null;
  p_value: number;
  adjusted_p_value: number | null;
  alpha: number;
  statistically_significant: boolean;
  effect_size: number | null;
  notes: string[];
}

export interface CategoryDeltaReport {
  category: SecurityCategory;
  baseline_asr: number | null;
  candidate_asr: number | null;
  asr_delta: number | null;
  baseline_block_rate: number | null;
  candidate_block_rate: number | null;
  block_rate_delta: number | null;
  significance: SignificanceTestOutput | null;
  status: "improved" | "degraded" | "unchanged" | "insufficient_data";
}

export interface BenchmarkComparisonReport {
  benchmark_id: string;
  benchmark_version: string;
  baseline_run_id: string;
  baseline_target_id: string;
  baseline_execution_config: Record<string, unknown>;
  candidate_run_id: string;
  candidate_target_id: string;
  candidate_execution_config: Record<string, unknown>;
  asr_delta: number | null;
  block_rate_delta: number | null;
  severity_weighted_asr_delta: number | null;
  security_score_delta: number | null;
  inconclusive_rate_delta: number | null;
  execution_error_rate_delta: number | null;
  baseline_asr_ci: ProportionCI | null;
  candidate_asr_ci: ProportionCI | null;
  overall_significance: SignificanceTestOutput | null;
  category_comparisons: Record<SecurityCategory, CategoryDeltaReport>;
  improved_categories: SecurityCategory[];
  degraded_categories: SecurityCategory[];
  regression_detected: boolean;
  regression_warnings: string[];
  timestamp: string;
}

export interface AttackFindingRecord {
  test_id: string;
  test_name: string | null;
  category: SecurityCategory | null;
  severity: SeverityLevel;
  attack_type: string | null;
  verification_classification: "deterministic_verified" | "evaluator_judgment" | "mixed_or_disputed";
  confidence: number | null;
  evaluator_ids: string[];
  has_disagreement: boolean;
  evidence_summary: string[];
  reasoning: string;
  output_excerpt: string | null;
}

export interface IncompleteTestRecord {
  test_id: string;
  failure_kind: string;
  execution_status: string;
  error_message: string | null;
  reasoning: string | null;
  has_disagreement: boolean;
}

export interface SeverityDistributionRow {
  severity: SeverityLevel;
  total: number;
  successful_attacks: number;
  blocked_attacks: number;
  inconclusive: number;
  execution_errors: number;
  evaluation_failures: number;
}

export interface ReportDocument {
  report_schema_version: string;
  generated_at: string;
  executive_summary: {
    run_id: string;
    run_status: RunStatus;
    is_complete_run: boolean;
    incomplete_run_reason: string | null;
    headline: string;
    total_samples: number;
    successful_attacks: number;
    blocked_attacks: number;
    inconclusive_samples: number;
    execution_error_samples: number;
    evaluation_failure_samples: number;
    deterministic_verified_compromises: number;
    evaluator_judgment_compromises: number;
    critical_compromises: number;
    attack_success_rate: number | null;
    attack_block_rate: number | null;
    security_score: number | null;
    warnings: string[];
  };
  target_information: {
    target_id: string;
    target_type: TargetModality;
    sanitized_target_config: Record<string, unknown>;
    created_at: string;
    started_at: string | null;
    completed_at: string | null;
  };
  benchmark_configuration: {
    benchmark_id: string;
    suite_id: string;
    scoring_profile_id: string;
    execution_config: Record<string, unknown>;
    total_tests_scheduled: number;
    completed_tests: number;
    failed_tests: number;
    platform_version: string;
    contract_schema_version: string;
    suite_content_digest: string | null;
  };
  benchmark_version: {
    benchmark_id: string;
    benchmark_version: string;
    suite_schema_version: string;
    suite_content_digest: string | null;
  };
  overall_security_metrics: SecurityMetrics;
  category_results: Array<{
    category: SecurityCategory;
    metrics: SecurityMetrics;
  }>;
  successful_attack_analysis: AttackFindingRecord[];
  failed_and_inconclusive_tests: {
    execution_errors: IncompleteTestRecord[];
    evaluation_failures: IncompleteTestRecord[];
    inconclusive_tests: IncompleteTestRecord[];
  };
  severity_distribution: SeverityDistributionRow[];
  statistical_confidence_intervals: {
    confidence_level: number;
    sample_size: number;
    is_small_sample: boolean;
    asr_wilson_ci: ProportionCI | null;
    asr_bootstrap_ci: ProportionCI | null;
    severity_weighted_asr_bootstrap_ci: ProportionCI | null;
    statistical_notes: string[];
  };
  benchmark_comparison: {
    available: boolean;
    reason: string | null;
    comparison: BenchmarkComparisonReport | null;
  };
  recommendations: string[];
  limitations: {
    methodology_summary: string;
    limitations: string[];
  };
}

export interface LeaderboardEntry {
  rank: number;
  run_id: string;
  target_id: string;
  target_type: TargetModality;
  provider: string | null;
  model_name: string | null;
  benchmark_id: string;
  benchmark_version: string;
  submission_type: "official_verified" | "community_submitted";
  security_score: number;
  attack_success_rate: number;
  attack_block_rate: number;
  severity_weighted_asr: number;
  inconclusive_rate: number;
  evaluation_coverage: number;
  total_samples: number;
  critical_compromises: number;
  high_compromises: number;
  score_capped_by_critical_policy: boolean;
  completed_at: string | null;
  category_asr: Record<string, number | null>;
}

export interface LeaderboardResponse {
  items: LeaderboardEntry[];
  total: number;
  eligible_runs_count: number;
  excluded_runs_count: number;
  eligibility_criteria: string;
}

export interface PlatformSettingsResponse {
  platform_version: string;
  storage_backend: string;
  builtin_datasets_loaded: boolean;
  default_timeout_seconds: number | null;
  available_adapter_types: string[];
  registered_target_count: number;
  registered_benchmark_count: number;
  scoring_profiles: string[];
  report_formats: string[];
  supported_run_statuses: RunStatus[];
  supported_result_statuses: TestExecutionStatus[];
}
