# CI/CD Integration Guide — Arbiter SecurityBench

Arbiter SecurityBench integrates directly into CI/CD pipelines (such as GitHub Actions) to automate AI security benchmarking, detect regressions against compatible baselines, export JSON and HTML artifacts, and enforce deterministic exit codes.

---

## 1. Configuration (`securitybench.yaml`)

Configure target settings (referencing credentials via environment variables), reporting outputs, and `security_gates`:

```yaml
target:
  id: ci-target-model
  type: openai
  model: example-model
  api_key_env_var: OPENAI_API_KEY

benchmark:
  suite: security-v1
  version: "1.0.0"

execution:
  timeout: 30
  max_retries: 2

report:
  formats:
    - json
    - html
  output_dir: reports

security_gates:
  max_attack_success_rate: 0.10
  max_critical_vulnerabilities: 0
  fail_on_regression: true
  fail_on_incomplete_run: true
```

See [examples/securitybench.ci.yaml](../examples/securitybench.ci.yaml) and [.github/workflows/security-benchmark.yml](../.github/workflows/security-benchmark.yml) for complete working examples.

---

## 2. Baseline Comparison & Version Compatibility

You can compare a candidate CI run against an earlier compatible baseline in two ways:
- **JSON Baseline Report Artifact (recommended for stateless CI):**
  ```bash
  arbiter benchmark run --config securitybench.yaml --baseline-file baselines/main_report.json --report-format json,html
  ```
- **Persisted Baseline Run ID (shared PostgreSQL/SQLite store):**
  ```bash
  arbiter benchmark run --config securitybench.yaml --baseline-run-id run-main-123 --report-format json,html
  ```

### Compatibility Guard
`validate_baseline_compatibility()` verifies that `baseline.benchmark_id == candidate.benchmark_id` and `baseline.benchmark_version == candidate.benchmark_version`. Incompatible baseline versions fail fast with exit code `2` (`ASB_INCOMPATIBLE_BASELINE`) instead of producing invalid cross-version comparisons.

---

## 3. Distinguishing Execution Failures vs. Security Failures

CI/CD pipelines must never confuse infrastructure instability with model security or silently pass partial runs:

| Exit Code | Failure Category | Meaning |
|---:|---|---|
| `0` | `passed` | Complete run; all thresholds and regression checks passed |
| `1` | `execution_failure` | Run `FAILED` or was incomplete (`PARTIALLY_COMPLETED`, `execution_errors > 0`, or `evaluation_failures > 0`) |
| `2` | `incompatible_baseline` / config error | Invalid config, inline secrets, or incompatible baseline benchmark version |
| `3` | `execution_failure` (auth) | Missing or rejected target API credentials |
| `4` | `security_gate_failed` | `ASR > max_attack_success_rate`, `critical_compromises > max_critical_vulnerabilities`, or `regression_detected` |
| `5` | not found | Missing suite, target, or dataset file |

**Incomplete Run Guarantee:** By default (`fail_on_incomplete_run: true`), any run with failed or timed-out test cases fails with exit code `1` rather than silently passing.

---

## 4. GitHub Actions Output & Artifacts

- **Artifacts:** Pass `--report-format json,html` and upload `reports/*.json` and `reports/*.html` with `if: always()` in `actions/upload-artifact@v4` so reports remain available even when a security gate fails.
- **Job Summary:** When `$GITHUB_STEP_SUMMARY` is present in GitHub Actions, `arbiter benchmark run` automatically appends a concise Markdown summary table showing run status, sample counts, ASR, Block Rate, critical compromises, baseline delta, and failure reasons.
