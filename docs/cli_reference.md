# Arbiter SecurityBench CLI Reference

The `arbiter` CLI (`arbiter_securitybench.cli`) provides standalone command-line workflows for initializing configuration, inspecting benchmarks, managing target adapters, executing security suites, validating datasets, and generating HTML/Markdown/JSON reports — **without requiring the FastAPI server to be running**.

Invoke via `arbiter <command>` (when installed) or `python -m arbiter_securitybench.cli <command>`.

---

## 1. Configuration (`securitybench.yaml`)

Arbiter SecurityBench looks for `securitybench.yaml` in the current working directory (or via `--config` / `ASB_CONFIG`).

```yaml
target:
  type: openai
  model: example-model
  api_key_env_var: OPENAI_API_KEY

benchmark:
  suite: security-v1

execution:
  timeout: 30
  max_retries: 2

report:
  format: html
  output_dir: reports
```

**Credential Safety Rule:** Never store raw `api_key` values in `securitybench.yaml`. Always reference an environment variable using `api_key_env_var` (the config loader rejects inline `api_key` values).

### Environment Variables

| Variable | Purpose |
|---|---|
| `ASB_CONFIG` | Path to `securitybench.yaml` |
| `ASB_DATABASE_URL` | Persistence URL (defaults to `sqlite:///.arbiter/securitybench.db`; supports `postgresql+psycopg://...`) |
| `ASB_JSON` | Set `1` or `true` to default to `--json` output |
| `ASB_NON_INTERACTIVE` | Set `1` or `true` to disable interactive prompts and spinners |
| `ASB_TIMEOUT` | Override `execution.timeout` (seconds) |
| `ASB_MAX_RETRIES` | Override `execution.max_retries` |
| `ASB_OUTPUT_DIR` | Override `report.output_dir` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | Target provider credentials |

---

## 2. CI/CD Exit Codes

| Code | Constant | Meaning |
|---:|---|---|
| `0` | `SUCCESS` | Operation succeeded and all security gates passed |
| `1` | `EXECUTION_OR_VALIDATION_FAILED` | Benchmark run failed or dataset validation failed |
| `2` | `CONFIGURATION_ERROR` | Invalid/missing `securitybench.yaml`, bad options, or inline secret detected |
| `3` | `AUTHENTICATION_ERROR` | Missing or rejected target API credentials |
| `4` | `SECURITY_GATE_FAILED` | `--fail-on-critical` or `--max-asr` threshold exceeded |
| `5` | `NOT_FOUND` | Requested benchmark, target, run, or dataset file not found |

Global root options: `--config / -c`, `--json`, `--non-interactive / -y`.

---

## 3. Command Reference & Examples

### `arbiter init`
Creates a secret-free `securitybench.yaml` template.

```bash
arbiter init --target-type openai --model gpt-4o-mini --non-interactive
arbiter init --path custom.yaml --force --json
```

### `arbiter version`
Displays platform, contract schema, methodology, and Python versions.

```bash
arbiter version
arbiter version --json
```

### `arbiter benchmark list`
Lists available benchmarks (`arbiter-security-benchmark` v1.0.0 plus any `--suite-file`).

```bash
arbiter benchmark list
arbiter benchmark list --category prompt_injection --json
```

### `arbiter benchmark inspect <benchmark_id>`
Displays suite metadata, difficulty/severity distribution, and sample test cases. Accepts aliases like `security-v1`.

```bash
arbiter benchmark inspect security-v1 --limit 10
arbiter benchmark inspect arbiter-security-benchmark --version 1.0.0 --json
```

### `arbiter target add` & `arbiter target list`
Manage targets configured in `securitybench.yaml` without storing API keys.

```bash
arbiter target add --id local-ollama --type ollama --model llama3.2 --non-interactive
arbiter target add --id internal-rag --type http --endpoint-url http://localhost:8080/ask --non-interactive
arbiter target list
arbiter target list --json
```

### `arbiter benchmark run`
Executes a benchmark suite standalone, runs evaluators and statistical scoring, persists the run and results to the database, and optionally enforces CI/CD security gates.

```bash
# Run full suite using securitybench.yaml
arbiter benchmark run

# CI/CD non-interactive run with JSON output, report export, and failure thresholds
arbiter --non-interactive benchmark run \
  --suite security-v1 \
  --target local-ollama \
  --timeout 30 \
  --max-retries 2 \
  --fail-on-critical \
  --max-asr 0.05 \
  --export-report \
  --json
```

### `arbiter report generate`
Generates `html`, `markdown`, or `json` reports from any persisted benchmark run.

```bash
# Export HTML report for the latest run using settings in securitybench.yaml
arbiter report generate

# Export Markdown report for a specific run ID
arbiter report generate --run-id run-abc123 --format markdown --output-dir ./reports
```

### `arbiter dataset validate`
Validates a benchmark dataset JSON file for schema compliance, duplicate IDs, near-duplicate prompts, evaluation criteria completeness, and credential safety.

```bash
arbiter dataset validate
arbiter dataset validate datasets/arbiter_security_benchmark_v1.0.json --json
```
