# Development Roadmap — Arbiter SecurityBench

**Roadmap Version:** `1.0.0`

This roadmap defines phased milestones, verifiable exit criteria, and open engineering decisions for building Arbiter SecurityBench from its Phase 0 architectural foundation to a production-grade open-source platform.

---

## Phase 0: Foundation, Contracts & Methodology *(Current Phase)*

### Scope
- Independent project repository structure (`backend`, `frontend`, `infra`)
- Core domain contracts (`arbiter_securitybench.contracts`): Pydantic v2 schemas, ABC/Protocol interfaces, lifecycle state machines, typed error taxonomy, semantic versioning & SHA-256 canonical digest helpers
- Foundational documentation (`README`, `ARCHITECTURE`, `BENCHMARK_METHODOLOGY`, `SCORING_METHODOLOGY`, `THREAT_MODEL`, `DEVELOPMENT_ROADMAP`)
- Contract unit tests validating schema invariants and lifecycle state transitions

### Exit Criteria
- [x] All 6 foundational documents authored and internally consistent
- [x] Core contracts importable with zero infrastructure dependencies (`pydantic` + stdlib only)
- [x] `pytest` contract suite passing

---

## Phase 1: Core Services, Storage & Deterministic Execution Engine

### Scope
- Implement `BenchmarkManager`, `BenchmarkRegistry`, and `TestCaseManager` with digest verification and lifecycle enforcement
- Implement `ResultStore` backed by PostgreSQL (SQLAlchemy + Alembic migrations) plus canonical `ResultBundle` JSON/JSONL + `checksums.sha256` exporter/importer
- Implement `AttackExecutor` with deterministic child-seed derivation, bounded retry/timeout handling, `ExecutionEnvironmentSnapshot` capture, and `ExecutionTrace` persistence
- Implement deterministic mock `TargetAdapter` implementations (vulnerable & hardened reference fixtures) for offline unit and reproducibility testing

### Exit Criteria
- [ ] Re-running an identical benchmark manifest against a deterministic mock adapter produces bit-for-bit identical `ExecutionTrace` digests (`tests/reproducibility/`)
- [ ] Lifecycle transitions and immutability of `PUBLISHED` benchmarks enforced at both service and DB constraint layers
- [ ] PostgreSQL `ResultStore` integration tests passing (`tests/integration/`)

---

## Phase 2: Target Adapters & Sandboxed Modality Harnesses

### Scope
- **LLM Adapters:** OpenAI-compatible HTTP adapter, Anthropic-compatible adapter, and local/vLLM adapter with strict secret-redacted `TargetConfig` snapshotting
- **RAG Harness & Adapter:** Ephemeral per-session vector/document fixture loader enforcing zero cross-case state bleed and recording `retrieved_context_refs`
- **Agent & Tool Sandbox Adapter:** Containerized/isolated tool router intercepting `ToolCallRecord` invocations, enforcing `tool_permissions`, simulating honey-tools, and blocking outbound network access
- Conformance test suite verifying every `TargetAdapter` adheres to `initialize_session` / `invoke_turn` / `teardown_session` and error-taxonomy contracts

### Exit Criteria
- [ ] All three `TargetModality` types (`LLM`, `RAG`, `AGENT`) runnable end-to-end against isolated reference harnesses
- [ ] Timeout, rate-limit, and transport failures reliably map to `AttackOutcome.EXECUTION_ERROR` + `VerificationStatus.ERRORED`
- [ ] Sandbox isolation verified against path-traversal and unauthorized outbound network attempts

---

## Phase 3: Evaluation, Scoring, Statistical Analysis & Reporting

### Scope
- **Evaluation Engine:**
  - Deterministic evaluators (`DETERMINISTIC_RULE`, `CANARY_MATCH`, `TOOL_POLICY_ASSERTION`)
  - Calibrated `LLM_JUDGE` / `CLASSIFIER` / `HYBRID_CONSENSUS` pipeline strictly emitting `PRELIMINARY` (`UNVERIFIED`) until calibrated/adjudicated
  - Human adjudication workflow promoting `PRELIMINARY` / `DISPUTED` -> `VERIFIED`
- **Scoring Engine:** Implementation of `ASR`, `DR`, `SWRS`, `Pass@k` diagnostics, and strict `verified_only` separation
- **Statistical Analyzer (NumPy + SciPy):** Wilson score & Clopper-Pearson intervals, clustered case-level bootstrap CIs, exact McNemar's test, Wilcoxon signed-rank test, Holm-Bonferroni / Benjamini-Hochberg adjustments, Cohen's $\kappa$ / Krippendorff's $\alpha$
- **Reporting:** JSON, Markdown, SARIF, and signed/checksummed `ResultBundle` archive generators

### Exit Criteria
- [ ] Statistical unit tests verified against exact reference values in SciPy
- [ ] Report generator refuses to present `UNVERIFIED` / `ERRORED` evaluations as verified findings
- [ ] Re-scoring an archived `ResultBundle` under a new `scoring_version` works offline without re-executing attacks

---

## Phase 4: REST API, Celery/Redis Workers, Docker & React Workbench

### Scope
- **FastAPI REST API (`api`):** Versioned `/api/v1` endpoints, OpenAPI schema generation, pagination, structured error responses
- **Celery + Redis (`workers`):** Distributed execution & batch evaluation queues with idempotent checkpointing and cancellation support
- **Docker Stack (`infra`):** Multi-container `docker-compose.yml` (API, Worker, Sandbox, PostgreSQL, Redis, Frontend)
- **React + TypeScript Frontend (`frontend`):** Benchmark browser, test case review queue, run launcher & progress view, verification/adjudication workbench, statistical comparison explorer, and bundle export

### Exit Criteria
- [ ] End-to-end containerized workflow: submit benchmark run via UI/API -> execute asynchronously in Celery -> evaluate -> inspect verified findings & CIs -> export `ResultBundle`
- [ ] Integration tests covering API + Celery + PostgreSQL + Redis lifecycle

---

## Phase 5: Enterprise Module Integration & Governance

### Scope
- Clean Python SDK facade (`arbiter_securitybench.sdk`) for embedding into larger enterprise AI security platforms
- Pluggable authentication/RBAC/multi-tenancy context hooks for `api` and `storage`
- Signed attestation support for `ResultBundle` and `BenchmarkSpec` releases (e.g., Sigstore / detached signatures)
- Initial community-reviewed open-source benchmark suite releases across all 7 `SecurityCategory` domains (authored through the `CALIBRATED` -> `PUBLISHED` curation pipeline)

---

## Unresolved Engineering & Governance Decisions

1. **Vector Store Backend for Reference RAG Harness:** Decide between an embedded pure-Python/FAISS ephemeral index vs. `pgvector` in Phase 2 (embedded ephemeral index strongly preferred for zero cross-case leakage).
2. **Async vs. Sync `ResultStore` Protocol:** Currently `ResultStore` methods are synchronous while `AttackExecutor` and `EvaluationEngine` are `async`; decide whether to introduce `AsyncResultStore` or keep storage calls explicitly bounded/offloaded before Phase 1 DB implementation.
3. **SARIF Mapping Granularity:** Define how `ExecutionTrace` + `EvaluationResult` map to SARIF `result` locations and `tool` rules for CI/CD security gate integrations in Phase 3.
4. **Judge Calibration Dataset Governance:** Establish rules for maintaining a held-out calibration corpus so judge prompts/models are not overfit to public test cases.
