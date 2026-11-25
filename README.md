# Arbiter SecurityBench

**Arbiter SecurityBench** is an independent, open-source AI security benchmarking platform designed to evaluate the security, robustness, and resilience of Large Language Models (LLMs), Retrieval-Augmented Generation (RAG) systems, and autonomous AI agents.

> **Project Status:** Phase 0 — Foundational Architecture, Domain Contracts, and Methodology Specification.
> No full application runtime, benchmark datasets, or model scores are included yet.

---

## Core Design Principles

1. **Independent & Open-Source:** Standalone codebase with zero runtime or build dependencies on any external proprietary or existing Arbiter repository.
2. **Composable & Enterprise-Ready:** Clean separation between domain contracts (`arbiter_securitybench.contracts`), execution/evaluation engines, storage, and transport layers (`api`, `workers`, `frontend`) so the core benchmarking engine can operate standalone or embed as a module inside a larger enterprise AI security platform.
3. **Reproducibility by Construction:** Every execution run is pinned by an immutable `ExecutionManifest` capturing benchmark content digests, pinned test case versions, target configuration snapshots, random seeds, component versions, and runtime environment metadata.
4. **Epistemic Integrity:**
   - Benchmark results are never fabricated, extrapolated, or hardcoded.
   - Unverified, preliminary, indeterminate, or errored evaluations (`VerificationStatus.UNVERIFIED`, `INDETERMINATE`, `ERRORED`) are never represented as verified security findings.
   - Adapter timeouts, rate limits, and sandbox failures are recorded explicitly as `AttackOutcome.EXECUTION_ERROR` rather than misclassified as target defenses.
5. **Scientific Validity:** Scoring relies on explicit outcome accounting, confidence intervals, hypothesis testing, and inter-rater reliability checks rather than uncalibrated single-number claims.

---

## Initial Security Categories

| Category (`SecurityCategory`) | Primary Target Modalities | Core Risk Focus |
|---|---|---|
| `prompt_injection` | LLM, RAG, Agent | Direct and indirect instruction override across untrusted data boundaries |
| `jailbreak_resistance` | LLM, Agent | Policy/safety bypass via encoding, roleplay, multi-turn escalation, or obfuscation |
| `sensitive_data_leakage` | LLM, RAG, Agent | Unauthorized disclosure of PII, secrets, credentials, or cross-tenant records |
| `system_prompt_extraction` | LLM, RAG, Agent | Recovery of confidential system instructions, routing rules, or hidden tool schemas |
| `tool_security` | Agent | Unauthorized tool invocation, parameter tampering, privilege escalation, SSRF/path traversal |
| `rag_security` | RAG, Agent | Corpus poisoning, retrieval hijacking, citation spoofing, and access-control bypass |
| `agent_security` | Agent | Goal hijacking, memory poisoning, delegation abuse, and multi-step unsafe action chains |

---

## Technology Stack

- **Backend & Core Contracts:** Python 3.11+, FastAPI, Pydantic v2
- **Frontend Workbench:** React, TypeScript
- **Persistence:** PostgreSQL + canonical content-addressed `ResultBundle` exports
- **Asynchronous Orchestration:** Celery, Redis
- **Statistical Analysis:** NumPy, SciPy
- **Testing & Quality:** Pytest, Ruff, Mypy
- **Containerization:** Docker

---

## Repository Structure

```text
.
├── README.md
├── ARCHITECTURE.md
├── BENCHMARK_METHODOLOGY.md
├── SCORING_METHODOLOGY.md
├── THREAT_MODEL.md
├── DEVELOPMENT_ROADMAP.md
├── pyproject.toml
├── backend/
│   ├── src/arbiter_securitybench/
│   │   ├── contracts/        # Zero-infra Pydantic v2 schemas, ABCs/Protocols, lifecycles, errors, versioning
│   │   ├── registry/         # Immutable benchmark registry (Phase 1)
│   │   ├── benchmarks/       # Benchmark authoring & lifecycle management (Phase 1)
│   │   ├── test_cases/       # Test case curation & calibration management (Phase 1)
│   │   ├── execution/        # Deterministic attack execution engine (Phase 1)
│   │   ├── adapters/         # Target adapters for LLM, RAG, and Agent systems (Phase 2)
│   │   ├── evaluation/       # Deterministic & hybrid evaluation engine (Phase 3)
│   │   ├── scoring/          # Category & severity-weighted scoring engine (Phase 3)
│   │   ├── statistics/       # NumPy/SciPy confidence intervals & significance tests (Phase 3)
│   │   ├── reporting/        # Reproducible JSON, Markdown, SARIF, bundle exporters (Phase 3)
│   │   ├── storage/          # PostgreSQL persistence & artifact store boundary (Phase 1)
│   │   ├── workers/          # Celery/Redis async execution workers (Phase 4)
│   │   └── api/              # FastAPI REST API transport layer (Phase 4)
│   └── tests/
│       ├── unit/contracts/   # Contract schema, lifecycle, error, and versioning tests
│       ├── integration/      # Planned DB, Celery, API, and adapter integration tests
│       └── reproducibility/  # Planned determinism & manifest round-trip tests
├── frontend/                 # Planned React + TypeScript workbench
└── infra/                    # Planned Dockerfiles & Compose stack
```

---

## Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md) — Modular architecture, core interfaces, lifecycles, storage format, error handling, versioning, and architectural risks.
- [BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md) — Reproducibility protocol, test case lifecycle, attack execution harnesses, and evaluation rules across all 7 categories.
- [SCORING_METHODOLOGY.md](SCORING_METHODOLOGY.md) — Mathematical definitions, missing/errored trace accounting, confidence intervals, hypothesis tests, and inter-rater agreement.
- [THREAT_MODEL.md](THREAT_MODEL.md) — Threat model covering both evaluated AI targets and the benchmarking platform itself.
- [DEVELOPMENT_ROADMAP.md](DEVELOPMENT_ROADMAP.md) — Phased implementation plan, milestones, exit criteria, and unresolved design decisions.

---

## Verifying Phase 0 Contracts

Phase 0 includes executable Python contracts (`backend/src/arbiter_securitybench/contracts/`) and contract unit tests (`backend/tests/unit/contracts/test_contracts.py`):

```bash
pytest
```
