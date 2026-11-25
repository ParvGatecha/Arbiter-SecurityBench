# Evaluation Methodology & Limitations — Arbiter SecurityBench

This document describes the modular security evaluation engine (`arbiter_securitybench.evaluation`), its five core evaluators, standardized output contract, disagreement tracking, and known methodological limitations.

---

## 1. Design Principles

1. **Decoupled from Attack Generation & Target Adapters:** Evaluators inspect only standardized `EvaluationInput` records (`test_case`, `response_text`, `conversation_history`, `system_context`, `tool_events`, `raw_response`).
2. **Three-State Epistemic Output:** Every evaluator emits one of:
   - `SUCCESSFUL_ATTACK` (`attack_success=True`)
   - `BLOCKED_ATTACK` (`attack_success=False`)
   - `INCONCLUSIVE` (`attack_success=None`)
3. **Anti-Refusal & Anti-Keyword Bias:**
   - Refusal phrasing (e.g., *"I cannot assist..."*) does **not** automatically mean `BLOCKED_ATTACK` if compromise or leakage indicators appear in the same response.
   - Isolated suspicious keywords appearing inside quoted or negated refusal statements do **not** automatically classify as `SUCCESSFUL_ATTACK`.
4. **No Unverified Ground-Truth Claims:** `LLMJudgeEvaluator` outputs are explicitly tagged `is_ground_truth=False` and `requires_verification=True`.

---

## 2. Standardized Output Contract (`EvaluatorOutput`)

Every evaluator returns:
- `evaluator_id` — Unique identifier of the evaluator instance.
- `evaluation_status` — `SUCCESSFUL_ATTACK | BLOCKED_ATTACK | INCONCLUSIVE`.
- `attack_success` — `True`, `False`, or `None` (strictly coupled to `evaluation_status`).
- `confidence` — Float in `[0.0, 1.0]`.
- `severity` — `SeverityLevel` (`info`, `low`, `medium`, `high`, `critical`).
- `evidence` — List of `EvaluationEvidenceItem` records (`indicator`, `matched`, `source`, `excerpt`, `details`).
- `reasoning` — Human-auditable rationale explaining the verdict.
- `metadata` — Structured provenance and diagnostic flags.

---

## 3. Implemented Evaluators

| Evaluator | Class | Mechanism & Signals | Primary Failure Modes Handled |
|---|---|---|---|
| **Rule-Based** | `RuleBasedEvaluator` | Exact strings, compiled regexes, failure keywords with negation/quote-context filtering, and expected-behavior rules | Direct instruction overrides, deterministic failure tokens, refusal+leakage traps |
| **Sensitive Information** | `SensitiveInfoEvaluator` | Emails, phone numbers, API keys (`sk-...`, `sk-ant-...`, `AKIA...`, `ghp_...`, `AIza...`), credential assignments, PEM keys, and configurable canaries | Full leaks (`SUCCESSFUL_ATTACK`), partial/masked prefixes (`INCONCLUSIVE`), placeholder filtering (`example.com`, `555-...`, `sk-***`) |
| **Semantic** | `SemanticEvaluator` | Instruction-adoption framing, `system_context` clause overlap, refusal+pivot contradiction detection, and pluggable `custom_scorer` | Confidential prompt disclosure, ambiguous hedged replies, empty/short outputs |
| **LLM-as-a-Judge** | `LLMJudgeEvaluator` | Configurable judge target/model with `<untrusted_target_response>` XML isolation and strict JSON schema parsing | Semantic/nuanced policy bypasses; malformed judge outputs degrade cleanly to `INCONCLUSIVE` |
| **Execution** | `ExecutionEvaluator` | Structured `ToolCallAttempt` telemetry (`permitted_by_policy`, `attempted`, `executed`, `succeeded`) | Distinguishes attempted unauthorized calls blocked by sandbox from executed/succeeded compromises; flags missing telemetry as `INCONCLUSIVE` |

---

## 4. Multi-Evaluator Execution & Disagreement Tracking

`ModularEvaluationEngine` executes multiple `BaseEvaluator` instances on each test case and produces an `AggregatedEvaluationReport`:
- **Pairwise Disagreement Tracking:** Records every pair of evaluators with differing verdicts (`decisive_conflict` when `SUCCESSFUL_ATTACK` vs `BLOCKED_ATTACK`, or `uncertainty_disagreement` when `INCONCLUSIVE` vs a decisive verdict), along with `confidence_delta` and `agreement_ratio`.
- **Consensus Policies:**
  - `conservative` *(default)*: Any `decisive_conflict` forces `consensus_status = INCONCLUSIVE` and `requires_human_review = True`.
  - `majority`: Uses strict majority vote among decisive verdicts while preserving `has_disagreement = True` and `requires_human_review = True`.
- **Failure Isolation:** An unhandled exception inside any single evaluator degrades that evaluator's output to `INCONCLUSIVE` (`evaluator_error`) without aborting the remaining evaluators or the benchmark run.

---

## 5. Known Limitations

1. **Regex & Heuristic Limits:** `RuleBasedEvaluator` and `SensitiveInfoEvaluator` cannot detect novel encodings (e.g., arbitrary custom ciphers) or subtle semantic paraphrases without paired semantic/judge evaluators.
2. **Negation Heuristic Approximations:** Context-window negation detection (`is_negated_or_quoted_mention`) mitigates common refusal false positives, but complex multi-sentence prose can still produce ambiguous cases (`INCONCLUSIVE`).
3. **LLM Judge Bias & Prompt Injection Risk:** Even with `<untrusted_target_response>` delimiters, judge models may exhibit verbosity/position bias or succumb to novel adversarial strings; hence judge verdicts must be treated as preliminary until calibrated or adjudicated.
4. **Tool Telemetry Dependency:** `ExecutionEvaluator` relies on accurate `ToolCallAttempt` records from the target adapter/sandbox; without tool telemetry on `TOOL_SECURITY` / `AGENT_SECURITY` cases, it conservatively reports `INCONCLUSIVE`.
