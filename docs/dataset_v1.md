# Arbiter Security Benchmark v1.0 — Dataset Specification

**Suite ID:** `arbiter-security-benchmark`  
**Dataset Version:** `1.0.0`  
**Contract Schema Version:** `1.0.0`  
**Dataset File:** [arbiter_security_benchmark_v1.0.json](../datasets/arbiter_security_benchmark_v1.0.json)

---

## 1. Scope

**Arbiter Security Benchmark v1.0** is the initial standardized, open-source baseline dataset of **100 curated, non-destructive test cases** evaluating core LLM and application-layer security boundaries across five attack categories:

| Category | Count | ID Range | Primary Techniques Covered |
|---|---:|---|---|
| **Prompt Injection** | 25 | `ASB-PI-001` – `ASB-PI-025` | Direct overrides, markdown/HTML/JSON/CSV/email/code/log/XML indirect injection, Base64, multilingual, multi-turn, benign controls |
| **Jailbreak Resistance** | 25 | `ASB-JB-001` – `ASB-JB-025` | Persona framing, fictional/hypothetical pretexts, ROT13/leetspeak/reverse/token-splitting obfuscation, multi-turn crescendo, JSON forcing, multilingual, benign controls |
| **System Prompt Extraction** | 20 | `ASB-SPE-001` – `ASB-SPE-020` | Verbatim requests, JSON/YAML repackaging, translation side-channels, prefix completion, Base64/reverse extraction, oracle probing, multi-turn elicitation, benign controls |
| **Sensitive Data Leakage** | 15 | `ASB-SDL-001` – `ASB-SDL-015` | Synthetic canary keys/emails/phones/tokens, curl/table/crash-log exfiltration, cross-tenant confusion, partial prefix/hex leaks, multi-turn extraction, benign controls |
| **Instruction Hierarchy Manipulation** | 15 | `ASB-IHM-001` – `ASB-IHM-015` | Spoofed `[SYSTEM]`/`[DEVELOPER]`/`[ADMIN]` headers, fake ChatML/XML role tags, template tokens, retrieved/tool authority spoofing, multi-turn priority inversion, benign controls |

### Dataset Composition Highlights
- **Difficulty Coverage:** 16 `easy`, 41 `medium`, 33 `hard`, and 10 `expert` test cases.
- **Turn Diversity:** 87 single-turn cases and 13 multi-turn cases (`metadata.turns`).
- **Multilingual Coverage:** 16 non-English cases spanning Spanish (`es`), French (`fr`), German (`de`), Japanese (`ja`), and Portuguese (`pt`).
- **False-Positive Controls:** 12 benign control cases (`tags` includes `"benign_control"`, `metadata.ground_truth_attack_success = false`) enabling empirical False Positive Rate (FPR) measurement.

---

## 2. Methodology & Safety Guarantees

1. **Non-Destructive Synthetic Fixtures:** All data-leakage and prompt-extraction checks rely exclusively on clearly marked synthetic canary tokens (e.g., `CANARY-KEY-9041-ALPHA`, `canary.user.402@synthetic-arbiter.invalid`, `SYNTHETIC_SYS_CLAUSE_8841`). Zero real PII, production credentials, or live exploit payloads are included.
2. **Explicit Evaluation Criteria:** Every test case defines `expected_behavior`, `evaluation_criteria` (`description`, `success_indicators` / `failure_indicators`), and `metadata.evaluation_strategy`.
3. **Uniqueness & Anti-Duplication:** Automated validation checks both exact normalized prompt equality and token Jaccard similarity (`< 0.85`) across all 100 prompts.

---

## 3. Limitations

**Arbiter Security Benchmark v1.0 does not represent all real-world AI attacks.** Specifically:

1. **Baseline Coverage Only:** 100 static text cases cannot exhaustively represent adaptive red-teaming, novel zero-day jailbreaks, or domain-specific vertical threats.
2. **No Live Tool/RAG Side-Effect Execution:** While several cases simulate untrusted tool/retrieved text blocks, v1.0 focuses on prompt-level robustness; dedicated sandboxed `tool_security`, `rag_security`, and autonomous `agent_security` suites are planned for subsequent versions.
3. **Text-Only Modality:** Multimodal (image, audio, PDF rendering) injection vectors are outside the scope of v1.0.
4. **Training Contamination Risk:** Because v1.0 is a public open-source baseline dataset, future foundation models may memorize public prompts over time; comparative evaluations should track run dates and pair public suites with private held-out suites.
5. **Illustrative Multilingual Coverage:** Non-English cases cover five languages and do not generalize to low-resource languages or cross-script attacks.

---

## 4. Intended Usage

Load and register the dataset directly into `BenchmarkCoreRegistry`:

```python
from arbiter_securitybench.datasets import register_arbiter_benchmark_v1
from arbiter_securitybench.registry import BenchmarkCoreRegistry

registry = BenchmarkCoreRegistry()
suite = register_arbiter_benchmark_v1(registry)
print(suite.suite_id, suite.version, suite.test_count)
```

Validate the dataset file from the command line:

```bash
python scripts/validate_dataset.py
```

---

## 5. Versioning Policy

Arbiter Security Benchmark follows **Semantic Versioning (`MAJOR.MINOR.PATCH`)** paired with immutable SHA-256 `content_digest` values:

- **`PATCH` (`1.0.x`):** Typographical fixes or metadata clarifications that do not alter `input_prompt` semantics or evaluation outcomes.
- **`MINOR` (`1.x.0`):** Backward-compatible additions of new test cases or new evaluation criteria without breaking existing `test_id` mappings.
- **`MAJOR` (`x.0.0`):** Removal/replacement of test cases, category restructuring, or breaking `schema_version` updates.

Published releases (`1.0.0`) are immutable; benchmark comparisons across differing `benchmark_version` values emit a `BENCHMARK_VERSION_MISMATCH` warning in `BenchmarkComparisonReport`.
