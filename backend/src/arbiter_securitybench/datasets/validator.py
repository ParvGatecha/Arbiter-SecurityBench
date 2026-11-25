"""Strict dataset quality, schema, uniqueness, and safety validator."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from arbiter_securitybench.attacks import AttackCategory
from arbiter_securitybench.contracts import (
    SCHEMA_VERSION,
    BenchmarkSuite,
    DifficultyLevel,
    SecurityCategory,
    TestCase,
    ValidationError,
)

# Real-world credential prefixes that must never appear in synthetic benchmark fixtures.
_FORBIDDEN_REAL_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class DatasetValidationReport(BaseModel):
    """Structured outcome of validating a benchmark dataset payload."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    total_cases: int = Field(ge=0)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    category_counts: dict[str, int] = Field(default_factory=dict)
    difficulty_counts: dict[str, int] = Field(default_factory=dict)
    benign_control_count: int = Field(default=0, ge=0)
    multi_turn_count: int = Field(default=0, ge=0)
    multilingual_count: int = Field(default=0, ge=0)


def _token_set(text: str) -> set[str]:
    return set(re.findall(r"[^\W_]{2,}", text.lower()))


def _jaccard_similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def validate_dataset_payload(
    raw_payload: dict[str, Any],
    *,
    expected_schema_version: str = SCHEMA_VERSION,
    near_duplicate_threshold: float = 0.85,
    strict: bool = False,
) -> DatasetValidationReport:
    """Validate a raw JSON dataset dict against schema, integrity, and quality rules."""
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(raw_payload, dict):
        msg = "Dataset root payload must be a JSON object."
        if strict:
            raise ValidationError(msg, component="datasets.validator")
        return DatasetValidationReport(valid=False, total_cases=0, errors=[msg])

    suite_schema_ver = raw_payload.get("schema_version")
    if suite_schema_ver != expected_schema_version:
        errors.append(
            f"Incorrect suite schema_version {suite_schema_ver!r}; expected {expected_schema_version!r}."
        )

    suite_version = raw_payload.get("version")
    raw_cases = raw_payload.get("test_cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        errors.append("Dataset must include a non-empty 'test_cases' list.")
        if strict:
            raise ValidationError("; ".join(errors), component="datasets.validator")
        return DatasetValidationReport(valid=False, total_cases=0, errors=errors)

    valid_categories = {c.value for c in SecurityCategory}
    seen_ids: set[str] = set()
    seen_prompts: dict[str, str] = {}
    prompt_tokens: list[tuple[str, set[str]]] = []
    validated_cases: list[TestCase] = []

    required_case_fields = (
        "test_id",
        "name",
        "description",
        "category",
        "attack_type",
        "difficulty",
        "severity",
        "input_prompt",
        "expected_behavior",
        "evaluation_criteria",
        "tags",
        "benchmark_version",
        "schema_version",
        "metadata",
    )

    for idx, item in enumerate(raw_cases):
        if not isinstance(item, dict):
            errors.append(f"Case at index {idx} must be an object.")
            continue

        missing = [f for f in required_case_fields if f not in item or item[f] is None]
        if missing:
            errors.append(
                f"Case {item.get('test_id', f'index-{idx}')!r} missing required fields: {', '.join(missing)}."
            )
            continue

        test_id = str(item["test_id"]).strip()
        if test_id in seen_ids:
            errors.append(f"Duplicate test_id detected: {test_id!r}.")
        seen_ids.add(test_id)

        if item.get("schema_version") != expected_schema_version:
            errors.append(
                f"Case {test_id!r} has incorrect schema_version {item.get('schema_version')!r} "
                f"(expected {expected_schema_version!r})."
            )

        if suite_version and item.get("benchmark_version") != suite_version:
            errors.append(
                f"Case {test_id!r} benchmark_version {item.get('benchmark_version')!r} "
                f"does not match suite version {suite_version!r}."
            )

        if item.get("category") not in valid_categories:
            errors.append(f"Case {test_id!r} has invalid category {item.get('category')!r}.")

        expected_behavior = item.get("expected_behavior")
        if not isinstance(expected_behavior, str) or not expected_behavior.strip():
            errors.append(f"Case {test_id!r} missing non-empty expected_behavior.")

        crit = item.get("evaluation_criteria")
        if not isinstance(crit, dict):
            errors.append(f"Case {test_id!r} evaluation_criteria must be an object.")
        else:
            desc = crit.get("description")
            succ = crit.get("success_indicators") or []
            fail = crit.get("failure_indicators") or []
            if not isinstance(desc, str) or not desc.strip():
                errors.append(f"Case {test_id!r} evaluation_criteria missing description.")
            if not succ and not fail:
                errors.append(
                    f"Case {test_id!r} evaluation_criteria must specify at least one success or failure indicator."
                )

        meta = item.get("metadata")
        if not isinstance(meta, dict) or not meta.get("evaluation_strategy"):
            errors.append(f"Case {test_id!r} metadata must include 'evaluation_strategy'.")

        # Validate full Pydantic TestCase model
        try:
            tc = TestCase.model_validate(item)
            validated_cases.append(tc)
        except PydanticValidationError as exc:
            errors.append(f"Case {test_id!r} failed Pydantic validation: {exc.errors()[0]['msg']}")
            continue

        # Check exact and near-duplicate input prompts
        norm_prompt = " ".join(tc.input_prompt.lower().split())
        if norm_prompt in seen_prompts:
            errors.append(
                f"Case {tc.test_id!r} duplicates input_prompt of {seen_prompts[norm_prompt]!r}."
            )
        else:
            seen_prompts[norm_prompt] = tc.test_id

        tokens = _token_set(tc.input_prompt)
        for other_id, other_tokens in prompt_tokens:
            sim = _jaccard_similarity(tokens, other_tokens)
            if sim >= near_duplicate_threshold:
                errors.append(
                    f"Case {tc.test_id!r} is nearly identical to {other_id!r} (Jaccard={sim:.2f})."
                )
        prompt_tokens.append((tc.test_id, tokens))

        # Safety check: forbid real-format credentials in prompts/system contexts
        combined_text = tc.input_prompt + "\n" + str(tc.metadata.get("system_context", ""))
        for pat in _FORBIDDEN_REAL_SECRET_PATTERNS:
            if pat.search(combined_text):
                errors.append(f"Case {tc.test_id!r} matched forbidden real-credential pattern.")

    # Validate full BenchmarkSuite coherence if case parsing succeeded
    if not errors:
        try:
            BenchmarkSuite.model_validate(raw_payload)
        except PydanticValidationError as exc:
            errors.append(f"BenchmarkSuite validation failed: {exc}")

    cat_counts: Counter[str] = Counter()
    diff_counts: Counter[str] = Counter()
    benign_count = 0
    multi_turn_count = 0
    multilingual_count = 0

    for tc in validated_cases:
        attack_cat = tc.metadata.get("attack_category")
        if attack_cat == AttackCategory.INSTRUCTION_HIERARCHY_MANIPULATION.value:
            cat_counts["instruction_hierarchy_manipulation"] += 1
        else:
            cat_counts[tc.category.value] += 1
        diff_counts[tc.difficulty.value] += 1
        if "benign_control" in tc.tags or tc.metadata.get("ground_truth_attack_success") is False:
            benign_count += 1
        if isinstance(tc.metadata.get("turns"), list) and len(tc.metadata["turns"]) > 1:
            multi_turn_count += 1
        if any(t.startswith("lang:") and t != "lang:en" for t in tc.tags):
            multilingual_count += 1

    if validated_cases:
        if len(diff_counts) < 3 or DifficultyLevel.EASY.value not in diff_counts:
            warnings.append("Dataset should cover easy, medium, and hard/expert difficulty levels.")
        if benign_count == 0:
            warnings.append("Dataset contains zero benign control cases for false-positive measurement.")
        if multi_turn_count == 0:
            warnings.append("Dataset contains zero multi-turn attack cases.")

    report = DatasetValidationReport(
        valid=len(errors) == 0,
        total_cases=len(raw_cases),
        errors=errors,
        warnings=warnings,
        category_counts=dict(sorted(cat_counts.items())),
        difficulty_counts=dict(sorted(diff_counts.items())),
        benign_control_count=benign_count,
        multi_turn_count=multi_turn_count,
        multilingual_count=multilingual_count,
    )
    if strict and not report.valid:
        raise ValidationError(
            f"Dataset validation failed with {len(errors)} error(s): {errors[0]}",
            component="datasets.validator",
            details={"error_count": len(errors), "errors": errors[:10]},
        )
    return report
