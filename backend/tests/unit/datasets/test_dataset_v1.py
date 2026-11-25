"""Automated validation and registry integration tests for Arbiter Security Benchmark v1.0."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from arbiter_securitybench.attacks import AttackRegistry
from arbiter_securitybench.contracts import DifficultyLevel, ValidationError
from arbiter_securitybench.datasets import (
    default_v1_dataset_path,
    load_benchmark_suite,
    register_arbiter_benchmark_v1,
    validate_dataset_payload,
)
from arbiter_securitybench.registry import BenchmarkCoreRegistry


def _load_raw_v1() -> dict[str, Any]:
    return json.loads(default_v1_dataset_path().read_text(encoding="utf-8"))


def test_v1_dataset_passes_validation_and_exact_distribution() -> None:
    raw = _load_raw_v1()
    report = validate_dataset_payload(raw, strict=True)

    assert report.valid is True
    assert report.errors == []
    assert report.warnings == []
    assert report.total_cases == 100
    assert report.category_counts == {
        "instruction_hierarchy_manipulation": 15,
        "jailbreak_resistance": 25,
        "prompt_injection": 25,
        "sensitive_data_leakage": 15,
        "system_prompt_extraction": 20,
    }
    assert report.difficulty_counts[DifficultyLevel.EASY.value] > 0
    assert report.difficulty_counts[DifficultyLevel.MEDIUM.value] > 0
    assert (
        report.difficulty_counts.get(DifficultyLevel.HARD.value, 0)
        + report.difficulty_counts.get(DifficultyLevel.EXPERT.value, 0)
    ) > 0
    assert report.benign_control_count >= 10
    assert report.multi_turn_count >= 10
    assert report.multilingual_count >= 10


def test_v1_dataset_loads_into_benchmark_registry_and_resolves_attacks() -> None:
    core_registry = BenchmarkCoreRegistry()
    suite = register_arbiter_benchmark_v1(core_registry)

    assert suite.suite_id == "arbiter-security-benchmark"
    assert suite.version == "1.0.0"
    assert suite.test_count == 100

    loaded = core_registry.get_benchmark("arbiter-security-benchmark", version="1.0.0")
    assert loaded.content_digest == suite.content_digest
    assert load_benchmark_suite().test_count == 100

    # Verify every test case resolves cleanly to an Attack in AttackRegistry
    attack_registry = AttackRegistry()
    for tc in loaded.test_cases:
        attack = attack_registry.resolve_for_test_case(tc)
        assert attack.attack_id == tc.metadata["attack_id"]


def test_validator_catches_duplicates_missing_fields_bad_categories_and_versions() -> None:
    base = _load_raw_v1()

    # 1. Duplicate test_id
    dup_id = copy.deepcopy(base)
    dup_id["test_cases"][1]["test_id"] = dup_id["test_cases"][0]["test_id"]
    rep_dup = validate_dataset_payload(dup_id)
    assert rep_dup.valid is False
    assert any("Duplicate test_id" in e for e in rep_dup.errors)

    # 2. Missing required fields
    missing_field = copy.deepcopy(base)
    del missing_field["test_cases"][0]["tags"]
    rep_missing = validate_dataset_payload(missing_field)
    assert rep_missing.valid is False
    assert any("missing required fields" in e for e in rep_missing.errors)

    # 3. Invalid category
    bad_cat = copy.deepcopy(base)
    bad_cat["test_cases"][0]["category"] = "nonexistent_category"
    rep_cat = validate_dataset_payload(bad_cat)
    assert rep_cat.valid is False
    assert any("invalid category" in e for e in rep_cat.errors)

    # 4. Missing expected_behavior
    no_exp = copy.deepcopy(base)
    no_exp["test_cases"][0]["expected_behavior"] = "   "
    rep_exp = validate_dataset_payload(no_exp)
    assert rep_exp.valid is False
    assert any("expected_behavior" in e for e in rep_exp.errors)

    # 5. Missing evaluation_criteria indicators
    no_crit = copy.deepcopy(base)
    no_crit["test_cases"][0]["evaluation_criteria"] = {
        "description": "Empty indicators",
        "success_indicators": [],
        "failure_indicators": [],
    }
    rep_crit = validate_dataset_payload(no_crit)
    assert rep_crit.valid is False
    assert any("evaluation_criteria" in e for e in rep_crit.errors)

    # 6. Incorrect schema version
    bad_ver = copy.deepcopy(base)
    bad_ver["schema_version"] = "9.9.9"
    bad_ver["test_cases"][0]["schema_version"] = "9.9.9"
    rep_ver = validate_dataset_payload(bad_ver)
    assert rep_ver.valid is False
    assert any("schema_version" in e for e in rep_ver.errors)

    # 7. Near-duplicate input prompt & strict=True raises ValidationError
    near_dup = copy.deepcopy(base)
    near_dup["test_cases"][1]["input_prompt"] = near_dup["test_cases"][0]["input_prompt"] + " "
    with pytest.raises(ValidationError):
        validate_dataset_payload(near_dup, strict=True)
