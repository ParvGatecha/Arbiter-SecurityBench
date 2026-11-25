"""Unit tests for BenchmarkCoreRegistry: registration, duplicates, versions, queries."""

from __future__ import annotations

import pytest

from arbiter_securitybench.contracts import (
    DuplicateRegistrationError,
    NotFoundError,
    SecurityCategory,
    TargetModality,
)
from arbiter_securitybench.registry import BenchmarkCoreRegistry
from conftest import build_suite, build_test_case


def test_register_and_retrieve_benchmark_suite() -> None:
    registry = BenchmarkCoreRegistry()
    suite = build_suite(suite_id="bench-alpha", version="1.0.0")
    saved = registry.register_suite(suite)

    assert saved.suite_id == "bench-alpha"
    fetched = registry.get_benchmark("bench-alpha")
    assert fetched.version == "1.0.0"
    assert fetched.test_count == 2

    definition = registry.get_benchmark_definition("bench-alpha")
    assert definition.latest_version == "1.0.0"
    assert definition.versions == ["1.0.0"]


def test_duplicate_suite_registration_raises() -> None:
    registry = BenchmarkCoreRegistry()
    suite = build_suite(suite_id="bench-dup", version="1.0.0")
    registry.register_suite(suite)

    with pytest.raises(DuplicateRegistrationError):
        registry.register_suite(suite)


def test_duplicate_test_case_registration_raises() -> None:
    registry = BenchmarkCoreRegistry()
    tc = build_test_case(test_id="tc-unique-1", benchmark_version="1.0.0")
    registry.register_test_case(tc)

    assert registry.get_test_case("tc-unique-1", "1.0.0").test_id == "tc-unique-1"
    with pytest.raises(DuplicateRegistrationError):
        registry.register_test_case(tc)


def test_benchmark_version_management_uses_semver_ordering() -> None:
    registry = BenchmarkCoreRegistry()
    registry.register_suite(build_suite(suite_id="bench-ver", version="1.2.0"))
    registry.register_suite(build_suite(suite_id="bench-ver", version="1.10.0"))
    registry.register_suite(build_suite(suite_id="bench-ver", version="1.0.0"))

    assert registry.list_versions("bench-ver") == ["1.0.0", "1.2.0", "1.10.0"]
    assert registry.get_benchmark("bench-ver").version == "1.10.0"
    assert registry.get_benchmark("bench-ver", version="1.2.0").version == "1.2.0"

    definition = registry.get_benchmark_definition("bench-ver")
    assert definition.latest_version == "1.10.0"
    assert definition.versions == ["1.0.0", "1.2.0", "1.10.0"]


def test_retrieve_and_filter_by_category_and_modality() -> None:
    registry = BenchmarkCoreRegistry()
    suite_rag = build_suite(
        suite_id="bench-rag",
        version="1.0.0",
        supported_target_types=[TargetModality.RAG],
        test_cases=[
            build_test_case(
                test_id="tc-rag-1",
                category=SecurityCategory.RAG_SECURITY,
            )
        ],
    )
    suite_tool = build_suite(
        suite_id="bench-tool",
        version="1.0.0",
        supported_target_types=[TargetModality.AGENT],
        test_cases=[
            build_test_case(
                test_id="tc-tool-1",
                category=SecurityCategory.TOOL_SECURITY,
            )
        ],
    )
    registry.register_suite(suite_rag)
    registry.register_suite(suite_tool)

    rag_suites = registry.get_benchmarks_by_category(SecurityCategory.RAG_SECURITY)
    assert [s.suite_id for s in rag_suites] == ["bench-rag"]

    agent_suites = registry.list_benchmarks(target_type=TargetModality.AGENT)
    assert [s.suite_id for s in agent_suites] == ["bench-tool"]

    with pytest.raises(NotFoundError):
        registry.get_benchmark("does-not-exist")
