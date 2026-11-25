"""Benchmark Registry service managing suites, test cases, and semantic versions."""

from __future__ import annotations

from datetime import UTC, datetime

from arbiter_securitybench.contracts import (
    BenchmarkDefinition,
    BenchmarkSuite,
    NotFoundError,
    SecurityCategory,
    SemanticVersion,
    TargetModality,
    TestCase,
)
from arbiter_securitybench.storage import BenchmarkRepository, InMemoryBenchmarkRepository


def _semver_sort_key(version: str) -> tuple[int, int, int, int, str]:
    parsed = SemanticVersion.parse(version)
    is_stable = 1 if parsed.prerelease is None else 0
    return (parsed.major, parsed.minor, parsed.patch, is_stable, parsed.prerelease or "")


class BenchmarkCoreRegistry:
    """Service layer for registering, querying, and versioning benchmarks and test cases."""

    def __init__(self, repository: BenchmarkRepository | None = None) -> None:
        self._repo = repository or InMemoryBenchmarkRepository()

    def register_suite(self, suite: BenchmarkSuite) -> BenchmarkSuite:
        """Register a new benchmark suite version and update its BenchmarkDefinition index."""
        saved = self._repo.save_suite(suite)

        now = datetime.now(UTC)
        existing_def = self._repo.get_definition(saved.benchmark_id)
        if existing_def is None:
            definition = BenchmarkDefinition(
                benchmark_id=saved.benchmark_id,
                name=saved.name,
                description=saved.description,
                categories=list(saved.categories),
                supported_target_types=list(saved.supported_target_types),
                versions=[saved.version],
                latest_version=saved.version,
                created_at=now,
                updated_at=now,
                metadata=dict(saved.metadata),
            )
        else:
            versions = sorted(
                set(existing_def.versions) | {saved.version},
                key=_semver_sort_key,
            )
            categories = list(dict.fromkeys([*existing_def.categories, *saved.categories]))
            target_types = list(
                dict.fromkeys([*existing_def.supported_target_types, *saved.supported_target_types])
            )
            latest_version = versions[-1]
            is_latest = latest_version == saved.version
            definition = BenchmarkDefinition(
                benchmark_id=existing_def.benchmark_id,
                name=saved.name if is_latest else existing_def.name,
                description=saved.description if is_latest else existing_def.description,
                categories=categories,
                supported_target_types=target_types,
                versions=versions,
                latest_version=latest_version,
                created_at=existing_def.created_at,
                updated_at=now,
                metadata=dict(saved.metadata) if is_latest else dict(existing_def.metadata),
            )

        self._repo.save_definition(definition)
        return saved

    def register_test_case(self, test_case: TestCase) -> TestCase:
        """Register an individual test case; rejects duplicate (test_id, benchmark_version)."""
        return self._repo.save_test_case(test_case)

    def get_benchmark(self, benchmark_id: str, version: str | None = None) -> BenchmarkSuite:
        """Retrieve a benchmark suite by ID and optional version (defaults to latest)."""
        suite = self._repo.get_suite(benchmark_id, version=version)
        if suite is None:
            detail = f" version {version!r}" if version is not None else ""
            raise NotFoundError(
                f"Benchmark {benchmark_id!r}{detail} was not found.",
                component="registry",
                details={"benchmark_id": benchmark_id, "version": version},
            )
        return suite

    def get_benchmark_definition(self, benchmark_id: str) -> BenchmarkDefinition:
        """Retrieve top-level metadata and version history for a benchmark_id."""
        definition = self._repo.get_definition(benchmark_id)
        if definition is None:
            raise NotFoundError(
                f"Benchmark definition {benchmark_id!r} was not found.",
                component="registry",
                details={"benchmark_id": benchmark_id},
            )
        return definition

    def get_benchmarks_by_category(self, category: SecurityCategory) -> list[BenchmarkSuite]:
        """Retrieve all registered benchmark suites covering the specified category."""
        return self._repo.list_suites(category=category)

    def list_benchmarks(
        self,
        *,
        category: SecurityCategory | None = None,
        target_type: TargetModality | None = None,
    ) -> list[BenchmarkSuite]:
        """List registered benchmark suites with optional category and target_type filters."""
        return self._repo.list_suites(category=category, target_type=target_type)

    def list_benchmark_definitions(self) -> list[BenchmarkDefinition]:
        """List all registered top-level benchmark definitions."""
        return self._repo.list_definitions()

    def list_versions(self, benchmark_id: str) -> list[str]:
        """List all registered semantic versions for a benchmark suite ID."""
        versions = self._repo.list_suite_versions(benchmark_id)
        if not versions:
            raise NotFoundError(
                f"Benchmark {benchmark_id!r} has no registered versions.",
                component="registry",
                details={"benchmark_id": benchmark_id},
            )
        return versions

    def get_test_case(self, test_id: str, benchmark_version: str) -> TestCase:
        """Retrieve a registered test case by test_id and benchmark_version."""
        tc = self._repo.get_test_case(test_id, benchmark_version)
        if tc is None:
            raise NotFoundError(
                f"Test case {test_id!r} for benchmark version {benchmark_version!r} was not found.",
                component="registry",
                details={"test_id": test_id, "benchmark_version": benchmark_version},
            )
        return tc

    def list_test_cases(
        self,
        *,
        category: SecurityCategory | None = None,
        benchmark_version: str | None = None,
    ) -> list[TestCase]:
        """List registered test cases with optional category and version filters."""
        return self._repo.list_test_cases(
            category=category,
            benchmark_version=benchmark_version,
        )
