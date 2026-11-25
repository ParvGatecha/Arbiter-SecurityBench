"""In-memory repository implementations for fast isolated unit testing."""

from __future__ import annotations

from threading import RLock

from arbiter_securitybench.contracts import (
    BenchmarkDefinition,
    BenchmarkRun,
    BenchmarkSuite,
    DuplicateRegistrationError,
    NotFoundError,
    RunStatus,
    SecurityCategory,
    SemanticVersion,
    TargetModality,
    TestCase,
    TestExecutionResult,
)
from arbiter_securitybench.storage.repositories import BenchmarkRepository, RunRepository


def _semver_sort_key(version: str) -> tuple[int, int, int, int, str]:
    parsed = SemanticVersion.parse(version)
    # Stable releases sort higher than prereleases of the same major.minor.patch.
    is_stable = 1 if parsed.prerelease is None else 0
    return (parsed.major, parsed.minor, parsed.patch, is_stable, parsed.prerelease or "")


class InMemoryBenchmarkRepository(BenchmarkRepository):
    """Thread-safe in-memory BenchmarkRepository."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._definitions: dict[str, BenchmarkDefinition] = {}
        self._suites: dict[tuple[str, str], BenchmarkSuite] = {}
        self._test_cases: dict[tuple[str, str], TestCase] = {}

    def save_definition(self, definition: BenchmarkDefinition) -> BenchmarkDefinition:
        with self._lock:
            self._definitions[definition.benchmark_id] = definition
            return definition

    def get_definition(self, benchmark_id: str) -> BenchmarkDefinition | None:
        with self._lock:
            return self._definitions.get(benchmark_id)

    def list_definitions(self) -> list[BenchmarkDefinition]:
        with self._lock:
            return sorted(self._definitions.values(), key=lambda d: d.benchmark_id)

    def save_suite(self, suite: BenchmarkSuite) -> BenchmarkSuite:
        with self._lock:
            key = (suite.suite_id, suite.version)
            if key in self._suites:
                raise DuplicateRegistrationError(
                    f"Benchmark suite {suite.suite_id!r} version {suite.version!r} is already registered.",
                    component="storage.memory",
                    details={"suite_id": suite.suite_id, "version": suite.version},
                )
            for tc in suite.test_cases:
                tc_key = (tc.test_id, tc.benchmark_version)
                existing = self._test_cases.get(tc_key)
                if existing is not None and existing.content_digest != tc.content_digest:
                    raise DuplicateRegistrationError(
                        f"Test case {tc.test_id!r} ({tc.benchmark_version}) conflicts with an existing definition.",
                        component="storage.memory",
                        details={"test_id": tc.test_id, "benchmark_version": tc.benchmark_version},
                    )
            for tc in suite.test_cases:
                self._test_cases[(tc.test_id, tc.benchmark_version)] = tc
            self._suites[key] = suite
            return suite

    def get_suite(self, suite_id: str, version: str | None = None) -> BenchmarkSuite | None:
        with self._lock:
            if version is not None:
                return self._suites.get((suite_id, version))
            versions = self.list_suite_versions(suite_id)
            if not versions:
                return None
            return self._suites[(suite_id, versions[-1])]

    def list_suites(
        self,
        *,
        category: SecurityCategory | None = None,
        target_type: TargetModality | None = None,
    ) -> list[BenchmarkSuite]:
        with self._lock:
            results: list[BenchmarkSuite] = []
            for suite in self._suites.values():
                if category is not None and category not in suite.categories:
                    continue
                if target_type is not None and target_type not in suite.supported_target_types:
                    continue
                results.append(suite)
            return sorted(results, key=lambda s: (s.suite_id, _semver_sort_key(s.version)))

    def list_suite_versions(self, suite_id: str) -> list[str]:
        with self._lock:
            versions = [ver for (sid, ver) in self._suites if sid == suite_id]
            return sorted(versions, key=_semver_sort_key)

    def save_test_case(self, test_case: TestCase) -> TestCase:
        with self._lock:
            key = (test_case.test_id, test_case.benchmark_version)
            if key in self._test_cases:
                raise DuplicateRegistrationError(
                    f"Test case {test_case.test_id!r} for benchmark version "
                    f"{test_case.benchmark_version!r} is already registered.",
                    component="storage.memory",
                    details={
                        "test_id": test_case.test_id,
                        "benchmark_version": test_case.benchmark_version,
                    },
                )
            self._test_cases[key] = test_case
            return test_case

    def get_test_case(self, test_id: str, benchmark_version: str) -> TestCase | None:
        with self._lock:
            return self._test_cases.get((test_id, benchmark_version))

    def list_test_cases(
        self,
        *,
        category: SecurityCategory | None = None,
        benchmark_version: str | None = None,
    ) -> list[TestCase]:
        with self._lock:
            results: list[TestCase] = []
            for tc in self._test_cases.values():
                if category is not None and tc.category != category:
                    continue
                if benchmark_version is not None and tc.benchmark_version != benchmark_version:
                    continue
                results.append(tc)
            return sorted(results, key=lambda t: (t.test_id, _semver_sort_key(t.benchmark_version)))


class InMemoryRunRepository(RunRepository):
    """Thread-safe in-memory RunRepository."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._runs: dict[str, BenchmarkRun] = {}
        self._results: dict[str, list[TestExecutionResult]] = {}

    def create_run(self, run: BenchmarkRun) -> BenchmarkRun:
        with self._lock:
            if run.run_id in self._runs:
                raise DuplicateRegistrationError(
                    f"Run {run.run_id!r} already exists.",
                    component="storage.memory",
                    details={"run_id": run.run_id},
                )
            self._runs[run.run_id] = run
            self._results[run.run_id] = []
            return run

    def update_run(self, run: BenchmarkRun) -> BenchmarkRun:
        with self._lock:
            if run.run_id not in self._runs:
                raise NotFoundError(
                    f"Run {run.run_id!r} does not exist.",
                    component="storage.memory",
                    details={"run_id": run.run_id},
                )
            self._runs[run.run_id] = run
            return run

    def get_run(self, run_id: str) -> BenchmarkRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(
        self,
        *,
        benchmark_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[BenchmarkRun]:
        with self._lock:
            filtered = [
                r
                for r in self._runs.values()
                if (benchmark_id is None or r.benchmark_id == benchmark_id)
                and (status is None or r.status == status)
            ]
            filtered.sort(key=lambda r: r.created_at, reverse=True)
            return filtered[offset : offset + limit]

    def save_test_result(self, result: TestExecutionResult) -> TestExecutionResult:
        with self._lock:
            if result.run_id not in self._runs:
                raise NotFoundError(
                    f"Cannot store result for unknown run {result.run_id!r}.",
                    component="storage.memory",
                    details={"run_id": result.run_id, "test_id": result.test_id},
                )
            self._results[result.run_id].append(result)
            return result

    def get_run_results(self, run_id: str) -> list[TestExecutionResult]:
        with self._lock:
            if run_id not in self._runs:
                raise NotFoundError(
                    f"Run {run_id!r} does not exist.",
                    component="storage.memory",
                    details={"run_id": run_id},
                )
            return list(self._results[run_id])
