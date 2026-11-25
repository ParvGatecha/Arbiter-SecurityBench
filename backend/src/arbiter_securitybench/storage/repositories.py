"""Repository abstractions separating persistence from domain logic."""

from __future__ import annotations

from abc import ABC, abstractmethod

from arbiter_securitybench.contracts import (
    BenchmarkDefinition,
    BenchmarkRun,
    BenchmarkSuite,
    RunStatus,
    SecurityCategory,
    TargetModality,
    TestCase,
    TestExecutionResult,
)


class BenchmarkRepository(ABC):
    """Persistence contract for benchmark definitions, suites, and test cases."""

    @abstractmethod
    def save_definition(self, definition: BenchmarkDefinition) -> BenchmarkDefinition:
        """Persist or update a benchmark definition index."""

    @abstractmethod
    def get_definition(self, benchmark_id: str) -> BenchmarkDefinition | None:
        """Fetch a benchmark definition by ID."""

    @abstractmethod
    def list_definitions(self) -> list[BenchmarkDefinition]:
        """List all registered benchmark definitions."""

    @abstractmethod
    def save_suite(self, suite: BenchmarkSuite) -> BenchmarkSuite:
        """Persist a new benchmark suite version; reject duplicate (suite_id, version)."""

    @abstractmethod
    def get_suite(self, suite_id: str, version: str | None = None) -> BenchmarkSuite | None:
        """Fetch a suite by ID and optional version (defaults to latest SemVer)."""

    @abstractmethod
    def list_suites(
        self,
        *,
        category: SecurityCategory | None = None,
        target_type: TargetModality | None = None,
    ) -> list[BenchmarkSuite]:
        """List suites optionally filtered by category and/or target modality."""

    @abstractmethod
    def list_suite_versions(self, suite_id: str) -> list[str]:
        """List all registered semantic versions for a given suite_id."""

    @abstractmethod
    def save_test_case(self, test_case: TestCase) -> TestCase:
        """Persist a test case; reject duplicate (test_id, benchmark_version)."""

    @abstractmethod
    def get_test_case(self, test_id: str, benchmark_version: str) -> TestCase | None:
        """Fetch a specific test case by ID and benchmark version."""

    @abstractmethod
    def list_test_cases(
        self,
        *,
        category: SecurityCategory | None = None,
        benchmark_version: str | None = None,
    ) -> list[TestCase]:
        """List registered test cases with optional category/version filters."""


class RunRepository(ABC):
    """Persistence contract for benchmark execution runs and individual test results."""

    @abstractmethod
    def create_run(self, run: BenchmarkRun) -> BenchmarkRun:
        """Persist a newly created benchmark run."""

    @abstractmethod
    def update_run(self, run: BenchmarkRun) -> BenchmarkRun:
        """Update an existing benchmark run's status, counts, and timestamps."""

    @abstractmethod
    def get_run(self, run_id: str) -> BenchmarkRun | None:
        """Fetch a benchmark run by run_id."""

    @abstractmethod
    def list_runs(
        self,
        *,
        benchmark_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[BenchmarkRun]:
        """List benchmark runs ordered newest-first with optional filters."""

    @abstractmethod
    def save_test_result(self, result: TestExecutionResult) -> TestExecutionResult:
        """Persist a single test execution result for a run."""

    @abstractmethod
    def get_run_results(self, run_id: str) -> list[TestExecutionResult]:
        """Fetch all test execution results belonging to run_id in execution order."""
