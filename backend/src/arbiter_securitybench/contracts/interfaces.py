"""Core component interfaces (Protocol / ABC contracts) for Arbiter SecurityBench.

Each component is decoupled through these contracts so implementations can be
tested independently, swapped, or embedded inside an external platform.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from arbiter_securitybench.contracts.lifecycles import (
    BenchmarkLifecycleState,
    TestCaseLifecycleState,
)
from arbiter_securitybench.contracts.schemas import (
    BenchmarkSpec,
    EvaluationResult,
    ExecutionManifest,
    ExecutionTrace,
    ReportArtifact,
    ReportFormat,
    ResultBundle,
    ScoreSummary,
    SecurityCategory,
    StatisticalAnalysisResult,
    TargetConfig,
    TargetModality,
    TestCaseSpec,
)


@runtime_checkable
class BenchmarkManager(Protocol):
    """Manages benchmark authoring, validation, and lifecycle transitions."""

    def create_benchmark(self, spec: BenchmarkSpec) -> BenchmarkSpec: ...

    def update_draft(self, benchmark_id: str, spec: BenchmarkSpec) -> BenchmarkSpec: ...

    def transition_state(
        self,
        benchmark_id: str,
        version: str,
        target_state: BenchmarkLifecycleState,
    ) -> BenchmarkSpec: ...

    def validate_benchmark(self, spec: BenchmarkSpec) -> list[str]: ...


@runtime_checkable
class BenchmarkRegistry(Protocol):
    """Immutable registry of validated and published benchmark suites."""

    def register(self, spec: BenchmarkSpec) -> BenchmarkSpec: ...

    def get(self, benchmark_id: str, version: str | None = None) -> BenchmarkSpec: ...

    def list_benchmarks(
        self,
        *,
        category: SecurityCategory | None = None,
        modality: TargetModality | None = None,
        state: BenchmarkLifecycleState | None = None,
    ) -> Sequence[BenchmarkSpec]: ...

    def verify_integrity(self, benchmark_id: str, version: str) -> bool: ...


@runtime_checkable
class TestCaseManager(Protocol):
    """Manages curation, calibration, and versioning of security test cases."""

    def create_test_case(self, spec: TestCaseSpec) -> TestCaseSpec: ...

    def get_test_case(self, test_case_id: str, version: str) -> TestCaseSpec: ...

    def transition_state(
        self,
        test_case_id: str,
        version: str,
        target_state: TestCaseLifecycleState,
    ) -> TestCaseSpec: ...

    def query_test_cases(
        self,
        *,
        category: SecurityCategory | None = None,
        modality: TargetModality | None = None,
        state: TestCaseLifecycleState | None = None,
    ) -> Sequence[TestCaseSpec]: ...


class TargetAdapter(ABC):
    """Unified adapter contract for LLM, RAG, and Agent target systems."""

    @property
    @abstractmethod
    def adapter_type(self) -> str:
        """Unique identifier of the adapter implementation."""

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Semantic version of the adapter implementation."""

    @abstractmethod
    def supported_modalities(self) -> frozenset[TargetModality]:
        """Return target modalities supported by this adapter."""

    @abstractmethod
    def health_check(self, config: TargetConfig) -> bool:
        """Verify target connectivity and configuration before starting a run."""

    @abstractmethod
    async def initialize_session(
        self,
        config: TargetConfig,
        test_case: TestCaseSpec,
        seed: int,
    ) -> dict[str, Any]:
        """Initialize an isolated session (e.g., sandbox tools, RAG index fixture)."""

    @abstractmethod
    async def invoke_turn(
        self,
        session_state: dict[str, Any],
        turn_payload: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        """Execute one interaction turn against the target and return structured telemetry."""

    @abstractmethod
    async def teardown_session(self, session_state: dict[str, Any]) -> None:
        """Release resources and reset isolation state after a test case attempt."""


@runtime_checkable
class AttackExecutor(Protocol):
    """Executes benchmark test cases against a TargetAdapter reproducibly."""

    async def execute_run(
        self,
        manifest: ExecutionManifest,
        benchmark: BenchmarkSpec,
        test_cases: Sequence[TestCaseSpec],
        adapter: TargetAdapter,
    ) -> tuple[ExecutionManifest, Sequence[ExecutionTrace]]: ...

    async def execute_case_attempt(
        self,
        manifest: ExecutionManifest,
        test_case: TestCaseSpec,
        adapter: TargetAdapter,
        attempt_index: int,
    ) -> ExecutionTrace: ...


@runtime_checkable
class EvaluationEngine(Protocol):
    """Evaluates raw execution traces into auditable EvaluationResult records."""

    async def evaluate_trace(
        self,
        test_case: TestCaseSpec,
        trace: ExecutionTrace,
    ) -> EvaluationResult: ...

    async def evaluate_run(
        self,
        test_cases_by_id: dict[str, TestCaseSpec],
        traces: Sequence[ExecutionTrace],
    ) -> Sequence[EvaluationResult]: ...


@runtime_checkable
class ScoringEngine(Protocol):
    """Computes category and overall security scores from EvaluationResult records."""

    def compute_scores(
        self,
        run_id: str,
        evaluations: Sequence[EvaluationResult],
        *,
        verified_only: bool = True,
    ) -> ScoreSummary: ...


@runtime_checkable
class StatisticalAnalyzer(Protocol):
    """Performs rigorous statistical estimation and hypothesis testing on run results."""

    def analyze_run(
        self,
        run_id: str,
        evaluations: Sequence[EvaluationResult],
        *,
        confidence_level: float = 0.95,
    ) -> StatisticalAnalysisResult: ...

    def compare_runs(
        self,
        baseline_evaluations: Sequence[EvaluationResult],
        candidate_evaluations: Sequence[EvaluationResult],
        *,
        confidence_level: float = 0.95,
    ) -> StatisticalAnalysisResult: ...


@runtime_checkable
class ReportGenerator(Protocol):
    """Renders reproducible benchmark reports strictly from persisted run outputs."""

    def generate(
        self,
        bundle: ResultBundle,
        report_format: ReportFormat,
        *,
        verified_findings_only: bool = True,
    ) -> tuple[ReportArtifact, bytes]: ...


@runtime_checkable
class ResultStore(Protocol):
    """Persistence boundary for manifests, traces, evaluations, scores, and bundles."""

    def save_manifest(self, manifest: ExecutionManifest) -> None: ...

    def save_traces(self, traces: Sequence[ExecutionTrace]) -> None: ...

    def save_evaluations(self, evaluations: Sequence[EvaluationResult]) -> None: ...

    def save_score_summary(self, summary: ScoreSummary) -> None: ...

    def save_statistical_analysis(self, analysis: StatisticalAnalysisResult) -> None: ...

    def load_result_bundle(self, run_id: str) -> ResultBundle: ...
