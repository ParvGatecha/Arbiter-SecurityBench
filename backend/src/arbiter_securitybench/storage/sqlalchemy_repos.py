"""SQLAlchemy repository implementations for PostgreSQL and SQLite."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.orm import Session, sessionmaker

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
from arbiter_securitybench.storage.models import (
    Base,
    BenchmarkDefinitionORM,
    BenchmarkRunORM,
    BenchmarkSuiteORM,
    TestCaseORM,
    TestExecutionResultORM,
)
from arbiter_securitybench.storage.repositories import BenchmarkRepository, RunRepository


def _semver_sort_key(version: str) -> tuple[int, int, int, int, str]:
    parsed = SemanticVersion.parse(version)
    is_stable = 1 if parsed.prerelease is None else 0
    return (parsed.major, parsed.minor, parsed.patch, is_stable, parsed.prerelease or "")


def create_db_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine for PostgreSQL or SQLite."""
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, echo=echo, future=True, connect_args=connect_args)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a configured SQLAlchemy session factory."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """Create database tables for environments without Alembic migrations yet."""
    Base.metadata.create_all(bind=engine)


class SQLAlchemyBenchmarkRepository(BenchmarkRepository):
    """SQLAlchemy-backed BenchmarkRepository supporting PostgreSQL and SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_definition(self, definition: BenchmarkDefinition) -> BenchmarkDefinition:
        with self._session_factory() as session:
            existing = session.get(BenchmarkDefinitionORM, definition.benchmark_id)
            if existing is None:
                orm = BenchmarkDefinitionORM(
                    benchmark_id=definition.benchmark_id,
                    name=definition.name,
                    description=definition.description,
                    categories=[c.value for c in definition.categories],
                    supported_target_types=[t.value for t in definition.supported_target_types],
                    versions=list(definition.versions),
                    latest_version=definition.latest_version,
                    metadata_json=dict(definition.metadata),
                    created_at=definition.created_at,
                    updated_at=definition.updated_at,
                )
                session.add(orm)
            else:
                existing.name = definition.name
                existing.description = definition.description
                existing.categories = [c.value for c in definition.categories]
                existing.supported_target_types = [t.value for t in definition.supported_target_types]
                existing.versions = list(definition.versions)
                existing.latest_version = definition.latest_version
                existing.metadata_json = dict(definition.metadata)
                existing.updated_at = definition.updated_at
            session.commit()
            return definition

    def get_definition(self, benchmark_id: str) -> BenchmarkDefinition | None:
        with self._session_factory() as session:
            orm = session.get(BenchmarkDefinitionORM, benchmark_id)
            if orm is None:
                return None
            return self._to_definition(orm)

    def list_definitions(self) -> list[BenchmarkDefinition]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(BenchmarkDefinitionORM).order_by(BenchmarkDefinitionORM.benchmark_id)
            ).all()
            return [self._to_definition(r) for r in rows]

    def save_suite(self, suite: BenchmarkSuite) -> BenchmarkSuite:
        with self._session_factory() as session:
            existing_suite = session.scalar(
                select(BenchmarkSuiteORM).where(
                    BenchmarkSuiteORM.suite_id == suite.suite_id,
                    BenchmarkSuiteORM.version == suite.version,
                )
            )
            if existing_suite is not None:
                raise DuplicateRegistrationError(
                    f"Benchmark suite {suite.suite_id!r} version {suite.version!r} is already registered.",
                    component="storage.sqlalchemy",
                    details={"suite_id": suite.suite_id, "version": suite.version},
                )

            for tc in suite.test_cases:
                existing_tc = session.scalar(
                    select(TestCaseORM).where(
                        TestCaseORM.test_id == tc.test_id,
                        TestCaseORM.benchmark_version == tc.benchmark_version,
                    )
                )
                if existing_tc is not None:
                    existing_digest = existing_tc.content_digest
                    new_digest = tc.content_digest.hex_digest if tc.content_digest else None
                    if existing_digest != new_digest:
                        raise DuplicateRegistrationError(
                            f"Test case {tc.test_id!r} ({tc.benchmark_version}) conflicts with an existing definition.",
                            component="storage.sqlalchemy",
                            details={
                                "test_id": tc.test_id,
                                "benchmark_version": tc.benchmark_version,
                            },
                        )
                else:
                    session.add(self._test_case_to_orm(tc))

            suite_orm = BenchmarkSuiteORM(
                suite_id=suite.suite_id,
                benchmark_id=suite.benchmark_id,
                name=suite.name,
                description=suite.description,
                version=suite.version,
                lifecycle_state=suite.lifecycle_state.value,
                content_digest=suite.content_digest.hex_digest if suite.content_digest else None,
                suite_json=suite.model_dump(mode="json"),
            )
            session.add(suite_orm)
            try:
                session.commit()
            except SAIntegrityError as exc:
                session.rollback()
                raise DuplicateRegistrationError(
                    f"Duplicate registration detected while saving suite {suite.suite_id!r} ({suite.version}).",
                    component="storage.sqlalchemy",
                    details={"suite_id": suite.suite_id, "version": suite.version},
                ) from exc
            return suite

    def get_suite(self, suite_id: str, version: str | None = None) -> BenchmarkSuite | None:
        with self._session_factory() as session:
            if version is not None:
                orm = session.scalar(
                    select(BenchmarkSuiteORM).where(
                        BenchmarkSuiteORM.suite_id == suite_id,
                        BenchmarkSuiteORM.version == version,
                    )
                )
                return BenchmarkSuite.model_validate(orm.suite_json) if orm else None

            rows = session.scalars(
                select(BenchmarkSuiteORM).where(BenchmarkSuiteORM.suite_id == suite_id)
            ).all()
            if not rows:
                return None
            latest = max(rows, key=lambda r: _semver_sort_key(r.version))
            return BenchmarkSuite.model_validate(latest.suite_json)

    def list_suites(
        self,
        *,
        category: SecurityCategory | None = None,
        target_type: TargetModality | None = None,
    ) -> list[BenchmarkSuite]:
        with self._session_factory() as session:
            rows = session.scalars(select(BenchmarkSuiteORM)).all()
            suites = [BenchmarkSuite.model_validate(r.suite_json) for r in rows]
            filtered = [
                s
                for s in suites
                if (category is None or category in s.categories)
                and (target_type is None or target_type in s.supported_target_types)
            ]
            return sorted(filtered, key=lambda s: (s.suite_id, _semver_sort_key(s.version)))

    def list_suite_versions(self, suite_id: str) -> list[str]:
        with self._session_factory() as session:
            versions = session.scalars(
                select(BenchmarkSuiteORM.version).where(BenchmarkSuiteORM.suite_id == suite_id)
            ).all()
            return sorted(versions, key=_semver_sort_key)

    def save_test_case(self, test_case: TestCase) -> TestCase:
        with self._session_factory() as session:
            existing = session.scalar(
                select(TestCaseORM).where(
                    TestCaseORM.test_id == test_case.test_id,
                    TestCaseORM.benchmark_version == test_case.benchmark_version,
                )
            )
            if existing is not None:
                raise DuplicateRegistrationError(
                    f"Test case {test_case.test_id!r} for benchmark version "
                    f"{test_case.benchmark_version!r} is already registered.",
                    component="storage.sqlalchemy",
                    details={
                        "test_id": test_case.test_id,
                        "benchmark_version": test_case.benchmark_version,
                    },
                )
            session.add(self._test_case_to_orm(test_case))
            try:
                session.commit()
            except SAIntegrityError as exc:
                session.rollback()
                raise DuplicateRegistrationError(
                    f"Duplicate test case {test_case.test_id!r} ({test_case.benchmark_version}).",
                    component="storage.sqlalchemy",
                ) from exc
            return test_case

    def get_test_case(self, test_id: str, benchmark_version: str) -> TestCase | None:
        with self._session_factory() as session:
            orm = session.scalar(
                select(TestCaseORM).where(
                    TestCaseORM.test_id == test_id,
                    TestCaseORM.benchmark_version == benchmark_version,
                )
            )
            return TestCase.model_validate(orm.spec_json) if orm else None

    def list_test_cases(
        self,
        *,
        category: SecurityCategory | None = None,
        benchmark_version: str | None = None,
    ) -> list[TestCase]:
        with self._session_factory() as session:
            stmt = select(TestCaseORM)
            if category is not None:
                stmt = stmt.where(TestCaseORM.category == category.value)
            if benchmark_version is not None:
                stmt = stmt.where(TestCaseORM.benchmark_version == benchmark_version)
            rows = session.scalars(stmt).all()
            cases = [TestCase.model_validate(r.spec_json) for r in rows]
            return sorted(cases, key=lambda t: (t.test_id, _semver_sort_key(t.benchmark_version)))

    @staticmethod
    def _to_definition(orm: BenchmarkDefinitionORM) -> BenchmarkDefinition:
        return BenchmarkDefinition(
            benchmark_id=orm.benchmark_id,
            name=orm.name,
            description=orm.description,
            categories=[SecurityCategory(c) for c in orm.categories],
            supported_target_types=[TargetModality(t) for t in orm.supported_target_types],
            versions=list(orm.versions),
            latest_version=orm.latest_version,
            created_at=orm.created_at,
            updated_at=orm.updated_at,
            metadata=dict(orm.metadata_json),
        )

    @staticmethod
    def _test_case_to_orm(tc: TestCase) -> TestCaseORM:
        return TestCaseORM(
            test_id=tc.test_id,
            benchmark_version=tc.benchmark_version,
            name=tc.name,
            category=tc.category.value,
            attack_type=tc.attack_type.value,
            difficulty=tc.difficulty.value,
            severity=tc.severity.value,
            content_digest=tc.content_digest.hex_digest if tc.content_digest else None,
            spec_json=tc.model_dump(mode="json"),
        )


class SQLAlchemyRunRepository(RunRepository):
    """SQLAlchemy-backed RunRepository supporting PostgreSQL and SQLite."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def create_run(self, run: BenchmarkRun) -> BenchmarkRun:
        with self._session_factory() as session:
            if session.get(BenchmarkRunORM, run.run_id) is not None:
                raise DuplicateRegistrationError(
                    f"Run {run.run_id!r} already exists.",
                    component="storage.sqlalchemy",
                    details={"run_id": run.run_id},
                )
            orm = BenchmarkRunORM(
                run_id=run.run_id,
                benchmark_id=run.benchmark_id,
                suite_id=run.suite_id,
                benchmark_version=run.benchmark_version,
                target_id=run.target_id,
                target_type=run.target_type.value,
                status=run.status.value,
                total_tests=run.total_tests,
                completed_tests=run.completed_tests,
                failed_tests=run.failed_tests,
                started_at=run.started_at,
                completed_at=run.completed_at,
                created_at=run.created_at,
                run_json=run.model_dump(mode="json"),
            )
            session.add(orm)
            session.commit()
            return run

    def update_run(self, run: BenchmarkRun) -> BenchmarkRun:
        with self._session_factory() as session:
            orm = session.get(BenchmarkRunORM, run.run_id)
            if orm is None:
                raise NotFoundError(
                    f"Run {run.run_id!r} does not exist.",
                    component="storage.sqlalchemy",
                    details={"run_id": run.run_id},
                )
            orm.status = run.status.value
            orm.completed_tests = run.completed_tests
            orm.failed_tests = run.failed_tests
            orm.started_at = run.started_at
            orm.completed_at = run.completed_at
            orm.run_json = run.model_dump(mode="json")
            session.commit()
            return run

    def get_run(self, run_id: str) -> BenchmarkRun | None:
        with self._session_factory() as session:
            orm = session.get(BenchmarkRunORM, run_id)
            return BenchmarkRun.model_validate(orm.run_json) if orm else None

    def list_runs(
        self,
        *,
        benchmark_id: str | None = None,
        status: RunStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[BenchmarkRun]:
        with self._session_factory() as session:
            stmt = select(BenchmarkRunORM)
            if benchmark_id is not None:
                stmt = stmt.where(BenchmarkRunORM.benchmark_id == benchmark_id)
            if status is not None:
                stmt = stmt.where(BenchmarkRunORM.status == status.value)
            stmt = stmt.order_by(BenchmarkRunORM.created_at.desc()).offset(offset).limit(limit)
            rows = session.scalars(stmt).all()
            return [BenchmarkRun.model_validate(r.run_json) for r in rows]

    def save_test_result(self, result: TestExecutionResult) -> TestExecutionResult:
        with self._session_factory() as session:
            if session.get(BenchmarkRunORM, result.run_id) is None:
                raise NotFoundError(
                    f"Cannot store result for unknown run {result.run_id!r}.",
                    component="storage.sqlalchemy",
                    details={"run_id": result.run_id, "test_id": result.test_id},
                )
            orm = TestExecutionResultORM(
                run_id=result.run_id,
                test_id=result.test_id,
                target_id=result.target_id,
                execution_status=result.execution_status.value,
                execution_time=result.execution_time,
                timestamp=result.timestamp,
                result_json=result.model_dump(mode="json"),
            )
            session.add(orm)
            session.commit()
            return result

    def get_run_results(self, run_id: str) -> list[TestExecutionResult]:
        with self._session_factory() as session:
            if session.get(BenchmarkRunORM, run_id) is None:
                raise NotFoundError(
                    f"Run {run_id!r} does not exist.",
                    component="storage.sqlalchemy",
                    details={"run_id": run_id},
                )
            rows = session.scalars(
                select(TestExecutionResultORM)
                .where(TestExecutionResultORM.run_id == run_id)
                .order_by(TestExecutionResultORM.id.asc())
            ).all()
            return [TestExecutionResult.model_validate(r.result_json) for r in rows]
