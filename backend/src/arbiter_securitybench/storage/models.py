"""SQLAlchemy 2.0 ORM models targeting PostgreSQL (with SQLite compatibility)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _json_variant() -> JSON:
    return JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    """Base SQLAlchemy declarative model."""


class BenchmarkDefinitionORM(Base):
    """Relational table for benchmark identity and version tracking."""

    __tablename__ = "benchmark_definitions"

    benchmark_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    categories: Mapped[list[str]] = mapped_column(_json_variant(), nullable=False)
    supported_target_types: Mapped[list[str]] = mapped_column(_json_variant(), nullable=False)
    versions: Mapped[list[str]] = mapped_column(_json_variant(), nullable=False)
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(_json_variant(), nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class BenchmarkSuiteORM(Base):
    """Relational table for immutable versioned benchmark suites."""

    __tablename__ = "benchmark_suites"
    __table_args__ = (
        UniqueConstraint("suite_id", "version", name="uq_suite_id_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    suite_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    benchmark_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    content_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suite_json: Mapped[dict[str, Any]] = mapped_column(_json_variant(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class TestCaseORM(Base):
    """Relational table for versioned security test cases."""

    __tablename__ = "test_cases"
    __table_args__ = (
        UniqueConstraint("test_id", "benchmark_version", name="uq_test_id_benchmark_version"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    test_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    benchmark_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(64), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    content_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    spec_json: Mapped[dict[str, Any]] = mapped_column(_json_variant(), nullable=False)


class BenchmarkRunORM(Base):
    """Relational table for benchmark execution runs."""

    __tablename__ = "benchmark_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    benchmark_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    suite_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    benchmark_version: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    total_tests: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_tests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_tests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    run_json: Mapped[dict[str, Any]] = mapped_column(_json_variant(), nullable=False)


class TestExecutionResultORM(Base):
    """Relational table for individual test execution results within a run."""

    __tablename__ = "test_execution_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("benchmark_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    test_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    execution_time: Mapped[float] = mapped_column(Float, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(_json_variant(), nullable=False)
