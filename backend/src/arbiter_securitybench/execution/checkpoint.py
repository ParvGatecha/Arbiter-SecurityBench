"""Cross-run test case checkpointing for resuming partial or slow benchmark suites."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

logger = logging.getLogger("arbiter_securitybench.execution.checkpoint")

from arbiter_securitybench.contracts import (
    BenchmarkSuite,
    BenchmarkTargetAdapter,
    TestCase,
    TestExecutionResult,
    TestExecutionStatus,
)


class CheckpointScope(BaseModel):
    """Compatibility identity ensuring checkpoints never cross models or benchmark versions."""

    model_config = ConfigDict(frozen=True)

    benchmark_id: str
    benchmark_version: str
    target_id: str
    target_type: str
    model_name: str
    execute_variants: bool = False
    seed: int = 0

    @property
    def scope_key(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_checkpoint_scope(
    *,
    suite: BenchmarkSuite,
    target: BenchmarkTargetAdapter,
    execute_variants: bool = False,
    seed: int = 0,
) -> CheckpointScope:
    """Derive a deterministic CheckpointScope from suite and target metadata."""
    get_info = getattr(target, "get_target_info", None)
    model_name = target.target_id
    if callable(get_info):
        info = get_info()
        model_name = str(getattr(info, "model_name", target.target_id) or target.target_id)
    return CheckpointScope(
        benchmark_id=suite.benchmark_id,
        benchmark_version=suite.version,
        target_id=target.target_id,
        target_type=target.target_type.value,
        model_name=model_name,
        execute_variants=execute_variants,
        seed=seed if execute_variants else 0,
    )


def default_checkpoint_path(scope: CheckpointScope, *, base_dir: Path | str = ".arbiter/checkpoints") -> Path:
    """Return deterministic default checkpoint file path for a scope."""
    return Path(base_dir) / f"checkpoint_{scope.scope_key[:12]}.json"


class _StoredCheckpointEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    test_id: str
    variant_id: str | None = None
    test_content_digest: str | None = None
    saved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    result: TestExecutionResult


class ExecutionCheckpointStore:
    """Atomic JSON checkpoint store caching COMPLETED test results across runs."""

    def __init__(self, path: Path | str, scope: CheckpointScope) -> None:
        self._path = Path(path)
        self._scope = scope
        self._lock = RLock()
        self._entries: dict[str, _StoredCheckpointEntry] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def scope(self) -> CheckpointScope:
        return self._scope

    @staticmethod
    def _entry_key(test_id: str, variant_id: str | None) -> str:
        return f"{test_id}::{variant_id or ''}"

    @staticmethod
    def _digest_of(test_case: TestCase) -> str | None:
        return test_case.content_digest.hex_digest if test_case.content_digest else None

    def _load(self) -> None:
        with self._lock:
            if not self._path.exists():
                return
            try:
                raw: Any = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            if not isinstance(raw, dict):
                return
            if raw.get("scope_key") != self._scope.scope_key:
                # Scope mismatch (e.g., upgraded model or benchmark version): ignore stale cache.
                return
            raw_entries = raw.get("entries")
            if not isinstance(raw_entries, dict):
                return
            for key, item in raw_entries.items():
                try:
                    entry = _StoredCheckpointEntry.model_validate(item)
                except (PydanticValidationError, ValueError) as exc:
                    logger.debug("Skipping invalid checkpoint entry %r: %s", key, exc)
                    continue
                if entry.result.execution_status == TestExecutionStatus.COMPLETED:
                    self._entries[str(key)] = entry

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.0.0",
            "scope_key": self._scope.scope_key,
            "scope": self._scope.model_dump(mode="json"),
            "updated_at": datetime.now(UTC).isoformat(),
            "entries": {
                key: entry.model_dump(mode="json")
                for key, entry in sorted(self._entries.items())
            },
        }
        tmp_path = self._path.with_name(f"{self._path.name}.{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp_path, self._path)

    def lookup(
        self,
        test_case: TestCase,
        *,
        variant_id: str | None,
        run_id: str,
        target_id: str,
    ) -> TestExecutionResult | None:
        """Return a reused COMPLETED TestExecutionResult if this test_case+variant is cached."""
        key = self._entry_key(test_case.test_id, variant_id)
        expected_digest = self._digest_of(test_case)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.test_content_digest != expected_digest:
                return None
            if entry.result.execution_status != TestExecutionStatus.COMPLETED:
                return None

            orig = entry.result
            merged_raw = {
                **(orig.raw_response or {}),
                "checkpoint_reused": True,
                "checkpoint_source_run_id": orig.run_id,
            }
            return orig.model_copy(
                update={
                    "run_id": run_id,
                    "target_id": target_id,
                    "raw_response": merged_raw,
                }
            )

    def record(
        self,
        test_case: TestCase,
        result: TestExecutionResult,
        *,
        variant_id: str | None = None,
    ) -> bool:
        """Persist a COMPLETED TestExecutionResult immediately; skips failed/errored results."""
        if result.execution_status != TestExecutionStatus.COMPLETED:
            return False
        key = self._entry_key(test_case.test_id, variant_id)
        entry = _StoredCheckpointEntry(
            test_id=test_case.test_id,
            variant_id=variant_id,
            test_content_digest=self._digest_of(test_case),
            result=result,
        )
        with self._lock:
            self._entries[key] = entry
            self._flush()
        return True
