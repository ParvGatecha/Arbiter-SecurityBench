"""Dataset loader integrating versioned JSON suites with BenchmarkCoreRegistry."""

from __future__ import annotations

import json
from pathlib import Path

from arbiter_securitybench.contracts import BenchmarkSuite, ValidationError
from arbiter_securitybench.datasets.validator import validate_dataset_payload
from arbiter_securitybench.registry import BenchmarkCoreRegistry


def default_v1_dataset_path() -> Path:
    """Resolve the repository path to Arbiter Security Benchmark v1.0 JSON."""
    # backend/src/arbiter_securitybench/datasets/loader.py -> repo root (5 parents up)
    repo_root = Path(__file__).resolve().parents[4]
    return repo_root / "datasets" / "arbiter_security_benchmark_v1.0.json"


def load_benchmark_suite(
    path: Path | str | None = None,
    *,
    validate: bool = True,
) -> BenchmarkSuite:
    """Load and validate a versioned benchmark dataset JSON file into a BenchmarkSuite."""
    resolved_path = Path(path) if path is not None else default_v1_dataset_path()
    if not resolved_path.exists():
        raise ValidationError(
            f"Dataset file not found: {resolved_path}",
            component="datasets.loader",
            details={"path": str(resolved_path)},
        )

    try:
        raw_payload = json.loads(resolved_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValidationError(
            f"Dataset file is not valid JSON: {exc}",
            component="datasets.loader",
            details={"path": str(resolved_path)},
        ) from exc

    if validate:
        validate_dataset_payload(raw_payload, strict=True)

    return BenchmarkSuite.model_validate(raw_payload)


def register_arbiter_benchmark_v1(
    registry: BenchmarkCoreRegistry,
    *,
    path: Path | str | None = None,
) -> BenchmarkSuite:
    """Load Arbiter Security Benchmark v1.0 and register it into BenchmarkCoreRegistry."""
    suite = load_benchmark_suite(path=path, validate=True)
    return registry.register_suite(suite)
