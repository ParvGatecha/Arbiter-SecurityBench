"""CLI validation script for Arbiter SecurityBench dataset files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parents[1] / "backend" / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from arbiter_securitybench.datasets.loader import default_v1_dataset_path
from arbiter_securitybench.datasets.validator import validate_dataset_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate an Arbiter SecurityBench JSON dataset file."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=str(default_v1_dataset_path()),
        help="Path to dataset JSON file (defaults to Arbiter Security Benchmark v1.0).",
    )
    args = parser.parse_args(argv)
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"ERROR: Dataset file not found: {target_path}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"ERROR: Invalid JSON in {target_path}: {exc}", file=sys.stderr)
        return 2

    report = validate_dataset_payload(payload, strict=False)
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
