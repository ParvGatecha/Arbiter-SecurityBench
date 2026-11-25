"""Versioning contracts and canonical content hashing for reproducibility."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

PLATFORM_VERSION = "0.1.0-alpha.0"
SCHEMA_VERSION = "1.0.0"

METHODOLOGY_VERSIONS: dict[str, str] = {
    "benchmark_methodology": "1.0.0",
    "scoring_methodology": "1.0.0",
    "statistical_methodology": "1.0.0",
}

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class SemanticVersion(BaseModel):
    """Parsed semantic version following SemVer 2.0.0."""

    model_config = ConfigDict(frozen=True)

    major: int = Field(ge=0)
    minor: int = Field(ge=0)
    patch: int = Field(ge=0)
    prerelease: str | None = None
    build: str | None = None

    @classmethod
    def parse(cls, raw: str) -> SemanticVersion:
        """Parse a SemVer 2.0.0 string into a structured SemanticVersion."""
        match = _SEMVER_RE.match(raw.strip())
        if not match:
            raise ValueError(f"Invalid semantic version string: {raw!r}")
        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            prerelease=match.group(4),
            build=match.group(5),
        )

    def is_compatible_with(self, other: SemanticVersion) -> bool:
        """Return True when major versions match and self >= other in minor/patch."""
        if self.major != other.major:
            return False
        if self.major == 0:
            # In 0.y.z pre-1.0 releases, minor bumps may break compatibility.
            return self.minor == other.minor and self.patch >= other.patch
        return (self.minor, self.patch) >= (other.minor, other.patch)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += f"-{self.prerelease}"
        if self.build:
            base += f"+{self.build}"
        return base


class ComponentVersions(BaseModel):
    """Pinned versions of all platform components involved in a benchmark run."""

    model_config = ConfigDict(frozen=True)

    platform_version: str = Field(default=PLATFORM_VERSION)
    schema_version: str = Field(default=SCHEMA_VERSION)
    benchmark_version: str
    adapter_version: str
    evaluator_version: str
    scoring_version: str = Field(default=METHODOLOGY_VERSIONS["scoring_methodology"])
    statistical_version: str = Field(default=METHODOLOGY_VERSIONS["statistical_methodology"])

    @field_validator(
        "platform_version",
        "schema_version",
        "benchmark_version",
        "adapter_version",
        "evaluator_version",
        "scoring_version",
        "statistical_version",
    )
    @classmethod
    def _validate_semver(cls, value: str) -> str:
        SemanticVersion.parse(value)
        return value


def compute_canonical_digest(payload: Any) -> str:
    """Compute a deterministic SHA-256 hex digest over canonicalized JSON data.

    Callers should exclude volatile metadata (such as runtime timestamps) before
    passing domain specs so digests remain reproducible across environments.
    """
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
