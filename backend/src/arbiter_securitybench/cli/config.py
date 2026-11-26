"""YAML configuration (`securitybench.yaml`) and environment variable support."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from arbiter_securitybench.contracts import ConfigurationError, TargetModality

DEFAULT_CONFIG_FILENAME = "securitybench.yaml"
DEFAULT_DB_URL = "sqlite:///.arbiter/securitybench.db"

_DEFAULT_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


class TargetEntryConfig(BaseModel):
    """Non-secret configuration for a single target entry in securitybench.yaml."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    type: str = Field(default="openai", min_length=1)
    model: str | None = None
    base_url: str | None = None
    endpoint_url: str | None = None
    health_check_url: str | None = None
    api_key_env_var: str | None = None
    modality: TargetModality = TargetModality.LLM
    allow_unauthenticated: bool | None = None
    prompt_field: str | None = None
    response_text_path: str | None = None

    @field_validator("type")
    @classmethod
    def _normalize_type(cls, value: str) -> str:
        return value.strip().lower()

    @classmethod
    def reject_inline_secrets(cls, raw: dict[str, Any]) -> None:
        if "api_key" in raw and raw["api_key"] is not None:
            raise ConfigurationError(
                "Storing raw 'api_key' values in securitybench.yaml is disallowed; "
                "use 'api_key_env_var' instead.",
                component="cli.config",
            )


class BenchmarkSectionConfig(BaseModel):
    """Benchmark selection configuration."""

    suite: str = Field(default="arbiter-security-benchmark", min_length=1)
    version: str | None = None
    suite_file: str | None = None


class ExecutionSectionConfig(BaseModel):
    """Execution resilience configuration."""

    timeout: float = Field(default=30.0, gt=0.0)
    max_retries: int = Field(default=2, ge=0, le=10)
    rate_limit_rps: float | None = Field(default=None, gt=0.0)
    concurrency: int = Field(default=1, ge=1, le=20)
    checkpoint: bool = False
    checkpoint_file: str | None = None
    seed: int = Field(default=0, ge=0)
    execute_variants: bool = False
    max_variants_per_test: int = Field(default=1, ge=1, le=10)


class ReportSectionConfig(BaseModel):
    """Report output configuration."""

    format: str = Field(default="html")
    formats: list[str] = Field(default_factory=list)
    output_dir: str = Field(default="reports", min_length=1)

    @field_validator("format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        fmt = value.strip().lower()
        if fmt not in {"html", "json", "pdf", "markdown", "md"}:
            raise ValueError(f"Unsupported report format: {value!r}")
        return fmt

    @field_validator("formats")
    @classmethod
    def _validate_formats(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for val in values:
            fmt = val.strip().lower()
            if fmt not in {"html", "json", "pdf", "markdown", "md"}:
                raise ValueError(f"Unsupported report format: {val!r}")
            if fmt not in cleaned:
                cleaned.append(fmt)
        return cleaned

    def resolved_formats(self) -> list[str]:
        return list(self.formats) if self.formats else [self.format]


class SecurityGatesSectionConfig(BaseModel):
    """CI/CD security gate thresholds matching securitybench.yaml `security_gates`."""

    max_attack_success_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    max_critical_vulnerabilities: int | None = Field(default=None, ge=0)
    fail_on_regression: bool = True
    fail_on_incomplete_run: bool = True
    max_inconclusive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    min_security_score: float | None = Field(default=None, ge=0.0, le=100.0)
    regression_asr_delta_threshold: float = Field(default=0.05, ge=0.0, le=1.0)


class StorageSectionConfig(BaseModel):
    """Local or PostgreSQL persistence configuration."""

    database_url: str = Field(default=DEFAULT_DB_URL, min_length=1)


class SecurityBenchConfig(BaseModel):
    """Top-level configuration schema matching securitybench.yaml."""

    target: TargetEntryConfig | None = None
    targets: dict[str, TargetEntryConfig] = Field(default_factory=dict)
    benchmark: BenchmarkSectionConfig = Field(default_factory=BenchmarkSectionConfig)
    execution: ExecutionSectionConfig = Field(default_factory=ExecutionSectionConfig)
    report: ReportSectionConfig = Field(default_factory=ReportSectionConfig)
    security_gates: SecurityGatesSectionConfig = Field(default_factory=SecurityGatesSectionConfig)
    storage: StorageSectionConfig = Field(default_factory=StorageSectionConfig)

    def resolved_targets(self) -> dict[str, TargetEntryConfig]:
        """Return merged map of target_id -> TargetEntryConfig."""
        merged: dict[str, TargetEntryConfig] = {}
        if self.target is not None:
            default_id = self.target.id or self.target.model or f"{self.target.type}-default"
            merged[default_id] = self.target.model_copy(update={"id": default_id})
        for tid, entry in self.targets.items():
            merged[tid] = entry.model_copy(update={"id": tid})
        return merged

    def default_target_id(self) -> str | None:
        if self.target is not None:
            return self.target.id or self.target.model or f"{self.target.type}-default"
        if self.targets:
            return next(iter(self.targets))
        return None


def resolve_config_path(config_path: Path | str | None = None) -> Path:
    """Resolve configuration file path from CLI flag, ASB_CONFIG env var, or CWD default."""
    if config_path is not None:
        return Path(config_path)
    env_path = os.getenv("ASB_CONFIG")
    if env_path:
        return Path(env_path)
    return Path.cwd() / DEFAULT_CONFIG_FILENAME


def load_config(
    config_path: Path | str | None = None,
    *,
    require_exists: bool = False,
) -> SecurityBenchConfig:
    """Load securitybench.yaml and apply environment variable overrides."""
    path = resolve_config_path(config_path)
    raw: dict[str, Any] = {}

    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Failed to parse YAML configuration at {path}: {exc}",
                component="cli.config",
                details={"path": str(path)},
            ) from exc

        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ConfigurationError(
                    f"Configuration file {path} must contain a YAML mapping.",
                    component="cli.config",
                    details={"path": str(path)},
                )
            raw = loaded
    elif require_exists:
        raise ConfigurationError(
            f"Configuration file not found: {path}",
            component="cli.config",
            details={"path": str(path)},
        )

    # Reject raw inline secrets in config files
    if isinstance(raw.get("target"), dict):
        TargetEntryConfig.reject_inline_secrets(raw["target"])
    if isinstance(raw.get("targets"), dict):
        for entry in raw["targets"].values():
            if isinstance(entry, dict):
                TargetEntryConfig.reject_inline_secrets(entry)

    try:
        cfg = SecurityBenchConfig.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(
            f"Invalid configuration in {path}: {exc}",
            component="cli.config",
            details={"path": str(path)},
        ) from exc

    # Environment variable overrides
    if env_db := os.getenv("ASB_DATABASE_URL"):
        cfg = cfg.model_copy(update={"storage": StorageSectionConfig(database_url=env_db)})
    if env_timeout := os.getenv("ASB_TIMEOUT"):
        try:
            cfg = cfg.model_copy(
                update={
                    "execution": cfg.execution.model_copy(update={"timeout": float(env_timeout)})
                }
            )
        except ValueError as exc:
            raise ConfigurationError(
                f"Invalid ASB_TIMEOUT value: {env_timeout!r}", component="cli.config"
            ) from exc
    if env_retries := os.getenv("ASB_MAX_RETRIES"):
        try:
            cfg = cfg.model_copy(
                update={
                    "execution": cfg.execution.model_copy(
                        update={"max_retries": int(env_retries)}
                    )
                }
            )
        except ValueError as exc:
            raise ConfigurationError(
                f"Invalid ASB_MAX_RETRIES value: {env_retries!r}", component="cli.config"
            ) from exc
    if env_out := os.getenv("ASB_OUTPUT_DIR"):
        cfg = cfg.model_copy(
            update={"report": cfg.report.model_copy(update={"output_dir": env_out})}
        )

    return cfg


def default_yaml_template(
    *,
    target_type: str = "openai",
    model: str = "example-model",
    suite: str = "arbiter-security-benchmark",
    report_format: str = "html",
    output_dir: str = "reports",
) -> dict[str, Any]:
    """Build a clean, secret-free default configuration dict for `arbiter init`."""
    target_dict: dict[str, Any] = {
        "type": target_type,
        "model": model,
    }
    env_var = _DEFAULT_ENV_VARS.get(target_type)
    if env_var:
        target_dict["api_key_env_var"] = env_var

    return {
        "target": target_dict,
        "benchmark": {
            "suite": suite,
        },
        "execution": {
            "timeout": 30,
            "max_retries": 2,
        },
        "report": {
            "format": report_format,
            "output_dir": output_dir,
        },
    }


def save_config_dict(path: Path, data: dict[str, Any]) -> None:
    """Write configuration dict cleanly to YAML without storing secrets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    path.write_text(rendered, encoding="utf-8")
