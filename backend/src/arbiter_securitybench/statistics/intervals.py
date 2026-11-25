"""Statistical confidence interval estimators using NumPy and SciPy."""

from __future__ import annotations

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator
from scipy import stats


class ProportionCI(BaseModel):
    """Confidence interval estimated for a proportion or bounded metric in [0, 1]."""

    model_config = ConfigDict(frozen=True)

    method: str = Field(min_length=1)
    confidence_level: float = Field(gt=0.0, lt=1.0)
    estimate: float = Field(ge=0.0, le=1.0)
    lower: float = Field(ge=0.0, le=1.0)
    upper: float = Field(ge=0.0, le=1.0)
    sample_size: int = Field(ge=0)

    @model_validator(mode="after")
    def _validate_bounds(self) -> ProportionCI:
        if self.lower > self.upper:
            raise ValueError("Lower bound cannot exceed upper bound.")
        return self


def wilson_confidence_interval(
    successes: int,
    trials: int,
    *,
    confidence_level: float = 0.95,
) -> ProportionCI | None:
    """Compute the Wilson score confidence interval for a binomial proportion.

    Returns None when trials <= 0.
    """
    if trials <= 0:
        return None
    if successes < 0 or successes > trials:
        raise ValueError(f"successes ({successes}) must be within [0, trials ({trials})].")
    if not (0.0 < confidence_level < 1.0):
        raise ValueError("confidence_level must be strictly between 0 and 1.")

    z = float(stats.norm.ppf(1.0 - (1.0 - confidence_level) / 2.0))
    n = float(trials)
    p_hat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    margin = (z / denom) * float(np.sqrt((p_hat * (1.0 - p_hat)) / n + z2 / (4.0 * n * n)))

    lower = float(np.clip(center - margin, 0.0, 1.0))
    upper = float(np.clip(center + margin, 0.0, 1.0))
    # Clamp tiny floating-point overshoot so lower <= estimate <= upper always holds.
    lower = min(lower, p_hat)
    upper = max(upper, p_hat)
    return ProportionCI(
        method="wilson",
        confidence_level=confidence_level,
        estimate=p_hat,
        lower=lower,
        upper=upper,
        sample_size=trials,
    )


def bootstrap_confidence_interval(
    values: list[float] | np.ndarray,
    *,
    weights: list[float] | np.ndarray | None = None,
    confidence_level: float = 0.95,
    n_bootstrap: int = 2000,
    seed: int = 42,
) -> ProportionCI | None:
    """Compute a deterministic percentile bootstrap CI for unweighted or weighted means.

    Returns None when values is empty.
    """
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return None
    if not (0.0 < confidence_level < 1.0):
        raise ValueError("confidence_level must be strictly between 0 and 1.")
    if n_bootstrap < 100:
        raise ValueError("n_bootstrap must be >= 100.")

    if weights is not None:
        w_arr = np.asarray(weights, dtype=np.float64)
        if w_arr.shape != arr.shape:
            raise ValueError("weights must have the same length as values.")
        if np.any(w_arr <= 0):
            raise ValueError("All weights must be strictly positive.")
        point = float(np.sum(arr * w_arr) / np.sum(w_arr))
    else:
        w_arr = None
        point = float(np.mean(arr))

    point = float(np.clip(point, 0.0, 1.0))

    # Zero-variance or single-item fast path avoids degenerate resampling artifacts.
    if arr.size == 1 or float(np.ptp(arr)) == 0.0:
        return ProportionCI(
            method="bootstrap_percentile",
            confidence_level=confidence_level,
            estimate=point,
            lower=point,
            upper=point,
            sample_size=int(arr.size),
        )

    rng = np.random.default_rng(seed)
    n = arr.size
    indices = rng.integers(0, n, size=(n_bootstrap, n))
    sampled_vals = arr[indices]
    if w_arr is not None:
        sampled_weights = w_arr[indices]
        boot_estimates = np.sum(sampled_vals * sampled_weights, axis=1) / np.sum(
            sampled_weights, axis=1
        )
    else:
        boot_estimates = np.mean(sampled_vals, axis=1)

    alpha = 1.0 - confidence_level
    lower = float(np.clip(np.quantile(boot_estimates, alpha / 2.0), 0.0, 1.0))
    upper = float(np.clip(np.quantile(boot_estimates, 1.0 - alpha / 2.0), 0.0, 1.0))
    lower = min(lower, upper)
    return ProportionCI(
        method="bootstrap_percentile",
        confidence_level=confidence_level,
        estimate=point,
        lower=lower,
        upper=upper,
        sample_size=int(n),
    )
