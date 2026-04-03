"""Datamodel health evaluation helpers."""

from __future__ import annotations

from detection_readiness.schemas.environment import EnvironmentProfile


def evaluate_datamodel_health(
    profile: EnvironmentProfile,
    *,
    min_health_score: float = 0.7,
    max_acceleration_lag_hours: float = 24.0,
) -> tuple[list[str], list[str]]:
    """Return (warnings, blockers) for datamodel readiness in a profile."""
    warnings: list[str] = []
    blockers: list[str] = []

    for name, datamodel in profile.datamodels.items():
        if not datamodel.available:
            blockers.append(f"Datamodel '{name}' is unavailable.")
            continue

        if datamodel.health_score < min_health_score:
            warnings.append(
                f"Datamodel '{name}' health score is low "
                f"({datamodel.health_score:.0%} < {min_health_score:.0%})."
            )

        if not datamodel.acceleration_enabled:
            warnings.append(
                f"Datamodel '{name}' acceleration is disabled; tstats performance may degrade."
            )
        elif datamodel.acceleration_lag_hours > max_acceleration_lag_hours:
            warnings.append(
                f"Datamodel '{name}' acceleration lag is high "
                f"({datamodel.acceleration_lag_hours:.1f}h > {max_acceleration_lag_hours:.1f}h)."
            )

    return warnings, blockers
