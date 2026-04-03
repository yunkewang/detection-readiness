"""Tests for datamodel health checks."""

from detection_readiness.schemas.environment import DatamodelInfo, EnvironmentProfile
from detection_readiness.scoring.datamodel_health import evaluate_datamodel_health


def test_healthy_datamodels():
    profile = EnvironmentProfile(
        environment_name="healthy",
        datamodels={
            "authentication": DatamodelInfo(
                available=True,
                acceleration_enabled=True,
                acceleration_lag_hours=2.0,
                health_score=0.95,
            )
        },
    )
    warnings, blockers = evaluate_datamodel_health(profile)
    assert warnings == []
    assert blockers == []


def test_unhealthy_datamodels():
    profile = EnvironmentProfile(
        environment_name="unhealthy",
        datamodels={
            "authentication": DatamodelInfo(
                available=False,
                acceleration_enabled=False,
                health_score=0.4,
            ),
            "endpoint": DatamodelInfo(
                available=True,
                acceleration_enabled=True,
                acceleration_lag_hours=36.0,
                health_score=0.5,
            ),
        },
    )
    warnings, blockers = evaluate_datamodel_health(profile)
    assert any("health score is low" in warning for warning in warnings)
    assert any("acceleration lag is high" in warning for warning in warnings)
    assert any("unavailable" in blocker for blocker in blockers)
