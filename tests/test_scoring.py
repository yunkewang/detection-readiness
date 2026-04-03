"""Tests for the deterministic scoring engine."""

from detection_readiness.schemas.environment import (
    DatamodelInfo,
    DataSource,
    EnvironmentProfile,
    FieldInfo,
)
from detection_readiness.schemas.family import DetectionFamily, ScoringWeights
from detection_readiness.scoring.scorer import (
    ScoreBreakdown,
    classify_status,
    evaluate,
)
from detection_readiness.schemas.result import ReadinessStatus


def _make_profile(**overrides) -> EnvironmentProfile:
    defaults = {
        "environment_name": "test",
        "data_sources": {
            "azure_ad_signin": DataSource(
                indexes=["idx"],
                sourcetypes=["azure:aad:signin"],
                fields={
                    "user": FieldInfo(candidates=["UserPrincipalName"], coverage=0.95),
                    "src_ip": FieldInfo(candidates=["ipAddress"], coverage=0.90),
                    "result": FieldInfo(candidates=["ResultType"], coverage=0.85),
                },
                query_modes={"raw": True, "datamodel": False},
            )
        },
        "datamodels": {"authentication": DatamodelInfo(available=False)},
        "constraints": {},
        "notes": [],
    }
    defaults.update(overrides)
    return EnvironmentProfile(**defaults)


def _make_family(**overrides) -> DetectionFamily:
    defaults = {
        "id": "password_spray",
        "display_name": "Password Spray",
        "description": "Detects password spray attacks.",
        "required_data_sources": ["azure_ad_signin"],
        "required_fields_by_source": {
            "azure_ad_signin": ["user", "src_ip", "result"]
        },
        "optional_fields_by_source": {"azure_ad_signin": ["app"]},
        "preferred_query_mode": "datamodel",
        "fallback_query_mode": "raw",
        "scoring_weights": ScoringWeights(),
        "remediation_guidance": {},
    }
    defaults.update(overrides)
    return DetectionFamily(**defaults)


class TestClassifyStatus:
    def test_ready(self):
        assert classify_status(85.0) == ReadinessStatus.READY

    def test_partially_ready(self):
        assert classify_status(65.0) == ReadinessStatus.PARTIALLY_READY

    def test_not_ready(self):
        assert classify_status(30.0) == ReadinessStatus.NOT_READY

    def test_boundary_ready(self):
        assert classify_status(80.0) == ReadinessStatus.READY

    def test_boundary_partial(self):
        assert classify_status(50.0) == ReadinessStatus.PARTIALLY_READY

    def test_custom_thresholds(self):
        assert classify_status(70.0, ready_threshold=90.0) == ReadinessStatus.PARTIALLY_READY


class TestEvaluate:
    def test_all_present_fallback_raw(self):
        """With all fields present and raw mode, should score well."""
        profile = _make_profile()
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert breakdown.earned > 0
        assert breakdown.possible > 0
        score = (breakdown.earned / breakdown.possible) * 100
        # Should be partially ready or better (has fallback but not preferred)
        assert score >= 50

    def test_missing_data_source(self):
        profile = _make_profile(data_sources={})
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert any("not present" in b for b in breakdown.blockers)
        score = (breakdown.earned / breakdown.possible) * 100
        assert score < 50

    def test_missing_required_field(self):
        ds = DataSource(
            indexes=["idx"],
            sourcetypes=["azure:aad:signin"],
            fields={
                "user": FieldInfo(candidates=["UserPrincipalName"], coverage=0.95),
                # src_ip missing
                "result": FieldInfo(candidates=["ResultType"], coverage=0.85),
            },
            query_modes={"raw": True, "datamodel": False},
        )
        profile = _make_profile(data_sources={"azure_ad_signin": ds})
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert any("src_ip" in b for b in breakdown.blockers)

    def test_low_coverage_warning(self):
        ds = DataSource(
            fields={
                "user": FieldInfo(candidates=["u"], coverage=0.50),
                "src_ip": FieldInfo(candidates=["ip"], coverage=0.90),
                "result": FieldInfo(candidates=["r"], coverage=0.90),
            },
            query_modes={"raw": True},
        )
        profile = _make_profile(data_sources={"azure_ad_signin": ds})
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert any("low coverage" in w for w in breakdown.warnings)

    def test_preferred_mode_available(self):
        ds = DataSource(
            fields={
                "user": FieldInfo(candidates=["u"], coverage=0.95),
                "src_ip": FieldInfo(candidates=["ip"], coverage=0.90),
                "result": FieldInfo(candidates=["r"], coverage=0.85),
            },
            query_modes={"raw": True, "datamodel": True},
        )
        profile = _make_profile(
            data_sources={"azure_ad_signin": ds},
            datamodels={"authentication": DatamodelInfo(available=True)},
        )
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert breakdown.recommended_query_strategy == "datamodel"

    def test_avoid_datamodel_constraint(self):
        ds = DataSource(
            fields={
                "user": FieldInfo(candidates=["u"], coverage=0.95),
                "src_ip": FieldInfo(candidates=["ip"], coverage=0.90),
                "result": FieldInfo(candidates=["r"], coverage=0.85),
            },
            query_modes={"raw": True},
        )
        profile = _make_profile(
            data_sources={"azure_ad_signin": ds},
            datamodels={"authentication": DatamodelInfo(available=True)},
            constraints={"avoid_datamodel": True},
        )
        family = _make_family()
        breakdown = evaluate(profile, family)
        assert breakdown.recommended_query_strategy == "raw"
        assert any("datamodel" in a.lower() for a in breakdown.assumptions)
