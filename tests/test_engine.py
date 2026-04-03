"""Tests for the assessment engine (end-to-end scoring + explanation)."""

from pathlib import Path

from detection_readiness.engine.assessor import assess
from detection_readiness.loaders.family_loader import load_family
from detection_readiness.loaders.profile_loader import load_profile
from detection_readiness.schemas.result import ReadinessStatus

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
FAMILIES_DIR = Path(__file__).resolve().parent.parent / "families"


def test_azure_password_spray():
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("password_spray", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.environment_name == "bluebay"
    assert result.detection_family_id == "password_spray"
    assert 0 <= result.readiness_score <= 100
    assert result.readiness_status in ReadinessStatus
    assert result.recommended_query_strategy == "raw"
    assert result.short_explanation
    assert result.detailed_explanation


def test_endpoint_suspicious_process():
    profile = load_profile(EXAMPLES_DIR / "endpoint_profile.yaml")
    family = load_family("suspicious_process_execution", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.environment_name == "ironforge"
    assert result.readiness_score >= 80
    assert result.readiness_status == ReadinessStatus.READY
    assert result.recommended_query_strategy == "datamodel"


def test_o365_email_impersonation():
    profile = load_profile(EXAMPLES_DIR / "o365_profile.yaml")
    family = load_family("email_impersonation", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.environment_name == "northwind"
    assert result.readiness_score > 0


def test_missing_data_source_produces_blocker():
    """Azure profile has no endpoint data — should block process detection."""
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("suspicious_process_execution", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.readiness_status == ReadinessStatus.NOT_READY
    assert any("endpoint_process" in b for b in result.blockers)


def test_result_serializable():
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("password_spray", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    json_str = result.model_dump_json()
    assert "readiness_score" in json_str
