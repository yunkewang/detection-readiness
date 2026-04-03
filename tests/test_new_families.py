"""Tests for the newly added detection families."""

from pathlib import Path

from detection_readiness.engine.assessor import assess
from detection_readiness.loaders.family_loader import list_families, load_family
from detection_readiness.loaders.profile_loader import load_profile
from detection_readiness.schemas.result import ReadinessStatus

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
FAMILIES_DIR = Path(__file__).resolve().parent.parent / "families"


def test_load_lateral_movement():
    fam = load_family("lateral_movement", families_dir=FAMILIES_DIR)
    assert fam.id == "lateral_movement"
    assert "endpoint_process" in fam.required_data_sources
    assert "network_traffic" in fam.required_data_sources


def test_load_data_exfiltration():
    fam = load_family("data_exfiltration", families_dir=FAMILIES_DIR)
    assert fam.id == "data_exfiltration"
    assert "network_traffic" in fam.required_data_sources
    assert "bytes_out" in fam.required_fields_by_source["network_traffic"]


def test_load_privilege_escalation():
    fam = load_family("privilege_escalation", families_dir=FAMILIES_DIR)
    assert fam.id == "privilege_escalation"
    assert "endpoint_process" in fam.required_data_sources


def test_all_seven_families_present():
    families = list_families(families_dir=FAMILIES_DIR)
    ids = {f.id for f in families}
    assert ids == {
        "password_spray",
        "impossible_travel",
        "suspicious_process_execution",
        "email_impersonation",
        "lateral_movement",
        "data_exfiltration",
        "privilege_escalation",
    }


def test_privilege_escalation_endpoint_ready():
    profile = load_profile(EXAMPLES_DIR / "endpoint_profile.yaml")
    family = load_family("privilege_escalation", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.readiness_score >= 70
    assert result.recommended_query_strategy is not None


def test_lateral_movement_needs_network():
    """Azure profile lacks network_traffic — should not be ready."""
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("lateral_movement", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.readiness_status == ReadinessStatus.NOT_READY
    assert any("network_traffic" in b for b in result.blockers)


def test_data_exfiltration_needs_network():
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("data_exfiltration", families_dir=FAMILIES_DIR)
    result = assess(profile, family)

    assert result.readiness_status == ReadinessStatus.NOT_READY
