"""Tests for the SPL generation content factory."""

from pathlib import Path

from detection_readiness.engine.assessor import assess
from detection_readiness.generators.spl_generator import generate_spl
from detection_readiness.loaders.family_loader import load_family
from detection_readiness.loaders.profile_loader import load_profile

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
FAMILIES_DIR = Path(__file__).resolve().parent.parent / "families"


def test_password_spray_raw_spl():
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("password_spray", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    spl = generate_spl(result)

    assert spl.strategy == "raw"
    assert "index=" in spl.query
    assert "stats" in spl.query
    assert spl.detection_family == "password_spray"


def test_process_execution_datamodel_spl():
    profile = load_profile(EXAMPLES_DIR / "endpoint_profile.yaml")
    family = load_family("suspicious_process_execution", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    spl = generate_spl(result)

    assert spl.strategy == "datamodel"
    assert "tstats" in spl.query


def test_email_impersonation_raw_spl():
    profile = load_profile(EXAMPLES_DIR / "o365_profile.yaml")
    family = load_family("email_impersonation", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    spl = generate_spl(result)

    assert "sender" in spl.query.lower() or "SenderAddress" in spl.query


def test_not_ready_produces_warning():
    """When env is not ready, the SPL output should include a warning note."""
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("suspicious_process_execution", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    assert result.readiness_status.value == "not_ready"

    spl = generate_spl(result)
    assert any("WARNING" in n or "not ready" in n.lower() for n in spl.notes)


def test_lateral_movement_spl():
    profile = load_profile(EXAMPLES_DIR / "endpoint_profile.yaml")
    family = load_family("lateral_movement", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    spl = generate_spl(result)

    assert spl.detection_family == "lateral_movement"
    assert len(spl.query) > 0


def test_spl_output_serializable():
    import dataclasses
    import json

    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    family = load_family("password_spray", families_dir=FAMILIES_DIR)
    result = assess(profile, family)
    spl = generate_spl(result)
    json_str = json.dumps(dataclasses.asdict(spl))
    assert "query" in json_str
