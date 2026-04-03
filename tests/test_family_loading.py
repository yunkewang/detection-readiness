"""Tests for detection family definition loading."""

from pathlib import Path

import pytest

from detection_readiness.loaders.family_loader import list_families, load_family

FAMILIES_DIR = Path(__file__).resolve().parent.parent / "families"


def test_load_password_spray():
    fam = load_family("password_spray", families_dir=FAMILIES_DIR)
    assert fam.id == "password_spray"
    assert "azure_ad_signin" in fam.required_data_sources
    assert "user" in fam.required_fields_by_source["azure_ad_signin"]


def test_load_impossible_travel():
    fam = load_family("impossible_travel", families_dir=FAMILIES_DIR)
    assert fam.id == "impossible_travel"
    assert "location" in fam.required_fields_by_source["azure_ad_signin"]


def test_load_suspicious_process_execution():
    fam = load_family("suspicious_process_execution", families_dir=FAMILIES_DIR)
    assert fam.id == "suspicious_process_execution"
    assert "endpoint_process" in fam.required_data_sources


def test_load_email_impersonation():
    fam = load_family("email_impersonation", families_dir=FAMILIES_DIR)
    assert fam.id == "email_impersonation"
    assert fam.preferred_query_mode == "raw"


def test_load_lateral_movement():
    fam = load_family("lateral_movement", families_dir=FAMILIES_DIR)
    assert fam.id == "lateral_movement"
    assert "endpoint_process" in fam.required_data_sources


def test_load_data_exfiltration():
    fam = load_family("data_exfiltration", families_dir=FAMILIES_DIR)
    assert fam.id == "data_exfiltration"
    assert "proxy_egress" in fam.required_data_sources


def test_list_all_families():
    families = list_families(families_dir=FAMILIES_DIR)
    ids = {f.id for f in families}
    assert ids == {
        "data_exfiltration",
        "lateral_movement",
        "password_spray",
        "impossible_travel",
        "suspicious_process_execution",
        "email_impersonation",
        "lateral_movement",
        "data_exfiltration",
        "privilege_escalation",
    }


def test_load_nonexistent_family():
    with pytest.raises(FileNotFoundError):
        load_family("does_not_exist", families_dir=FAMILIES_DIR)
