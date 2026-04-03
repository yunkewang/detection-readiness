"""Tests for environment profile loading and validation."""

from pathlib import Path

import pytest
import yaml

from detection_readiness.loaders.profile_loader import load_profile
from detection_readiness.schemas.environment import EnvironmentProfile

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_load_azure_profile():
    profile = load_profile(EXAMPLES_DIR / "azure_profile.yaml")
    assert profile.environment_name == "bluebay"
    assert "azure_ad_signin" in profile.data_sources
    ds = profile.data_sources["azure_ad_signin"]
    assert ds.fields["user"].coverage == 0.95
    assert ds.query_modes["raw"] is True


def test_load_o365_profile():
    profile = load_profile(EXAMPLES_DIR / "o365_profile.yaml")
    assert profile.environment_name == "northwind"
    assert "o365_email" in profile.data_sources
    assert "azure_ad_signin" in profile.data_sources


def test_load_endpoint_profile():
    profile = load_profile(EXAMPLES_DIR / "endpoint_profile.yaml")
    assert profile.environment_name == "ironforge"
    assert profile.datamodels["endpoint"].available is True


def test_load_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        load_profile("/nonexistent/path.yaml")


def test_load_invalid_format(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("hello")
    with pytest.raises(ValueError, match="Unsupported file format"):
        load_profile(bad)


def test_load_json_profile(tmp_path):
    data = {
        "environment_name": "test_env",
        "data_sources": {},
    }
    import json

    path = tmp_path / "profile.json"
    path.write_text(json.dumps(data))
    profile = load_profile(path)
    assert profile.environment_name == "test_env"


def test_validation_rejects_bad_coverage(tmp_path):
    data = {
        "environment_name": "bad",
        "data_sources": {
            "src": {
                "fields": {
                    "f": {"candidates": ["a"], "coverage": 1.5}
                }
            }
        },
    }
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.dump(data))
    with pytest.raises(Exception):
        load_profile(path)
