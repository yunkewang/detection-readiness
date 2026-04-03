"""Tests for environment profile auto-generation."""

from pathlib import Path

import yaml

from detection_readiness.discovery.field_discovery import discover_fields_from_events
from detection_readiness.generators.profile_generator import (
    generate_profile_from_discovery,
    save_profile,
)

SAMPLE_EVENTS_DIR = Path(__file__).resolve().parent.parent / "examples" / "sample_events"


def test_generate_from_azure_events():
    discovery = discover_fields_from_events(
        SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
    )
    profile = generate_profile_from_discovery(
        environment_name="test_env",
        source_name="azure_ad_signin",
        discovery=discovery,
        index="test_idx",
        sourcetype="azure:aad:signin",
    )

    assert profile.environment_name == "test_env"
    assert "azure_ad_signin" in profile.data_sources
    ds = profile.data_sources["azure_ad_signin"]
    assert ds.indexes == ["test_idx"]
    assert ds.sourcetypes == ["azure:aad:signin"]
    assert "UserPrincipalName" in ds.fields
    assert ds.fields["UserPrincipalName"].coverage == 1.0


def test_generate_from_sysmon_events():
    discovery = discover_fields_from_events(
        SAMPLE_EVENTS_DIR / "sysmon_process.csv"
    )
    profile = generate_profile_from_discovery(
        environment_name="endpoint_test",
        source_name="endpoint_process",
        discovery=discovery,
    )

    assert "endpoint_process" in profile.data_sources
    ds = profile.data_sources["endpoint_process"]
    assert "Image" in ds.fields
    assert "CommandLine" in ds.fields


def test_coverage_threshold_filters_fields():
    discovery = discover_fields_from_events(
        SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
    )
    profile = generate_profile_from_discovery(
        environment_name="test",
        source_name="src",
        discovery=discovery,
        coverage_threshold=0.9,
    )
    ds = profile.data_sources["src"]
    # All remaining fields should have coverage >= 0.9
    for field_info in ds.fields.values():
        assert field_info.coverage >= 0.9


def test_save_and_reload(tmp_path):
    discovery = discover_fields_from_events(
        SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
    )
    profile = generate_profile_from_discovery(
        environment_name="save_test",
        source_name="azure_ad_signin",
        discovery=discovery,
    )

    path = tmp_path / "generated_profile.yaml"
    save_profile(profile, path)

    assert path.exists()
    data = yaml.safe_load(path.read_text())
    assert data["environment_name"] == "save_test"
    assert "azure_ad_signin" in data["data_sources"]

    # Verify it can be loaded back
    from detection_readiness.loaders.profile_loader import load_profile
    reloaded = load_profile(path)
    assert reloaded.environment_name == "save_test"


def test_generated_profile_notes():
    discovery = discover_fields_from_events(
        SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
    )
    profile = generate_profile_from_discovery(
        environment_name="test",
        source_name="src",
        discovery=discovery,
    )
    assert any("Auto-generated" in n for n in profile.notes)
