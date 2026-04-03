"""Tests for sample-event-based field discovery."""

import json
from pathlib import Path

import pytest

from detection_readiness.discovery.field_discovery import (
    DiscoveryResult,
    discover_fields_from_events,
)

SAMPLE_EVENTS_DIR = Path(__file__).resolve().parent.parent / "examples" / "sample_events"


class TestJSONLDiscovery:
    def test_discover_azure_ad_events(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
        )
        assert result.total_events == 10
        field_names = {f.name for f in result.fields}
        assert "UserPrincipalName" in field_names
        assert "ipAddress" in field_names
        assert "ResultType" in field_names

    def test_coverage_values(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
        )
        by_name = {f.name: f for f in result.fields}
        # UserPrincipalName is in all 10 events
        assert by_name["UserPrincipalName"].coverage == 1.0
        # UserAgent is missing from some events
        assert by_name["UserAgent"].coverage < 1.0

    def test_nested_fields_flattened(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
        )
        field_names = {f.name for f in result.fields}
        assert "Location.City" in field_names
        assert "Location.CountryOrRegion" in field_names

    def test_sample_values_populated(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
        )
        by_name = {f.name: f for f in result.fields}
        assert len(by_name["ResultType"].sample_values) > 0


class TestCSVDiscovery:
    def test_discover_sysmon_events(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "sysmon_process.csv"
        )
        assert result.total_events == 8
        field_names = {f.name for f in result.fields}
        assert "Image" in field_names
        assert "CommandLine" in field_names
        assert "User" in field_names

    def test_all_fields_full_coverage(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "sysmon_process.csv"
        )
        for f in result.fields:
            assert f.coverage == 1.0


class TestJSONDiscovery:
    def test_json_array(self, tmp_path):
        events = [
            {"user": "alice", "action": "login"},
            {"user": "bob", "action": "login"},
            {"user": "charlie"},
        ]
        path = tmp_path / "events.json"
        path.write_text(json.dumps(events))
        result = discover_fields_from_events(path)
        assert result.total_events == 3
        by_name = {f.name: f for f in result.fields}
        assert by_name["user"].coverage == 1.0
        assert by_name["action"].coverage == pytest.approx(2 / 3, abs=0.01)

    def test_single_object(self, tmp_path):
        path = tmp_path / "single.json"
        path.write_text(json.dumps({"field_a": "value"}))
        result = discover_fields_from_events(path)
        assert result.total_events == 1


class TestEdgeCases:
    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        result = discover_fields_from_events(path)
        assert result.total_events == 0
        assert result.fields == []

    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            discover_fields_from_events("/nonexistent/path.jsonl")

    def test_result_serializable(self):
        result = discover_fields_from_events(
            SAMPLE_EVENTS_DIR / "azure_ad_signin.jsonl"
        )
        json_str = result.model_dump_json()
        assert "total_events" in json_str
        # Round-trip
        parsed = DiscoveryResult.model_validate_json(json_str)
        assert parsed.total_events == result.total_events
