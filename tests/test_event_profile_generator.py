"""Tests for profile generation from sample events."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from detection_readiness.loaders.event_profile_generator import (
    build_profile,
    infer_fields,
    load_events,
    write_profile,
)


def test_load_events_from_jsonl(tmp_path: Path):
    events_path = tmp_path / "events.jsonl"
    events_path.write_text('{"user":"alice"}\n{"user":"bob","src_ip":"1.1.1.1"}\n')

    events = load_events(events_path)
    assert len(events) == 2
    assert events[1]["src_ip"] == "1.1.1.1"


def test_infer_fields_with_min_coverage():
    events = [
        {"user": "alice", "src_ip": "1.1.1.1", "location": "US"},
        {"user": "bob", "src_ip": "2.2.2.2"},
        {"user": "carol"},
    ]

    inferred = infer_fields(events, min_coverage=0.66)
    assert "user" in inferred
    assert "src_ip" in inferred
    assert "location" not in inferred
    assert inferred["src_ip"].coverage == 0.6667


def test_build_and_write_yaml_profile(tmp_path: Path):
    events = [
        {"user": "alice", "src_ip": "1.1.1.1"},
        {"user": "bob", "src_ip": ""},
    ]

    profile = build_profile(
        environment_name="generated_env",
        data_source_id="azure_ad_signin",
        index="idx_auth",
        sourcetype="azure:aad:signin",
        events=events,
        min_coverage=0.5,
    )

    out = tmp_path / "profile.yaml"
    write_profile(profile, out)

    rendered = yaml.safe_load(out.read_text())
    fields = rendered["data_sources"]["azure_ad_signin"]["fields"]
    assert rendered["environment_name"] == "generated_env"
    assert fields["user"]["coverage"] == 1.0
    assert fields["src_ip"]["coverage"] == 0.5


def test_load_events_from_json_array(tmp_path: Path):
    events_path = tmp_path / "events.json"
    events_path.write_text(json.dumps([{"a": 1}, {"a": 2, "b": 3}]))

    events = load_events(events_path)
    assert len(events) == 2
    assert events[1]["b"] == 3


def test_load_events_from_csv(tmp_path: Path):
    events_path = tmp_path / "events.csv"
    events_path.write_text("user,src_ip,result\nalice,1.1.1.1,success\nbob,,failure\n")

    events = load_events(events_path)
    assert len(events) == 2
    assert events[0]["user"] == "alice"
    assert events[1]["src_ip"] == ""
