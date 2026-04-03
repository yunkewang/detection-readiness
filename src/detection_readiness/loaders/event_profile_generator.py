"""Build environment profiles from sample events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from detection_readiness.schemas.environment import DataSource, EnvironmentProfile, FieldInfo

_EMPTY_VALUES = {None, ""}


def _is_present(value: Any) -> bool:
    """Return True if a value should count toward field coverage."""
    if isinstance(value, str):
        return value.strip() != ""
    return value not in _EMPTY_VALUES


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load events from JSON/JSONL input.

    Supports either:
      * JSON Lines where each line is an event object
      * A JSON array of event objects
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Events file not found: {file_path}")

    text = file_path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError("Events file is empty")

    if file_path.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            raise ValueError("JSON input must be an array of objects")
        return data

    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("Each JSONL line must be an object")
        events.append(event)

    if not events:
        raise ValueError("No events were found in input")

    return events


def infer_fields(events: list[dict[str, Any]], min_coverage: float = 0.0) -> dict[str, FieldInfo]:
    """Infer candidate fields and coverage from raw events."""
    if not events:
        raise ValueError("Cannot infer fields from zero events")

    presence_counts: dict[str, int] = {}
    total_events = len(events)

    for event in events:
        for key, value in event.items():
            if _is_present(value):
                presence_counts[key] = presence_counts.get(key, 0) + 1

    inferred: dict[str, FieldInfo] = {}
    for field_name in sorted(presence_counts):
        coverage = presence_counts[field_name] / total_events
        if coverage >= min_coverage:
            inferred[field_name] = FieldInfo(candidates=[field_name], coverage=round(coverage, 4))

    return inferred


def build_profile(
    *,
    environment_name: str,
    data_source_id: str,
    index: str,
    sourcetype: str,
    events: list[dict[str, Any]],
    min_coverage: float = 0.0,
) -> EnvironmentProfile:
    """Build an ``EnvironmentProfile`` from sample events."""
    inferred_fields = infer_fields(events, min_coverage=min_coverage)

    data_source = DataSource(
        indexes=[index],
        sourcetypes=[sourcetype],
        fields=inferred_fields,
        query_modes={"raw": True, "datamodel": False},
    )

    return EnvironmentProfile(
        environment_name=environment_name,
        data_sources={data_source_id: data_source},
        datamodels={},
        constraints={},
        notes=[
            "Auto-generated from sample events; validate coverage against production volume.",
        ],
    )


def write_profile(profile: EnvironmentProfile, output_path: str | Path) -> None:
    """Write profile as YAML or JSON based on file extension."""
    output = Path(output_path)
    suffix = output.suffix.lower()
    data = profile.model_dump(mode="json")

    if suffix in (".yaml", ".yml"):
        output.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return
    if suffix == ".json":
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return

    raise ValueError("Output path must end in .yaml, .yml, or .json")
