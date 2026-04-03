"""Sample-event-based field discovery.

Analyzes sample events (JSON lines, JSON array, or CSV) to discover which
fields are present and estimate their coverage. This enables auto-profiling
an environment without direct Splunk API access.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class DiscoveredField(BaseModel):
    """A field discovered from sample events."""

    name: str
    occurrence_count: int
    total_events: int
    coverage: float = Field(ge=0.0, le=1.0)
    sample_values: list[str] = Field(default_factory=list, max_length=5)


class DiscoveryResult(BaseModel):
    """Result of field discovery on a set of sample events."""

    source_file: str
    total_events: int
    fields: list[DiscoveredField]


def discover_fields_from_events(
    path: str | Path,
    *,
    max_sample_values: int = 5,
) -> DiscoveryResult:
    """Discover fields and coverage from a sample event file.

    Supports:
    - JSON Lines (.jsonl) — one JSON object per line
    - JSON array (.json) — a top-level array of objects
    - CSV (.csv) — standard CSV with a header row

    Args:
        path: Path to the sample event file.
        max_sample_values: Maximum unique sample values to keep per field.

    Returns:
        A DiscoveryResult with per-field statistics.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Sample event file not found: {path}")

    events = _load_events(path)
    if not events:
        return DiscoveryResult(
            source_file=str(path), total_events=0, fields=[]
        )

    total = len(events)
    field_counts: Counter[str] = Counter()
    field_samples: dict[str, set[str]] = {}

    for event in events:
        for key, value in _flatten(event).items():
            if value is not None and value != "":
                field_counts[key] += 1
                samples = field_samples.setdefault(key, set())
                if len(samples) < max_sample_values:
                    samples.add(str(value)[:200])

    discovered: list[DiscoveredField] = []
    for name, count in field_counts.most_common():
        discovered.append(
            DiscoveredField(
                name=name,
                occurrence_count=count,
                total_events=total,
                coverage=round(count / total, 4),
                sample_values=sorted(field_samples.get(name, set()))[:max_sample_values],
            )
        )

    return DiscoveryResult(
        source_file=str(path),
        total_events=total,
        fields=discovered,
    )


def _load_events(path: Path) -> list[dict[str, Any]]:
    """Load events from JSON, JSONL, or CSV."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return _load_csv(text)
    elif suffix == ".jsonl":
        return _load_jsonl(text)
    elif suffix == ".json":
        return _load_json(text)
    else:
        # Try JSON first, then JSONL, then CSV
        for loader in (_load_json, _load_jsonl, _load_csv):
            try:
                result = loader(text)
                if result:
                    return result
            except Exception:
                continue
        raise ValueError(f"Could not parse events from {path}")


def _load_json(text: str) -> list[dict[str, Any]]:
    data = json.loads(text)
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _load_jsonl(text: str) -> list[dict[str, Any]]:
    events = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
    return events


def _load_csv(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def _flatten(
    obj: dict[str, Any], prefix: str = "", sep: str = "."
) -> dict[str, Any]:
    """Flatten nested dicts into dot-separated keys."""
    items: dict[str, Any] = {}
    for key, value in obj.items():
        full_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            items.update(_flatten(value, full_key, sep))
        elif isinstance(value, list):
            # Keep list as-is (present but not recursed)
            items[full_key] = str(value) if value else None
        else:
            items[full_key] = value
    return items
