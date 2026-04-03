"""Datamodel health checks via the Splunk REST API.

Checks whether CIM datamodels are present, accelerated, and have recent data.
Can also be used with static configuration (no live Splunk connection).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from detection_readiness.splunk.client import SplunkClient


@dataclass
class DatamodelHealthResult:
    """Health check result for a single datamodel."""

    name: str
    exists: bool = False
    accelerated: bool = False
    acceleration_complete: bool = False
    event_count: int = 0
    earliest_time: str = ""
    latest_time: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.exists and self.accelerated and self.event_count > 0


def check_datamodel_health(
    client: SplunkClient,
    model_names: list[str] | None = None,
) -> list[DatamodelHealthResult]:
    """Check the health of one or more datamodels.

    Args:
        client: An authenticated SplunkClient.
        model_names: Specific models to check. If None, checks all.

    Returns:
        A list of DatamodelHealthResult, one per model.
    """
    all_models = client.get_datamodels()
    available_names = {e["name"] for e in all_models}

    targets = model_names if model_names else sorted(available_names)
    results: list[DatamodelHealthResult] = []

    for name in targets:
        result = DatamodelHealthResult(name=name)

        if name not in available_names:
            result.warnings.append(f"Datamodel '{name}' not found on this Splunk instance.")
            results.append(result)
            continue

        result.exists = True

        accel = client.get_datamodel_acceleration(name)
        content = _content(accel)

        accel_enabled = content.get("acceleration", "0")
        result.accelerated = str(accel_enabled).lower() in ("1", "true")

        if not result.accelerated:
            result.warnings.append(
                f"Datamodel '{name}' exists but acceleration is not enabled."
            )

        # Try to get summary info
        summary = content.get("acceleration.summary", {})
        if isinstance(summary, dict):
            result.event_count = int(summary.get("event_count", 0))
            result.earliest_time = str(summary.get("earliest_time", ""))
            result.latest_time = str(summary.get("latest_time", ""))
            if summary.get("is_complete"):
                result.acceleration_complete = True

        if result.accelerated and result.event_count == 0:
            result.warnings.append(
                f"Datamodel '{name}' is accelerated but has 0 events — "
                "check acceleration status or time range."
            )

        results.append(result)

    return results


def _content(entry: dict[str, Any]) -> dict[str, Any]:
    """Extract the content dict from a Splunk REST entry."""
    return entry.get("content", entry)
