"""Auto-generate environment profiles from sample events or Splunk API.

Two entry points:
- ``generate_profile_from_discovery`` — builds a profile from field discovery results
- ``generate_profile_from_splunk`` — builds a profile from a live Splunk instance
"""

from __future__ import annotations

from pathlib import Path

import yaml

from detection_readiness.discovery.field_discovery import (
    DiscoveryResult,
    discover_fields_from_events,
)
from detection_readiness.schemas.environment import (
    DatamodelInfo,
    DataSource,
    EnvironmentProfile,
    FieldInfo,
)
from detection_readiness.splunk.client import SplunkClient


def generate_profile_from_discovery(
    environment_name: str,
    source_name: str,
    discovery: DiscoveryResult,
    *,
    index: str = "main",
    sourcetype: str = "unknown",
    coverage_threshold: float = 0.5,
) -> EnvironmentProfile:
    """Build an EnvironmentProfile from a DiscoveryResult.

    Fields below *coverage_threshold* are excluded.
    """
    fields: dict[str, FieldInfo] = {}
    for f in discovery.fields:
        if f.coverage >= coverage_threshold:
            fields[f.name] = FieldInfo(
                candidates=[f.name],
                coverage=f.coverage,
            )

    ds = DataSource(
        indexes=[index],
        sourcetypes=[sourcetype],
        fields=fields,
        query_modes={"raw": True, "datamodel": False},
    )

    return EnvironmentProfile(
        environment_name=environment_name,
        data_sources={source_name: ds},
        notes=[f"Auto-generated from {discovery.source_file}"],
    )


def generate_profile_from_splunk(
    client: SplunkClient,
    environment_name: str,
    source_configs: list[dict[str, str]],
    *,
    check_datamodels: list[str] | None = None,
) -> EnvironmentProfile:
    """Build an EnvironmentProfile by querying a live Splunk instance.

    Args:
        client: Authenticated SplunkClient.
        environment_name: Name for the resulting profile.
        source_configs: A list of dicts with keys ``name``, ``index``,
            ``sourcetype`` describing the data sources to probe.
        check_datamodels: Optional list of datamodel names to check.

    Returns:
        An EnvironmentProfile populated from live data.
    """
    data_sources: dict[str, DataSource] = {}

    for cfg in source_configs:
        name = cfg["name"]
        idx = cfg["index"]
        stype = cfg["sourcetype"]

        summary = client.get_field_summary(idx, stype)
        # Determine total events from the max count across fields
        max_count = max((v["count"] for v in summary.values()), default=0)

        fields: dict[str, FieldInfo] = {}
        for fname, stats in summary.items():
            if fname.startswith("_") and fname not in ("_time",):
                continue  # skip internal fields
            count = stats["count"]
            coverage = count / max_count if max_count > 0 else 0.0
            fields[fname] = FieldInfo(
                candidates=[fname],
                coverage=round(coverage, 4),
            )

        data_sources[name] = DataSource(
            indexes=[idx],
            sourcetypes=[stype],
            fields=fields,
            query_modes={"raw": True, "datamodel": False},
        )

    # Datamodel checks
    datamodels: dict[str, DatamodelInfo] = {}
    if check_datamodels:
        from detection_readiness.splunk.datamodel_health import check_datamodel_health

        health_results = check_datamodel_health(client, check_datamodels)
        for hr in health_results:
            datamodels[hr.name] = DatamodelInfo(available=hr.healthy)

    return EnvironmentProfile(
        environment_name=environment_name,
        data_sources=data_sources,
        datamodels=datamodels,
        notes=["Auto-generated from live Splunk instance"],
    )


def save_profile(profile: EnvironmentProfile, path: str | Path) -> None:
    """Serialize and save an environment profile to YAML."""
    path = Path(path)
    data = profile.model_dump(mode="json")
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
