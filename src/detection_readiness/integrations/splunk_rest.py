"""Splunk REST integration for live environment profiling."""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from detection_readiness.schemas.environment import DataSource, DatamodelInfo, EnvironmentProfile


class SplunkRestError(RuntimeError):
    """Raised when a Splunk REST call fails."""


@dataclass
class SplunkConnectionSettings:
    """Connection settings for Splunk management API."""

    host: str
    token: str
    port: int = 8089
    scheme: str = "https"
    verify_ssl: bool = True
    timeout_seconds: int = 20


class SplunkRestClient:
    """Minimal Splunk REST client using urllib from the stdlib."""

    def __init__(self, settings: SplunkConnectionSettings) -> None:
        self.settings = settings
        self._ssl_context = None
        if not settings.verify_ssl and settings.scheme == "https":
            self._ssl_context = ssl._create_unverified_context()

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        query = urlencode(params or {})
        suffix = f"?{query}" if query else ""
        url = f"{self.settings.scheme}://{self.settings.host}:{self.settings.port}{path}{suffix}"
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {self.settings.token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urlopen(
                request,
                timeout=self.settings.timeout_seconds,
                context=self._ssl_context,
            ) as response:
                payload = response.read().decode("utf-8")
            return json.loads(payload)
        except HTTPError as exc:
            raise SplunkRestError(f"HTTP {exc.code} calling {path}: {exc.reason}") from exc
        except URLError as exc:
            raise SplunkRestError(f"Connection error calling {path}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise SplunkRestError(f"Invalid JSON response from {path}") from exc



def build_profile_from_splunk(
    settings: SplunkConnectionSettings,
    *,
    environment_name: str,
    data_source_id: str = "splunk_live",
    field_coverage_default: float = 0.95,
) -> EnvironmentProfile:
    """Build a coarse environment profile by probing Splunk REST endpoints."""
    client = SplunkRestClient(settings)

    indexes = _safe_names(
        client,
        "/servicesNS/-/-/data/indexes",
        params={"count": 0, "output_mode": "json"},
    )
    sourcetypes = _safe_names(
        client,
        "/servicesNS/-/-/data/props/sourcetypes",
        params={"count": 0, "output_mode": "json"},
    )
    datamodel_entries = _safe_entries(
        client,
        "/servicesNS/-/-/datamodel/model",
        params={"count": 0, "output_mode": "json"},
    )

    datamodels: dict[str, DatamodelInfo] = {}
    for item in datamodel_entries:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            continue

        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acceleration = (
            content.get("acceleration", {}) if isinstance(content.get("acceleration"), dict) else {}
        )
        enabled = bool(acceleration.get("enabled", False))

        datamodels[name.lower()] = DatamodelInfo(
            available=True,
            acceleration_enabled=enabled,
            acceleration_lag_hours=0.0,
            health_score=1.0 if enabled else 0.8,
        )

    notes = [
        "Profile auto-generated from Splunk REST metadata; field coverage is estimated.",
        "Indexes and sourcetypes were discovered from management endpoints.",
    ]

    data_source = DataSource(
        indexes=indexes,
        sourcetypes=sourcetypes,
        fields={},
        query_modes={"raw": True, "datamodel": bool(datamodels)},
    )

    return EnvironmentProfile(
        environment_name=environment_name,
        data_sources={data_source_id: data_source},
        datamodels=datamodels,
        constraints={},
        notes=notes,
    )


def _safe_names(client: SplunkRestClient, path: str, params: dict[str, Any]) -> list[str]:
    entries = _safe_entries(client, path, params=params)
    names: list[str] = []
    for item in entries:
        name = item.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return sorted(set(names))


def _safe_entries(client: SplunkRestClient, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        payload = client.get_json(path, params=params)
    except SplunkRestError:
        return []

    raw_entries = payload.get("entry", [])
    if not isinstance(raw_entries, list):
        return []
    return [item for item in raw_entries if isinstance(item, dict)]
