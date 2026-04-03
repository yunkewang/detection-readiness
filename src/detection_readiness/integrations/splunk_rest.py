"""Splunk REST integration for live environment profiling."""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from detection_readiness.dependencies.parser import extract_macro_refs_from_definition
from detection_readiness.schemas.environment import (
    DataSource,
    DatamodelInfo,
    EnvironmentProfile,
    EventtypeInfo,
    FieldAliasInfo,
    KnowledgeObjects,
    LookupInfo,
    MLTKModelInfo,
    MacroInfo,
    SavedSearchInfo,
    TagInfo,
)


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
    include_knowledge_objects: bool = False,
) -> EnvironmentProfile:
    """Build a coarse environment profile by probing Splunk REST endpoints.

    When *include_knowledge_objects* is ``True``, additional REST calls are
    made to populate the ``knowledge_objects`` section of the profile with
    macros, eventtypes, lookups, saved searches, and MLTK models.

    Any endpoint that cannot be reached is noted in ``knowledge_objects.collection_notes``
    rather than raising, so callers always receive a (possibly partial) profile.
    """
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

    ko = KnowledgeObjects()
    if include_knowledge_objects:
        ko = _collect_knowledge_objects(client)

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
        knowledge_objects=ko,
    )


# ---------------------------------------------------------------------------
# Knowledge object collection
# ---------------------------------------------------------------------------


def _collect_knowledge_objects(client: SplunkRestClient) -> KnowledgeObjects:
    """Collect knowledge objects from Splunk REST and return a KnowledgeObjects instance."""
    ko = KnowledgeObjects()

    ko.macros = _collect_macros(client, ko.collection_notes)
    ko.eventtypes = _collect_eventtypes(client, ko.macros, ko.collection_notes)
    ko.lookups = _collect_lookups(client, ko.collection_notes)
    ko.saved_searches = _collect_saved_searches(client, ko.collection_notes)
    ko.mltk_models = _collect_mltk_models(client, ko.collection_notes)
    ko.tags = _collect_tags(client, ko.collection_notes)
    ko.field_aliases = _collect_field_aliases(client, ko.collection_notes)

    return ko


def _collect_macros(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, MacroInfo]:
    """Collect macro definitions from /servicesNS/-/-/admin/macros."""
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/admin/macros",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="macros",
    )
    macros: dict[str, MacroInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        definition: str | None = content.get("definition")
        # Parse argument names from the macro name (e.g. "my_macro(2)" → ["arg1","arg2"])
        arguments: list[str] = []
        arg_str = content.get("args", "")
        if arg_str:
            arguments = [a.strip() for a in str(arg_str).split(",") if a.strip()]

        depends_on: list[str] = []
        if definition:
            depends_on = extract_macro_refs_from_definition(definition)

        macros[name] = MacroInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            owner=acl.get("owner"),
            sharing=acl.get("sharing"),
            definition=definition,
            arguments=arguments,
            depends_on_macros=depends_on,
        )
    return macros


def _collect_eventtypes(
    client: SplunkRestClient,
    macros: dict[str, MacroInfo],
    notes: list[str],
) -> dict[str, EventtypeInfo]:
    """Collect eventtype definitions from /servicesNS/-/-/saved/eventtypes."""
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/saved/eventtypes",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="eventtypes",
    )
    eventtypes: dict[str, EventtypeInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        search: str | None = content.get("search")

        # Find macros referenced in this eventtype's search
        from detection_readiness.dependencies.parser import _RE_MACRO
        depends_on: list[str] = []
        if search:
            depends_on = sorted(set(_RE_MACRO.findall(search)))

        eventtypes[name] = EventtypeInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            owner=acl.get("owner"),
            sharing=acl.get("sharing"),
            search=search,
            depends_on_macros=depends_on,
        )
    return eventtypes


def _collect_lookups(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, LookupInfo]:
    """Collect lookup definitions and cross-reference with transforms and files."""
    # Lookup definitions live in /admin/transforms-lookup (lookup table transforms)
    transform_entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/data/transforms/lookups",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="lookup transforms",
    )

    # Lookup table files (uploaded CSV lookups)
    file_entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/data/lookup-table-files",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="lookup table files",
    )
    known_files: set[str] = {
        item.get("name", "") for item in file_entries if item.get("name")
    }

    lookups: dict[str, LookupInfo] = {}
    for item in transform_entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}

        filename: str | None = content.get("filename")
        # KV store lookups have a "collection" field instead of "filename"
        collection: str | None = content.get("collection")

        backing_type: str | None = None
        file_available: bool | None = None

        if collection:
            backing_type = "kvstore"
            # KV store availability cannot be confirmed from this endpoint alone
            file_available = None
        elif filename:
            backing_type = "csv"
            file_available = filename in known_files
        else:
            # External lookup (script-based)
            backing_type = "external"

        lookups[name] = LookupInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            owner=acl.get("owner"),
            sharing=acl.get("sharing"),
            backing_type=backing_type,
            filename=filename or collection,
            transform_available=True,
            file_available=file_available,
            notes=(
                [f"KV store collection '{collection}' availability not verified via REST"]
                if collection
                else []
            ),
        )
    return lookups


def _collect_saved_searches(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, SavedSearchInfo]:
    """Collect saved searches from /servicesNS/-/-/saved/searches."""
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/saved/searches",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="saved searches",
    )
    saved: dict[str, SavedSearchInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        cron: str | None = content.get("cron_schedule")
        is_scheduled = bool(content.get("is_scheduled", False))
        saved[name] = SavedSearchInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            owner=acl.get("owner"),
            sharing=acl.get("sharing"),
            search=content.get("search"),
            cron_schedule=cron,
            is_scheduled=is_scheduled,
        )
    return saved


def _collect_mltk_models(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, MLTKModelInfo]:
    """Attempt to collect MLTK model metadata.

    MLTK models do not have a standard REST endpoint in all Splunk versions.
    We try the common app-specific endpoint; on failure we record a note and
    return an empty dict rather than failing the entire profile collection.
    """
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/mltk/models",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="MLTK models",
        missing_ok=True,
    )
    models: dict[str, MLTKModelInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        models[name] = MLTKModelInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            algorithm=content.get("algorithm"),
        )
    return models


def _collect_tags(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, TagInfo]:
    """Collect tag definitions (best-effort, partial collection is normal)."""
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/search/tags",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="tags",
        missing_ok=True,
    )
    tags: dict[str, TagInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        tags[name] = TagInfo(name=name, available=True, app=acl.get("app"))
    return tags


def _collect_field_aliases(
    client: SplunkRestClient, notes: list[str]
) -> dict[str, FieldAliasInfo]:
    """Collect field alias definitions (best-effort)."""
    entries = _safe_entries_with_notes(
        client,
        "/servicesNS/-/-/data/props/fieldaliases",
        params={"count": 0, "output_mode": "json"},
        notes=notes,
        label="field aliases",
        missing_ok=True,
    )
    aliases: dict[str, FieldAliasInfo] = {}
    for item in entries:
        name = item.get("name", "")
        if not name:
            continue
        content = item.get("content", {}) if isinstance(item.get("content"), dict) else {}
        acl = item.get("acl", {}) if isinstance(item.get("acl"), dict) else {}
        # Field alias content uses "alias.<target>" = "<source>" pattern
        src: str | None = None
        tgt: str | None = None
        for k, v in content.items():
            if k.startswith("alias."):
                tgt = k[len("alias."):]
                src = v
                break
        aliases[name] = FieldAliasInfo(
            name=name,
            available=True,
            app=acl.get("app"),
            source_field=src,
            target_field=tgt,
        )
    return aliases


# ---------------------------------------------------------------------------
# Low-level REST helpers
# ---------------------------------------------------------------------------


def _safe_names(client: SplunkRestClient, path: str, params: dict[str, Any]) -> list[str]:
    entries = _safe_entries(client, path, params=params)
    names: list[str] = []
    for item in entries:
        name = item.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return sorted(set(names))


def _safe_entries(
    client: SplunkRestClient, path: str, params: dict[str, Any]
) -> list[dict[str, Any]]:
    try:
        payload = client.get_json(path, params=params)
    except SplunkRestError:
        return []

    raw_entries = payload.get("entry", [])
    if not isinstance(raw_entries, list):
        return []
    return [item for item in raw_entries if isinstance(item, dict)]


def _safe_entries_with_notes(
    client: SplunkRestClient,
    path: str,
    params: dict[str, Any],
    notes: list[str],
    label: str,
    missing_ok: bool = False,
) -> list[dict[str, Any]]:
    """Like _safe_entries but records collection errors in *notes*."""
    try:
        payload = client.get_json(path, params=params)
    except SplunkRestError as exc:
        if not missing_ok:
            notes.append(f"Could not collect {label}: {exc}")
        else:
            notes.append(
                f"{label.title()} endpoint unavailable ({exc}); "
                f"{label} will not appear in this profile."
            )
        return []

    raw_entries = payload.get("entry", [])
    if not isinstance(raw_entries, list):
        notes.append(f"Unexpected response format for {label}; collection skipped.")
        return []
    return [item for item in raw_entries if isinstance(item, dict)]
