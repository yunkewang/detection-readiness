"""Pydantic models for environment profiles."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FieldInfo(BaseModel):
    """Describes a single field within a data source."""

    candidates: list[str] = Field(
        description="Candidate field names in the raw data"
    )
    coverage: float = Field(
        ge=0.0, le=1.0, description="Estimated coverage ratio (0.0–1.0)"
    )


class DataSource(BaseModel):
    """Describes a data source available in the environment."""

    indexes: list[str] = Field(default_factory=list)
    sourcetypes: list[str] = Field(default_factory=list)
    fields: dict[str, FieldInfo] = Field(default_factory=dict)
    query_modes: dict[str, bool] = Field(
        default_factory=lambda: {"raw": True, "datamodel": False}
    )


class DatamodelInfo(BaseModel):
    """Describes the availability of a CIM datamodel."""

    available: bool = False
    acceleration_enabled: bool = False
    acceleration_lag_hours: float = Field(
        default=0.0,
        ge=0.0,
        description="Estimated lag in hours for acceleration summaries.",
    )
    health_score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Datamodel health score where 1.0 is fully healthy.",
    )
    # Optional CIM detail: which dataset objects are confirmed present
    available_objects: list[str] = Field(
        default_factory=list,
        description="Confirmed available dataset/object names within this datamodel.",
    )


# ---------------------------------------------------------------------------
# Knowledge object schemas (new in v0.2)
# ---------------------------------------------------------------------------


class MacroInfo(BaseModel):
    """Metadata about a Splunk macro."""

    name: str
    available: bool = False
    app: str | None = None
    owner: str | None = None
    sharing: str | None = None
    definition: str | None = None
    arguments: list[str] = Field(default_factory=list)
    # Macros this macro's definition itself references (parsed, best-effort)
    depends_on_macros: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EventtypeInfo(BaseModel):
    """Metadata about a Splunk eventtype."""

    name: str
    available: bool = False
    app: str | None = None
    owner: str | None = None
    sharing: str | None = None
    search: str | None = None
    # Macros referenced inside the eventtype search
    depends_on_macros: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class LookupInfo(BaseModel):
    """Metadata about a Splunk lookup / lookup definition."""

    name: str
    available: bool = False
    app: str | None = None
    owner: str | None = None
    sharing: str | None = None
    # "csv", "kvstore", "external", or None if unknown
    backing_type: str | None = None
    filename: str | None = None
    # True if the backing transform entry exists; None = not checked
    transform_available: bool | None = None
    # True if the backing file / KV store collection is confirmed present
    file_available: bool | None = None
    notes: list[str] = Field(default_factory=list)


class MLTKModelInfo(BaseModel):
    """Metadata about an MLTK saved model."""

    name: str
    available: bool = False
    app: str | None = None
    algorithm: str | None = None
    created_at: str | None = None
    notes: list[str] = Field(default_factory=list)


class SavedSearchInfo(BaseModel):
    """Metadata about a Splunk saved search."""

    name: str
    available: bool = False
    app: str | None = None
    owner: str | None = None
    sharing: str | None = None
    search: str | None = None
    cron_schedule: str | None = None
    is_scheduled: bool = False
    notes: list[str] = Field(default_factory=list)


class TagInfo(BaseModel):
    """Metadata about a Splunk tag."""

    name: str
    available: bool = False
    app: str | None = None
    notes: list[str] = Field(default_factory=list)


class FieldAliasInfo(BaseModel):
    """Metadata about a Splunk field alias."""

    name: str
    available: bool = False
    app: str | None = None
    source_field: str | None = None
    target_field: str | None = None
    notes: list[str] = Field(default_factory=list)


class KnowledgeObjects(BaseModel):
    """Container for all Splunk knowledge object metadata in an environment profile.

    All fields default to empty so existing profiles remain valid.
    The ``collection_notes`` list records any partial-collection warnings or
    errors captured during live profiling.
    """

    macros: dict[str, MacroInfo] = Field(default_factory=dict)
    eventtypes: dict[str, EventtypeInfo] = Field(default_factory=dict)
    lookups: dict[str, LookupInfo] = Field(default_factory=dict)
    mltk_models: dict[str, MLTKModelInfo] = Field(default_factory=dict)
    saved_searches: dict[str, SavedSearchInfo] = Field(default_factory=dict)
    tags: dict[str, TagInfo] = Field(default_factory=dict)
    field_aliases: dict[str, FieldAliasInfo] = Field(default_factory=dict)
    collection_notes: list[str] = Field(default_factory=list)


class EnvironmentProfile(BaseModel):
    """Top-level environment profile schema."""

    environment_name: str
    data_sources: dict[str, DataSource] = Field(default_factory=dict)
    datamodels: dict[str, DatamodelInfo] = Field(default_factory=dict)
    constraints: dict[str, bool] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    # New in v0.2: optional knowledge object inventory.
    # Defaults to empty KnowledgeObjects so existing profiles load unchanged.
    knowledge_objects: KnowledgeObjects = Field(default_factory=KnowledgeObjects)
