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


class EnvironmentProfile(BaseModel):
    """Top-level environment profile schema."""

    environment_name: str
    data_sources: dict[str, DataSource] = Field(default_factory=dict)
    datamodels: dict[str, DatamodelInfo] = Field(default_factory=dict)
    constraints: dict[str, bool] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
