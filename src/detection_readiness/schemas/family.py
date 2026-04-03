"""Pydantic models for detection family definitions."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScoringWeights(BaseModel):
    """Weights used by the scoring engine for a detection family."""

    required_data_source: float = Field(default=30.0)
    required_fields: float = Field(default=35.0)
    optional_fields: float = Field(default=10.0)
    preferred_query_mode: float = Field(default=15.0)
    fallback_query_mode: float = Field(default=10.0)
    # New in v0.2: weight for knowledge-object dependency completeness.
    # Defaults to 0.0 so existing families score identically to v0.1.
    # Set to a positive value (e.g. 20.0) in families that declare dependencies.
    dependency_completeness: float = Field(default=0.0)


class ExecutionDependencies(BaseModel):
    """Declares the Splunk knowledge objects a detection requires to execute.

    All fields are optional lists so families can declare only what applies.
    When ``spl_template`` is populated, the engine can also auto-extract
    dependencies from the SPL text instead of requiring explicit lists.
    """

    required_macros: list[str] = Field(default_factory=list)
    optional_macros: list[str] = Field(default_factory=list)
    required_eventtypes: list[str] = Field(default_factory=list)
    optional_eventtypes: list[str] = Field(default_factory=list)
    required_lookups: list[str] = Field(default_factory=list)
    optional_lookups: list[str] = Field(default_factory=list)
    required_mltk_models: list[str] = Field(default_factory=list)
    optional_mltk_models: list[str] = Field(default_factory=list)
    required_saved_searches: list[str] = Field(default_factory=list)
    optional_saved_searches: list[str] = Field(default_factory=list)
    # CIM datamodel object paths required beyond top-level datamodel availability,
    # e.g. "Authentication.action" or "Endpoint.Processes"
    required_datamodel_objects: list[str] = Field(default_factory=list)
    # If set, the engine will auto-extract deps from this SPL template in
    # addition to (or instead of) explicit lists above.
    spl_template: str | None = Field(default=None)


class DetectionFamily(BaseModel):
    """Schema for a detection family definition."""

    id: str
    display_name: str
    description: str
    required_data_sources: list[str]
    required_fields_by_source: dict[str, list[str]]
    optional_fields_by_source: dict[str, list[str]] = Field(default_factory=dict)
    preferred_query_mode: str = "datamodel"
    fallback_query_mode: str = "raw"
    scoring_weights: ScoringWeights = Field(default_factory=ScoringWeights)
    remediation_guidance: dict[str, str] = Field(default_factory=dict)
    # New in v0.2: optional execution dependency declarations
    execution_dependencies: ExecutionDependencies = Field(
        default_factory=ExecutionDependencies
    )
