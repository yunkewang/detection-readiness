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
