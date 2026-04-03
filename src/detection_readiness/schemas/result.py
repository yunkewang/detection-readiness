"""Pydantic models for assessment results."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ReadinessStatus(str, Enum):
    READY = "ready"
    PARTIALLY_READY = "partially_ready"
    NOT_READY = "not_ready"


class FieldReadiness(BaseModel):
    """Readiness details for a single field."""

    field: str
    present: bool
    coverage: float | None = None
    candidates: list[str] = Field(default_factory=list)
    required: bool = True


class DataSourceReadiness(BaseModel):
    """Readiness details for a single data source."""

    source: str
    present: bool
    indexes: list[str] = Field(default_factory=list)
    sourcetypes: list[str] = Field(default_factory=list)
    fields: list[FieldReadiness] = Field(default_factory=list)
    query_modes: dict[str, bool] = Field(default_factory=dict)


class AssessmentResult(BaseModel):
    """Full assessment output."""

    # Metadata
    environment_name: str
    detection_family_id: str
    detection_family_name: str

    # Data source evaluation
    evaluated_data_sources: list[DataSourceReadiness] = Field(default_factory=list)

    # Scoring
    readiness_score: float = 0.0
    readiness_status: ReadinessStatus = ReadinessStatus.NOT_READY

    # Findings
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)

    # Recommendations
    recommended_query_strategy: str | None = None
    remediation_suggestions: list[str] = Field(default_factory=list)

    # Explanations
    short_explanation: str = ""
    detailed_explanation: str = ""
