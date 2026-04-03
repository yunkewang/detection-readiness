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


# ---------------------------------------------------------------------------
# Dependency result models (new in v0.2)
# ---------------------------------------------------------------------------


class DependencyStatus(BaseModel):
    """Resolution status for a single knowledge-object dependency."""

    name: str
    dep_type: str  # macro | eventtype | lookup | mltk_model | saved_search | datamodel_object
    required: bool
    # resolved = exists and appears healthy
    resolved: bool = False
    # healthy = exists but may have issues (empty definition, broken chain, etc.)
    healthy: bool | None = None
    notes: list[str] = Field(default_factory=list)


class DependencySummary(BaseModel):
    """Aggregated dependency resolution output for an assessment."""

    resolved: list[DependencyStatus] = Field(default_factory=list)
    missing: list[DependencyStatus] = Field(default_factory=list)
    unhealthy: list[DependencyStatus] = Field(default_factory=list)
    unknown: list[DependencyStatus] = Field(default_factory=list)
    # Flat chain representation for troubleshooting nested macro chains
    dependency_chain: list[str] = Field(default_factory=list)

    @property
    def all_required_resolved(self) -> bool:
        return not any(d.required for d in self.missing) and not any(
            d.required for d in self.unhealthy
        )

    @property
    def total_checked(self) -> int:
        return (
            len(self.resolved)
            + len(self.missing)
            + len(self.unhealthy)
            + len(self.unknown)
        )


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

    # New in v0.2: dependency resolution summary.
    # None means dependencies were not evaluated (no knowledge objects in profile
    # and no execution_dependencies declared by the family).
    dependency_summary: DependencySummary | None = None
