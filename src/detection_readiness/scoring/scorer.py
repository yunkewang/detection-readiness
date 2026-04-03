"""Deterministic scoring engine for detection readiness assessments."""

from __future__ import annotations

from dataclasses import dataclass, field

from detection_readiness.schemas.environment import EnvironmentProfile
from detection_readiness.schemas.family import DetectionFamily
from detection_readiness.schemas.result import (
    DataSourceReadiness,
    FieldReadiness,
    ReadinessStatus,
)

# Coverage threshold below which a required field is considered a blocker
COVERAGE_THRESHOLD = 0.70

# Default readiness status thresholds
READY_THRESHOLD = 80.0
PARTIAL_THRESHOLD = 50.0


@dataclass
class ScoreBreakdown:
    """Intermediate scoring state accumulated during evaluation."""

    earned: float = 0.0
    possible: float = 0.0
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    data_source_results: list[DataSourceReadiness] = field(default_factory=list)
    recommended_query_strategy: str | None = None


def classify_status(
    score: float,
    *,
    ready_threshold: float = READY_THRESHOLD,
    partial_threshold: float = PARTIAL_THRESHOLD,
) -> ReadinessStatus:
    """Return the readiness status for a given score."""
    if score >= ready_threshold:
        return ReadinessStatus.READY
    if score >= partial_threshold:
        return ReadinessStatus.PARTIALLY_READY
    return ReadinessStatus.NOT_READY


def evaluate(
    profile: EnvironmentProfile,
    family: DetectionFamily,
    *,
    ready_threshold: float = READY_THRESHOLD,
    partial_threshold: float = PARTIAL_THRESHOLD,
    coverage_threshold: float = COVERAGE_THRESHOLD,
) -> ScoreBreakdown:
    """Run the deterministic scoring engine.

    Returns a ``ScoreBreakdown`` with earned/possible points, blockers,
    warnings, assumptions, and per-source readiness details.
    """
    weights = family.scoring_weights
    breakdown = ScoreBreakdown()

    # --- 1. Required data source presence ---
    breakdown.possible += weights.required_data_source
    sources_present = 0
    for src_name in family.required_data_sources:
        if src_name in profile.data_sources:
            sources_present += 1
        else:
            breakdown.blockers.append(
                f"Required data source '{src_name}' is not present in the environment."
            )
    if family.required_data_sources:
        ratio = sources_present / len(family.required_data_sources)
        breakdown.earned += weights.required_data_source * ratio

    # --- 2. Per-source field evaluation ---
    breakdown.possible += weights.required_fields
    breakdown.possible += weights.optional_fields
    total_req_fields = 0
    covered_req_fields = 0.0
    total_opt_fields = 0
    covered_opt_fields = 0.0

    for src_name in family.required_data_sources:
        env_source = profile.data_sources.get(src_name)
        ds_result = DataSourceReadiness(
            source=src_name,
            present=env_source is not None,
            indexes=env_source.indexes if env_source else [],
            sourcetypes=env_source.sourcetypes if env_source else [],
            query_modes=dict(env_source.query_modes) if env_source else {},
        )

        # Required fields
        req_fields = family.required_fields_by_source.get(src_name, [])
        for fname in req_fields:
            total_req_fields += 1
            finfo = env_source.fields.get(fname) if env_source else None
            if finfo is None:
                ds_result.fields.append(
                    FieldReadiness(field=fname, present=False, required=True)
                )
                breakdown.blockers.append(
                    f"Required field '{fname}' is missing from data source '{src_name}'."
                )
            else:
                ds_result.fields.append(
                    FieldReadiness(
                        field=fname,
                        present=True,
                        coverage=finfo.coverage,
                        candidates=finfo.candidates,
                        required=True,
                    )
                )
                if finfo.coverage < coverage_threshold:
                    breakdown.warnings.append(
                        f"Field '{fname}' in '{src_name}' has low coverage "
                        f"({finfo.coverage:.0%} < {coverage_threshold:.0%})."
                    )
                    covered_req_fields += finfo.coverage
                else:
                    covered_req_fields += 1.0

        # Optional fields
        opt_fields = family.optional_fields_by_source.get(src_name, [])
        for fname in opt_fields:
            total_opt_fields += 1
            finfo = env_source.fields.get(fname) if env_source else None
            if finfo is None:
                ds_result.fields.append(
                    FieldReadiness(field=fname, present=False, required=False)
                )
                breakdown.warnings.append(
                    f"Optional field '{fname}' is missing from data source '{src_name}'."
                )
            else:
                ds_result.fields.append(
                    FieldReadiness(
                        field=fname,
                        present=True,
                        coverage=finfo.coverage,
                        candidates=finfo.candidates,
                        required=False,
                    )
                )
                covered_opt_fields += min(finfo.coverage / coverage_threshold, 1.0)

        breakdown.data_source_results.append(ds_result)

    if total_req_fields:
        breakdown.earned += weights.required_fields * (
            covered_req_fields / total_req_fields
        )
    else:
        breakdown.earned += weights.required_fields  # no fields required → full credit

    if total_opt_fields:
        breakdown.earned += weights.optional_fields * (
            covered_opt_fields / total_opt_fields
        )
    else:
        breakdown.earned += weights.optional_fields

    # --- 3. Query mode evaluation ---
    breakdown.possible += weights.preferred_query_mode
    breakdown.possible += weights.fallback_query_mode

    preferred_available = _check_query_mode(profile, family, family.preferred_query_mode)
    fallback_available = _check_query_mode(profile, family, family.fallback_query_mode)

    if preferred_available:
        breakdown.earned += weights.preferred_query_mode
        breakdown.earned += weights.fallback_query_mode
        breakdown.recommended_query_strategy = family.preferred_query_mode
    elif fallback_available:
        breakdown.earned += weights.fallback_query_mode
        breakdown.warnings.append(
            f"Preferred query mode '{family.preferred_query_mode}' is unavailable; "
            f"falling back to '{family.fallback_query_mode}'."
        )
        breakdown.recommended_query_strategy = family.fallback_query_mode
    else:
        breakdown.blockers.append(
            f"Neither preferred ('{family.preferred_query_mode}') nor fallback "
            f"('{family.fallback_query_mode}') query mode is available."
        )

    # --- 4. Constraints-based assumptions ---
    if profile.constraints.get("preserve_original_field_names"):
        breakdown.assumptions.append(
            "Field names will not be normalized; detections must use original field names."
        )
    if profile.constraints.get("avoid_datamodel"):
        breakdown.assumptions.append(
            "Datamodel-based searches are to be avoided per environment constraints."
        )
        if breakdown.recommended_query_strategy == "datamodel":
            breakdown.recommended_query_strategy = family.fallback_query_mode
            breakdown.warnings.append(
                "Recommended strategy changed from 'datamodel' to "
                f"'{family.fallback_query_mode}' due to 'avoid_datamodel' constraint."
            )

    # --- 5. Remediation ---
    # Remediation suggestions are attached by the engine layer based on blockers.

    return breakdown


def _check_query_mode(
    profile: EnvironmentProfile,
    family: DetectionFamily,
    mode: str,
) -> bool:
    """Return True if *mode* is available across all required data sources."""
    if mode == "datamodel":
        # Check datamodel availability for related datamodels
        for dm in profile.datamodels.values():
            if dm.available:
                return True
        return False

    # For raw / hybrid, check that at least one required source supports it.
    for src_name in family.required_data_sources:
        src = profile.data_sources.get(src_name)
        if src and src.query_modes.get(mode, False):
            return True
    return False
