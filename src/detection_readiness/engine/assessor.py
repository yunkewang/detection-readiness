"""Core assessment engine that ties together loading, scoring, and explanation."""

from __future__ import annotations

from detection_readiness.explain.explainer import (
    generate_detailed_explanation,
    generate_short_explanation,
)
from detection_readiness.schemas.environment import EnvironmentProfile
from detection_readiness.schemas.family import DetectionFamily
from detection_readiness.schemas.result import AssessmentResult
from detection_readiness.scoring.scorer import (
    COVERAGE_THRESHOLD,
    PARTIAL_THRESHOLD,
    READY_THRESHOLD,
    classify_status,
    evaluate,
)


def assess(
    profile: EnvironmentProfile,
    family: DetectionFamily,
    *,
    ready_threshold: float = READY_THRESHOLD,
    partial_threshold: float = PARTIAL_THRESHOLD,
    coverage_threshold: float = COVERAGE_THRESHOLD,
) -> AssessmentResult:
    """Run a full readiness assessment and return a structured result."""
    breakdown = evaluate(
        profile,
        family,
        ready_threshold=ready_threshold,
        partial_threshold=partial_threshold,
        coverage_threshold=coverage_threshold,
    )

    score = 0.0
    if breakdown.possible > 0:
        score = round((breakdown.earned / breakdown.possible) * 100, 1)

    status = classify_status(
        score,
        ready_threshold=ready_threshold,
        partial_threshold=partial_threshold,
    )

    # Build remediation suggestions from family guidance keyed on blocker keywords
    remediation: list[str] = []
    for blocker in breakdown.blockers:
        for key, suggestion in family.remediation_guidance.items():
            if key.lower() in blocker.lower():
                remediation.append(suggestion)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_remediation: list[str] = []
    for r in remediation:
        if r not in seen:
            seen.add(r)
            unique_remediation.append(r)

    result = AssessmentResult(
        environment_name=profile.environment_name,
        detection_family_id=family.id,
        detection_family_name=family.display_name,
        evaluated_data_sources=breakdown.data_source_results,
        readiness_score=score,
        readiness_status=status,
        blockers=breakdown.blockers,
        warnings=breakdown.warnings,
        assumptions=breakdown.assumptions,
        recommended_query_strategy=breakdown.recommended_query_strategy,
        remediation_suggestions=unique_remediation,
        dependency_summary=breakdown.dependency_summary,
    )

    result.short_explanation = generate_short_explanation(result)
    result.detailed_explanation = generate_detailed_explanation(result)

    return result
