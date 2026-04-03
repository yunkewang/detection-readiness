"""Template-based explanation generator for assessment results."""

from __future__ import annotations

from detection_readiness.schemas.result import AssessmentResult, ReadinessStatus


def generate_short_explanation(result: AssessmentResult) -> str:
    """Return a one-paragraph summary of the assessment."""
    status_label = {
        ReadinessStatus.READY: "ready",
        ReadinessStatus.PARTIALLY_READY: "partially ready",
        ReadinessStatus.NOT_READY: "not ready",
    }[result.readiness_status]

    blocker_note = ""
    if result.blockers:
        blocker_note = f" There {'is' if len(result.blockers) == 1 else 'are'} {len(result.blockers)} blocker(s)."

    strategy_note = ""
    if result.recommended_query_strategy:
        strategy_note = (
            f" Recommended query strategy: {result.recommended_query_strategy}."
        )

    return (
        f"Environment '{result.environment_name}' is {status_label} for "
        f"'{result.detection_family_name}' with a readiness score of "
        f"{result.readiness_score:.0f}/100.{blocker_note}{strategy_note}"
    )


def generate_detailed_explanation(result: AssessmentResult) -> str:
    """Return a multi-section detailed explanation."""
    lines: list[str] = []
    lines.append(f"=== Detection Readiness Report ===")
    lines.append(f"Environment : {result.environment_name}")
    lines.append(f"Detection   : {result.detection_family_name}")
    lines.append(f"Score       : {result.readiness_score:.0f}/100")
    lines.append(f"Status      : {result.readiness_status.value}")
    if result.recommended_query_strategy:
        lines.append(f"Strategy    : {result.recommended_query_strategy}")
    lines.append("")

    # Data sources
    lines.append("--- Data Sources ---")
    for ds in result.evaluated_data_sources:
        icon = "+" if ds.present else "-"
        lines.append(f"  [{icon}] {ds.source}")
        for f in ds.fields:
            f_icon = "+" if f.present else "-"
            cov = f" (coverage: {f.coverage:.0%})" if f.coverage is not None else ""
            req = "required" if f.required else "optional"
            lines.append(f"      [{f_icon}] {f.field} [{req}]{cov}")
    lines.append("")

    # Blockers
    if result.blockers:
        lines.append("--- Blockers ---")
        for b in result.blockers:
            lines.append(f"  ! {b}")
        lines.append("")

    # Warnings
    if result.warnings:
        lines.append("--- Warnings ---")
        for w in result.warnings:
            lines.append(f"  ~ {w}")
        lines.append("")

    # Assumptions
    if result.assumptions:
        lines.append("--- Assumptions ---")
        for a in result.assumptions:
            lines.append(f"  * {a}")
        lines.append("")

    # Remediation
    if result.remediation_suggestions:
        lines.append("--- Remediation ---")
        for r in result.remediation_suggestions:
            lines.append(f"  -> {r}")
        lines.append("")

    return "\n".join(lines)
