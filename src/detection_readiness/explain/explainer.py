"""Template-based explanation generator for assessment results."""

from __future__ import annotations

from detection_readiness.schemas.result import AssessmentResult, DependencySummary, ReadinessStatus


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

    dep_note = ""
    if result.dependency_summary is not None:
        ds = result.dependency_summary
        missing_req = sum(1 for d in ds.missing if d.required)
        unhealthy_req = sum(1 for d in ds.unhealthy if d.required)
        if missing_req or unhealthy_req:
            dep_note = (
                f" Detection execution is blocked by {missing_req + unhealthy_req} "
                f"unresolved knowledge object dependency(ies)."
            )
        elif ds.unknown:
            dep_note = (
                f" {len(ds.unknown)} dependency(ies) could not be verified "
                "(knowledge objects not collected)."
            )

    return (
        f"Environment '{result.environment_name}' is {status_label} for "
        f"'{result.detection_family_name}' with a readiness score of "
        f"{result.readiness_score:.0f}/100.{blocker_note}{strategy_note}{dep_note}"
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

    # Dependency summary (v0.2)
    if result.dependency_summary is not None:
        lines.extend(_format_dependency_section(result.dependency_summary))

    return "\n".join(lines)


def generate_dependency_explanation(summary: DependencySummary) -> str:
    """Return a focused explanation of dependency resolution results only."""
    lines = _format_dependency_section(summary)
    return "\n".join(lines)


def _format_dependency_section(summary: DependencySummary) -> list[str]:
    """Format the dependency summary as a list of explanation lines."""
    lines: list[str] = []
    lines.append("--- Knowledge Object Dependencies ---")

    total = summary.total_checked
    if total == 0:
        lines.append("  No execution dependencies declared for this detection family.")
        lines.append("")
        return lines

    resolved_count = len(summary.resolved)
    missing_req = [d for d in summary.missing if d.required]
    missing_opt = [d for d in summary.missing if not d.required]
    unhealthy_req = [d for d in summary.unhealthy if d.required]
    unhealthy_opt = [d for d in summary.unhealthy if not d.required]

    lines.append(
        f"  Checked: {total} | Resolved: {resolved_count} | "
        f"Missing: {len(summary.missing)} | "
        f"Unhealthy: {len(summary.unhealthy)} | "
        f"Unknown: {len(summary.unknown)}"
    )
    lines.append("")

    if summary.resolved:
        lines.append("  Resolved dependencies:")
        for d in summary.resolved:
            req_label = "required" if d.required else "optional"
            lines.append(f"    [+] {d.dep_type}: {d.name} [{req_label}]")
    lines.append("")

    if missing_req:
        lines.append("  Missing REQUIRED dependencies (blockers):")
        for d in missing_req:
            lines.append(f"    [!] {d.dep_type}: {d.name}")
            for note in d.notes:
                lines.append(f"        {note}")

    if unhealthy_req:
        lines.append("  Unhealthy REQUIRED dependencies (blockers):")
        for d in unhealthy_req:
            lines.append(f"    [!] {d.dep_type}: {d.name} (exists but unhealthy)")
            for note in d.notes:
                lines.append(f"        {note}")

    if missing_req or unhealthy_req:
        lines.append("")

    if missing_opt:
        lines.append("  Missing optional dependencies (warnings):")
        for d in missing_opt:
            lines.append(f"    [~] {d.dep_type}: {d.name}")

    if unhealthy_opt:
        lines.append("  Unhealthy optional dependencies (warnings):")
        for d in unhealthy_opt:
            lines.append(f"    [~] {d.dep_type}: {d.name}")
            for note in d.notes:
                lines.append(f"        {note}")

    if missing_opt or unhealthy_opt:
        lines.append("")

    if summary.unknown:
        lines.append("  Dependencies with unknown status (knowledge objects not collected):")
        for d in summary.unknown:
            req_label = "required" if d.required else "optional"
            lines.append(f"    [?] {d.dep_type}: {d.name} [{req_label}]")
        lines.append("")

    if summary.dependency_chain:
        lines.append("  Macro dependency chain:")
        for link in summary.dependency_chain:
            lines.append(f"    {link}")
        lines.append("")

    return lines
