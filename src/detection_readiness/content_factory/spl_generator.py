"""Generate starter SPL content from readiness results."""

from __future__ import annotations

from detection_readiness.schemas.result import AssessmentResult, DependencySummary


BASE_TEMPLATES: dict[str, str] = {
    "password_spray": (
        'search index={index} sourcetype={sourcetype} '
        '| stats count as attempts dc(src_ip) as src_ip_count by user '
        '| where attempts >= 10 AND src_ip_count >= 3'
    ),
    "impossible_travel": (
        'search index={index} sourcetype={sourcetype} '
        '| sort 0 user _time '
        '| streamstats current=f last(lat) as prev_lat last(lon) as prev_lon last(_time) as prev_time by user '
        '| eval impossible=if(isnull(prev_time),0,1) '
        '| where impossible=1'
    ),
    "email_impersonation": (
        'search index={index} sourcetype={sourcetype} '
        '| eval suspicious=if(match(sender_domain, "(?i)microsof[t]+|goog1e|okta-security"),1,0) '
        '| where suspicious=1'
    ),
}


def generate_spl(result: AssessmentResult) -> str:
    """Generate a starter SPL query and metadata comments from assessment results.

    When dependency information is available the generated SPL includes:
    - Inline comments listing required dependencies
    - Warnings for unresolved / unhealthy dependencies
    - A fallback annotation if missing dependencies prevent normal execution
    """
    source = result.evaluated_data_sources[0] if result.evaluated_data_sources else None
    index = source.indexes[0] if source and source.indexes else "main"
    sourcetype = source.sourcetypes[0] if source and source.sourcetypes else "*"

    template = BASE_TEMPLATES.get(
        result.detection_family_id,
        'search index={index} sourcetype={sourcetype} | head 100',
    )
    query = template.format(index=index, sourcetype=sourcetype)

    lines: list[str] = []

    # --- Header block ---
    lines.append(f"# Detection family: {result.detection_family_name}")
    lines.append(f"# Readiness score: {result.readiness_score:.1f}/100 ({result.readiness_status.value})")
    lines.append(f"# Recommended strategy: {result.recommended_query_strategy or 'unknown'}")

    if result.blockers:
        lines.append("# NOTE: blockers exist; tune and validate this query before production use.")
    if result.warnings:
        lines.append("# NOTE: warnings were detected during readiness assessment.")

    # --- Dependency annotations (v0.2) ---
    dep_lines = _build_dependency_annotations(result.dependency_summary)
    lines.extend(dep_lines)

    # --- SPL ---
    lines.append("")
    lines.append(query)

    return "\n".join(lines)


def generate_dependency_safe_spl(result: AssessmentResult) -> str:
    """Generate a dependency-safe variant that avoids macros when possible.

    When the assessment reveals missing macros, this variant substitutes
    inline raw-field searches for any macro-based lookups, annotating each
    substitution with a comment so the operator knows what was skipped.

    This is always a raw-mode query; it never uses tstats/datamodel.
    """
    source = result.evaluated_data_sources[0] if result.evaluated_data_sources else None
    index = source.indexes[0] if source and source.indexes else "main"
    sourcetype = source.sourcetypes[0] if source and source.sourcetypes else "*"

    lines: list[str] = [
        f"# Detection family: {result.detection_family_name} [DEPENDENCY-SAFE VARIANT]",
        f"# This variant avoids macros, lookups, and datamodel references.",
        f"# It is suitable for initial triage but may miss enrichment.",
        "",
    ]

    dep_sum = result.dependency_summary
    if dep_sum:
        missing_macros = [d.name for d in dep_sum.missing if d.dep_type == "macro" and d.required]
        missing_lookups = [d.name for d in dep_sum.missing if d.dep_type == "lookup" and d.required]
        if missing_macros:
            lines.append(f"# SKIPPED macros (missing): {', '.join(missing_macros)}")
        if missing_lookups:
            lines.append(f"# SKIPPED lookups (missing): {', '.join(missing_lookups)}")
        if missing_macros or missing_lookups:
            lines.append("")

    # Emit a raw search without any macro/lookup references
    query = f"search index={index} sourcetype={sourcetype}"

    # Add basic field filters for known required fields
    req_fields: list[str] = []
    for ds in result.evaluated_data_sources:
        for f in ds.fields:
            if f.required and f.present:
                req_fields.append(f.field)
    if req_fields:
        field_comment = ", ".join(req_fields[:8])
        lines.append(f"# Using raw fields: {field_comment}")
        query += f"\n| fields _time {' '.join(req_fields[:8])}"
        query += "\n| head 1000"

    lines.append(query)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_dependency_annotations(dep_sum: DependencySummary | None) -> list[str]:
    """Build SPL comment lines annotating dependency status."""
    if dep_sum is None:
        return []

    lines: list[str] = []
    total = dep_sum.total_checked
    if total == 0:
        return []

    lines.append(
        f"# Dependencies: {len(dep_sum.resolved)} resolved, "
        f"{len(dep_sum.missing)} missing, "
        f"{len(dep_sum.unhealthy)} unhealthy, "
        f"{len(dep_sum.unknown)} unknown"
    )

    required_missing = [d for d in dep_sum.missing if d.required]
    required_unhealthy = [d for d in dep_sum.unhealthy if d.required]
    optional_missing = [d for d in dep_sum.missing if not d.required]

    if required_missing:
        names = ", ".join(f"`{d.name}`" if d.dep_type == "macro" else d.name
                         for d in required_missing)
        lines.append(f"# REQUIRED MISSING ({len(required_missing)}): {names}")
        lines.append("# WARNING: This query may fail at runtime due to missing dependencies.")

    if required_unhealthy:
        names = ", ".join(d.name for d in required_unhealthy)
        lines.append(f"# UNHEALTHY REQUIRED ({len(required_unhealthy)}): {names}")

    if optional_missing:
        names = ", ".join(d.name for d in optional_missing[:5])
        suffix = f" (+{len(optional_missing) - 5} more)" if len(optional_missing) > 5 else ""
        lines.append(f"# Optional missing: {names}{suffix}")

    if dep_sum.unknown:
        lines.append(
            f"# UNVERIFIED: {len(dep_sum.unknown)} dep(s) could not be checked "
            "(run with --include-knowledge-objects to verify)"
        )

    return lines
