"""Generate starter SPL content from readiness results."""

from __future__ import annotations

from detection_readiness.schemas.result import AssessmentResult


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
    """Generate a starter SPL query and metadata comments from assessment results."""
    source = result.evaluated_data_sources[0] if result.evaluated_data_sources else None
    index = source.indexes[0] if source and source.indexes else "main"
    sourcetype = source.sourcetypes[0] if source and source.sourcetypes else "*"

    template = BASE_TEMPLATES.get(
        result.detection_family_id,
        'search index={index} sourcetype={sourcetype} | head 100',
    )
    query = template.format(index=index, sourcetype=sourcetype)

    lines = [
        f"# Detection family: {result.detection_family_name}",
        f"# Readiness score: {result.readiness_score:.1f}/100 ({result.readiness_status.value})",
        f"# Recommended strategy: {result.recommended_query_strategy or 'unknown'}",
    ]
    if result.blockers:
        lines.append("# NOTE: blockers exist; tune and validate this query before production use.")
    if result.warnings:
        lines.append("# NOTE: warnings were detected during readiness assessment.")

    lines.append(query)
    return "\n".join(lines)
