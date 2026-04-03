"""Content factory — generate starter SPL queries from assessment results.

Produces query templates based on the recommended strategy and available
fields. These are starting points, not production-ready detections.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from detection_readiness.schemas.result import AssessmentResult, ReadinessStatus


@dataclass
class SPLOutput:
    """Generated SPL content for a detection."""

    detection_family: str
    strategy: str
    query: str
    description: str
    notes: list[str] = dc_field(default_factory=list)


# ---------------------------------------------------------------------------
# SPL templates keyed by (family_id, strategy)
# ---------------------------------------------------------------------------

_TEMPLATES: dict[tuple[str, str], str] = {
    # Password spray
    ("password_spray", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| stats count as attempt_count dc({user_field}) as unique_users '
        'values({user_field}) as targeted_users by {src_ip_field}\n'
        '| where attempt_count > 10 AND unique_users > 5'
    ),
    ("password_spray", "datamodel"): (
        '| tstats count from datamodel=Authentication '
        'where Authentication.action="failure" '
        'by Authentication.src Authentication.user _time span=5m\n'
        '| stats count dc(Authentication.user) as unique_users by Authentication.src\n'
        '| where count > 10 AND unique_users > 5'
    ),
    # Impossible travel
    ("impossible_travel", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| stats earliest(_time) as first_seen latest(_time) as last_seen '
        'values({location_field}) as locations by {user_field}\n'
        '| where mvcount(locations) > 1'
    ),
    ("impossible_travel", "datamodel"): (
        '| tstats earliest(_time) as first_seen latest(_time) as last_seen '
        'values(Authentication.src) as sources '
        'from datamodel=Authentication by Authentication.user\n'
        '| where mvcount(sources) > 1'
    ),
    # Suspicious process execution
    ("suspicious_process_execution", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| search {process_name_field} IN '
        '("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe")\n'
        '| table _time {dest_field} {user_field} {process_name_field} '
        '{parent_process_name_field} {command_line_field}'
    ),
    ("suspicious_process_execution", "datamodel"): (
        '| tstats count from datamodel=Endpoint.Processes '
        'where Processes.process_name IN '
        '("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe") '
        'by Processes.dest Processes.user Processes.process_name '
        'Processes.parent_process_name _time span=1h'
    ),
    # Email impersonation
    ("email_impersonation", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| eval sender_domain=mvindex(split({sender_field},"@"),1)\n'
        '| search NOT sender_domain IN ("yourdomain.com","trusted-partner.com")\n'
        '| table _time {sender_field} {recipient_field} {subject_field} sender_domain'
    ),
    # Lateral movement
    ("lateral_movement", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| search {dest_port_field} IN ("445","135","3389","5985","5986")\n'
        '| stats count values({dest_ip_field}) as targets by {src_ip_field}\n'
        '| where count > 5 AND mvcount(targets) > 3'
    ),
    ("lateral_movement", "datamodel"): (
        '| tstats count from datamodel=Network_Traffic '
        'where Network_Traffic.dest_port IN ("445","135","3389","5985","5986") '
        'by Network_Traffic.src Network_Traffic.dest _time span=1h\n'
        '| stats count dc(Network_Traffic.dest) as unique_targets '
        'by Network_Traffic.src\n'
        '| where count > 5 AND unique_targets > 3'
    ),
    # Data exfiltration
    ("data_exfiltration", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| stats sum({bytes_out_field}) as total_bytes by {src_ip_field} {dest_ip_field}\n'
        '| where total_bytes > 104857600\n'
        '| sort -total_bytes'
    ),
    ("data_exfiltration", "datamodel"): (
        '| tstats sum(Network_Traffic.bytes_out) as total_bytes '
        'from datamodel=Network_Traffic '
        'by Network_Traffic.src Network_Traffic.dest _time span=1h\n'
        '| where total_bytes > 104857600\n'
        '| sort -total_bytes'
    ),
    # Privilege escalation
    ("privilege_escalation", "raw"): (
        'index={index} sourcetype={sourcetype}\n'
        '| search {process_name_field} IN '
        '("runas.exe","powershell.exe","cmd.exe","psexec.exe","sc.exe")\n'
        '| regex {command_line_field}="(?i)(token|impersonate|privilege|runas|'
        'sc\\s+create|schtasks)"\n'
        '| table _time {dest_field} {user_field} {process_name_field} '
        '{command_line_field}'
    ),
    ("privilege_escalation", "datamodel"): (
        '| tstats count from datamodel=Endpoint.Processes '
        'where Processes.process_name IN '
        '("runas.exe","powershell.exe","cmd.exe","psexec.exe","sc.exe") '
        'by Processes.dest Processes.user Processes.process_name '
        'Processes.process _time span=1h'
    ),
}


def generate_spl(result: AssessmentResult) -> SPLOutput:
    """Generate a starter SPL query from an assessment result.

    Uses the recommended query strategy and available field information to
    produce a parameterized query template.

    Returns an SPLOutput with the query and notes.
    """
    family_id = result.detection_family_id
    strategy = result.recommended_query_strategy or "raw"
    notes: list[str] = []

    if result.readiness_status == ReadinessStatus.NOT_READY:
        notes.append(
            "WARNING: Environment is not ready for this detection. "
            "The generated query is a best-effort template — review blockers first."
        )

    # Find matching template
    template = _TEMPLATES.get((family_id, strategy))
    if not template:
        # Try generic raw fallback
        template = _TEMPLATES.get((family_id, "raw"))
    if not template:
        return SPLOutput(
            detection_family=family_id,
            strategy=strategy,
            query=f"# No SPL template available for {family_id} ({strategy})",
            description=f"No template available for {result.detection_family_name}.",
            notes=["Add a template to spl_generator._TEMPLATES for this family."],
        )

    # Build substitution context from assessed data sources
    context = _build_context(result)
    try:
        query = template.format_map(_SafeDict(context))
    except (KeyError, ValueError):
        query = template  # leave placeholders unresolved
        notes.append("Some template placeholders could not be resolved.")

    if strategy == "datamodel":
        notes.append(
            "This query uses tstats against an accelerated datamodel. "
            "Ensure the datamodel is enabled and populated."
        )

    return SPLOutput(
        detection_family=family_id,
        strategy=strategy,
        query=query,
        description=f"Starter {strategy} query for {result.detection_family_name}.",
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_context(result: AssessmentResult) -> dict[str, str]:
    """Build a template substitution context from the assessment result."""
    ctx: dict[str, str] = {}

    for ds in result.evaluated_data_sources:
        if ds.indexes:
            ctx["index"] = ds.indexes[0]
        if ds.sourcetypes:
            ctx["sourcetype"] = ds.sourcetypes[0]

        for f in ds.fields:
            if f.present and f.candidates:
                # Use the first candidate as the field name
                ctx[f"{f.field}_field"] = f.candidates[0]
            elif f.present:
                ctx[f"{f.field}_field"] = f.field

    return ctx


class _SafeDict(dict):
    """Dict subclass that returns the key as a placeholder on missing lookups."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
