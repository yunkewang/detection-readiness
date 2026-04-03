"""Dependency resolution: match declared/extracted deps against an environment profile.

Given:
- A :class:`~detection_readiness.schemas.family.DetectionFamily` that declares
  execution dependencies (or carries an SPL template to parse them from), and
- An :class:`~detection_readiness.schemas.environment.EnvironmentProfile` whose
  ``knowledge_objects`` section has been populated (e.g. by
  ``generate-live-profile --include-knowledge-objects``),

this module resolves each dependency and returns a
:class:`~detection_readiness.schemas.result.DependencySummary` that can be
directly attached to the :class:`~detection_readiness.schemas.result.AssessmentResult`.

Design principles:
- Deterministic: same inputs → same output, no randomness.
- Conservative: if profile knowledge_objects are empty (profile predates v0.2 or
  was generated without --include-knowledge-objects), all declared deps are
  marked ``unknown`` rather than silently passing.
- Transparent: every DependencyStatus carries human-readable ``notes``.
- Chain-aware: macro→macro chains are walked up to a configurable depth to
  detect broken transitive dependencies.
"""

from __future__ import annotations

from detection_readiness.dependencies.parser import (
    extract_dependencies,
    extract_macro_refs_from_definition,
)
from detection_readiness.schemas.environment import KnowledgeObjects
from detection_readiness.schemas.family import DetectionFamily, ExecutionDependencies
from detection_readiness.schemas.result import DependencySummary, DependencyStatus

# Maximum depth for recursive macro chain resolution
_MACRO_CHAIN_DEPTH = 8


def resolve_dependencies(
    family: DetectionFamily,
    ko: KnowledgeObjects,
) -> DependencySummary:
    """Resolve all execution dependencies for *family* against *ko*.

    If the family's ``execution_dependencies.spl_template`` is set, the
    resolver auto-extracts additional references from that SPL text and
    merges them with any explicitly declared lists (explicit lists take
    precedence for the required/optional classification).

    Returns a fully-populated :class:`~detection_readiness.schemas.result.DependencySummary`.
    """
    deps = family.execution_dependencies
    profile_populated = _ko_has_data(ko)

    # Merge explicit declarations with auto-extracted ones from SPL template
    merged = _merge_deps(deps)

    summary = DependencySummary()

    # --- macros ---
    chain_log: list[str] = []
    _resolve_list(
        merged["required_macros"],
        required=True,
        dep_type="macro",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
        chain_log=chain_log,
    )
    _resolve_list(
        merged["optional_macros"],
        required=False,
        dep_type="macro",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
        chain_log=chain_log,
    )

    # --- eventtypes ---
    _resolve_list(
        merged["required_eventtypes"],
        required=True,
        dep_type="eventtype",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )
    _resolve_list(
        merged["optional_eventtypes"],
        required=False,
        dep_type="eventtype",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )

    # --- lookups ---
    _resolve_list(
        merged["required_lookups"],
        required=True,
        dep_type="lookup",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )
    _resolve_list(
        merged["optional_lookups"],
        required=False,
        dep_type="lookup",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )

    # --- MLTK models ---
    _resolve_list(
        merged["required_mltk_models"],
        required=True,
        dep_type="mltk_model",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )
    _resolve_list(
        merged["optional_mltk_models"],
        required=False,
        dep_type="mltk_model",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )

    # --- saved searches ---
    _resolve_list(
        merged["required_saved_searches"],
        required=True,
        dep_type="saved_search",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )
    _resolve_list(
        merged["optional_saved_searches"],
        required=False,
        dep_type="saved_search",
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )

    # --- datamodel objects ---
    _resolve_datamodel_objects(
        merged["required_datamodel_objects"],
        ko=ko,
        profile_populated=profile_populated,
        summary=summary,
    )

    summary.dependency_chain = chain_log
    return summary


def build_blockers_from_summary(summary: DependencySummary) -> list[str]:
    """Convert a DependencySummary into blocker strings for the scorer."""
    blockers: list[str] = []
    for d in summary.missing:
        if d.required:
            blockers.append(
                f"Required {d.dep_type} '{d.name}' is missing from the environment."
            )
    for d in summary.unhealthy:
        if d.required:
            note_str = "; ".join(d.notes) if d.notes else "see dependency summary"
            blockers.append(
                f"Required {d.dep_type} '{d.name}' exists but is unhealthy: {note_str}"
            )
    return blockers


def build_warnings_from_summary(summary: DependencySummary) -> list[str]:
    """Convert a DependencySummary into warning strings for the scorer."""
    warnings: list[str] = []
    for d in summary.missing:
        if not d.required:
            warnings.append(
                f"Optional {d.dep_type} '{d.name}' is missing from the environment."
            )
    for d in summary.unhealthy:
        if not d.required:
            note_str = "; ".join(d.notes) if d.notes else "see dependency summary"
            warnings.append(
                f"Optional {d.dep_type} '{d.name}' has issues: {note_str}"
            )
    for d in summary.unknown:
        warnings.append(
            f"{d.dep_type.title()} '{d.name}' could not be verified "
            "(knowledge objects not collected in this profile)."
        )
    return warnings


def compute_dependency_completeness(summary: DependencySummary) -> float:
    """Return a 0.0–1.0 completeness score for use in the weighted scorer.

    Required missing/unhealthy deps contribute a larger penalty than optional.
    Unknown deps are conservatively treated as 50 % partial credit.
    """
    if summary.total_checked == 0:
        return 1.0  # no dependencies declared → full credit

    score = 0.0
    total_weight = 0.0

    for d in summary.resolved:
        w = 1.0 if d.required else 0.5
        score += w
        total_weight += w

    for d in summary.unhealthy:
        w = 1.0 if d.required else 0.5
        score += w * 0.3  # partial credit for unhealthy
        total_weight += w

    for d in summary.missing:
        w = 1.0 if d.required else 0.5
        # No credit for missing
        total_weight += w

    for d in summary.unknown:
        w = 1.0 if d.required else 0.5
        score += w * 0.5  # conservative 50 % for unknown
        total_weight += w

    if total_weight == 0:
        return 1.0
    return min(score / total_weight, 1.0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _merge_deps(deps: ExecutionDependencies) -> dict[str, list[str]]:
    """Merge explicit dependency lists with any auto-extracted from spl_template."""
    merged: dict[str, list[str]] = {
        "required_macros": list(deps.required_macros),
        "optional_macros": list(deps.optional_macros),
        "required_eventtypes": list(deps.required_eventtypes),
        "optional_eventtypes": list(deps.optional_eventtypes),
        "required_lookups": list(deps.required_lookups),
        "optional_lookups": list(deps.optional_lookups),
        "required_mltk_models": list(deps.required_mltk_models),
        "optional_mltk_models": list(deps.optional_mltk_models),
        "required_saved_searches": list(deps.required_saved_searches),
        "optional_saved_searches": list(deps.optional_saved_searches),
        "required_datamodel_objects": list(deps.required_datamodel_objects),
    }

    if not deps.spl_template:
        return merged

    extracted = extract_dependencies(deps.spl_template)

    # Auto-extracted items are treated as optional unless they appear in
    # an explicit required list.
    declared_required_macros = set(deps.required_macros)
    for name in extracted.macros:
        if name not in declared_required_macros and name not in merged["optional_macros"]:
            merged["optional_macros"].append(name)

    declared_required_lookups = set(deps.required_lookups)
    for name in extracted.lookups:
        if name not in declared_required_lookups and name not in merged["optional_lookups"]:
            merged["optional_lookups"].append(name)

    declared_required_eventtypes = set(deps.required_eventtypes)
    for name in extracted.eventtypes:
        if name not in declared_required_eventtypes and name not in merged["optional_eventtypes"]:
            merged["optional_eventtypes"].append(name)

    declared_required_mltk = set(deps.required_mltk_models)
    for name in extracted.mltk_models:
        if name not in declared_required_mltk and name not in merged["optional_mltk_models"]:
            merged["optional_mltk_models"].append(name)

    declared_required_ss = set(deps.required_saved_searches)
    for name in extracted.saved_searches:
        if name not in declared_required_ss and name not in merged["optional_saved_searches"]:
            merged["optional_saved_searches"].append(name)

    return merged


def _ko_has_data(ko: KnowledgeObjects) -> bool:
    """Return True if the KnowledgeObjects section appears to have been populated."""
    return bool(
        ko.macros or ko.eventtypes or ko.lookups
        or ko.mltk_models or ko.saved_searches
    )


def _resolve_list(
    names: list[str],
    *,
    required: bool,
    dep_type: str,
    ko: KnowledgeObjects,
    profile_populated: bool,
    summary: DependencySummary,
    chain_log: list[str] | None = None,
) -> None:
    for name in names:
        status = _resolve_single(
            name,
            required=required,
            dep_type=dep_type,
            ko=ko,
            profile_populated=profile_populated,
            chain_log=chain_log,
        )
        _bucket(status, summary)


def _resolve_single(
    name: str,
    *,
    required: bool,
    dep_type: str,
    ko: KnowledgeObjects,
    profile_populated: bool,
    chain_log: list[str] | None = None,
    _depth: int = 0,
) -> DependencyStatus:
    """Resolve one named dependency and return its DependencyStatus."""
    if not profile_populated:
        return DependencyStatus(
            name=name,
            dep_type=dep_type,
            required=required,
            resolved=False,
            healthy=None,
            notes=[
                "Knowledge objects were not collected in this profile. "
                "Re-run with --include-knowledge-objects to check this dependency."
            ],
        )

    if dep_type == "macro":
        return _resolve_macro(name, required=required, ko=ko, chain_log=chain_log, _depth=_depth)
    if dep_type == "eventtype":
        return _resolve_eventtype(name, required=required, ko=ko)
    if dep_type == "lookup":
        return _resolve_lookup(name, required=required, ko=ko)
    if dep_type == "mltk_model":
        return _resolve_mltk(name, required=required, ko=ko)
    if dep_type == "saved_search":
        return _resolve_saved_search(name, required=required, ko=ko)
    # Unknown type — mark as unknown
    return DependencyStatus(
        name=name, dep_type=dep_type, required=required, resolved=False,
        notes=[f"Dependency type '{dep_type}' is not supported by the resolver."],
    )


def _resolve_macro(
    name: str,
    *,
    required: bool,
    ko: KnowledgeObjects,
    chain_log: list[str] | None,
    _depth: int = 0,
) -> DependencyStatus:
    info = ko.macros.get(name)
    if info is None or not info.available:
        # healthy=False (not None) so _bucket places it in missing, not unknown
        return DependencyStatus(
            name=name, dep_type="macro", required=required, resolved=False, healthy=False,
        )

    notes: list[str] = list(info.notes)

    # Empty definition is suspicious
    if info.definition is not None and not info.definition.strip():
        notes.append("Macro definition is empty.")
        return DependencyStatus(
            name=name, dep_type="macro", required=required,
            resolved=True, healthy=False, notes=notes,
        )

    # Walk transitive macro dependencies
    transitive_missing: list[str] = []
    if info.definition and _depth < _MACRO_CHAIN_DEPTH:
        child_macros = info.depends_on_macros or extract_macro_refs_from_definition(info.definition)
        for child in child_macros:
            if chain_log is not None:
                chain_log.append(f"{name} -> {child}")
            child_status = _resolve_macro(
                child, required=required, ko=ko, chain_log=chain_log, _depth=_depth + 1
            )
            if not child_status.resolved:
                transitive_missing.append(child)
    elif _depth >= _MACRO_CHAIN_DEPTH:
        notes.append(f"Macro chain depth limit ({_MACRO_CHAIN_DEPTH}) reached; deeper deps not checked.")

    if transitive_missing:
        notes.append(
            f"Macro chain broken: missing transitive macro(s): {', '.join(transitive_missing)}"
        )
        return DependencyStatus(
            name=name, dep_type="macro", required=required,
            resolved=True, healthy=False, notes=notes,
        )

    return DependencyStatus(
        name=name, dep_type="macro", required=required,
        resolved=True, healthy=True, notes=notes,
    )


def _resolve_eventtype(
    name: str, *, required: bool, ko: KnowledgeObjects
) -> DependencyStatus:
    info = ko.eventtypes.get(name)
    if info is None or not info.available:
        return DependencyStatus(name=name, dep_type="eventtype", required=required, resolved=False, healthy=False)

    notes: list[str] = list(info.notes)

    if info.search is not None and not info.search.strip():
        notes.append("Eventtype search string is empty.")
        return DependencyStatus(
            name=name, dep_type="eventtype", required=required,
            resolved=True, healthy=False, notes=notes,
        )

    # Check if eventtype's search references missing macros
    if info.depends_on_macros:
        missing_macros = [m for m in info.depends_on_macros if m not in ko.macros or not ko.macros[m].available]
        if missing_macros:
            notes.append(
                f"Eventtype search references missing macro(s): {', '.join(missing_macros)}"
            )
            return DependencyStatus(
                name=name, dep_type="eventtype", required=required,
                resolved=True, healthy=False, notes=notes,
            )

    return DependencyStatus(
        name=name, dep_type="eventtype", required=required,
        resolved=True, healthy=True, notes=notes,
    )


def _resolve_lookup(
    name: str, *, required: bool, ko: KnowledgeObjects
) -> DependencyStatus:
    info = ko.lookups.get(name)
    if info is None or not info.available:
        return DependencyStatus(name=name, dep_type="lookup", required=required, resolved=False, healthy=False)

    notes: list[str] = list(info.notes)
    healthy = True

    if info.transform_available is False:
        notes.append("Lookup transform definition is missing.")
        healthy = False

    if info.file_available is False:
        notes.append(
            f"Lookup backing {'file' if info.backing_type != 'kvstore' else 'KV store collection'} "
            "is missing or inaccessible."
        )
        healthy = False

    return DependencyStatus(
        name=name, dep_type="lookup", required=required,
        resolved=True, healthy=healthy, notes=notes,
    )


def _resolve_mltk(
    name: str, *, required: bool, ko: KnowledgeObjects
) -> DependencyStatus:
    info = ko.mltk_models.get(name)
    if info is None or not info.available:
        return DependencyStatus(name=name, dep_type="mltk_model", required=required, resolved=False, healthy=False)
    return DependencyStatus(
        name=name, dep_type="mltk_model", required=required,
        resolved=True, healthy=True, notes=list(info.notes),
    )


def _resolve_saved_search(
    name: str, *, required: bool, ko: KnowledgeObjects
) -> DependencyStatus:
    info = ko.saved_searches.get(name)
    if info is None or not info.available:
        return DependencyStatus(
            name=name, dep_type="saved_search", required=required, resolved=False, healthy=False
        )
    return DependencyStatus(
        name=name, dep_type="saved_search", required=required,
        resolved=True, healthy=True, notes=list(info.notes),
    )


def _resolve_datamodel_objects(
    object_paths: list[str],
    *,
    ko: KnowledgeObjects,
    profile_populated: bool,
    summary: DependencySummary,
) -> None:
    """Resolve datamodel object paths like 'Authentication.action'."""
    # KnowledgeObjects doesn't carry per-object datamodel detail directly;
    # that lives in EnvironmentProfile.datamodels[].available_objects.
    # We record these as unknown if we cannot verify, rather than silently passing.
    for path in object_paths:
        if not profile_populated:
            status = DependencyStatus(
                name=path, dep_type="datamodel_object", required=True,
                resolved=False,
                notes=[
                    "Datamodel object verification requires an enriched profile. "
                    "Re-run with --include-knowledge-objects."
                ],
            )
        else:
            # Best-effort: mark as unknown since object-level detail is in
            # EnvironmentProfile.datamodels, not ko.
            status = DependencyStatus(
                name=path, dep_type="datamodel_object", required=True,
                resolved=False, healthy=None,
                notes=[
                    "Datamodel object availability is checked via the datamodels section "
                    "of the environment profile, not the knowledge_objects section."
                ],
            )
        _bucket(status, summary)


def _bucket(status: DependencyStatus, summary: DependencySummary) -> None:
    """Route a DependencyStatus into the right summary bucket."""
    if status.healthy is None and not status.resolved:
        summary.unknown.append(status)
    elif not status.resolved:
        summary.missing.append(status)
    elif status.healthy is False:
        summary.unhealthy.append(status)
    else:
        summary.resolved.append(status)
