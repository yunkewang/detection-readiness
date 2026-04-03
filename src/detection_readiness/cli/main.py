"""CLI entry point using Typer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from detection_readiness.ai.narrative import NarrativeError, generate_narrative_summary
from detection_readiness.content_factory.spl_generator import (
    generate_dependency_safe_spl,
    generate_spl,
)
from detection_readiness.dependencies.parser import extract_dependencies
from detection_readiness.dependencies.resolver import resolve_dependencies
from detection_readiness.discovery.field_discovery import discover_fields_from_events
from detection_readiness.engine.assessor import assess
from detection_readiness.explain.explainer import (
    generate_dependency_explanation,
    generate_detailed_explanation,
    generate_short_explanation,
)
from detection_readiness.integrations.splunk_rest import (
    SplunkConnectionSettings,
    SplunkRestError,
    build_profile_from_splunk,
)
from detection_readiness.loaders.event_profile_generator import (
    build_profile,
    load_events,
    write_profile,
)
from detection_readiness.loaders.family_loader import list_families, load_family
from detection_readiness.loaders.profile_loader import load_profile
from detection_readiness.schemas.result import AssessmentResult
from detection_readiness.scoring.datamodel_health import evaluate_datamodel_health

app = typer.Typer(
    name="detection-readiness",
    help="Assess Splunk environment readiness for detection use cases.",
    add_completion=False,
)
console = Console()


@app.command()
def assess_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
    family: Annotated[
        str, typer.Option("--family", "-f", help="Detection family id to assess")
    ],
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
    families_dir: Annotated[
        Optional[Path],
        typer.Option("--families-dir", help="Directory containing family definitions"),
    ] = None,
) -> None:
    """Assess environment readiness for a detection family."""
    try:
        env = load_profile(profile)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading profile:[/red] {exc}")
        raise typer.Exit(code=1)

    try:
        fam = load_family(family, families_dir=families_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error loading family:[/red] {exc}")
        raise typer.Exit(code=1)

    result = assess(env, fam)

    if output == "json":
        console.print_json(result.model_dump_json(indent=2))
    else:
        _print_result(result)

@app.command("generate-profile")
def generate_profile_cmd(
    events: Annotated[
        Path,
        typer.Option(
            "--events", "-e", help="Path to sample events (JSONL, JSON array, or CSV)"
        ),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination profile (.yaml/.yml/.json)"),
    ],
    environment_name: Annotated[
        str,
        typer.Option("--environment-name", help="Environment name for generated profile"),
    ] = "auto_generated",
    data_source: Annotated[
        str, typer.Option("--data-source", help="Data source id to create")
    ] = "sample_source",
    index: Annotated[
        str, typer.Option("--index", help="Primary index for sample events")
    ] = "main",
    sourcetype: Annotated[
        str, typer.Option("--sourcetype", help="Primary sourcetype for sample events")
    ] = "unknown",
    min_coverage: Annotated[
        float,
        typer.Option(
            "--min-coverage",
            min=0.0,
            max=1.0,
            help="Only include fields with at least this coverage",
        ),
    ] = 0.5,
) -> None:
    """Generate an environment profile from sample events."""
    try:
        sample_events = load_events(events)
        profile = build_profile(
            environment_name=environment_name,
            data_source_id=data_source,
            index=index,
            sourcetype=sourcetype,
            events=sample_events,
            min_coverage=min_coverage,
        )
        write_profile(profile, output)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Profile generation failed:[/red] {exc}")
        raise typer.Exit(code=1)

    inferred_fields = len(profile.data_sources[data_source].fields)
    console.print(f"[green]Generated profile:[/green] {output}")
    console.print(f"  Environment : {profile.environment_name}")
    console.print(f"  Data source : {data_source}")
    console.print(f"  Sample events: {len(sample_events)}")
    console.print(f"  Fields kept : {inferred_fields} (min coverage: {min_coverage:.2f})")


@app.command("list-families")
def list_families_cmd(
    families_dir: Annotated[
        Optional[Path],
        typer.Option("--families-dir", help="Directory containing family definitions"),
    ] = None,
) -> None:
    """List all available detection families."""
    families = list_families(families_dir)
    if not families:
        console.print("[yellow]No detection families found.[/yellow]")
        raise typer.Exit()

    table = Table(title="Detection Families")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Description")
    for fam in families:
        table.add_row(fam.id, fam.display_name, fam.description)
    console.print(table)


@app.command("validate-profile")
def validate_profile_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
) -> None:
    """Validate an environment profile."""
    try:
        env = load_profile(profile)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Validation failed:[/red] {exc}")
        raise typer.Exit(code=1)

    ko = env.knowledge_objects
    console.print(f"[green]Profile '{env.environment_name}' is valid.[/green]")
    console.print(f"  Data sources : {len(env.data_sources)}")
    console.print(f"  Datamodels   : {len(env.datamodels)}")
    console.print(f"  Constraints  : {len(env.constraints)}")
    console.print(f"  Notes        : {len(env.notes)}")
    console.print(f"  Macros       : {len(ko.macros)}")
    console.print(f"  Eventtypes   : {len(ko.eventtypes)}")
    console.print(f"  Lookups      : {len(ko.lookups)}")
    console.print(f"  MLTK models  : {len(ko.mltk_models)}")
    console.print(f"  Saved searches: {len(ko.saved_searches)}")


@app.command("check-datamodels")
def check_datamodels_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
) -> None:
    """Run datamodel health checks and print findings."""
    try:
        env = load_profile(profile)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Datamodel health check failed:[/red] {exc}")
        raise typer.Exit(code=1)

    warnings, blockers = evaluate_datamodel_health(env)
    console.print("[bold]Datamodel Health Check[/bold]")
    console.print(f"  Environment : {env.environment_name}")
    console.print(f"  Datamodels  : {len(env.datamodels)}")
    console.print()

    if blockers:
        console.print("[red bold]Blockers:[/red bold]")
        for blocker in blockers:
            console.print(f"  ! {blocker}")
        console.print()

    if warnings:
        console.print("[yellow bold]Warnings:[/yellow bold]")
        for warning in warnings:
            console.print(f"  ~ {warning}")
        console.print()

    if not blockers and not warnings:
        console.print("[green]All datamodels look healthy.[/green]")

@app.command()
def explain(
    input: Annotated[
        Path, typer.Option("--input", "-i", help="Path to assessment result JSON")
    ],
) -> None:
    """Generate a human-readable explanation from a JSON assessment result."""
    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)

    # Regenerate explanations
    result.short_explanation = generate_short_explanation(result)
    result.detailed_explanation = generate_detailed_explanation(result)

    console.print()
    console.print(result.detailed_explanation)


@app.command("generate-spl")
def generate_spl_cmd(
    input: Annotated[
        Path, typer.Option("--input", "-i", help="Path to assessment result JSON")
    ],
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Optional output .spl file")
    ] = None,
    safe: Annotated[
        bool,
        typer.Option(
            "--safe/--no-safe",
            help="Generate dependency-safe variant that avoids macros/lookups",
        ),
    ] = False,
) -> None:
    """Generate starter SPL from readiness assessment output."""
    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)
    spl = generate_dependency_safe_spl(result) if safe else generate_spl(result)

    if output:
        output.write_text(spl + "\n", encoding="utf-8")
        console.print(f"[green]Generated SPL:[/green] {output}")
    else:
        console.print(spl)


@app.command("summarize")
def summarize_cmd(
    input: Annotated[
        Path, typer.Option("--input", "-i", help="Path to assessment result JSON")
    ],
    provider: Annotated[
        str, typer.Option("--provider", help="Narrative provider (openai|deterministic)")
    ] = "openai",
    model: Annotated[
        str, typer.Option("--model", help="Model name when provider=openai")
    ] = "gpt-4.1-mini",
) -> None:
    """Generate an optional narrative summary from an assessment result."""
    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)
    actual_provider = "deterministic" if provider == "deterministic" else "openai"

    try:
        summary = generate_narrative_summary(
            result,
            provider=actual_provider,
            model=model,
        )
    except NarrativeError as exc:
        console.print(f"[red]Summary generation failed:[/red] {exc}")
        raise typer.Exit(code=1)

    console.print(summary)


@app.command("generate-live-profile")
def generate_live_profile_cmd(
    host: Annotated[str, typer.Option("--host", help="Splunk management host, e.g. splunk.local")],
    token: Annotated[str, typer.Option("--token", help="Splunk bearer token")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination profile (.yaml/.yml/.json)"),
    ],
    environment_name: Annotated[
        str, typer.Option("--environment-name", help="Environment name in generated profile")
    ] = "splunk_live",
    data_source: Annotated[
        str, typer.Option("--data-source", help="Data source id to create")
    ] = "splunk_live",
    port: Annotated[int, typer.Option("--port", help="Splunk management port")] = 8089,
    scheme: Annotated[str, typer.Option("--scheme", help="http or https")] = "https",
    verify_ssl: Annotated[
        bool, typer.Option("--verify-ssl/--no-verify-ssl", help="Enable TLS certificate validation")
    ] = True,
    include_knowledge_objects: Annotated[
        bool,
        typer.Option(
            "--include-knowledge-objects/--no-knowledge-objects",
            help="Collect macros, eventtypes, lookups, saved searches, and MLTK models",
        ),
    ] = False,
) -> None:
    """Generate an environment profile by querying Splunk REST endpoints."""
    settings = SplunkConnectionSettings(
        host=host,
        token=token,
        port=port,
        scheme=scheme,
        verify_ssl=verify_ssl,
    )
    try:
        profile = build_profile_from_splunk(
            settings,
            environment_name=environment_name,
            data_source_id=data_source,
            include_knowledge_objects=include_knowledge_objects,
        )
        write_profile(profile, output)
    except SplunkRestError as exc:
        console.print(f"[red]Live profile generation failed:[/red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]Generated live profile:[/green] {output}")
    console.print(f"  Environment : {profile.environment_name}")
    console.print(f"  Data source : {data_source}")
    discovered = profile.data_sources[data_source]
    console.print(f"  Indexes     : {len(discovered.indexes)}")
    console.print(f"  Sourcetypes : {len(discovered.sourcetypes)}")
    console.print(f"  Datamodels  : {len(profile.datamodels)}")
    if include_knowledge_objects:
        ko = profile.knowledge_objects
        console.print(f"  Macros      : {len(ko.macros)}")
        console.print(f"  Eventtypes  : {len(ko.eventtypes)}")
        console.print(f"  Lookups     : {len(ko.lookups)}")
        console.print(f"  Saved searches: {len(ko.saved_searches)}")
        console.print(f"  MLTK models : {len(ko.mltk_models)}")
        if ko.collection_notes:
            console.print("[yellow]Collection notes:[/yellow]")
            for note in ko.collection_notes:
                console.print(f"  ~ {note}")


@app.command("discover-fields")
def discover_fields_cmd(
    events: Annotated[
        Path,
        typer.Option("--events", "-e", help="Path to sample events file (JSON, JSONL, CSV)"),
    ],
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
    min_coverage: Annotated[
        float,
        typer.Option("--min-coverage", help="Only show fields with coverage >= this value"),
    ] = 0.0,
) -> None:
    """Discover fields and coverage from sample events."""
    try:
        result = discover_fields_from_events(events)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    if output == "json":
        console.print_json(result.model_dump_json(indent=2))
        return

    console.print()
    console.print(f"[bold]Field Discovery Report[/bold]")
    console.print(f"  Source : {result.source_file}")
    console.print(f"  Events : {result.total_events}")
    console.print()

    table = Table(title="Discovered Fields")
    table.add_column("Field", style="cyan")
    table.add_column("Coverage", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Samples")
    for f in result.fields:
        if f.coverage < min_coverage:
            continue
        cov_color = "green" if f.coverage >= 0.9 else "yellow" if f.coverage >= 0.7 else "red"
        table.add_row(
            f.name,
            f"[{cov_color}]{f.coverage:.0%}[/{cov_color}]",
            str(f.occurrence_count),
            ", ".join(f.sample_values[:3]) + ("..." if len(f.sample_values) > 3 else ""),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# New v0.2 commands
# ---------------------------------------------------------------------------


@app.command("check-dependencies")
def check_dependencies_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
    family: Annotated[
        str, typer.Option("--family", "-f", help="Detection family id to check")
    ],
    families_dir: Annotated[
        Optional[Path],
        typer.Option("--families-dir", help="Directory containing family definitions"),
    ] = None,
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
) -> None:
    """Check knowledge object dependencies for a detection family against an environment profile.

    Reports which macros, eventtypes, lookups, MLTK models, and saved searches
    are resolved, missing, unhealthy, or unknown.
    """
    try:
        env = load_profile(profile)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading profile:[/red] {exc}")
        raise typer.Exit(code=1)

    try:
        fam = load_family(family, families_dir=families_dir)
    except FileNotFoundError as exc:
        console.print(f"[red]Error loading family:[/red] {exc}")
        raise typer.Exit(code=1)

    summary = resolve_dependencies(fam, env.knowledge_objects)

    if output == "json":
        console.print_json(summary.model_dump_json(indent=2))
        return

    console.print()
    console.print("[bold]Dependency Check[/bold]")
    console.print(f"  Environment : {env.environment_name}")
    console.print(f"  Family      : {fam.display_name}")
    console.print(
        f"  Total deps  : {summary.total_checked} "
        f"(resolved: {len(summary.resolved)}, missing: {len(summary.missing)}, "
        f"unhealthy: {len(summary.unhealthy)}, unknown: {len(summary.unknown)})"
    )
    console.print()

    if summary.resolved:
        console.print("[green bold]Resolved:[/green bold]")
        for d in summary.resolved:
            req = "required" if d.required else "optional"
            console.print(f"  [+] {d.dep_type}: {d.name} [{req}]")
        console.print()

    if summary.missing:
        console.print("[red bold]Missing:[/red bold]")
        for d in summary.missing:
            req = "REQUIRED" if d.required else "optional"
            console.print(f"  [!] {d.dep_type}: {d.name} [{req}]")
            for note in d.notes:
                console.print(f"      {note}")
        console.print()

    if summary.unhealthy:
        console.print("[yellow bold]Unhealthy:[/yellow bold]")
        for d in summary.unhealthy:
            req = "REQUIRED" if d.required else "optional"
            console.print(f"  [~] {d.dep_type}: {d.name} [{req}]")
            for note in d.notes:
                console.print(f"      {note}")
        console.print()

    if summary.unknown:
        console.print("[blue bold]Unknown (not collected):[/blue bold]")
        for d in summary.unknown:
            req = "required" if d.required else "optional"
            console.print(f"  [?] {d.dep_type}: {d.name} [{req}]")
        console.print()

    if summary.dependency_chain:
        console.print("[dim]Macro dependency chain:[/dim]")
        for link in summary.dependency_chain:
            console.print(f"  [dim]{link}[/dim]")
        console.print()

    if summary.all_required_resolved:
        console.print("[green]All required dependencies are resolved.[/green]")
    else:
        console.print("[red]One or more required dependencies are missing or unhealthy.[/red]")


@app.command("list-knowledge-objects")
def list_knowledge_objects_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
    kind: Annotated[
        str,
        typer.Option(
            "--kind",
            "-k",
            help="Kind to list: all, macros, eventtypes, lookups, mltk_models, saved_searches, tags, field_aliases",
        ),
    ] = "all",
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
) -> None:
    """List knowledge objects collected in an environment profile."""
    try:
        env = load_profile(profile)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading profile:[/red] {exc}")
        raise typer.Exit(code=1)

    ko = env.knowledge_objects

    if output == "json":
        if kind == "all":
            console.print_json(ko.model_dump_json(indent=2))
        else:
            section = getattr(ko, kind, None)
            if section is None:
                console.print(f"[red]Unknown kind '{kind}'. Use: all, macros, eventtypes, lookups, mltk_models, saved_searches, tags, field_aliases[/red]")
                raise typer.Exit(code=1)
            import json as _json
            console.print_json(_json.dumps({k: v.model_dump() for k, v in section.items()}, indent=2))
        return

    console.print()
    console.print(f"[bold]Knowledge Objects — {env.environment_name}[/bold]")
    console.print()

    sections = {
        "macros": ko.macros,
        "eventtypes": ko.eventtypes,
        "lookups": ko.lookups,
        "mltk_models": ko.mltk_models,
        "saved_searches": ko.saved_searches,
        "tags": ko.tags,
        "field_aliases": ko.field_aliases,
    }

    for section_name, items in sections.items():
        if kind not in ("all", section_name):
            continue
        if not items:
            if kind == section_name:
                console.print(f"[yellow]No {section_name} found in this profile.[/yellow]")
            continue
        table = Table(title=section_name.replace("_", " ").title())
        table.add_column("Name", style="cyan")
        table.add_column("App")
        table.add_column("Status")
        table.add_column("Notes")
        for name, obj in sorted(items.items()):
            status = "[green]OK[/green]" if obj.available else "[red]unavailable[/red]"
            note_str = "; ".join(obj.notes[:2]) if obj.notes else ""
            app = getattr(obj, "app", None) or ""
            table.add_row(name, app, status, note_str)
        console.print(table)

    if ko.collection_notes:
        console.print()
        console.print("[yellow bold]Collection notes:[/yellow bold]")
        for note in ko.collection_notes:
            console.print(f"  ~ {note}")


@app.command("analyze-spl")
def analyze_spl_cmd(
    spl_file: Annotated[
        Optional[Path],
        typer.Option("--spl-file", "-f", help="Path to .spl file to analyze"),
    ] = None,
    spl_text: Annotated[
        Optional[str],
        typer.Option("--spl", "-s", help="SPL string to analyze (use quotes)"),
    ] = None,
    profile: Annotated[
        Optional[Path],
        typer.Option("--profile", "-p", help="Optional profile to cross-reference against"),
    ] = None,
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
) -> None:
    """Extract and optionally verify knowledge object dependencies from an SPL query.

    Parses the SPL for macros, eventtypes, lookups, MLTK models, and saved
    search references.  If a profile with knowledge_objects is supplied, each
    reference is checked against the collected inventory.
    """
    if not spl_file and not spl_text:
        console.print("[red]Provide --spl-file or --spl.[/red]")
        raise typer.Exit(code=1)

    if spl_file:
        if not spl_file.exists():
            console.print(f"[red]File not found:[/red] {spl_file}")
            raise typer.Exit(code=1)
        spl = spl_file.read_text(encoding="utf-8")
    else:
        spl = spl_text or ""

    extracted = extract_dependencies(spl)

    if output == "json":
        import dataclasses
        import json as _json
        result_dict = dataclasses.asdict(extracted)
        # Cross-reference if profile provided
        if profile:
            try:
                env = load_profile(profile)
            except (FileNotFoundError, ValueError) as exc:
                console.print(f"[red]Error loading profile:[/red] {exc}")
                raise typer.Exit(code=1)
            result_dict["profile_cross_reference"] = _cross_reference_extracted(extracted, env)
        console.print_json(_json.dumps(result_dict, indent=2))
        return

    console.print()
    console.print("[bold]SPL Dependency Analysis[/bold]")
    if spl_file:
        console.print(f"  Source: {spl_file}")
    console.print()

    _print_extracted_deps(extracted)

    if profile:
        try:
            env = load_profile(profile)
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]Error loading profile:[/red] {exc}")
            raise typer.Exit(code=1)
        cross = _cross_reference_extracted(extracted, env)
        console.print()
        console.print(f"[bold]Cross-reference against '{env.environment_name}'[/bold]")
        for dep_type, items in cross.items():
            for item in items:
                status = "[green]+[/green]" if item["found"] else "[red]![/red]"
                console.print(f"  {status} {dep_type}: {item['name']}")


@app.command("explain-dependencies")
def explain_dependencies_cmd(
    input: Annotated[
        Path, typer.Option("--input", "-i", help="Path to assessment result JSON")
    ],
) -> None:
    """Show a focused dependency explanation from a saved assessment result."""
    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)

    if result.dependency_summary is None:
        console.print(
            "[yellow]No dependency summary in this result. "
            "Re-run assess with a family that declares execution_dependencies.[/yellow]"
        )
        raise typer.Exit()

    console.print()
    console.print(generate_dependency_explanation(result.dependency_summary))


# ---------------------------------------------------------------------------
# Shared printing helpers
# ---------------------------------------------------------------------------


def _print_result(result: AssessmentResult) -> None:
    """Pretty-print an assessment result to the terminal."""
    status_color = {
        "ready": "green",
        "partially_ready": "yellow",
        "not_ready": "red",
    }.get(result.readiness_status.value, "white")

    console.print()
    console.print(f"[bold]Detection Readiness Assessment[/bold]")
    console.print(f"  Environment : {result.environment_name}")
    console.print(f"  Detection   : {result.detection_family_name}")
    console.print(
        f"  Score       : [{status_color}]{result.readiness_score:.0f}/100[/{status_color}]"
    )
    console.print(
        f"  Status      : [{status_color}]{result.readiness_status.value}[/{status_color}]"
    )
    if result.recommended_query_strategy:
        console.print(f"  Strategy    : {result.recommended_query_strategy}")
    console.print()

    if result.blockers:
        console.print("[red bold]Blockers:[/red bold]")
        for b in result.blockers:
            console.print(f"  ! {b}")
        console.print()

    if result.warnings:
        console.print("[yellow bold]Warnings:[/yellow bold]")
        for w in result.warnings:
            console.print(f"  ~ {w}")
        console.print()

    if result.assumptions:
        console.print("[blue bold]Assumptions:[/blue bold]")
        for a in result.assumptions:
            console.print(f"  * {a}")
        console.print()

    if result.remediation_suggestions:
        console.print("[magenta bold]Remediation:[/magenta bold]")
        for r in result.remediation_suggestions:
            console.print(f"  -> {r}")
        console.print()

    # Dependency summary (v0.2)
    if result.dependency_summary is not None:
        ds = result.dependency_summary
        if ds.total_checked > 0:
            console.print("[bold]Dependencies:[/bold]")
            console.print(
                f"  resolved: {len(ds.resolved)}  missing: {len(ds.missing)}  "
                f"unhealthy: {len(ds.unhealthy)}  unknown: {len(ds.unknown)}"
            )
            req_missing = [d for d in ds.missing if d.required]
            if req_missing:
                console.print("[red]  Required missing:[/red]")
                for d in req_missing:
                    console.print(f"    ! {d.dep_type}: {d.name}")
            console.print()

    console.print(f"[dim]{result.short_explanation}[/dim]")
    console.print()


def _print_extracted_deps(extracted) -> None:  # type: ignore[no-untyped-def]
    """Print extracted dependency info as a text table."""
    categories = [
        ("Macros", extracted.macros),
        ("Eventtypes", extracted.eventtypes),
        ("Lookups", extracted.lookups),
        ("Datamodels", extracted.datamodels),
        ("MLTK Models", extracted.mltk_models),
        ("Saved Searches", extracted.saved_searches),
    ]
    any_found = False
    for cat, items in categories:
        if items:
            any_found = True
            console.print(f"[cyan]{cat}:[/cyan] {', '.join(items)}")
    if not any_found:
        console.print("[dim]No dependency references detected in this SPL.[/dim]")


def _cross_reference_extracted(extracted, env) -> dict:  # type: ignore[no-untyped-def]
    """Cross-reference extracted deps against environment knowledge objects."""
    ko = env.knowledge_objects
    result: dict = {
        "macros": [],
        "eventtypes": [],
        "lookups": [],
        "mltk_models": [],
        "saved_searches": [],
    }
    for name in extracted.macros:
        result["macros"].append({"name": name, "found": name in ko.macros})
    for name in extracted.eventtypes:
        result["eventtypes"].append({"name": name, "found": name in ko.eventtypes})
    for name in extracted.lookups:
        result["lookups"].append({"name": name, "found": name in ko.lookups})
    for name in extracted.mltk_models:
        result["mltk_models"].append({"name": name, "found": name in ko.mltk_models})
    for name in extracted.saved_searches:
        result["saved_searches"].append({"name": name, "found": name in ko.saved_searches})
    return result
