"""CLI entry point using Typer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from detection_readiness.ai.narrative import NarrativeError, generate_narrative_summary
from detection_readiness.content_factory.spl_generator import generate_spl
from detection_readiness.discovery.field_discovery import discover_fields_from_events
from detection_readiness.engine.assessor import assess
from detection_readiness.explain.explainer import (
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

    console.print(f"[green]Profile '{env.environment_name}' is valid.[/green]")
    console.print(f"  Data sources : {len(env.data_sources)}")
    console.print(f"  Datamodels   : {len(env.datamodels)}")
    console.print(f"  Constraints  : {len(env.constraints)}")
    console.print(f"  Notes        : {len(env.notes)}")


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
) -> None:
    """Generate starter SPL from readiness assessment output."""
    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)
    spl = generate_spl(result)

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

    console.print(f"[dim]{result.short_explanation}[/dim]")
    console.print()
