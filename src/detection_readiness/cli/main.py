"""CLI entry point using Typer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from detection_readiness.discovery.field_discovery import discover_fields_from_events
from detection_readiness.engine.assessor import assess
from detection_readiness.explain.explainer import (
    generate_detailed_explanation,
    generate_short_explanation,
)
from detection_readiness.generators.profile_generator import (
    generate_profile_from_discovery,
    save_profile,
)
from detection_readiness.generators.spl_generator import generate_spl
from detection_readiness.loaders.family_loader import list_families, load_family
from detection_readiness.loaders.profile_loader import load_profile
from detection_readiness.schemas.result import AssessmentResult

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


@app.command()
def narrate(
    input: Annotated[
        Path, typer.Option("--input", "-i", help="Path to assessment result JSON")
    ],
    provider: Annotated[
        str, typer.Option("--provider", help="AI provider: auto, anthropic, or openai")
    ] = "auto",
) -> None:
    """Generate an AI-powered narrative summary (requires API key)."""
    from detection_readiness.explain.ai_narrator import (
        AINarratorError,
        generate_ai_narrative,
        is_available,
    )

    if not is_available():
        console.print(
            "[yellow]No AI provider configured.[/yellow] "
            "Set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable narration."
        )
        raise typer.Exit(code=1)

    if not input.exists():
        console.print(f"[red]File not found:[/red] {input}")
        raise typer.Exit(code=1)

    data = json.loads(input.read_text(encoding="utf-8"))
    result = AssessmentResult.model_validate(data)

    try:
        narrative = generate_ai_narrative(result, provider=provider)
    except AINarratorError as exc:
        console.print(f"[red]AI narration failed:[/red] {exc}")
        raise typer.Exit(code=1)

    console.print()
    console.print("[bold]AI Narrative Summary[/bold]")
    console.print()
    console.print(narrative)
    console.print()


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


@app.command("generate-spl")
def generate_spl_cmd(
    profile: Annotated[
        Path, typer.Option("--profile", "-p", help="Path to environment profile YAML/JSON")
    ],
    family: Annotated[
        str, typer.Option("--family", "-f", help="Detection family id")
    ],
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output format: text or json")
    ] = "text",
    families_dir: Annotated[
        Optional[Path],
        typer.Option("--families-dir", help="Directory containing family definitions"),
    ] = None,
) -> None:
    """Generate a starter SPL query for a detection family."""
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
    spl = generate_spl(result)

    if output == "json":
        import dataclasses
        console.print_json(json.dumps(dataclasses.asdict(spl), indent=2))
        return

    console.print()
    console.print(f"[bold]Generated SPL — {spl.detection_family}[/bold]")
    console.print(f"  Strategy: {spl.strategy}")
    console.print()
    console.print(spl.query)
    console.print()
    if spl.notes:
        for note in spl.notes:
            console.print(f"  [dim]* {note}[/dim]")
        console.print()


@app.command("generate-profile")
def generate_profile_cmd(
    events: Annotated[
        Path,
        typer.Option("--events", "-e", help="Path to sample events file"),
    ],
    name: Annotated[
        str, typer.Option("--name", "-n", help="Environment name"),
    ],
    source: Annotated[
        str, typer.Option("--source", "-s", help="Data source name"),
    ],
    index: Annotated[
        str, typer.Option("--index", help="Index name"),
    ] = "main",
    sourcetype: Annotated[
        str, typer.Option("--sourcetype", help="Sourcetype"),
    ] = "unknown",
    output_path: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Save profile to this path (YAML)"),
    ] = None,
) -> None:
    """Auto-generate an environment profile from sample events."""
    try:
        discovery = discover_fields_from_events(events)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    profile = generate_profile_from_discovery(
        environment_name=name,
        source_name=source,
        discovery=discovery,
        index=index,
        sourcetype=sourcetype,
    )

    if output_path:
        save_profile(profile, output_path)
        console.print(
            f"[green]Profile saved to {output_path}[/green] "
            f"({len(profile.data_sources[source].fields)} fields)"
        )
    else:
        import yaml
        console.print(yaml.dump(profile.model_dump(mode="json"), default_flow_style=False, sort_keys=False))


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
