"""CLI entry point using Typer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from detection_readiness.engine.assessor import assess
from detection_readiness.explain.explainer import (
    generate_detailed_explanation,
    generate_short_explanation,
)
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
