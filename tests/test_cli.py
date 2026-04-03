"""Smoke tests for the CLI."""

from pathlib import Path

from typer.testing import CliRunner

from detection_readiness.cli.main import app

runner = CliRunner()

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
FAMILIES_DIR = Path(__file__).resolve().parent.parent / "families"


def test_assess_text_output():
    result = runner.invoke(
        app,
        [
            "assess-cmd",
            "--profile", str(EXAMPLES_DIR / "azure_profile.yaml"),
            "--family", "password_spray",
            "--families-dir", str(FAMILIES_DIR),
        ],
    )
    assert result.exit_code == 0
    assert "readiness" in result.output.lower() or "Score" in result.output


def test_assess_json_output():
    result = runner.invoke(
        app,
        [
            "assess-cmd",
            "--profile", str(EXAMPLES_DIR / "azure_profile.yaml"),
            "--family", "password_spray",
            "--output", "json",
            "--families-dir", str(FAMILIES_DIR),
        ],
    )
    assert result.exit_code == 0
    assert "readiness_score" in result.output


def test_list_families():
    result = runner.invoke(
        app,
        ["list-families", "--families-dir", str(FAMILIES_DIR)],
    )
    assert result.exit_code == 0
    assert "password_spray" in result.output


def test_validate_profile():
    result = runner.invoke(
        app,
        [
            "validate-profile",
            "--profile", str(EXAMPLES_DIR / "azure_profile.yaml"),
        ],
    )
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_validate_bad_profile(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("hello")
    result = runner.invoke(
        app,
        ["validate-profile", "--profile", str(bad)],
    )
    assert result.exit_code == 1


def test_assess_bad_family():
    result = runner.invoke(
        app,
        [
            "assess-cmd",
            "--profile", str(EXAMPLES_DIR / "azure_profile.yaml"),
            "--family", "nonexistent_family",
            "--families-dir", str(FAMILIES_DIR),
        ],
    )
    assert result.exit_code == 1


def test_generate_profile(tmp_path):
    events = tmp_path / "events.jsonl"
    output = tmp_path / "generated.yaml"
    events.write_text('{"user":"alice","src_ip":"1.1.1.1"}\n{"user":"bob"}\n')

    result = runner.invoke(
        app,
        [
            "generate-profile",
            "--events", str(events),
            "--output", str(output),
            "--environment-name", "autogen",
            "--data-source", "azure_ad_signin",
            "--index", "idx_auth",
            "--sourcetype", "azure:aad:signin",
            "--min-coverage", "0.5",
        ],
    )
    assert result.exit_code == 0
    assert "Generated profile" in result.output
    assert output.exists()
