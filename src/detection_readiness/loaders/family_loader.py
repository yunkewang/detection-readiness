"""Load detection family definitions from YAML/JSON files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from detection_readiness.schemas.family import DetectionFamily

_FAMILIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "families"


def _parse_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    elif suffix == ".json":
        return json.loads(text)
    raise ValueError(f"Unsupported file format: {suffix}")


def load_family(family_id: str, families_dir: str | Path | None = None) -> DetectionFamily:
    """Load a single detection family by its id.

    Searches for ``<family_id>.yaml`` or ``<family_id>.json`` in *families_dir*.
    """
    search_dir = Path(families_dir) if families_dir else _FAMILIES_DIR
    for ext in (".yaml", ".yml", ".json"):
        candidate = search_dir / f"{family_id}{ext}"
        if candidate.exists():
            data = _parse_file(candidate)
            return DetectionFamily.model_validate(data)
    raise FileNotFoundError(
        f"Detection family '{family_id}' not found in {search_dir}"
    )


def list_families(families_dir: str | Path | None = None) -> list[DetectionFamily]:
    """Load all detection family definitions from *families_dir*."""
    search_dir = Path(families_dir) if families_dir else _FAMILIES_DIR
    families: list[DetectionFamily] = []
    if not search_dir.is_dir():
        return families
    for path in sorted(search_dir.iterdir()):
        if path.suffix.lower() in (".yaml", ".yml", ".json"):
            data = _parse_file(path)
            families.append(DetectionFamily.model_validate(data))
    return families
