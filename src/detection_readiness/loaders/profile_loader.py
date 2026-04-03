"""Load and validate environment profiles from YAML or JSON files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from detection_readiness.schemas.environment import EnvironmentProfile


def load_profile(path: str | Path) -> EnvironmentProfile:
    """Load an environment profile from a YAML or JSON file.

    Args:
        path: Path to the profile file.

    Returns:
        Validated EnvironmentProfile instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is unsupported or content is invalid.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Profile not found: {path}")

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"Unsupported file format: {suffix}")

    if not isinstance(data, dict):
        raise ValueError("Profile must be a YAML/JSON mapping")

    return EnvironmentProfile.model_validate(data)
