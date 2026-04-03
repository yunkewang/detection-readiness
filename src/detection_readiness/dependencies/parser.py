"""Regex-based SPL dependency extractor.

This module is intentionally heuristic, not a full SPL parser.  It uses
carefully chosen regular expressions to extract knowledge-object references
that are reliable enough for practical readiness checks while remaining
transparent about what it can and cannot detect.

Limitations (documented):
- Macro argument values are captured but not recursively expanded here.
- ``lookup`` command aliases (via transforms.conf) cannot be detected from
  SPL text alone.
- ``inputcsv``/``outputcsv`` are not treated as lookup references.
- Subsearches and pipe-chained lookups nested inside eval strings are
  detected on a best-effort basis.
- MLTK fit/apply detection requires that the model name immediately follows
  the command keyword (no intervening options).
- Comments embedded in SPL (``` `` ``` style) may confuse the macro regex if
  the comment itself contains backtick sequences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Macro: `name` or `name(args...)` — backtick-delimited
_RE_MACRO = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]*)(?:\([^`]*\))?`"
)

# eventtype=<name>  or  eventtype = "<name>"
_RE_EVENTTYPE = re.compile(
    r"\beventtype\s*=\s*[\"']?([A-Za-z0-9_\-\.]+)[\"']?"
)

# lookup / inputlookup / outputlookup <table_name> [...]
# Stops at the first whitespace after the table name
_RE_LOOKUP_CMD = re.compile(
    r"\b(?:lookup|inputlookup|outputlookup)\s+([A-Za-z0-9_\-\.]+)"
)

# tstats ... from datamodel=<name> / | datamodel <name>
_RE_DATAMODEL = re.compile(
    r"\bdatamodel\s*=\s*[\"']?([A-Za-z0-9_\-\.]+)[\"']?"
    r"|"
    r"\bdatamodel\s+([A-Za-z0-9_\-\.]+)"
)

# | fit <ModelName> or | apply <ModelName>  (MLTK)
_RE_MLTK = re.compile(
    r"\b(?:fit|apply)\s+([A-Za-z0-9_\-\.]+)"
)

# savedsearch <name>  — direct saved-search invocation
_RE_SAVEDSEARCH = re.compile(
    r"\bsavedsearch\s+([A-Za-z0-9_\-\. ]+?)(?:\s+\w+=|\s*\||\s*$)"
)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


@dataclass
class ExtractedDependencies:
    """All dependency references extracted from a single SPL string."""

    macros: list[str] = field(default_factory=list)
    eventtypes: list[str] = field(default_factory=list)
    lookups: list[str] = field(default_factory=list)
    datamodels: list[str] = field(default_factory=list)
    mltk_models: list[str] = field(default_factory=list)
    saved_searches: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([
            self.macros, self.eventtypes, self.lookups,
            self.datamodels, self.mltk_models, self.saved_searches,
        ])

    def all_names(self) -> list[str]:
        return (
            self.macros
            + self.eventtypes
            + self.lookups
            + self.datamodels
            + self.mltk_models
            + self.saved_searches
        )


def extract_dependencies(spl: str) -> ExtractedDependencies:
    """Extract knowledge-object references from an SPL query string.

    Returns an :class:`ExtractedDependencies` dataclass with de-duplicated,
    sorted lists per dependency type.

    The function is pure (no I/O) and deterministic for a given input string.
    """
    result = ExtractedDependencies()

    result.macros = _unique_sorted(_RE_MACRO.findall(spl))
    result.eventtypes = _unique_sorted(_RE_EVENTTYPE.findall(spl))
    result.lookups = _unique_sorted(_RE_LOOKUP_CMD.findall(spl))

    # Datamodel regex has two capture groups; flatten
    dm_raw = _RE_DATAMODEL.findall(spl)
    result.datamodels = _unique_sorted(
        grp for pair in dm_raw for grp in pair if grp
    )

    result.mltk_models = _unique_sorted(_RE_MLTK.findall(spl))

    ss_raw = _RE_SAVEDSEARCH.findall(spl)
    result.saved_searches = _unique_sorted(s.strip() for s in ss_raw if s.strip())

    return result


def extract_macro_refs_from_definition(definition: str) -> list[str]:
    """Extract macro names referenced inside a macro definition string.

    Useful for building nested macro dependency chains.
    """
    return _unique_sorted(_RE_MACRO.findall(definition))


def _unique_sorted(items) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        s = item.strip()
        if s and s not in seen:
            seen.add(s)
            result.append(s)
    return sorted(result)
