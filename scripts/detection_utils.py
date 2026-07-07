#!/usr/bin/env python3
"""
Splunk security_content detection helpers.

Provides discovery and parsing of detection YAML files (from
https://github.com/splunk/security_content) and, crucially, a function that
rewrites a detection's SPL so that the ``host`` field is retained as an output
field.

Why rewrite the search? Every attack data event is uploaded with its own unique
UUID as the Splunk ``host``. If a detection outputs ``host`` we learn exactly
which uploaded events triggered it, which is what lets us export only the data
that produced detection results (``index=test host IN (uuid1, uuid2, ...)``).

The rewrite is heuristic but covers the common security_content patterns:
  * ``stats`` / ``tstats`` / ``eventstats`` / ``streamstats`` / ``sistats``:
    ``host`` is appended to the ``by`` clause (or ``by host`` is added when the
    aggregation has none), so the aggregation is grouped per host and emits it.
  * ``table`` / ``fields``: ``host`` is appended to the field list so it is not
    projected away.
Raw (non-aggregating) searches already carry ``host`` through to the output.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

STATS_COMMANDS = ("tstats", "sistats", "stats", "eventstats", "streamstats")
PROJECT_COMMANDS = ("table", "fields")


def find_detection_files(path: str) -> List[Path]:
    """Return detection YAML files for a single file or a folder (recursive)."""
    p = Path(path)
    if p.is_file():
        return [p] if p.suffix.lower() in (".yml", ".yaml") else []
    if not p.is_dir():
        return []
    files: List[Path] = []
    for pattern in ("**/*.yml", "**/*.yaml"):
        files.extend(p.glob(pattern))
    files = [f for f in files if not f.name.startswith("ssa___")]
    return sorted(set(files))


def parse_detection_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Parse a detection YAML file into a dict, or None if it is not a detection."""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (yaml.YAMLError, OSError):
        return None

    if not isinstance(data, dict):
        return None
    search = data.get("search")
    name = data.get("name")
    if not search or not name:
        return None

    return {
        "file": str(file_path),
        "name": name,
        "id": data.get("id", ""),
        "type": data.get("type", ""),
        "status": data.get("status", ""),
        "search": search,
    }


def split_pipeline(search: str) -> List[str]:
    """Split an SPL string on top-level pipes.

    Pipes inside single/double quotes or inside (), [], {} are ignored so we do
    not break subsearches, eval expressions, or quoted strings.
    """
    stages: List[str] = []
    current: List[str] = []
    depth = 0
    quote: Optional[str] = None

    for char in search:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
            continue
        if char == "|" and depth == 0:
            stages.append("".join(current))
            current = []
            continue
        current.append(char)

    stages.append("".join(current))
    return stages


def _has_host_token(text: str) -> bool:
    return re.search(r"\bhost\b", text, flags=re.IGNORECASE) is not None


def _command_of(stage: str) -> str:
    stripped = stage.strip()
    if not stripped:
        return ""
    return stripped.split(None, 1)[0].lower()


def _add_host_to_stats(stage: str) -> str:
    """Ensure a stats-family stage groups by / emits host."""
    # Locate a top-level ' by ' within this single stage (no pipes here).
    match = re.search(r"\bby\b", stage, flags=re.IGNORECASE)
    if match:
        by_clause = stage[match.end():]
        if _has_host_token(by_clause):
            return stage
        # Append host to the existing by-field list, preserving trailing space.
        stripped = stage.rstrip()
        trailing = stage[len(stripped):]
        return f"{stripped}, host{trailing}"
    # No by clause: add one so host is emitted per unique host.
    stripped = stage.rstrip()
    trailing = stage[len(stripped):] or " "
    return f"{stripped} by host{trailing}"


def _add_host_to_projection(stage: str) -> str:
    """Ensure a table/fields stage keeps host in its projected field list."""
    if _has_host_token(stage):
        return stage
    stripped = stage.rstrip()
    trailing = stage[len(stripped):]
    return f"{stripped}, host{trailing}"


def add_host_output_field(search: str) -> str:
    """Rewrite an SPL search so that ``host`` survives to the output."""
    stages = split_pipeline(search)
    rewritten: List[str] = []
    for stage in stages:
        command = _command_of(stage)
        if command in STATS_COMMANDS:
            rewritten.append(_add_host_to_stats(stage))
        elif command in PROJECT_COMMANDS:
            rewritten.append(_add_host_to_projection(stage))
        else:
            rewritten.append(stage)
    return "|".join(rewritten)
