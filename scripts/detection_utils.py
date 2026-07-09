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
from urllib.parse import urlparse

import yaml

STATS_COMMANDS = ("tstats", "sistats", "stats", "eventstats", "streamstats")
PROJECT_COMMANDS = ("table", "fields")
IGNORED_DETECTION_STATUSES = frozenset({"experimental", "deprecated"})
ATTACK_DATA_GITHUB_BASE = (
    "https://media.githubusercontent.com/media/splunk/attack_data/master"
)


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


def load_full_detection(file_path: Path) -> Optional[Dict[str, Any]]:
    """Parse a detection YAML file including id, name, search, and tests."""
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
        "tests": data.get("tests", []),
    }


def parse_detection_tests(detection_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract ``attack_data`` entries from a detection's ``tests`` section."""
    entries: List[Dict[str, str]] = []
    for test in detection_data.get("tests", []) or []:
        if not isinstance(test, dict):
            continue
        for attack_data in test.get("attack_data", []) or []:
            if not isinstance(attack_data, dict):
                continue
            data_url = attack_data.get("data")
            if not data_url:
                continue
            entry: Dict[str, str] = {"data_url": str(data_url)}
            if attack_data.get("source"):
                entry["source"] = str(attack_data["source"])
            if attack_data.get("sourcetype"):
                entry["sourcetype"] = str(attack_data["sourcetype"])
            entries.append(entry)
    return entries


def github_url_to_repo_path(url: str) -> Optional[str]:
    """Convert an attack_data GitHub media URL to a repo-relative ``/datasets/...`` path."""
    if not url:
        return None

    parsed = urlparse(url.strip())
    path = parsed.path.lstrip("/")
    marker = "splunk/attack_data/master/"
    if marker in path:
        path = path.split(marker, 1)[1]
    elif path.startswith("datasets/"):
        pass
    else:
        return None

    if not path.startswith("datasets/"):
        path = f"datasets/{path}"
    return f"/{path}"


def path_to_attack_data_url(path: str) -> str:
    """Convert a repo dataset path to the attack_data GitHub raw URL."""
    clean = path.lstrip("/")
    if not clean.startswith("datasets/"):
        clean = f"datasets/{clean}"
    return f"{ATTACK_DATA_GITHUB_BASE}/{clean}"


def is_ignored_detection_status(status: str) -> bool:
    """Return True when a detection YAML status should not be run (e.g. experimental)."""
    return status.strip().lower() in IGNORED_DETECTION_STATUSES


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


def _is_filter_macro_stage(stage: str) -> bool:
    """Return True when a pipeline stage is a security_content ``*_filter`` macro."""
    stripped = stage.strip()
    return re.fullmatch(r"`[^`]+_filter`", stripped) is not None


def remove_trailing_filter_macro(search: str) -> str:
    """Drop the terminal ``*_filter`` macro stage from a detection search."""
    stages = split_pipeline(search)
    if stages and _is_filter_macro_stage(stages[-1]):
        stages = stages[:-1]
    return "|".join(stages)


def prepare_detection_search(search: str) -> str:
    """Rewrite a detection search for execution in the migrate pipeline."""
    return add_host_output_field(remove_trailing_filter_macro(search))


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
