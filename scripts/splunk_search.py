#!/usr/bin/env python3
"""
Splunk search helpers (REST / management API).

Used to run security_content detections and to export matching raw events.
Uploading of data is handled separately over HEC in migrate.py; searching uses
the Splunk management port (default 8089) with username/password.
"""

import time
from typing import Dict, Iterable, List, Optional, Set

import splunklib.client as client
import splunklib.results as results

DEFAULT_MGMT_PORT = 8089
# Attack data timestamps can be years old, so default to an all-time window.
DEFAULT_EARLIEST = "0"
DEFAULT_LATEST = "now"
# Max UUIDs per exported search to keep the SPL query length reasonable.
EXPORT_HOST_CHUNK = 500


def connect(
    host: str,
    port: int,
    username: str,
    password: str,
    verify_ssl: bool = False,
):
    """Connect to Splunk via the management API and return a service handle."""
    return client.connect(
        host=host,
        port=int(port),
        username=username,
        password=password,
        scheme="https",
        verify=verify_ssl,
    )


def _as_search_command(spl: str) -> str:
    """Ensure the SPL is dispatchable (must start with 'search' or '|')."""
    stripped = spl.strip()
    if stripped.startswith("|") or stripped.lower().startswith("search "):
        return stripped
    return f"search {stripped}"


def run_search(
    service,
    spl: str,
    earliest_time: str = DEFAULT_EARLIEST,
    latest_time: str = DEFAULT_LATEST,
    max_count: int = 50000,
) -> List[Dict[str, str]]:
    """Run a blocking search and return result rows as dicts."""
    query = _as_search_command(spl)
    job = service.jobs.create(
        query,
        earliest_time=earliest_time,
        latest_time=latest_time,
        max_count=max_count,
        output_mode="json",
        exec_mode="normal",
    )
    while not job.is_done():
        time.sleep(0.5)

    rows: List[Dict[str, str]] = []
    stream = job.results(output_mode="json", count=max_count)
    for item in results.JSONResultsReader(stream):
        if isinstance(item, dict):
            rows.append(item)
    job.cancel()
    return rows


def delete_index_data(service, index: str) -> int:
    """Delete all events in an index via ``search index=<index> | delete``.

    Requires a Splunk user with the ``can_delete`` capability. Uses an all-time
    window so every event is removed regardless of its timestamp. Returns the
    number of events reported deleted.
    """
    query = f"search index={index} | delete"
    print(f"    cleanup: {query}")
    rows = run_search(service, query, earliest_time="0", latest_time="now", max_count=1)
    deleted = 0
    for row in rows:
        try:
            deleted += int(row.get("deleted", 0))
        except (TypeError, ValueError):
            continue
    return deleted


def collect_hosts_from_rows(rows: List[Dict[str, str]]) -> Set[str]:
    """Extract the set of non-empty host values from search result rows."""
    hosts: Set[str] = set()
    for row in rows:
        value = row.get("host")
        if isinstance(value, list):
            hosts.update(str(v) for v in value if v)
        elif value:
            hosts.add(str(value))
    return hosts


def _chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def build_export_query(index: str, host_uuids: List[str]) -> str:
    """Build an export query of the form: index=<index> host IN (...)."""
    quoted = ", ".join(f'"{h}"' for h in host_uuids)
    return f'search index={index} host IN ({quoted})'


def export_events(
    service,
    index: str,
    host_uuids: Set[str],
    earliest_time: str = DEFAULT_EARLIEST,
    latest_time: str = DEFAULT_LATEST,
    max_count: int = 100000,
) -> List[str]:
    """Export the raw events for the given host UUIDs from an index.

    Runs one search per chunk of host UUIDs (to bound query length) and returns
    the collected ``_raw`` event strings.
    """
    raw_events: List[str] = []
    ordered = sorted(host_uuids)
    for chunk in _chunked(ordered, EXPORT_HOST_CHUNK):
        query = build_export_query(index, chunk) + " | table _raw"
        rows = run_search(
            service,
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_count=max_count,
        )
        for row in rows:
            raw = row.get("_raw")
            if raw:
                raw_events.append(raw)
    return raw_events
