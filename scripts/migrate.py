#!/usr/bin/env python3
"""
Attack Data -> Splunk pipeline.

Detection-first pipeline for validating Splunk security_content detections
against attack_data datasets:

  1. For each detection (alphabetically): resolve ``tests[].attack_data[]`` entries
     (data URL, source, sourcetype) to local log files.
  2. upload  Replay those logs to Splunk HEC with per-event UUID hosts; store
     mappings in memory for the duration of the run.
  3. detect  Run only that detection (with ``host`` preserved in output).
  4. export  Export matched events and create or update curated attack data YAML
     files named ``{technique}_{folder}.yml`` (e.g. ``T1001_snapattack.yml``).
  5. cleanup Delete uploaded events from the Splunk index before the next
     detection.

The ``run`` subcommand performs this loop. ``upload`` remains available standalone.
``--detection`` accepts a single file or folder.

Connection settings (CLI flags override environment variables):
    SPLUNK_HOST        Splunk hostname/IP                (required)
    SPLUNK_HEC_TOKEN   HEC token for uploading           (required for upload)
    SPLUNK_HEC_PORT    HEC port                          (default: 8088)
    SPLUNK_USERNAME    Splunk user for searching         (required for run)
    SPLUNK_PASSWORD    Splunk password for searching     (required for run)
    SPLUNK_PORT        Splunk management port            (default: 8089)

Examples:
    # Detection-first pipeline over a folder of detections
    python scripts/migrate.py run \\
        --detection scripts/detection_tests

    # Use an alternate attack data root (e.g. local test copies)
    python scripts/migrate.py run \\
        --detection scripts/detection_tests \\
        --attack-data-root scripts/attack_technique_tests

    # Resume after a failure at a specific detection UUID
    python scripts/migrate.py run \\
        --detection scripts/detection_tests \\
        --start-from-detection-id fb4c31b0-13e8-4155-8aa5-24de4b8d6717

    # Also update detection YAML tests with curated attack data URLs
    python scripts/migrate.py run \\
        --detection scripts/detection_tests \\
        --update-detection-tests

    # Upload only (still requires --attack-data)
    python scripts/migrate.py upload --attack-data datasets/malware/qakbot
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import requests
import yaml
from urllib3 import disable_warnings

import memory_store
import detection_utils
import splunk_search

DEFAULT_INDEX = "test"
DEFAULT_HEC_PORT = "8088"
DEFAULT_MGMT_PORT = "8089"
DEFAULT_BATCH_SIZE = 500
DEFAULT_INDEX_WAIT_SECONDS = 10
DEFAULT_RUN_LOG = "migrate_run.log"
CURATED_ATTACK_DATA_YML = re.compile(r"^T[\d.]+_.+\.(ya?ml)$", re.IGNORECASE)
EXTRACTION_SUCCESS_STATUSES = frozenset({"curated"})
ATTACK_DATA_AUTHOR = "STRT"


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def get_project_root() -> Path:
    """Return the repository root (the parent of the scripts/ directory)."""
    return Path(__file__).resolve().parent.parent


def load_env() -> None:
    """Load environment variables from a .env file if one is present.

    Looks for a .env file next to this script first, then at the repository
    root. Each run re-loads the .env file and overrides any existing values
    already present in the environment.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        print("Warning: python-dotenv not installed; skipping .env loading")
        return
    script_dir = Path(__file__).resolve().parent
    for candidate in (script_dir / ".env", get_project_root() / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=True)
            print(f"Loaded environment from {candidate}")


def load_hec_config(args: argparse.Namespace) -> Dict[str, str]:
    """Resolve Splunk HEC (upload) settings from CLI args or environment."""
    host = args.host or os.environ.get("SPLUNK_HOST")
    token = args.hec_token or os.environ.get("SPLUNK_HEC_TOKEN")
    port = args.hec_port or os.environ.get("SPLUNK_HEC_PORT") or DEFAULT_HEC_PORT

    missing = []
    if not host:
        missing.append("SPLUNK_HOST (or --host)")
    if not token:
        missing.append("SPLUNK_HEC_TOKEN (or --hec-token)")
    if missing:
        raise ValueError("Missing HEC settings: " + ", ".join(missing))

    return {"host": host, "token": token, "port": str(port)}


def load_mgmt_config(args: argparse.Namespace) -> Dict[str, str]:
    """Resolve Splunk management (search) settings from CLI args or environment."""
    host = args.host or os.environ.get("SPLUNK_HOST")
    username = args.username or os.environ.get("SPLUNK_USERNAME")
    password = args.password or os.environ.get("SPLUNK_PASSWORD")
    port = args.mgmt_port or os.environ.get("SPLUNK_PORT") or DEFAULT_MGMT_PORT

    missing = []
    if not host:
        missing.append("SPLUNK_HOST (or --host)")
    if not username:
        missing.append("SPLUNK_USERNAME (or --username)")
    if not password:
        missing.append("SPLUNK_PASSWORD (or --password)")
    if missing:
        raise ValueError("Missing Splunk management settings: " + ", ".join(missing))

    return {"host": host, "username": username, "password": password, "port": str(port)}


# --------------------------------------------------------------------------- #
# Attack data discovery / parsing
# --------------------------------------------------------------------------- #
def find_attack_data_files(path: Path) -> List[Path]:
    """Return attack data YAML files for a single file or a folder (recursive)."""
    if path.is_file():
        return [path] if path.suffix.lower() in (".yml", ".yaml") else []
    if not path.is_dir():
        return []
    yaml_files: List[Path] = []
    for pattern in ("**/*.yml", "**/*.yaml"):
        yaml_files.extend(path.glob(pattern))
    yaml_files = [
        f
        for f in yaml_files
        if not f.name.startswith("TEMPLATE") and "old" not in f.name.lower()
    ]
    return sorted(set(yaml_files))


def parse_attack_data_file(
    yml_file: Path,
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """Parse an attack data YAML file into (file_id, datasets)."""
    try:
        with open(yml_file, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except (yaml.YAMLError, OSError) as exc:
        print(f"  ! Error parsing {yml_file}: {exc}")
        return None, []

    if not isinstance(data, dict):
        return None, []
    file_id = data.get("id")
    datasets = data.get("datasets")
    if not file_id or not isinstance(datasets, list):
        return None, []
    return file_id, datasets


def resolve_dataset_path(project_root: Path, yml_file: Path, dataset_path: str) -> Path:
    """Resolve a dataset path (``/datasets/...`` = repo-relative) to an absolute path."""
    if dataset_path.startswith("/"):
        return project_root / dataset_path.lstrip("/")
    return yml_file.parent / dataset_path


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def resolve_attack_data_root(raw_path: Optional[str], project_root: Path) -> Path:
    """Resolve the attack data root directory used for test URL lookup."""
    rel = raw_path or "datasets"
    path = Path(rel)
    if not path.is_absolute():
        candidate = (Path.cwd() / path)
        path = candidate if candidate.exists() else (project_root / rel)
    return path.resolve()


def resolve_attack_data_log_path(
    repo_path: str,
    project_root: Path,
    attack_data_root: Path,
) -> Optional[Path]:
    """Resolve a ``/datasets/...`` repo path to a local attack data log file."""
    relative = repo_path.lstrip("/")
    root = attack_data_root.resolve()
    default_root = (project_root / "datasets").resolve()

    root_candidates: List[Path] = []
    if relative.startswith("datasets/"):
        remainder = relative[len("datasets/"):]
        root_candidates.append(root / remainder)
        if remainder.startswith("attack_techniques/"):
            root_candidates.append(root / remainder[len("attack_techniques/"):])
    else:
        root_candidates.append(root / relative)

    repo_candidate = project_root / relative
    if root != default_root:
        candidates = root_candidates + [repo_candidate]
    else:
        candidates = [repo_candidate] + root_candidates

    seen: Set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file():
            return resolved
    return None


def is_curated_attack_data_yml(name: str) -> bool:
    """Return True if ``name`` looks like a generated curated attack data YAML."""
    return bool(CURATED_ATTACK_DATA_YML.match(name))


def curated_attack_data_path(folder: Path) -> Path:
    """Return the curated YAML path for a dataset folder."""
    technique = folder.parent.name
    folder_name = folder.name
    return folder / f"{technique}_{folder_name}.yml"


def curated_attack_data_path_from_source(source_yml: Path) -> Path:
    """Return the curated YAML path for a legacy source attack data YAML file."""
    return curated_attack_data_path(source_yml.parent)


def _dataset_name_from_log(log_path: Path) -> str:
    return log_path.stem


def _mitre_techniques_from_detection(detection: Dict[str, Any]) -> List[str]:
    tags = detection.get("tags") or {}
    technique_ids = tags.get("mitre_attack_id") or []
    return [str(item) for item in technique_ids]


def resolve_detection_test_datasets(
    detection: Dict[str, Any],
    project_root: Path,
    attack_data_root: Path,
) -> List[Dict[str, Any]]:
    """Resolve detection test attack_data entries to local upload specs."""
    specs: List[Dict[str, Any]] = []
    seen_logs: Set[Path] = set()

    for test_entry in detection_utils.parse_detection_tests(detection):
        repo_path = detection_utils.github_url_to_repo_path(test_entry["data_url"])
        if not repo_path:
            print(f"  ! Could not parse attack data URL: {test_entry['data_url']}")
            continue

        log_path = resolve_attack_data_log_path(
            repo_path, project_root, attack_data_root
        )
        if log_path is None:
            print(f"  ! Attack data log not found for {repo_path} "
                  f"(root={attack_data_root})")
            continue

        resolved_log = log_path.resolve()
        if resolved_log in seen_logs:
            continue
        seen_logs.add(resolved_log)

        source = test_entry.get("source")
        sourcetype = test_entry.get("sourcetype")
        if not source or not sourcetype:
            print(f"  ! Missing source or sourcetype for {repo_path}, skipping")
            continue

        specs.append(
            {
                "name": _dataset_name_from_log(log_path),
                "log_path": resolved_log,
                "source": source,
                "sourcetype": sourcetype,
                "data_url": test_entry["data_url"],
                "repo_path": repo_path,
                "output_folder": resolved_log.parent,
            }
        )
    return specs


def _group_detection_datasets_by_folder(
    dataset_specs: List[Dict[str, Any]],
) -> Dict[Path, List[Dict[str, Any]]]:
    grouped: Dict[Path, List[Dict[str, Any]]] = {}
    for spec in dataset_specs:
        grouped.setdefault(spec["output_folder"], []).append(spec)
    return grouped


def _attack_data_uuid_for_folder(folder: Path) -> str:
    curated_path = curated_attack_data_path(folder)
    if curated_path.is_file():
        file_id, _ = parse_attack_data_file(curated_path)
        if file_id:
            return file_id
    return str(uuid.uuid4())


def find_source_attack_data_yml(folder: Path) -> Optional[Path]:
    """Find the original attack data YAML in a dataset folder."""
    candidates: List[Path] = []
    for yml_file in folder.glob("*.yml"):
        if is_curated_attack_data_yml(yml_file.name):
            continue
        if yml_file.name.startswith("TEMPLATE") or "old" in yml_file.name.lower():
            continue
        file_id, datasets = parse_attack_data_file(yml_file)
        if file_id and datasets:
            candidates.append(yml_file)

    if not candidates:
        for yml_file in folder.glob("*.yaml"):
            if is_curated_attack_data_yml(yml_file.name):
                continue
            if yml_file.name.startswith("TEMPLATE") or "old" in yml_file.name.lower():
                continue
            file_id, datasets = parse_attack_data_file(yml_file)
            if file_id and datasets:
                candidates.append(yml_file)

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    preferred = folder / f"{folder.name}.yml"
    if preferred in candidates:
        return preferred
    return sorted(candidates)[0]


def resolve_source_attack_data_ymls(
    detection_file: Path,
    project_root: Path,
    attack_data_root: Path,
) -> List[Path]:
    """Resolve detection test URLs to local source attack data YAML files."""
    detection = detection_utils.load_full_detection(detection_file)
    if not detection:
        return []

    source_ymls: Dict[Path, bool] = {}
    for test_entry in detection_utils.parse_detection_tests(detection):
        repo_path = detection_utils.github_url_to_repo_path(test_entry["data_url"])
        if not repo_path:
            print(f"  ! Could not parse attack data URL: {test_entry['data_url']}")
            continue

        log_path = resolve_attack_data_log_path(
            repo_path, project_root, attack_data_root
        )
        if log_path is None:
            print(f"  ! Attack data log not found for {repo_path} "
                  f"(root={attack_data_root})")
            continue

        source_yml = find_source_attack_data_yml(log_path.parent)
        if not source_yml:
            print(f"  ! No source attack data YAML in {log_path.parent}")
            continue
        source_ymls[source_yml.resolve()] = True

    return sorted(source_ymls.keys())


def sort_detections_by_name(detection_files: List[Path]) -> List[Path]:
    """Sort detection files alphabetically by detection name."""
    def sort_key(det_file: Path) -> str:
        detection = detection_utils.parse_detection_file(det_file)
        return (detection or {}).get("name", det_file.stem).lower()

    return sorted(detection_files, key=sort_key)


def filter_detections_from_id(
    detection_files: List[Path],
    start_from_id: Optional[str],
) -> List[Path]:
    """Return detections sorted by name, optionally starting at a detection UUID."""
    sorted_files = sort_detections_by_name(detection_files)
    if not start_from_id:
        return sorted_files

    for index, det_file in enumerate(sorted_files):
        detection = detection_utils.load_full_detection(det_file)
        if detection and detection.get("id", "").lower() == start_from_id.lower():
            if index > 0:
                print(f"Resuming at detection id={start_from_id} "
                      f"({detection['name']}); skipping {index} earlier detection(s)")
            return sorted_files[index:]

    print(f"Warning: --start-from-detection-id {start_from_id} not found; "
          "processing all detections")
    return sorted_files


def filter_runnable_detections(
    detection_files: List[Path],
) -> Tuple[List[Path], List[Tuple[str, str, str]]]:
    """Drop experimental and deprecated detections from the run list."""
    runnable: List[Path] = []
    ignored: List[Tuple[str, str, str]] = []

    for det_file in detection_files:
        detection = detection_utils.parse_detection_file(det_file)
        det_path = str(det_file)
        if not detection:
            runnable.append(det_file)
            continue
        status = detection.get("status", "")
        if detection_utils.is_ignored_detection_status(status):
            ignored.append((detection["name"], det_path, status))
            continue
        runnable.append(det_file)

    return runnable, ignored


# --------------------------------------------------------------------------- #
# HEC upload
# --------------------------------------------------------------------------- #
def build_hec_url(config: Dict[str, str]) -> str:
    return urllib.parse.urljoin(
        f"https://{config['host']}:{config['port']}",
        "services/collector/event",
    )


def send_event_batch(
    session: requests.Session,
    url: str,
    config: Dict[str, str],
    events: List[Dict[str, Any]],
    verify_tls: bool,
) -> bool:
    """Send a batch of events to the HEC JSON event endpoint."""
    if not events:
        return True
    headers = {
        "Authorization": f"Splunk {config['token']}",
        "X-Splunk-Request-Channel": str(uuid.uuid4()),
    }
    payload = "\n".join(json.dumps(event) for event in events)
    try:
        res = session.post(
            url, data=payload.encode("utf-8"), headers=headers, verify=verify_tls
        )
    except requests.RequestException as exc:
        print(f"    x Error sending batch of {len(events)} event(s): {exc}")
        return False

    if res.ok:
        return True
    print(f"    x HTTP {res.status_code} sending batch of {len(events)} event(s)")
    try:
        data = res.json()
        print(f"      HEC response: code={data.get('code')}, text={data.get('text')}")
    except ValueError:
        print(f"      HEC raw response: {res.text.strip()}")
    return False


def iter_event_lines(file_path: Path) -> Iterator[str]:
    """Yield each non-empty line of a dataset file (line endings stripped)."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as datafile:
        for line in datafile:
            line = line.rstrip("\n").rstrip("\r")
            if line.strip():
                yield line


def _is_powershell_xml_dataset(source: str, sourcetype: str) -> bool:
    """Return True when a dataset file contains multi-line Windows PowerShell XML events."""
    return (
        sourcetype.lower() == "xmlwineventlog"
        and "powershell" in source.lower()
    )


def iter_xml_events(file_path: Path) -> Iterator[str]:
    """Yield each top-level ``<Event>...</Event>`` document from a file."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as datafile:
        content = datafile.read()

    start = 0
    while True:
        event_start = content.find("<Event", start)
        if event_start < 0:
            break
        event_end = content.find("</Event>", event_start)
        if event_end < 0:
            break
        event_end += len("</Event>")
        event = content[event_start:event_end]
        if event.strip():
            yield event
        start = event_end


def iter_dataset_events(
    file_path: Path,
    source: str,
    sourcetype: str,
) -> Iterator[str]:
    """Yield uploadable events from a dataset file.

    Line-delimited files (JSON, single-line XML, etc.) yield one event per non-empty
    line. PowerShell ``XmlWinEventLog`` files can contain multi-line script block
    events and are split into individual ``<Event>...</Event>`` documents instead.
    """
    if _is_powershell_xml_dataset(source, sourcetype):
        yield from iter_xml_events(file_path)
        return
    yield from iter_event_lines(file_path)


def upload_dataset_lines(
    session: requests.Session,
    url: str,
    config: Dict[str, str],
    file_path: Path,
    index: str,
    source: str,
    sourcetype: str,
    batch_size: int,
    verify_tls: bool,
) -> Tuple[List[str], int]:
    """Upload each event in a dataset file to HEC with its own UUID host."""
    event_uuids: List[str] = []
    failed = 0
    batch: List[Dict[str, Any]] = []
    batch_uuids: List[str] = []

    def flush() -> None:
        nonlocal failed
        if not batch:
            return
        if send_event_batch(session, url, config, batch, verify_tls):
            event_uuids.extend(batch_uuids)
        else:
            failed += len(batch)
        batch.clear()
        batch_uuids.clear()

    for event in iter_dataset_events(file_path, source, sourcetype):
        event_uuid = str(uuid.uuid4())
        batch.append(
            {
                "event": event,
                "host": event_uuid,
                "source": source,
                "sourcetype": sourcetype,
                "index": index,
            }
        )
        batch_uuids.append(event_uuid)
        if len(batch) >= batch_size:
            flush()
    flush()
    return event_uuids, failed


def upload_attack_data_file(
    session: requests.Session,
    url: str,
    store: memory_store.MigrationStore,
    yml_file: Path,
    project_root: Path,
    config: Dict[str, str],
    index: str,
    batch_size: int,
    verify_tls: bool,
) -> Tuple[Optional[str], str, Dict[str, Set[str]], int, int]:
    """Upload every dataset in one attack data file; record the UUID map in memory.

    Returns (attack_data_uuid, attack_data_file, dataset_uuids, sent, failed) where
    dataset_uuids maps each dataset name to its set of event UUIDs.
    """
    rel_file = _relative(yml_file, project_root)
    print(f"\nProcessing {rel_file}...")
    file_id, datasets = parse_attack_data_file(yml_file)
    if not file_id or not datasets:
        print("  ! Skipping - no valid attack data structure found")
        return None, rel_file, {}, 0, 0

    print(f"  attack data uuid: {file_id}")
    dataset_uuids: Dict[str, Set[str]] = {}
    sent_events = 0
    failed_events = 0

    for dataset in datasets:
        name = dataset.get("name", "unknown")
        dataset_path = dataset.get("path")
        source = dataset.get("source")
        sourcetype = dataset.get("sourcetype")
        if not dataset_path or not source or not sourcetype:
            print(f"  ! Dataset '{name}' missing path/source/sourcetype, skipping")
            continue

        full_path = resolve_dataset_path(project_root, yml_file, dataset_path)
        if not full_path.exists():
            print(f"  ! Dataset file not found: {full_path}")
            continue

        print(f"  dataset '{name}' -> index={index}, source={source}, "
              f"sourcetype={sourcetype}")
        event_uuids, failed = upload_dataset_lines(
            session=session,
            url=url,
            config=config,
            file_path=full_path,
            index=index,
            source=source,
            sourcetype=sourcetype,
            batch_size=batch_size,
            verify_tls=verify_tls,
        )
        print(f"    + {len(event_uuids)} event(s) sent, {failed} failed")

        store.store_upload(
            attack_data_uuid=file_id,
            attack_data_file=rel_file,
            dataset_name=name,
            source=source,
            sourcetype=sourcetype,
            index_name=index,
            event_uuids=event_uuids,
        )
        # Multiple datasets may share a name; merge their UUID sets.
        dataset_uuids.setdefault(name, set()).update(event_uuids)
        sent_events += len(event_uuids)
        failed_events += failed

    return file_id, rel_file, dataset_uuids, sent_events, failed_events


def do_upload(
    yaml_files: List[Path],
    store: memory_store.MigrationStore,
    hec_config: Dict[str, str],
    project_root: Path,
    index: str,
    batch_size: int,
    verify_tls: bool,
) -> Dict[str, Dict[str, Any]]:
    """Upload all attack data files.

    Returns {attack_data_uuid: {"file": <path>, "datasets": {name: {uuids}}}}.
    """
    if not verify_tls:
        disable_warnings()
    session = requests.Session()
    url = build_hec_url(hec_config)

    uuid_map: Dict[str, Dict[str, Any]] = {}
    total_sent = 0
    total_failed = 0
    for yml_file in yaml_files:
        file_id, rel_file, dataset_uuids, sent, failed = upload_attack_data_file(
            session=session,
            url=url,
            store=store,
            yml_file=yml_file,
            project_root=project_root,
            config=hec_config,
            index=index,
            batch_size=batch_size,
            verify_tls=verify_tls,
        )
        total_sent += sent
        total_failed += failed
        if file_id and dataset_uuids:
            entry = uuid_map.setdefault(file_id, {"file": rel_file, "datasets": {}})
            for name, uuids in dataset_uuids.items():
                entry["datasets"].setdefault(name, set()).update(uuids)

    print(f"\nUpload complete: {total_sent} event(s) sent, {total_failed} failed, "
          f"{len(uuid_map)} attack data file(s) mapped in memory")
    return uuid_map


# --------------------------------------------------------------------------- #
# Detection running + attribution
# --------------------------------------------------------------------------- #
def _file_uuid_set(entry: Dict[str, Any]) -> Set[str]:
    """Union of all dataset UUID sets for one attack data file entry."""
    result: Set[str] = set()
    for uuids in entry["datasets"].values():
        result.update(uuids)
    return result


def do_detect(
    detection_files: List[Path],
    service,
    store: memory_store.MigrationStore,
    uuid_map: Dict[str, Dict[str, Any]],
    index: str,
    earliest: str,
    latest: str,
) -> Tuple[Set[str], Dict[str, Dict[str, Set[str]]], Dict[str, str]]:
    """Run detections, attribute matched hosts to attack data files, store in memory.

    Returns the global set of matched host UUIDs (across all detections), a
    per-detection map ``{detection_file: {attack_data_uuid: matched_hosts}}``,
    and a per-detection status map ``{detection_file: reason}``.
    """
    all_matched: Set[str] = set()
    detection_matches: Dict[str, Dict[str, Set[str]]] = {}
    detection_status: Dict[str, str] = {}
    our_uuids: Set[str] = set()
    for entry in uuid_map.values():
        our_uuids.update(_file_uuid_set(entry))

    print(f"\nRunning {len(detection_files)} detection(s) over index={index} "
          f"(earliest={earliest}, latest={latest})")

    for det_file in detection_files:
        detection = detection_utils.parse_detection_file(det_file)
        if not detection:
            print(f"  ! Skipping non-detection file: {det_file}")
            detection_status[str(det_file)] = "skipped"
            continue

        det_path = detection["file"]
        patched = detection_utils.prepare_detection_search(detection["search"])
        print(f"\n  Detection: {detection['name']}")
        try:
            rows = splunk_search.run_search(
                service, patched, earliest_time=earliest, latest_time=latest
            )
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"    x Search failed: {exc}")
            detection_status[det_path] = "search_failed"
            continue

        matched_hosts = splunk_search.collect_hosts_from_rows(rows)
        # Restrict to hosts we uploaded (ignore any pre-existing data in the index).
        matched_hosts &= our_uuids
        print(f"    results: {len(rows)} row(s), {len(matched_hosts)} matched host(s)")

        if not matched_hosts:
            detection_status[det_path] = "no_matches"
            continue
        all_matched.update(matched_hosts)
        detection_status[det_path] = "matched"

        file_matches: Dict[str, Set[str]] = {}
        # Attribute matched hosts back to each attack data file.
        for attack_data_uuid, entry in uuid_map.items():
            attributed = matched_hosts & _file_uuid_set(entry)
            if not attributed:
                continue
            file_matches[attack_data_uuid] = attributed
            store.store_detection_result(
                attack_data_uuid=attack_data_uuid,
                detection_id=detection.get("id", ""),
                detection_name=detection["name"],
                detection_file=detection["file"],
                matched_host_uuids=sorted(attributed),
            )
            print(f"      {attack_data_uuid}: {len(attributed)} matched event(s)")

        if file_matches:
            detection_matches[detection["file"]] = file_matches

    return all_matched, detection_matches, detection_status


def run_single_detection(
    detection_file: Path,
    service,
    store: memory_store.MigrationStore,
    uuid_map: Dict[str, Dict[str, Any]],
    earliest: str,
    latest: str,
) -> Tuple[Set[str], Dict[str, Set[str]], str]:
    """Run one detection and return matched hosts plus per-file attribution."""
    detection = detection_utils.parse_detection_file(detection_file)
    if not detection:
        return set(), {}, "skipped"

    our_uuids: Set[str] = set()
    for entry in uuid_map.values():
        our_uuids.update(_file_uuid_set(entry))

    det_path = detection["file"]
    patched = detection_utils.prepare_detection_search(detection["search"])
    print(f"\n  Detection: {detection['name']}")
    try:
        rows = splunk_search.run_search(
            service, patched, earliest_time=earliest, latest_time=latest
        )
    except Exception as exc:  # noqa: BLE001 - report and continue
        print(f"    x Search failed: {exc}")
        return set(), {}, "search_failed"

    matched_hosts = splunk_search.collect_hosts_from_rows(rows)
    matched_hosts &= our_uuids
    print(f"    results: {len(rows)} row(s), {len(matched_hosts)} matched host(s)")
    if not matched_hosts:
        return set(), {}, "no_matches"

    file_matches: Dict[str, Set[str]] = {}
    for attack_data_uuid, entry in uuid_map.items():
        attributed = matched_hosts & _file_uuid_set(entry)
        if not attributed:
            continue
        file_matches[attack_data_uuid] = attributed
        store.store_detection_result(
            attack_data_uuid=attack_data_uuid,
            detection_id=detection.get("id", ""),
            detection_name=detection["name"],
            detection_file=detection["file"],
            matched_host_uuids=sorted(attributed),
        )
        print(f"      {attack_data_uuid}: {len(attributed)} matched event(s)")

    return matched_hosts, file_matches, "matched"


def upload_source_ymls(
    source_ymls: List[Path],
    session: requests.Session,
    url: str,
    store: memory_store.MigrationStore,
    hec_config: Dict[str, str],
    project_root: Path,
    index: str,
    batch_size: int,
    verify_tls: bool,
) -> Dict[str, Dict[str, Any]]:
    """Upload all datasets from the given source attack data YAML files."""
    uuid_map: Dict[str, Dict[str, Any]] = {}
    for yml_file in source_ymls:
        file_id, rel_file, dataset_uuids, _, _ = upload_attack_data_file(
            session=session,
            url=url,
            store=store,
            yml_file=yml_file,
            project_root=project_root,
            config=hec_config,
            index=index,
            batch_size=batch_size,
            verify_tls=verify_tls,
        )
        if file_id and dataset_uuids:
            uuid_map[file_id] = {
                "file": rel_file,
                "datasets": dataset_uuids,
                "source_yml": str(yml_file.resolve()),
                "curated_path": str(curated_attack_data_path_from_source(yml_file).resolve()),
                "output_folder": str(yml_file.parent.resolve()),
            }
    return uuid_map


def upload_detection_test_datasets(
    dataset_specs: List[Dict[str, Any]],
    session: requests.Session,
    url: str,
    store: memory_store.MigrationStore,
    hec_config: Dict[str, str],
    project_root: Path,
    index: str,
    batch_size: int,
    verify_tls: bool,
) -> Dict[str, Dict[str, Any]]:
    """Upload log files referenced directly by a detection's tests."""
    uuid_map: Dict[str, Dict[str, Any]] = {}

    for folder, folder_specs in _group_detection_datasets_by_folder(dataset_specs).items():
        attack_data_uuid = _attack_data_uuid_for_folder(folder)
        curated_path = curated_attack_data_path(folder)
        rel_curated = _relative(curated_path, project_root)
        print(f"\nProcessing test datasets in {folder}...")
        print(f"  attack data uuid: {attack_data_uuid}")

        entry: Dict[str, Any] = {
            "file": rel_curated,
            "datasets": {},
            "dataset_meta": {},
            "output_folder": str(folder),
            "curated_path": str(curated_path.resolve()),
        }
        sent_events = 0
        failed_events = 0

        for spec in folder_specs:
            name = spec["name"]
            source = spec["source"]
            sourcetype = spec["sourcetype"]
            log_path = spec["log_path"]
            print(f"  dataset '{name}' -> index={index}, source={source}, "
                  f"sourcetype={sourcetype}")
            event_uuids, failed = upload_dataset_lines(
                session=session,
                url=url,
                config=hec_config,
                file_path=log_path,
                index=index,
                source=source,
                sourcetype=sourcetype,
                batch_size=batch_size,
                verify_tls=verify_tls,
            )
            print(f"    + {len(event_uuids)} event(s) sent, {failed} failed")
            if not event_uuids:
                continue

            store.store_upload(
                attack_data_uuid=attack_data_uuid,
                attack_data_file=rel_curated,
                dataset_name=name,
                source=source,
                sourcetype=sourcetype,
                index_name=index,
                event_uuids=event_uuids,
            )
            entry["datasets"].setdefault(name, set()).update(event_uuids)
            entry["dataset_meta"][name] = {
                "source": source,
                "sourcetype": sourcetype,
                "path": spec["repo_path"],
            }
            sent_events += len(event_uuids)
            failed_events += failed

        if entry["datasets"]:
            uuid_map[attack_data_uuid] = entry
        elif sent_events == 0 and failed_events == 0:
            print(f"  ! No events uploaded from {folder}")

    return uuid_map


def export_and_curate_detection(
    service,
    index: str,
    uuid_map: Dict[str, Dict[str, Any]],
    matched_hosts: Set[str],
    export_dir: Optional[str],
    project_root: Path,
    earliest: str,
    latest: str,
    detection: Optional[Dict[str, Any]] = None,
) -> bool:
    """Export matched events for one detection and merge into curated YAML files."""
    if not matched_hosts:
        return False

    out_dir: Optional[Path] = None
    if export_dir:
        out_dir = Path(export_dir)
        if not out_dir.is_absolute():
            out_dir = (Path.cwd() / out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nExporting matched events per dataset from index={index}")
    curated_any = False

    for attack_data_uuid, entry in uuid_map.items():
        if not (matched_hosts & _file_uuid_set(entry)):
            continue

        curated_path = Path(entry.get("curated_path", ""))
        if not curated_path.is_file():
            curated_path = curated_attack_data_path(
                Path(entry.get("output_folder", project_root))
            )
        source_yml_path = entry.get("source_yml")
        source_yml = Path(source_yml_path) if source_yml_path else None
        if source_yml and not source_yml.is_file():
            source_yml = _resolve_attack_data_yml(project_root, entry.get("file", ""))
            if not source_yml.is_file():
                source_yml = None

        dataset_events: Dict[str, List[str]] = {}
        for dataset_name, dataset_uuids in entry["datasets"].items():
            hosts = matched_hosts & dataset_uuids
            if not hosts:
                continue

            raw_events = splunk_search.export_events(
                service, index, hosts, earliest_time=earliest, latest_time=latest
            )
            filename = _dataset_log_filename(dataset_name, attack_data_uuid)
            print(f"  {dataset_name} ({attack_data_uuid}): "
                  f"{len(hosts)} matched host(s), {len(raw_events)} event(s) -> {filename}")
            if out_dir is not None:
                _write_events(out_dir / filename, raw_events)
            dataset_events[dataset_name] = raw_events

        if dataset_events:
            merge_curated_attack_data_yml(
                curated_path,
                dataset_events,
                project_root,
                attack_data_uuid,
                entry.get("dataset_meta", {}),
                source_yml=source_yml,
                detection=detection,
            )
            curated_any = True

    return curated_any


def build_attack_data_entries_from_uuid_map(
    uuid_map: Dict[str, Dict[str, Any]],
    matched_dataset_names: Set[str],
    project_root: Path,
) -> List[Dict[str, str]]:
    """Build detection test attack_data entries from curated UUID map entries."""
    entries: List[Dict[str, str]] = []
    seen_urls: Set[str] = set()

    for entry in uuid_map.values():
        curated_path = Path(entry.get("curated_path", ""))
        if curated_path.is_file():
            meta_by_name = load_attack_data_dataset_meta(curated_path)
        else:
            meta_by_name = entry.get("dataset_meta", {})

        for dataset_name, meta in meta_by_name.items():
            if dataset_name not in matched_dataset_names:
                continue
            path = meta.get("path", "")
            sourcetype = meta.get("sourcetype", "")
            if not path or not sourcetype:
                continue
            data_url = path_to_attack_data_url(path)
            if data_url in seen_urls:
                continue
            seen_urls.add(data_url)
            attack_entry: Dict[str, str] = {
                "data": data_url,
                "sourcetype": sourcetype,
            }
            if meta.get("source"):
                attack_entry["source"] = meta["source"]
            entries.append(attack_entry)
    return entries


def build_attack_data_entries_from_curated(
    source_ymls: List[Path],
    matched_dataset_names: Set[str],
    project_root: Path,
) -> List[Dict[str, str]]:
    """Build detection test attack_data entries from curated YAML files."""
    entries: List[Dict[str, str]] = []
    seen_urls: Set[str] = set()

    for source_yml in source_ymls:
        curated_path = curated_attack_data_path_from_source(source_yml)
        yml_to_read = curated_path if curated_path.is_file() else source_yml
        meta_by_name = load_attack_data_dataset_meta(yml_to_read)
        for dataset_name, meta in meta_by_name.items():
            if dataset_name not in matched_dataset_names:
                continue
            if not meta.get("path") or not meta.get("sourcetype"):
                continue
            data_url = path_to_attack_data_url(meta["path"])
            if data_url in seen_urls:
                continue
            seen_urls.add(data_url)
            entry: Dict[str, str] = {
                "data": data_url,
                "sourcetype": meta["sourcetype"],
            }
            if meta.get("source"):
                entry["source"] = meta["source"]
            entries.append(entry)
    return entries


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def _safe_filename(text: str) -> str:
    """Make a dataset name safe to use as a filename component."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "dataset"


def _dataset_log_filename(dataset_name: str, file_uuid: str) -> str:
    """Build an exported dataset log filename: ``<dataset_name>-<uuid>.log``."""
    return f"{_safe_filename(dataset_name)}-{file_uuid}.log"


def _write_events(path: Path, raw_events: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for raw in raw_events:
            handle.write(raw.rstrip("\n") + "\n")


def update_attack_data_yml(
    project_root: Path,
    file_rel: str,
    attack_data_uuid: str,
    dataset_events: Dict[str, List[str]],
) -> None:
    """Save curated per-dataset logs next to the YAML and update the YAML in place.

    For each dataset that produced matches, its exported events are written to
    ``<yml_folder>/<dataset_name>-<attack_data_uuid>.log``. The attack data YAML
    is then updated with today's date and a datasets section repointed to those
    curated files (datasets without matches are dropped).
    """
    yml_abs = Path(file_rel)
    if not yml_abs.is_absolute():
        yml_abs = (project_root / file_rel).resolve()
    if not yml_abs.is_file():
        print(f"    ! Cannot update attack data yml (not found): {yml_abs}")
        return

    folder = yml_abs.parent
    written_paths: Dict[str, str] = {}
    for name, events in dataset_events.items():
        out_file = folder / _dataset_log_filename(name, attack_data_uuid)
        _write_events(out_file, events)
        try:
            written_paths[name] = "/" + str(out_file.relative_to(project_root))
        except ValueError:
            written_paths[name] = out_file.name

    try:
        with open(yml_abs, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (yaml.YAMLError, OSError) as exc:
        print(f"    ! Failed to read {yml_abs}: {exc}")
        return
    if not isinstance(data, dict):
        print(f"    ! Unexpected YAML structure in {yml_abs}; not updating")
        return

    data["date"] = datetime.now().strftime("%Y-%m-%d")
    data["author"] = ATTACK_DATA_AUTHOR
    new_datasets = []
    for dataset in data.get("datasets", []):
        name = dataset.get("name")
        if name in written_paths:
            updated = dict(dataset)
            updated["path"] = written_paths[name]
            new_datasets.append(updated)
    if new_datasets:
        data["datasets"] = new_datasets

    try:
        with open(yml_abs, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                data, handle, sort_keys=False, default_flow_style=False,
                allow_unicode=True,
            )
    except OSError as exc:
        print(f"    ! Failed to write {yml_abs}: {exc}")
        return
    print(f"    updated attack data yml: {yml_abs} "
          f"(date + {len(new_datasets)} dataset(s))")


def path_to_attack_data_url(path: str) -> str:
    """Convert a repo dataset path to the attack_data GitHub raw URL."""
    return detection_utils.path_to_attack_data_url(path)


def merge_curated_attack_data_yml(
    curated_path: Path,
    dataset_events: Dict[str, List[str]],
    project_root: Path,
    attack_data_uuid: str,
    dataset_meta: Dict[str, Dict[str, str]],
    *,
    source_yml: Optional[Path] = None,
    detection: Optional[Dict[str, Any]] = None,
) -> None:
    """Create or update a curated attack data YAML from exported dataset events."""
    if not dataset_events:
        return

    source_data: Dict[str, Any] = {}
    source_datasets: Dict[str, Dict[str, Any]] = {}
    if source_yml and source_yml.is_file():
        try:
            with open(source_yml, "r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle)
        except (yaml.YAMLError, OSError) as exc:
            print(f"    ! Failed to read source attack data {source_yml}: {exc}")
            return
        if isinstance(loaded, dict):
            source_data = loaded
            source_datasets = {
                ds.get("name"): ds
                for ds in source_data.get("datasets", [])
                if isinstance(ds, dict) and ds.get("name")
            }

    folder = curated_path.parent
    new_entries: List[Dict[str, Any]] = []

    for name, events in dataset_events.items():
        meta = dataset_meta.get(name, {})
        source_ds = source_datasets.get(name, {})
        log_filename = _dataset_log_filename(name, attack_data_uuid)
        out_log = folder / log_filename
        _write_events(out_log, events)
        try:
            path_str = "/" + str(out_log.relative_to(project_root))
        except ValueError:
            path_str = out_log.name

        entry: Dict[str, Any] = {
            "name": name,
            "path": path_str,
            "sourcetype": meta.get("sourcetype") or source_ds.get("sourcetype", ""),
        }
        source = meta.get("source") or source_ds.get("source")
        if source:
            entry["source"] = source
        new_entries.append(entry)

    if curated_path.is_file():
        try:
            with open(curated_path, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except (yaml.YAMLError, OSError) as exc:
            print(f"    ! Failed to read curated YAML {curated_path}: {exc}")
            return
        if not isinstance(data, dict):
            print(f"    ! Unexpected curated YAML structure in {curated_path}")
            return

        existing_names = {
            ds.get("name")
            for ds in data.get("datasets", [])
            if isinstance(ds, dict)
        }
        existing_paths = {
            ds.get("path")
            for ds in data.get("datasets", [])
            if isinstance(ds, dict)
        }
        appended = 0
        for entry in new_entries:
            if entry["name"] in existing_names or entry["path"] in existing_paths:
                continue
            data.setdefault("datasets", []).append(entry)
            existing_names.add(entry["name"])
            existing_paths.add(entry["path"])
            appended += 1
        data["date"] = datetime.now().strftime("%Y-%m-%d")
        data["author"] = ATTACK_DATA_AUTHOR
        print(f"    merged {appended} dataset(s) into {curated_path}")
    else:
        description = ""
        if detection:
            description = (
                f"Curated attack data generated for detection {detection.get('name', '')}"
            )
        elif source_data.get("description"):
            description = str(source_data["description"])
        data = {
            "author": ATTACK_DATA_AUTHOR,
            "id": attack_data_uuid,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "description": description,
            "environment": source_data.get("environment", "attack_range"),
            "directory": folder.name,
            "mitre_technique": (
                _mitre_techniques_from_detection(detection)
                if detection
                else source_data.get("mitre_technique", [])
            ),
            "datasets": new_entries,
        }
        print(f"    created curated attack data YAML: {curated_path} "
              f"({len(new_entries)} dataset(s))")

    try:
        with open(curated_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                data, handle, sort_keys=False, default_flow_style=False,
                allow_unicode=True,
            )
    except OSError as exc:
        print(f"    ! Failed to write curated YAML {curated_path}: {exc}")


def load_attack_data_dataset_meta(yml_file: Path) -> Dict[str, Dict[str, str]]:
    """Return ``{dataset_name: {path, source, sourcetype}}`` from an attack data YAML."""
    _, datasets = parse_attack_data_file(yml_file)
    meta: Dict[str, Dict[str, str]] = {}
    for dataset in datasets:
        name = dataset.get("name")
        if not name:
            continue
        meta[name] = {
            "path": dataset.get("path", ""),
            "source": dataset.get("source", ""),
            "sourcetype": dataset.get("sourcetype", ""),
        }
    return meta


def _resolve_attack_data_yml(project_root: Path, file_rel: str) -> Path:
    yml_abs = Path(file_rel)
    if not yml_abs.is_absolute():
        yml_abs = (project_root / file_rel).resolve()
    return yml_abs


def update_detection_tests_yml(
    detection_file: Path,
    attack_data_entries: List[Dict[str, str]],
) -> bool:
    """Replace a detection YAML's ``tests`` section with matched attack data."""
    if not detection_file.is_file():
        print(f"    ! Cannot update detection tests (not found): {detection_file}")
        return False

    try:
        with open(detection_file, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (yaml.YAMLError, OSError) as exc:
        print(f"    ! Failed to read {detection_file}: {exc}")
        return False
    if not isinstance(data, dict):
        print(f"    ! Unexpected YAML structure in {detection_file}; not updating")
        return False

    data["date"] = datetime.now().strftime("%Y-%m-%d")
    data["tests"] = [
        {
            "name": "True Positive Test",
            "attack_data": attack_data_entries,
        }
    ]

    try:
        with open(detection_file, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                data, handle, sort_keys=False, default_flow_style=False,
                allow_unicode=True,
            )
    except OSError as exc:
        print(f"    ! Failed to write {detection_file}: {exc}")
        return False
    print(f"    updated detection tests: {detection_file} "
          f"({len(attack_data_entries)} dataset(s))")
    return True


def do_update_detection_tests(
    detection_matches: Dict[str, Dict[str, Set[str]]],
    uuid_map: Dict[str, Dict[str, Any]],
    project_root: Path,
) -> Set[str]:
    """Update each detection YAML's tests with attack data that matched it.

    Returns the set of detection file paths that were updated.
    """
    updated_files: Set[str] = set()
    if not detection_matches:
        print("\nNo per-detection matches available; detection tests not updated.")
        return updated_files

    print("\nUpdating detection test attack_data sections")
    for detection_file, file_matches in sorted(detection_matches.items()):
        if not file_matches:
            print(f"  ! WARNING: no attack data matches for {detection_file}; "
                  "leaving detection tests unchanged")
            continue

        attack_data_entries: List[Dict[str, str]] = []
        seen_urls: Set[str] = set()

        for attack_data_uuid, matched_hosts in file_matches.items():
            entry = uuid_map.get(attack_data_uuid)
            if not entry or not matched_hosts:
                continue

            yml_abs = _resolve_attack_data_yml(project_root, entry.get("file", ""))
            if not yml_abs.is_file():
                print(f"    ! Cannot load attack data yml: {yml_abs}")
                continue

            meta_by_name = load_attack_data_dataset_meta(yml_abs)
            for dataset_name, dataset_uuids in entry["datasets"].items():
                if not (matched_hosts & dataset_uuids):
                    continue
                meta = meta_by_name.get(dataset_name)
                if not meta or not meta.get("path") or not meta.get("sourcetype"):
                    print(f"    ! Missing metadata for dataset '{dataset_name}' "
                          f"in {yml_abs}")
                    continue

                data_url = path_to_attack_data_url(meta["path"])
                if data_url in seen_urls:
                    continue
                seen_urls.add(data_url)

                attack_data_entry: Dict[str, str] = {
                    "data": data_url,
                    "sourcetype": meta["sourcetype"],
                }
                if meta.get("source"):
                    attack_data_entry["source"] = meta["source"]
                attack_data_entries.append(attack_data_entry)

        if not attack_data_entries:
            print(f"  ! WARNING: no attack data matches for {detection_file}; "
                  "leaving detection tests unchanged")
            continue

        if update_detection_tests_yml(Path(detection_file), attack_data_entries):
            updated_files.add(detection_file)

    return updated_files


def _detection_display_name(detection_file: str) -> str:
    """Return a human-readable detection label for summary output."""
    path = Path(detection_file)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if isinstance(data, dict) and data.get("name"):
            return str(data["name"])
    except (yaml.YAMLError, OSError):
        pass
    return path.stem


def _status_description(status: str) -> str:
    """Return a short human-readable description for a detection status code."""
    descriptions = {
        "curated": "matched and curated attack data exported",
        "matched": "matched events (no curated output written)",
        "no_matches": "no matches",
        "search_failed": "Splunk search failed",
        "skipped": "skipped (not a valid detection file)",
        "no_tests_urls": "no tests.attack_data URLs found",
        "no_test_datasets": "no resolvable test datasets found",
        "no_source_yml": "no source attack data YAML found",
        "upload_failed": "upload failed",
        "not_run": "not run",
    }
    return descriptions.get(status, status.replace("_", " "))


def _partition_detection_results(
    detection_files: List[Path],
    detection_status: Dict[str, str],
    detection_matched_counts: Dict[str, int],
) -> Tuple[List[Tuple[str, str, str, int]], List[Tuple[str, str, str, int]]]:
    """Split detections into successfully extracted vs failed result tuples."""
    successful: List[Tuple[str, str, str, int]] = []
    failed: List[Tuple[str, str, str, int]] = []

    for det_file in detection_files:
        det_path = str(det_file)
        status = detection_status.get(det_path, "not_run")
        name = _detection_display_name(det_path)
        matched_count = detection_matched_counts.get(det_path, 0)
        entry = (name, det_path, status, matched_count)
        if status in EXTRACTION_SUCCESS_STATUSES:
            successful.append(entry)
        else:
            failed.append(entry)
    return successful, failed


def print_extraction_summary(
    detection_files: List[Path],
    detection_status: Dict[str, str],
    detection_matched_counts: Dict[str, int],
    ignored_detections: Optional[List[Tuple[str, str, str]]] = None,
) -> None:
    """Print successful and failed detection extractions at the end of a run."""
    ignored_detections = ignored_detections or []
    successful, failed = _partition_detection_results(
        detection_files, detection_status, detection_matched_counts
    )

    print("\n" + "=" * 60)
    print(f"SUCCESSFUL EXTRACTIONS ({len(successful)})")
    print("=" * 60)
    if successful:
        for name, path, status, matched_count in sorted(
            successful, key=lambda item: item[0].lower()
        ):
            print(f"  - {name}")
            print(f"    file: {path}")
            print(f"    status: {status}")
            print(f"    matched events: {matched_count}")
    else:
        print("  (none)")

    print("\n" + "=" * 60)
    print(f"FAILED EXTRACTIONS ({len(failed)})")
    print("=" * 60)
    if failed:
        for name, path, status, matched_count in sorted(
            failed, key=lambda item: item[0].lower()
        ):
            print(f"  - {name}")
            print(f"    file: {path}")
            print(f"    status: {status}")
            print(f"    reason: {_status_description(status)}")
            if matched_count:
                print(f"    matched events: {matched_count}")
    else:
        print("  (none)")

    if ignored_detections:
        print("\n" + "=" * 60)
        print(f"IGNORED ({len(ignored_detections)})")
        print("=" * 60)
        for name, path, status in sorted(ignored_detections, key=lambda item: item[0].lower()):
            print(f"  - {name}")
            print(f"    file: {path}")
            print(f"    status: {status}")


def write_migration_run_log(
    log_path: Path,
    detection_files: List[Path],
    detection_status: Dict[str, str],
    detection_matched_counts: Dict[str, int],
    *,
    index: str,
    total_matched: int,
    ignored_detections: Optional[List[Tuple[str, str, str]]] = None,
) -> None:
    """Write a summary log of successful and failed detections from a ``run``."""
    ignored_detections = ignored_detections or []
    successful, failed = _partition_detection_results(
        detection_files, detection_status, detection_matched_counts
    )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"Migrate run log - {timestamp}",
        "=" * 60,
        f"Index: {index}",
        f"Detections processed: {len(detection_files)}",
        f"Ignored (experimental/deprecated): {len(ignored_detections)}",
        f"Successful extractions: {len(successful)}",
        f"Failed extractions: {len(failed)}",
        f"Total matched events: {total_matched}",
        "",
        f"SUCCESSFUL EXTRACTIONS ({len(successful)})",
        "-" * 60,
    ]
    if successful:
        for name, path, status, matched_count in sorted(
            successful, key=lambda item: item[0].lower()
        ):
            lines.extend(
                [
                    f"- {name}",
                    f"  file: {path}",
                    f"  status: {status}",
                    f"  reason: {_status_description(status)}",
                    f"  matched events: {matched_count}",
                    "",
                ]
            )
    else:
        lines.append("  (none)")
        lines.append("")

    lines.extend([f"FAILED EXTRACTIONS ({len(failed)})", "-" * 60])
    if failed:
        for name, path, status, matched_count in sorted(
            failed, key=lambda item: item[0].lower()
        ):
            block = [
                f"- {name}",
                f"  file: {path}",
                f"  status: {status}",
                f"  reason: {_status_description(status)}",
            ]
            if matched_count:
                block.append(f"  matched events: {matched_count}")
            block.append("")
            lines.extend(block)
    else:
        lines.append("  (none)")
        lines.append("")

    if ignored_detections:
        lines.extend([f"IGNORED ({len(ignored_detections)})", "-" * 60])
        for name, path, status in sorted(ignored_detections, key=lambda item: item[0].lower()):
            lines.extend(
                [
                    f"- {name}",
                    f"  file: {path}",
                    f"  status: {status}",
                    "",
                ]
            )

    try:
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines).rstrip() + "\n")
    except OSError as exc:
        print(f"  ! Failed to write run log {log_path}: {exc}")
        return
    print(f"\nRun log written to {log_path}")


def print_not_updated_detections(
    detection_files: List[Path],
    detection_status: Dict[str, str],
    updated_files: Set[str],
    curated_files: Set[str],
    update_detection_tests: bool,
) -> None:
    """Print detections that were not curated or had their tests updated."""
    not_updated: List[Tuple[str, str, str]] = []

    for det_file in detection_files:
        det_path = str(det_file)
        status = detection_status.get(det_path, "not_run")

        if det_path in curated_files:
            if update_detection_tests and det_path not in updated_files:
                reason = "curated_without_test_update"
            else:
                continue
        elif update_detection_tests:
            if det_path in updated_files:
                continue
            if status == "matched":
                reason = "no_attack_data_entries"
            else:
                reason = status
        elif status == "matched":
            reason = "no_curated_output"
        elif status in ("curated",):
            continue
        elif status not in (
            "no_matches",
            "search_failed",
            "skipped",
            "no_tests_urls",
            "no_test_datasets",
            "no_source_yml",
            "upload_failed",
            "not_run",
        ):
            continue
        else:
            reason = status

        name = _detection_display_name(det_path)
        not_updated.append((name, det_path, reason))

    print("\n" + "=" * 60)
    print("DETECTIONS NOT UPDATED")
    print("=" * 60)
    if not not_updated:
        print("  (none)")
        return

    for name, path, reason in sorted(not_updated, key=lambda item: item[0].lower()):
        print(f"  - {name}")
        print(f"    file: {path}")
        print(f"    reason: {reason.replace('_', ' ')}")


def do_export(
    service,
    index: str,
    uuid_map: Dict[str, Dict[str, Any]],
    matched_hosts: Set[str],
    export_dir: Optional[str],
    update_attack_data: bool,
    project_root: Path,
    earliest: str,
    latest: str,
) -> None:
    """Export matched events, one file per dataset.

    For every dataset of every attack data file, the intersection of that
    dataset's uploaded UUIDs with the globally matched hosts is exported to
    ``<export_dir>/<dataset_name>-<attack_data_uuid>.log``. When
    ``update_attack_data`` is set, the curated events are also written into the
    attack data YAML's own folder and the YAML is updated (new date + datasets
    section).
    """
    if not matched_hosts:
        print("\nNo matched host UUIDs to export.")
        for attack_data_uuid, entry in uuid_map.items():
            print(f"  ! WARNING: no detection matches for "
                  f"{entry.get('file', attack_data_uuid)}; "
                  "leaving attack data unchanged (no export)")
        return

    out_dir: Optional[Path] = None
    if export_dir:
        out_dir = Path(export_dir)
        if not out_dir.is_absolute():
            out_dir = (Path.cwd() / out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nExporting matched events per dataset from index={index}")
    total_events = 0
    total_files = 0

    for attack_data_uuid, entry in uuid_map.items():
        # Skip files with no detection hits: no export, no yml update, warn.
        if not (matched_hosts & _file_uuid_set(entry)):
            print(f"  ! WARNING: no detection matches for "
                  f"{entry.get('file', attack_data_uuid)}; "
                  "leaving attack data unchanged (no export)")
            continue

        dataset_events: Dict[str, List[str]] = {}
        for dataset_name, dataset_uuids in entry["datasets"].items():
            hosts = matched_hosts & dataset_uuids
            if not hosts:
                continue

            raw_events = splunk_search.export_events(
                service, index, hosts, earliest_time=earliest, latest_time=latest
            )
            total_events += len(raw_events)
            filename = _dataset_log_filename(dataset_name, attack_data_uuid)
            print(f"  {dataset_name} ({attack_data_uuid}): "
                  f"{len(hosts)} matched host(s), {len(raw_events)} event(s) -> {filename}")

            if out_dir is not None:
                _write_events(out_dir / filename, raw_events)
                total_files += 1
            dataset_events[dataset_name] = raw_events

        if update_attack_data and dataset_events:
            update_attack_data_yml(
                project_root, entry.get("file", ""), attack_data_uuid, dataset_events
            )

    if out_dir is not None:
        print(f"Wrote {total_files} dataset file(s), {total_events} event(s) to {out_dir}")
    elif not update_attack_data:
        print(f"Retrieved {total_events} event(s) "
              "(no --export-dir / --update-attack-data; not written)")


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def add_common_splunk_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", help="Splunk host (default: $SPLUNK_HOST)")
    parser.add_argument(
        "--index", default=DEFAULT_INDEX,
        help=f"Target Splunk index (default: {DEFAULT_INDEX})",
    )


def add_hec_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hec-token", help="HEC token (default: $SPLUNK_HEC_TOKEN)")
    parser.add_argument(
        "--hec-port", help=f"HEC port (default: $SPLUNK_HEC_PORT or {DEFAULT_HEC_PORT})"
    )
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE,
        help="Events per HEC request; use 1 for one request per line "
        f"(default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--verify-tls", action="store_true",
        help="Verify the Splunk TLS certificate (disabled by default)",
    )


def add_search_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--username", help="Splunk user (default: $SPLUNK_USERNAME)")
    parser.add_argument("--password", help="Splunk password (default: $SPLUNK_PASSWORD)")
    parser.add_argument(
        "--mgmt-port",
        help=f"Splunk management port (default: $SPLUNK_PORT or {DEFAULT_MGMT_PORT})",
    )
    parser.add_argument(
        "--earliest", default=splunk_search.DEFAULT_EARLIEST,
        help="Search earliest time (default: 0 / all time)",
    )
    parser.add_argument(
        "--latest", default=splunk_search.DEFAULT_LATEST,
        help="Search latest time (default: now)",
    )
    parser.add_argument(
        "--verify-ssl", action="store_true",
        help="Verify the Splunk TLS certificate for searches (disabled by default)",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # upload
    p_upload = sub.add_parser("upload", help="Upload attack data to Splunk HEC")
    p_upload.add_argument(
        "--attack-data", required=True,
        help="Attack data YAML file or folder to upload",
    )
    add_common_splunk_args(p_upload)
    add_hec_args(p_upload)

    # run (upload + detect + export)
    p_run = sub.add_parser(
        "run", help="Upload, run detections, and export matching events"
    )
    p_run.add_argument(
        "--attack-data-root", "--attack-data",
        dest="attack_data_root",
        default="datasets",
        help="Root folder for resolving detection test URLs to local attack data "
        "(default: datasets). Use e.g. scripts/attack_technique_tests for alternate "
        "layouts.",
    )
    p_run.add_argument(
        "--detection", required=True,
        help="Detection YAML file or folder (security_content)",
    )
    p_run.add_argument(
        "--start-from-detection-id",
        help="Resume processing at this detection UUID (inclusive, alphabetical order)",
    )
    p_run.add_argument(
        "--export-dir",
        help="Optional folder for extra exported log copies",
    )
    p_run.add_argument(
        "--update-attack-data", action="store_true",
        help="(Legacy) Also mutate source attack data YAML files in place",
    )
    p_run.add_argument(
        "--update-detection-tests", action="store_true",
        help="Update each detection YAML's tests section with attack data that "
        "matched that detection",
    )
    p_run.add_argument(
        "--no-delete", action="store_true",
        help="Do not run 'index=<index> | delete' to clean up the index after "
        "the run (cleanup is on by default)",
    )
    p_run.add_argument(
        "--index-wait", type=int, default=DEFAULT_INDEX_WAIT_SECONDS,
        help="Seconds to wait after HEC upload before running detection searches, "
        f"so Splunk can index events (default: {DEFAULT_INDEX_WAIT_SECONDS}; 0 to disable)",
    )
    p_run.add_argument(
        "--run-log", default=DEFAULT_RUN_LOG,
        help=f"Write a success/failure summary log to this file (default: {DEFAULT_RUN_LOG})",
    )
    add_common_splunk_args(p_run)
    add_hec_args(p_run)
    add_search_args(p_run)

    return parser.parse_args()


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #
def resolve_attack_data_files(raw_path: str, project_root: Path) -> List[Path]:
    path = Path(raw_path)
    if not path.is_absolute():
        candidate = (Path.cwd() / path)
        path = candidate if candidate.exists() else (project_root / raw_path)
    files = find_attack_data_files(path)
    if not files:
        print(f"Error: no attack data files found at {path}")
        sys.exit(1)
    return files


def resolve_detection_files(raw_path: str) -> List[Path]:
    files = detection_utils.find_detection_files(raw_path)
    if not files:
        print(f"Error: no detection files found at {raw_path}")
        sys.exit(1)
    return files


def cmd_upload(args: argparse.Namespace) -> None:
    project_root = get_project_root()
    try:
        hec_config = load_hec_config(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    if args.batch_size < 1:
        print("Error: --batch-size must be >= 1")
        sys.exit(1)

    yaml_files = resolve_attack_data_files(args.attack_data, project_root)
    store = memory_store.MigrationStore()
    print(f"Uploading to Splunk HEC at {hec_config['host']}:{hec_config['port']} "
          f"(index={args.index})")
    print(f"Found {len(yaml_files)} attack data file(s)")

    do_upload(
        yaml_files=yaml_files,
        store=store,
        hec_config=hec_config,
        project_root=project_root,
        index=args.index,
        batch_size=args.batch_size,
        verify_tls=args.verify_tls,
    )


def cmd_run(args: argparse.Namespace) -> None:
    project_root = get_project_root()
    if args.batch_size < 1:
        print("Error: --batch-size must be >= 1")
        sys.exit(1)

    try:
        mgmt_config = load_mgmt_config(args)
        hec_config = load_hec_config(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    all_detection_files = resolve_detection_files(args.detection)
    detection_files = filter_detections_from_id(
        all_detection_files,
        args.start_from_detection_id,
    )
    detection_files, ignored_detections = filter_runnable_detections(detection_files)
    attack_data_root = resolve_attack_data_root(args.attack_data_root, project_root)
    store = memory_store.MigrationStore()
    print(f"Attack data root: {attack_data_root}")
    if ignored_detections:
        print(f"Ignoring {len(ignored_detections)} detection(s) "
              f"with status experimental or deprecated:")
        for name, path, status in ignored_detections:
            print(f"  - {name} ({path}): status={status}")
    print(f"Processing {len(detection_files)} detection(s) in alphabetical order")

    if not args.verify_ssl:
        disable_warnings()
    service = splunk_search.connect(
        host=mgmt_config["host"],
        port=mgmt_config["port"],
        username=mgmt_config["username"],
        password=mgmt_config["password"],
        verify_ssl=args.verify_ssl,
    )

    hec_session: Optional[requests.Session] = None
    hec_url: Optional[str] = None
    if not args.verify_tls:
        disable_warnings()
    hec_session = requests.Session()
    hec_url = build_hec_url(hec_config)

    detection_status: Dict[str, str] = {}
    detection_matched_counts: Dict[str, int] = {}
    updated_detection_files: Set[str] = set()
    curated_detection_files: Set[str] = set()
    total_matched = 0
    test_dataset_count = 0

    for det_file in detection_files:
        detection = detection_utils.load_full_detection(det_file)
        det_path = str(det_file)
        print("\n" + "=" * 60)
        if detection:
            print(f"Detection: {detection['name']} ({det_path})")
        else:
            print(f"Detection: {det_path}")

        if not detection:
            detection_status[det_path] = "skipped"
            continue

        test_entries = detection_utils.parse_detection_tests(detection)
        if not test_entries:
            print("  ! No tests.attack_data URLs found; skipping")
            detection_status[det_path] = "no_tests_urls"
            continue

        dataset_specs = resolve_detection_test_datasets(
            detection, project_root, attack_data_root
        )
        if not dataset_specs:
            detection_status[det_path] = "no_test_datasets"
            continue
        test_dataset_count += len(dataset_specs)

        uuid_map = upload_detection_test_datasets(
            dataset_specs=dataset_specs,
            session=hec_session,
            url=hec_url,
            store=store,
            hec_config=hec_config,
            project_root=project_root,
            index=args.index,
            batch_size=args.batch_size,
            verify_tls=args.verify_tls,
        )

        if not any(entry["datasets"] for entry in uuid_map.values()):
            print("  ! No event UUIDs uploaded for this detection; skipping")
            detection_status[det_path] = "upload_failed"
            continue

        if args.index_wait > 0:
            print(f"  Waiting {args.index_wait}s for Splunk indexing...")
            time.sleep(args.index_wait)

        matched, _, status = run_single_detection(
            detection_file=det_file,
            service=service,
            store=store,
            uuid_map=uuid_map,
            earliest=args.earliest,
            latest=args.latest,
        )
        detection_status[det_path] = status
        detection_matched_counts[det_path] = len(matched)
        total_matched += len(matched)

        if status == "matched":
            curated = export_and_curate_detection(
                service=service,
                index=args.index,
                uuid_map=uuid_map,
                matched_hosts=matched,
                export_dir=args.export_dir,
                project_root=project_root,
                earliest=args.earliest,
                latest=args.latest,
                detection=detection,
            )
            if curated:
                detection_status[det_path] = "curated"
                curated_detection_files.add(det_path)

            if args.update_attack_data:
                do_export(
                    service=service,
                    index=args.index,
                    uuid_map=uuid_map,
                    matched_hosts=matched,
                    export_dir=None,
                    update_attack_data=True,
                    project_root=project_root,
                    earliest=args.earliest,
                    latest=args.latest,
                )

            if args.update_detection_tests:
                matched_dataset_names: Set[str] = set()
                for entry in uuid_map.values():
                    for dataset_name, dataset_uuids in entry["datasets"].items():
                        if matched & dataset_uuids:
                            matched_dataset_names.add(dataset_name)
                attack_data_entries = build_attack_data_entries_from_uuid_map(
                    uuid_map, matched_dataset_names, project_root
                )
                if attack_data_entries and update_detection_tests_yml(
                    det_file, attack_data_entries
                ):
                    updated_detection_files.add(det_path)

        if not args.no_delete:
            deleted = splunk_search.delete_index_data(service, args.index)
            print(f"    deleted {deleted} event(s) from index={args.index}")

    print("\n" + "=" * 60)
    print("PIPELINE SUMMARY")
    print("=" * 60)
    print(f"Detections processed: {len(detection_files)}")
    print(f"Test datasets referenced: {test_dataset_count}")
    print(f"Curated detections:    {len(curated_detection_files)}")
    print(f"Total matched events:  {total_matched}")

    print_extraction_summary(
        detection_files=detection_files,
        detection_status=detection_status,
        detection_matched_counts=detection_matched_counts,
        ignored_detections=ignored_detections,
    )

    print_not_updated_detections(
        detection_files=detection_files,
        detection_status=detection_status,
        updated_files=updated_detection_files,
        curated_files=curated_detection_files,
        update_detection_tests=args.update_detection_tests,
    )

    run_log_path = Path(args.run_log)
    if not run_log_path.is_absolute():
        run_log_path = (Path.cwd() / run_log_path).resolve()
    write_migration_run_log(
        run_log_path,
        detection_files,
        detection_status,
        detection_matched_counts,
        index=args.index,
        total_matched=total_matched,
        ignored_detections=ignored_detections,
    )


def main() -> None:
    args = parse_arguments()
    load_env()
    if args.command == "upload":
        cmd_upload(args)
    elif args.command == "run":
        cmd_run(args)
    else:  # pragma: no cover - argparse enforces valid commands
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
