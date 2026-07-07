#!/usr/bin/env python3
"""
Attack Data -> Splunk pipeline.

A three-stage pipeline for validating Splunk security_content detections
against attack_data datasets:

  1. upload  Split each dataset log file line-by-line, assign every line its own
             UUID, and upload each event to Splunk HEC with that UUID as the
             ``host``. The UUID map is stored in DynamoDB (not the filesystem).

  2. detect  Run security_content detections (rewritten so ``host`` is an output
             field) against the uploaded data. The event UUIDs each detection
             matches are attributed back to their attack data file and stored in
             DynamoDB.

  3. export  Export only the events that produced detection results using
             ``index=<index> host IN (uuid1, uuid2, ...)``.

The ``run`` subcommand performs all three stages in one pass. ``upload`` and
``export`` are also available standalone. Both ``--attack-data`` and
``--detection`` accept either a single file or a folder (searched recursively).

Connection settings (CLI flags override environment variables):
    SPLUNK_HOST        Splunk hostname/IP                (required)
    SPLUNK_HEC_TOKEN   HEC token for uploading           (required for upload)
    SPLUNK_HEC_PORT    HEC port                          (default: 8088)
    SPLUNK_USERNAME    Splunk user for searching         (required for detect/export)
    SPLUNK_PASSWORD    Splunk password for searching     (required for detect/export)
    SPLUNK_PORT        Splunk management port            (default: 8089)
    DYNAMODB_TABLE     DynamoDB table name               (default: attack_data_map)
    AWS_REGION         AWS region for DynamoDB           (optional)

DynamoDB table setup (create it manually once):
    aws dynamodb create-table \\
        --table-name attack_data_map \\
        --attribute-definitions AttributeName=pk,AttributeType=S \\
                                AttributeName=sk,AttributeType=S \\
        --key-schema AttributeName=pk,KeyType=HASH \\
                     AttributeName=sk,KeyType=RANGE \\
        --billing-mode PAY_PER_REQUEST \\
        --region <your-region>

Examples:
    # Full pipeline: one attack data file + one detection
    python scripts/migrate.py run \\
        --attack-data datasets/malware/qakbot/qakbot.yml \\
        --detection ~/security_content/detections/endpoint/some_detection.yml \\
        --export-dir exported

    # Full pipeline over whole folders
    python scripts/migrate.py run \\
        --attack-data datasets/malware/qakbot \\
        --detection ~/security_content/detections/endpoint \\
        --export-dir exported

    # Minimize datasets in place: save curated logs next to each YAML and
    # update the YAML (new date + datasets section)
    python scripts/migrate.py run \\
        --attack-data datasets/malware/qakbot \\
        --detection ~/security_content/detections/endpoint \\
        --update-attack-data

    # Upload only
    python scripts/migrate.py upload --attack-data datasets/malware/qakbot

    # Export previously-matched events recorded in DynamoDB (one file per dataset)
    python scripts/migrate.py export --export-dir exported
"""

import argparse
import json
import os
import re
import sys
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import requests
import yaml
from urllib3 import disable_warnings

import dynamo_utils
import detection_utils
import splunk_search

DEFAULT_INDEX = "test"
DEFAULT_HEC_PORT = "8088"
DEFAULT_MGMT_PORT = "8089"
DEFAULT_BATCH_SIZE = 500


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def get_project_root() -> Path:
    """Return the repository root (the parent of the scripts/ directory)."""
    return Path(__file__).resolve().parent.parent


def load_env() -> None:
    """Load environment variables from a .env file if one is present.

    Looks for a .env file next to this script first, then at the repository
    root. Existing environment variables are not overridden, so real shell
    variables always win over the .env file.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        print("Warning: python-dotenv not installed; skipping .env loading")
        return
    script_dir = Path(__file__).resolve().parent
    for candidate in (script_dir / ".env", get_project_root() / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
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


def get_dynamo_table(args: argparse.Namespace):
    """Return the configured DynamoDB table resource."""
    table_name = (
        args.dynamodb_table
        or os.environ.get("DYNAMODB_TABLE")
        or dynamo_utils.DEFAULT_TABLE_NAME
    )
    region = args.aws_region or os.environ.get("AWS_REGION")
    return dynamo_utils.get_table(table_name, region), table_name


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
    """Split a dataset file line-by-line, upload each line with its own UUID host."""
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

    for line in iter_event_lines(file_path):
        event_uuid = str(uuid.uuid4())
        batch.append(
            {
                "event": line,
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
    table,
    yml_file: Path,
    project_root: Path,
    config: Dict[str, str],
    index: str,
    batch_size: int,
    verify_tls: bool,
) -> Tuple[Optional[str], str, Dict[str, Set[str]], int, int]:
    """Upload every dataset in one attack data file; record the UUID map in DynamoDB.

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

        dynamo_utils.store_upload(
            table=table,
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
    table,
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
            table=table,
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
          f"{len(uuid_map)} attack data file(s) mapped in DynamoDB")
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
    table,
    uuid_map: Dict[str, Dict[str, Any]],
    index: str,
    earliest: str,
    latest: str,
) -> Set[str]:
    """Run detections, attribute matched hosts to attack data files, store in DynamoDB.

    Returns the global set of matched host UUIDs (across all detections).
    """
    all_matched: Set[str] = set()
    our_uuids: Set[str] = set()
    for entry in uuid_map.values():
        our_uuids.update(_file_uuid_set(entry))

    print(f"\nRunning {len(detection_files)} detection(s) over index={index} "
          f"(earliest={earliest}, latest={latest})")

    for det_file in detection_files:
        detection = detection_utils.parse_detection_file(det_file)
        if not detection:
            print(f"  ! Skipping non-detection file: {det_file}")
            continue

        patched = detection_utils.add_host_output_field(detection["search"])
        print(f"\n  Detection: {detection['name']}")
        try:
            rows = splunk_search.run_search(
                service, patched, earliest_time=earliest, latest_time=latest
            )
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"    x Search failed: {exc}")
            continue

        matched_hosts = splunk_search.collect_hosts_from_rows(rows)
        # Restrict to hosts we uploaded (ignore any pre-existing data in the index).
        matched_hosts &= our_uuids
        print(f"    results: {len(rows)} row(s), {len(matched_hosts)} matched host(s)")

        if not matched_hosts:
            continue
        all_matched.update(matched_hosts)

        # Attribute matched hosts back to each attack data file.
        for attack_data_uuid, entry in uuid_map.items():
            attributed = sorted(matched_hosts & _file_uuid_set(entry))
            if not attributed:
                continue
            dynamo_utils.store_detection_result(
                table=table,
                attack_data_uuid=attack_data_uuid,
                detection_id=detection.get("id", ""),
                detection_name=detection["name"],
                detection_file=detection["file"],
                matched_host_uuids=attributed,
            )
            print(f"      {attack_data_uuid}: {len(attributed)} matched event(s)")

    return all_matched


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def _safe_filename(text: str) -> str:
    """Make a dataset name safe to use as a filename component."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "dataset"


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
    ``<yml_folder>/<dataset_name>_<attack_data_uuid>.log``. The attack data YAML
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
        out_file = folder / f"{_safe_filename(name)}_{attack_data_uuid}.log"
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
    ``<export_dir>/<dataset_name>_<attack_data_uuid>.log``. When
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
            filename = f"{_safe_filename(dataset_name)}_{attack_data_uuid}.log"
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
    parser.add_argument(
        "--dynamodb-table",
        help="DynamoDB table name (default: $DYNAMODB_TABLE or "
        f"{dynamo_utils.DEFAULT_TABLE_NAME})",
    )
    parser.add_argument("--aws-region", help="AWS region (default: $AWS_REGION)")


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
        "--attack-data", required=True,
        help="Attack data YAML file or folder",
    )
    p_run.add_argument(
        "--detection", required=True,
        help="Detection YAML file or folder (security_content)",
    )
    p_run.add_argument(
        "--export-dir",
        help="Folder to write exported logs, one file per dataset named "
        "<dataset_name>_<attack_data_uuid>.log",
    )
    p_run.add_argument(
        "--update-attack-data", action="store_true",
        help="Save curated logs into each attack data YAML's own folder and "
        "update the YAML (new date + datasets section)",
    )
    p_run.add_argument(
        "--skip-upload", action="store_true",
        help="Skip uploading (reuse event UUIDs already in DynamoDB)",
    )
    p_run.add_argument(
        "--no-delete", action="store_true",
        help="Do not run 'index=<index> | delete' to clean up after each "
        "attack data file (cleanup is on by default)",
    )
    add_common_splunk_args(p_run)
    add_hec_args(p_run)
    add_search_args(p_run)

    # export
    p_export = sub.add_parser(
        "export", help="Export events matched by detections (from DynamoDB)"
    )
    p_export.add_argument(
        "--export-dir",
        help="Folder to write exported logs, one file per dataset named "
        "<dataset_name>_<attack_data_uuid>.log",
    )
    p_export.add_argument(
        "--update-attack-data", action="store_true",
        help="Save curated logs into each attack data YAML's own folder and "
        "update the YAML (new date + datasets section)",
    )
    add_common_splunk_args(p_export)
    add_search_args(p_export)

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
    table, table_name = get_dynamo_table(args)
    print(f"Uploading to Splunk HEC at {hec_config['host']}:{hec_config['port']} "
          f"(index={args.index}); DynamoDB table={table_name}")
    print(f"Found {len(yaml_files)} attack data file(s)")

    do_upload(
        yaml_files=yaml_files,
        table=table,
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
        if not args.skip_upload:
            hec_config = load_hec_config(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    yaml_files = resolve_attack_data_files(args.attack_data, project_root)
    detection_files = resolve_detection_files(args.detection)
    table, table_name = get_dynamo_table(args)
    print(f"DynamoDB table={table_name}")

    # Stage 1: upload every attack data file first, building the full UUID map.
    if args.skip_upload:
        print("\nSkipping upload; loading event UUIDs from DynamoDB")
        uuid_map: Dict[str, Dict[str, Any]] = {}
        for yml_file in yaml_files:
            file_id, _ = parse_attack_data_file(yml_file)
            if not file_id:
                continue
            datasets = dynamo_utils.get_uploads_for_attack_data(table, file_id)
            uuid_map[file_id] = {
                "file": _relative(yml_file, project_root),
                "datasets": datasets,
            }
            total = sum(len(u) for u in datasets.values())
            print(f"  {file_id}: {len(datasets)} dataset(s), {total} event UUID(s)")
    else:
        uuid_map = do_upload(
            yaml_files=yaml_files,
            table=table,
            hec_config=hec_config,
            project_root=project_root,
            index=args.index,
            batch_size=args.batch_size,
            verify_tls=args.verify_tls,
        )

    if not any(entry["datasets"] for entry in uuid_map.values()):
        print("No uploaded event UUIDs available; aborting.")
        sys.exit(1)

    if not args.verify_ssl:
        disable_warnings()
    service = splunk_search.connect(
        host=mgmt_config["host"],
        port=mgmt_config["port"],
        username=mgmt_config["username"],
        password=mgmt_config["password"],
        verify_ssl=args.verify_ssl,
    )

    # Stage 2: run all detections once over the whole index. do_detect attributes
    # each matched host UUID back to its attack data file via the UUID map.
    matched = do_detect(
        detection_files=detection_files,
        service=service,
        table=table,
        uuid_map=uuid_map,
        index=args.index,
        earliest=args.earliest,
        latest=args.latest,
    )

    # Stage 3: export only the events with detection hits, per dataset/file.
    do_export(
        service=service,
        index=args.index,
        uuid_map=uuid_map,
        matched_hosts=matched,
        export_dir=args.export_dir,
        update_attack_data=args.update_attack_data,
        project_root=project_root,
        earliest=args.earliest,
        latest=args.latest,
    )

    # Stage 4: clean up the index once everything has been detected and exported.
    do_cleanup = not args.no_delete and not args.skip_upload
    if args.skip_upload and not args.no_delete:
        print("\nNote: --skip-upload set; index cleanup skipped")
    if do_cleanup:
        deleted = splunk_search.delete_index_data(service, args.index)
        print(f"\nCleanup: deleted {deleted} event(s) from index={args.index}")

    print("\n" + "=" * 60)
    print("PIPELINE SUMMARY")
    print("=" * 60)
    print(f"Attack data files: {len(uuid_map)}")
    print(f"Detections run:    {len(detection_files)}")
    print(f"Matched events:    {len(matched)}")


def cmd_export(args: argparse.Namespace) -> None:
    project_root = get_project_root()
    try:
        mgmt_config = load_mgmt_config(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    table, table_name = get_dynamo_table(args)
    print(f"DynamoDB table={table_name}")
    uuid_map = dynamo_utils.get_all_uploads(table)
    matched = dynamo_utils.get_all_matched_host_uuids(table)
    print(f"Found {len(uuid_map)} attack data file(s) and "
          f"{len(matched)} matched host UUID(s) in DynamoDB")

    if not args.verify_ssl:
        disable_warnings()
    service = splunk_search.connect(
        host=mgmt_config["host"],
        port=mgmt_config["port"],
        username=mgmt_config["username"],
        password=mgmt_config["password"],
        verify_ssl=args.verify_ssl,
    )
    do_export(
        service=service,
        index=args.index,
        uuid_map=uuid_map,
        matched_hosts=matched,
        export_dir=args.export_dir,
        update_attack_data=args.update_attack_data,
        project_root=project_root,
        earliest=args.earliest,
        latest=args.latest,
    )


def main() -> None:
    args = parse_arguments()
    load_env()
    if args.command == "upload":
        cmd_upload(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "export":
        cmd_export(args)
    else:  # pragma: no cover - argparse enforces valid commands
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
