#!/usr/bin/env python3
"""
DynamoDB store for the attack_data -> Splunk pipeline.

This module replaces the filesystem UUID map. It records, per attack data file:
  * the individual event UUIDs that were uploaded (the ``host`` value of every
    single-line event), and
  * which of those event UUIDs were matched by which security_content
    detection.

Single-table design (create the table manually, see README/instructions):

    Table name : configurable (default "attack_data_map")
    Partition  : pk (String)
    Sort key   : sk (String)
    Billing    : PAY_PER_REQUEST (on-demand) recommended

Item layouts
------------
Upload record (event UUIDs are chunked to stay under the 400 KB item limit):
    pk = "ATTACK_DATA#<attack_data_uuid>"
    sk = "DATASET#<dataset_name>#<chunk_index:05d>"
    record_type      = "upload"
    attack_data_uuid, attack_data_file, dataset_name,
    source, sourcetype, index_name, chunk_index, event_count,
    event_uuids      = [<uuid>, ...]

Detection result record (matched host UUIDs are chunked the same way):
    pk = "ATTACK_DATA#<attack_data_uuid>"
    sk = "DETECTION#<detection_id>#<chunk_index:05d>"
    record_type      = "detection_result"
    attack_data_uuid, detection_id, detection_name, detection_file,
    chunk_index, matched_count, updated_at,
    matched_host_uuids = [<uuid>, ...]

Because uploads and detection results for the same attack data file share the
same partition key, a single Query on ``pk`` returns everything about that
file.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import boto3
from boto3.dynamodb.conditions import Attr, Key

DEFAULT_TABLE_NAME = "attack_data_map"
RECORD_UPLOAD = "upload"
RECORD_DETECTION = "detection_result"

# Keep list attributes well under the 400 KB DynamoDB item size limit.
# ~40 bytes per UUID -> 5000 UUIDs is roughly 200 KB.
CHUNK_SIZE = 5000

ATTACK_DATA_PREFIX = "ATTACK_DATA#"


def get_table(table_name: str, region: Optional[str] = None):
    """Return a boto3 DynamoDB Table resource."""
    kwargs = {"region_name": region} if region else {}
    resource = boto3.resource("dynamodb", **kwargs)
    return resource.Table(table_name)


def _chunk(items: List[str], size: int = CHUNK_SIZE) -> Iterable[Tuple[int, List[str]]]:
    for index in range(0, len(items), size):
        yield index // size, items[index : index + size]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def store_upload(
    table,
    attack_data_uuid: str,
    attack_data_file: str,
    dataset_name: str,
    source: str,
    sourcetype: str,
    index_name: str,
    event_uuids: List[str],
) -> None:
    """Persist the event UUIDs uploaded for one dataset of an attack data file."""
    if not event_uuids:
        return
    pk = f"{ATTACK_DATA_PREFIX}{attack_data_uuid}"
    with table.batch_writer() as batch:
        for chunk_index, chunk in _chunk(event_uuids):
            batch.put_item(
                Item={
                    "pk": pk,
                    "sk": f"DATASET#{dataset_name}#{chunk_index:05d}",
                    "record_type": RECORD_UPLOAD,
                    "attack_data_uuid": attack_data_uuid,
                    "attack_data_file": attack_data_file,
                    "dataset_name": dataset_name,
                    "source": source,
                    "sourcetype": sourcetype,
                    "index_name": index_name,
                    "chunk_index": chunk_index,
                    "event_count": len(chunk),
                    "event_uuids": chunk,
                }
            )


def store_detection_result(
    table,
    attack_data_uuid: str,
    detection_id: str,
    detection_name: str,
    detection_file: str,
    matched_host_uuids: List[str],
) -> None:
    """Persist which event UUIDs of an attack data file a detection matched."""
    if not matched_host_uuids:
        return
    pk = f"{ATTACK_DATA_PREFIX}{attack_data_uuid}"
    safe_id = detection_id or detection_name
    updated_at = _now_iso()
    with table.batch_writer() as batch:
        for chunk_index, chunk in _chunk(matched_host_uuids):
            batch.put_item(
                Item={
                    "pk": pk,
                    "sk": f"DETECTION#{safe_id}#{chunk_index:05d}",
                    "record_type": RECORD_DETECTION,
                    "attack_data_uuid": attack_data_uuid,
                    "detection_id": detection_id,
                    "detection_name": detection_name,
                    "detection_file": detection_file,
                    "chunk_index": chunk_index,
                    "matched_count": len(chunk),
                    "updated_at": updated_at,
                    "matched_host_uuids": chunk,
                }
            )


def get_event_uuids_for_attack_data(table, attack_data_uuid: str) -> Set[str]:
    """Return all uploaded event UUIDs recorded for an attack data file."""
    uuids: Set[str] = set()
    for dataset_uuids in get_uploads_for_attack_data(table, attack_data_uuid).values():
        uuids.update(dataset_uuids)
    return uuids


def get_uploads_for_attack_data(
    table, attack_data_uuid: str
) -> Dict[str, Set[str]]:
    """Return {dataset_name: {event_uuids}} recorded for an attack data file."""
    pk = f"{ATTACK_DATA_PREFIX}{attack_data_uuid}"
    datasets: Dict[str, Set[str]] = {}
    kwargs = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("DATASET#"),
    }
    while True:
        resp = table.query(**kwargs)
        for item in resp.get("Items", []):
            name = item.get("dataset_name", "unknown")
            datasets.setdefault(name, set()).update(item.get("event_uuids", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return datasets


def get_all_uploads(table) -> Dict[str, Dict[str, Any]]:
    """Scan all upload records and return the per-dataset UUID map.

    Returns::

        { attack_data_uuid: {
            "file": <attack_data_file>,
            "datasets": { dataset_name: {event_uuids} },
        } }
    """
    uploads: Dict[str, Dict[str, Any]] = {}
    kwargs = {"FilterExpression": Attr("record_type").eq(RECORD_UPLOAD)}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            attack_data_uuid = item.get("attack_data_uuid")
            if not attack_data_uuid:
                continue
            entry = uploads.setdefault(
                attack_data_uuid,
                {"file": item.get("attack_data_file", ""), "datasets": {}},
            )
            name = item.get("dataset_name", "unknown")
            entry["datasets"].setdefault(name, set()).update(
                item.get("event_uuids", [])
            )
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return uploads


def get_all_matched_host_uuids(table) -> Set[str]:
    """Scan the table and return the union of all detection-matched host UUIDs."""
    uuids: Set[str] = set()
    kwargs = {
        "FilterExpression": Attr("record_type").eq(RECORD_DETECTION),
    }
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            uuids.update(item.get("matched_host_uuids", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return uuids


def get_all_detection_matches(table) -> Dict[str, Dict[str, Set[str]]]:
    """Scan detection results and return per-detection attribution.

    Returns::

        { detection_file: { attack_data_uuid: {matched_host_uuids} } }
    """
    matches: Dict[str, Dict[str, Set[str]]] = {}
    kwargs = {
        "FilterExpression": Attr("record_type").eq(RECORD_DETECTION),
    }
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            detection_file = item.get("detection_file", "")
            attack_data_uuid = item.get("attack_data_uuid", "")
            if not detection_file or not attack_data_uuid:
                continue
            matches.setdefault(detection_file, {}).setdefault(
                attack_data_uuid, set()
            ).update(item.get("matched_host_uuids", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return matches
