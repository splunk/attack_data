#!/usr/bin/env python3
"""
In-memory store for the attack_data -> Splunk pipeline.

Records, per attack data file:
  * the individual event UUIDs uploaded (the ``host`` value of every event), and
  * which of those event UUIDs were matched by which security_content detection.

State lives only for the lifetime of the current process.
"""

from typing import Any, Dict, List, Set


class MigrationStore:
    """Process-local store for upload and detection attribution data."""

    def __init__(self) -> None:
        self._uploads: Dict[str, Dict[str, Any]] = {}
        self._detection_matches: Dict[str, Dict[str, Set[str]]] = {}

    def store_upload(
        self,
        attack_data_uuid: str,
        attack_data_file: str,
        dataset_name: str,
        source: str,
        sourcetype: str,
        index_name: str,
        event_uuids: List[str],
    ) -> None:
        """Record the event UUIDs uploaded for one dataset of an attack data file."""
        if not event_uuids:
            return
        entry = self._uploads.setdefault(
            attack_data_uuid,
            {"file": attack_data_file, "datasets": {}},
        )
        entry["file"] = attack_data_file
        entry["datasets"].setdefault(dataset_name, set()).update(event_uuids)

    def store_detection_result(
        self,
        attack_data_uuid: str,
        detection_id: str,
        detection_name: str,
        detection_file: str,
        matched_host_uuids: List[str],
    ) -> None:
        """Record which event UUIDs of an attack data file a detection matched."""
        if not matched_host_uuids:
            return
        self._detection_matches.setdefault(detection_file, {}).setdefault(
            attack_data_uuid, set()
        ).update(matched_host_uuids)

    def get_event_uuids_for_attack_data(self, attack_data_uuid: str) -> Set[str]:
        """Return all uploaded event UUIDs recorded for an attack data file."""
        uuids: Set[str] = set()
        for dataset_uuids in self.get_uploads_for_attack_data(attack_data_uuid).values():
            uuids.update(dataset_uuids)
        return uuids

    def get_uploads_for_attack_data(
        self, attack_data_uuid: str
    ) -> Dict[str, Set[str]]:
        """Return {dataset_name: {event_uuids}} recorded for an attack data file."""
        entry = self._uploads.get(attack_data_uuid, {})
        datasets = entry.get("datasets", {})
        return {name: set(uuids) for name, uuids in datasets.items()}

    def get_all_uploads(self) -> Dict[str, Dict[str, Any]]:
        """Return the per-dataset UUID map for all uploaded attack data files."""
        uploads: Dict[str, Dict[str, Any]] = {}
        for attack_data_uuid, entry in self._uploads.items():
            uploads[attack_data_uuid] = {
                "file": entry.get("file", ""),
                "datasets": {
                    name: set(uuids)
                    for name, uuids in entry.get("datasets", {}).items()
                },
            }
        return uploads

    def get_all_matched_host_uuids(self) -> Set[str]:
        """Return the union of all detection-matched host UUIDs."""
        uuids: Set[str] = set()
        for file_matches in self._detection_matches.values():
            for matched in file_matches.values():
                uuids.update(matched)
        return uuids

    def get_all_detection_matches(self) -> Dict[str, Dict[str, Set[str]]]:
        """Return per-detection attribution."""
        return {
            detection_file: {
                attack_data_uuid: set(matched)
                for attack_data_uuid, matched in file_matches.items()
            }
            for detection_file, file_matches in self._detection_matches.items()
        }

    def clear(self) -> int:
        """Clear all stored data. Returns the number of upload records removed."""
        removed = len(self._uploads)
        self._uploads.clear()
        self._detection_matches.clear()
        return removed
