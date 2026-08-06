#!/usr/bin/env python3
"""
Pydantic models and shared constants for the datasets archive (attack_data_archive/).

Used by build_dataset_archive.py to generate metadata.yml, and by any tool
that reads the archive back (e.g. fetch_archived_dataset.py).
"""

import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import yaml
    from pydantic import BaseModel, Field, field_serializer
except ImportError as exc:
    sys.exit(f"Error: missing dependency ({exc}). Install with: pip install -r bin/requirements.txt")

OUTPUT_DIR_NAME = "attack_data_archive"
ARCHIVE_FILE_NAME = "attack_data_archive.zip"
METADATA_FILE_NAME = "metadata.yml"


def _as_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime as a UTC ISO-8601 string ending in 'Z', or None if dt is None."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


class LfsFileEntry(BaseModel):
    """Details for a single git-lfs-tracked file, keyed by its download URL in metadata.yml."""

    relative_path: str
    uncompressed_size: int
    last_updated: Optional[datetime] = Field(default=None, alias="last-updated")

    model_config = {"populate_by_name": True}

    @field_serializer("last_updated", when_used="json")
    def _serialize_last_updated(self, value: Optional[datetime]) -> Optional[str]:
        """Serialize last_updated as a UTC ISO-8601 string."""
        return _as_utc_iso(value)


class Metadata(BaseModel):
    """Contents of metadata.yml: generation info, and the LFS/non-LFS file listing."""

    generated_at_utc: datetime
    file_count: int
    gitref: str
    github_url: str
    total_uncompressed_size_bytes: int
    lfs_files: Dict[str, LfsFileEntry] = Field(default_factory=dict, alias="lfs-files")
    non_lfs_files: List[str] = Field(default_factory=list, alias="non-lfs-files")

    model_config = {"populate_by_name": True}

    @field_serializer("generated_at_utc", when_used="json")
    def _serialize_generated_at_utc(self, value: datetime) -> str:
        """Serialize generated_at_utc as a UTC ISO-8601 string."""
        return _as_utc_iso(value)


def to_yaml(model: BaseModel) -> str:
    """Serialize a pydantic model to a YAML document, using its field aliases as keys."""
    return yaml.safe_dump(model.model_dump(mode="json", by_alias=True), sort_keys=False, default_flow_style=False)


def parse_metadata_yaml(text: str) -> Metadata:
    """Parse a metadata.yml document (as text) into a Metadata model."""
    return Metadata(**yaml.safe_load(text))
