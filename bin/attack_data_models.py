#!/usr/bin/env python3
"""
Models, constants, and the reader library for the datasets archive (attack_data_archive/).

Used by build_dataset_archive.py to generate metadata.yml, and by any tool that reads
the archive back via AttackDataArchiveResolver.

AttackDataArchiveResolver does the one-time verification (archive folder exists,
attack_data_archive.zip exists inside it) once, at construction, and reads its
embedded metadata.yml. Reuse the same instance across many calls to verify_path /
get_data to avoid re-verifying and re-reading metadata.yml every time.

By default (require_attack_data_archive=False) the archive is optional: if it's
missing, verify_path/get_data resolve HttpUrls with HEAD/GET requests instead of
raising. Set require_attack_data_archive=True to fail construction if it's missing.

verify_path and get_data are the only public entry points; everything else on
AttackDataArchiveResolver is a private implementation detail. Both accept either a
FilePath (an existing local file) or an HttpUrl (an LFS download URL), and both
return an AttackDataProvenance saying where the data came from (or, for get_data's
URL_GET case, was fetched from):
  - verify_path checks that a FilePath exists, or that an HttpUrl is a known,
    present-in-the-zip LFS file (i.e. it's in the cache) — or, if
    check_existence_with_head_request is enabled, that an uncached HttpUrl is
    reachable via a HEAD request.
  - get_data calls verify_path, then returns the bytes alongside it: read from disk
    for a FilePath, from the cache for a cached HttpUrl, or via a GET request otherwise.

Every HttpUrl that misses the cache is recorded on the instance (see
missing_from_archive_log / write_missing_from_cache) for downstream tooling to
consume.

This is a library, meant to be imported; it has no CLI of its own.

Requires Python 3.14+ (zipfile.ZIP_ZSTANDARD support), pydantic.
"""

import sys
import zipfile
from datetime import datetime, timezone
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Dict, List, Mapping, Optional, Tuple, Union

try:
    import requests
    import yaml
    from pydantic import BaseModel, Field, FilePath, HttpUrl, field_serializer, validate_call
except ImportError as exc:
    sys.exit(f"Error: missing dependency ({exc}). Install with: pip install -r bin/requirements.txt")

OUTPUT_DIR_NAME = "attack_data_archive"
ARCHIVE_FILE_NAME = "attack_data_archive.zip"
METADATA_FILE_NAME = "metadata.yml"
MISSING_FROM_CACHE_FILE_NAME = "missing_from_cache.yml"


def _now_utc_iso() -> str:
    """The current time as a UTC ISO-8601 string ending in 'Z'."""
    return datetime.now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime as a UTC ISO-8601 string ending in 'Z', or None if dt is None."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


class AttackDataProvenance(StrEnum):
    """Where AttackDataArchiveResolver.verify_path/get_data found (or would fetch) a path's data."""

    FILE = "file"
    ATTACK_DATA_CACHE = "attack_data_cache"
    URL_GET = "url_get"
    DOES_NOT_EXIST = "does_not_exist"


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

    generated_at_utc: str = Field(default_factory=_now_utc_iso)
    file_count: int
    gitref: str
    github_url: str
    total_uncompressed_size_bytes: int
    lfs_files: Dict[str, LfsFileEntry] = Field(default_factory=dict, alias="lfs-files")
    non_lfs_files: List[str] = Field(default_factory=list, alias="non-lfs-files")

    model_config = {"populate_by_name": True}


class MissingFromCache(BaseModel):
    """Every HttpUrl that missed the attack_data_archive cache during a run, keyed by url, with how it resolved."""

    generated_at_utc: str = Field(default_factory=_now_utc_iso)
    files: Dict[str, AttackDataProvenance] = Field(default_factory=dict)


def to_yaml(model: BaseModel) -> str:
    """Serialize a pydantic model to a YAML document, using its field aliases as keys."""
    return yaml.safe_dump(model.model_dump(mode="json", by_alias=True), sort_keys=False, default_flow_style=False)


def parse_metadata_yaml(text: str) -> Metadata:
    """Parse a metadata.yml document (as text) into a Metadata model."""
    return Metadata(**yaml.safe_load(text))


def missing_from_cache_to_markdown(model: MissingFromCache) -> str:
    """Render a MissingFromCache model as a markdown table, one row per missing URL."""
    lines = ["| URL | Provenance |", "| --- | --- |"]
    lines += [f"| {url} | {provenance.value} |" for url, provenance in model.files.items()]
    return "\n".join(lines) + "\n"


class ArchiveVerificationError(Exception):
    """Raised when the attack_data_archive folder, its zip, or a requested LFS entry fail verification."""


class UrlUnreachable(ArchiveVerificationError):
    """Raised when an HttpUrl not found in the cache fails a HEAD/GET request."""


HTTP_REQUEST_MAX_ATTEMPTS = 3
HTTP_REQUEST_RETRY_STATUS_CODES = {403, 503}
HTTP_REQUEST_TIMEOUT_SECONDS = 10


def _request_with_retry(
    request_fn: Callable[..., requests.Response], method_name: str, url: HttpUrl
) -> "requests.Response":
    """Call request_fn(url), retrying up to HTTP_REQUEST_MAX_ATTEMPTS total attempts on 403/503.

    Returns the response on a 200. Raises UrlUnreachable if every attempt returns 403/503,
    or on the first response with any other non-200 status.
    """
    last_status: Optional[int] = None
    for _ in range(1, HTTP_REQUEST_MAX_ATTEMPTS + 1):
        response = request_fn(str(url), timeout=HTTP_REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 200:
            return response
        if response.status_code not in HTTP_REQUEST_RETRY_STATUS_CODES:
            raise UrlUnreachable(f"{method_name} {url} returned {response.status_code}")
        last_status = response.status_code

    raise UrlUnreachable(
        f"{method_name} {url} returned {last_status} on all {HTTP_REQUEST_MAX_ATTEMPTS} attempts"
    )


def _verify_url_reachable(url: HttpUrl) -> None:
    """HEAD-request url, using the same retry/success/failure modes as a GET (see _request_with_retry)."""
    _request_with_retry(requests.head, "HEAD", url)


def default_archive_dir() -> Path:
    """The attack_data_archive/ folder that build_dataset_archive.py writes, alongside this repo's bin/ folder."""
    return Path(__file__).resolve().parent.parent / OUTPUT_DIR_NAME


class AttackDataArchiveResolver:
    """Verifies the local attack_data_archive/ once, then resolves many files/URLs against it cheaply.

    Construction verifies that attack_data_archive.zip exists inside archive_dir, and reads its
    embedded metadata.yml (the single source of truth for what the archive contains). Reuse the
    same instance across many calls to verify_path / get_data to avoid re-verifying and re-parsing
    metadata.yml on every call. Treat an instance as read-only after construction — archive_dir
    isn't meant to change afterwards.

    require_attack_data_archive controls what happens if archive_dir or attack_data_archive.zip is
    missing: if True, construction raises ArchiveVerificationError; if False (the default),
    construction succeeds with the cache disabled, and verify_path/get_data resolve every HttpUrl
    via HEAD/GET requests instead.

    Every HttpUrl that misses the cache is recorded in missing_from_archive_log, keyed by url, as
    whichever of URL_GET/DOES_NOT_EXIST it resolved to. Call write_missing_from_cache() to persist
    that log to disk for other tooling to consume.
    """

    def __init__(
        self,
        archive_dir: Optional[Path] = None,
        require_attack_data_archive: bool = False,
    ) -> None:
        self.archive_dir = Path(archive_dir) if archive_dir is not None else default_archive_dir()
        # If an archive directory is supplied, any URLs not in the archive MUST be resolved
        # with a HEAD request.
        if self.archive_dir is not None:
            self.check_existence_with_head_request = True
        else:
            self.check_existence_with_head_request = False
        self.require_attack_data_archive = require_attack_data_archive

        self._metadata: Optional[Metadata] = None
        self._missing_from_archive_log: Dict[str, AttackDataProvenance] = {}

        self._verify_archive()

    def _verify_archive(self) -> None:
        """Read metadata.yml out of attack_data_archive.zip, if the zip is present.

        If archive_dir or the zip is missing: raises ArchiveVerificationError when
        require_attack_data_archive is True, otherwise leaves the cache disabled
        (self._metadata stays None).
        """
        zip_path = self._zip_path
        if not zip_path.is_file():
            if self.require_attack_data_archive:
                raise ArchiveVerificationError(f"Archive zip not found: {zip_path}")
            return

        with zipfile.ZipFile(zip_path) as zf:
            try:
                metadata_text = zf.read(METADATA_FILE_NAME).decode()
            except KeyError:
                raise ArchiveVerificationError(
                    f"{METADATA_FILE_NAME} not found inside {zip_path}"
                ) from None

        self._metadata = parse_metadata_yaml(metadata_text)

    @property
    def missing_from_archive_log(self) -> Mapping[str, AttackDataProvenance]:
        """Read-only view of every HttpUrl that has missed the cache so far, and how it resolved."""
        return MappingProxyType(self._missing_from_archive_log)

    def missing_from_cache(self) -> MissingFromCache:
        """Snapshot missing_from_archive_log as a MissingFromCache model, timestamped with the current time."""
        return MissingFromCache(files=dict(self._missing_from_archive_log))

    def write_missing_from_cache(self) -> Optional[Tuple[Path, Path]]:
        """Write missing_from_cache.yml plus a markdown table into archive_dir, for other tooling to consume.

        Returns the (yml_path, md_path) written, or None if nothing has missed the cache yet.
        """
        if not self._missing_from_archive_log:
            return None

        missing = self.missing_from_cache()
        self.archive_dir.mkdir(parents=True, exist_ok=True)

        yml_path = self.archive_dir / MISSING_FROM_CACHE_FILE_NAME
        yml_path.write_text(to_yaml(missing))

        md_path = yml_path.with_suffix(".md")
        md_path.write_text(missing_from_cache_to_markdown(missing))

        return yml_path, md_path

    @property
    def _zip_path(self) -> Path:
        """Path to attack_data_archive.zip inside archive_dir."""
        return self.archive_dir / ARCHIVE_FILE_NAME

    @cached_property
    def _zip_namelist(self) -> frozenset:
        """Set of every relative path stored inside the zip, computed once since the archive is immutable."""
        with zipfile.ZipFile(self._zip_path) as zf:
            return frozenset(zf.namelist())

    def _cached_lfs_relative_path(self, url: str) -> Optional[str]:
        """Look up url in the cached metadata.yml and verify its file is present in the zip.

        Returns the file's relative path within the zip if url is a known, present-in-the-zip
        LFS file, or None if the archive isn't present (no cache) or url is not a known LFS
        file at all (i.e. not in the cache).

        Raises ArchiveVerificationError if url is a known LFS file but its file is missing
        from the zip.
        """
        if self._metadata is None:
            return None

        entry = self._metadata.lfs_files.get(url)
        if entry is None:
            return None

        if entry.relative_path not in self._zip_namelist:
            raise ArchiveVerificationError(
                f"{entry.relative_path} is listed in {METADATA_FILE_NAME} but missing from {self._zip_path}"
            )

        return entry.relative_path

    @validate_call
    def verify_path(self, path: Union[FilePath, HttpUrl]) -> AttackDataProvenance:
        """Verify that path exists, whether it's a local file or an HttpUrl.

        A FilePath is verified simply by being accepted as an argument (pydantic's
        FilePath validation already requires it to exist on disk).

        An HttpUrl is verified if it's a known, present-in-the-zip LFS file (i.e. it's
        in the cache). If the archive isn't present at all, or it's not in the cache and
        check_existence_with_head_request is enabled, falls back to a HEAD request
        (see _verify_url_reachable).

        Returns where the data was found (or, for URL_GET, would be fetched from).

        Every HttpUrl that misses the cache is recorded in _missing_from_archive_log,
        keyed by url, as either URL_GET or DOES_NOT_EXIST.

        Raises ArchiveVerificationError if path is an HttpUrl that's neither in the
        cache nor (when the archive is present and check_existence_with_head_request
        is disabled) reachable via HEAD request.
        """
        if isinstance(path, Path):
            return AttackDataProvenance.FILE

        if self._cached_lfs_relative_path(str(path)) is not None:
            return AttackDataProvenance.ATTACK_DATA_CACHE

        url = str(path)

        if self._metadata is not None and not self.check_existence_with_head_request:
            self._missing_from_archive_log[url] = AttackDataProvenance.DOES_NOT_EXIST
            raise ArchiveVerificationError(
                f"URL not found in {METADATA_FILE_NAME}'s lfs-files: {path}"
            )

        try:
            _verify_url_reachable(path)
        except UrlUnreachable:
            self._missing_from_archive_log[url] = AttackDataProvenance.DOES_NOT_EXIST
            raise

        self._missing_from_archive_log[url] = AttackDataProvenance.URL_GET
        return AttackDataProvenance.URL_GET

    @validate_call
    def get_data(self, path: Union[FilePath, HttpUrl]) -> Tuple[bytes, AttackDataProvenance]:
        """Return the bytes at path plus where they came from, whether path is a local file or an HttpUrl.

        Calls verify_path first, then reuses its result: a FilePath's bytes are read
        directly from disk, an HttpUrl's bytes are read from the cache if it's a known,
        present-in-the-zip LFS file, or otherwise downloaded with a GET request.
        """
        provenance = self.verify_path(path)

        if provenance is AttackDataProvenance.FILE:
            return path.read_bytes(), provenance

        if provenance is AttackDataProvenance.ATTACK_DATA_CACHE:
            relative_path = self._cached_lfs_relative_path(str(path))
            with zipfile.ZipFile(self._zip_path) as zf:
                return zf.read(relative_path), provenance

        return _request_with_retry(requests.get, "GET", path).content, provenance
