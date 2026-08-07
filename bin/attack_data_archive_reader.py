#!/usr/bin/env python3
"""
Fetch a single dataset file's bytes, either from the local attack_data_archive/
folder produced by build_dataset_archive.py or, for LFS URLs not present in that
archive, straight from GitHub.

AttackDataArchiveResolver does the one-time verification (archive folder exists,
attack_data_archive.zip and metadata.yml exist inside it, and the standalone
metadata.yml matches the copy embedded in the zip) once, at construction. Reuse the
same instance across many calls to verify_path / get_data to avoid re-verifying and
re-reading metadata.yml every time.

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

Can be used as a CLI, or imported and used as a class (see AttackDataArchiveResolver).

Requires Python 3.14+ (zipfile.ZIP_ZSTANDARD support), pydantic, and pydantic-settings.
"""

import sys
import zipfile
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Dict, Mapping, Optional, Tuple, Union

import requests
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FilePath,
    HttpUrl,
    PrivateAttr,
    validate_call,
)
from pydantic_settings import (
    BaseSettings,
    CliApp,
    CliImplicitFlag,
    CliPositionalArg,
    SettingsConfigDict,
)

from attack_data_archive_models import (
    ARCHIVE_FILE_NAME,
    METADATA_FILE_NAME,
    OUTPUT_DIR_NAME,
    Metadata,
    parse_metadata_yaml,
)

MIN_PYTHON = (3, 14)

if sys.version_info < MIN_PYTHON:
    sys.exit(
        f"Error: this script requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ "
        f"(zipfile.ZIP_ZSTANDARD support). Running {sys.version_info.major}.{sys.version_info.minor}."
    )


class ArchiveVerificationError(Exception):
    """Raised when the attack_data_archive folder, its files, or a requested LFS entry fail verification."""


class MetadataFilesDiffer(ArchiveVerificationError):
    """Raised when the standalone metadata.yml and the copy embedded in the zip are not byte-identical."""


class UrlUnreachable(ArchiveVerificationError):
    """Raised when an HttpUrl not found in the cache fails a HEAD/GET request."""


class AttackDataProvenance(StrEnum):
    """Where verify_path/get_data found (or would fetch) a path's data."""

    FILE = "file"
    ATTACK_DATA_CACHE = "attack_data_cache"
    URL_GET = "url_get"
    DOES_NOT_EXIST = "does_not_exist"


HTTP_REQUEST_MAX_ATTEMPTS = 3
HTTP_REQUEST_RETRY_STATUS_CODES = {403, 503}
HTTP_REQUEST_TIMEOUT_SECONDS = 10


def _first_differing_line(a: str, b: str) -> int:
    """Return the 1-indexed line number of the first line where a and b differ.

    If one text is a prefix of the other, returns the line just past the shorter text's end.
    """
    x = requests.head

    a_lines = a.splitlines()
    b_lines = b.splitlines()
    for i, (a_line, b_line) in enumerate(zip(a_lines, b_lines), start=1):
        if a_line != b_line:
            return i
    return min(len(a_lines), len(b_lines)) + 1


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


class AttackDataArchiveResolver(BaseModel):
    """Verifies the local attack_data_archive/ once, then resolves many files/URLs against it cheaply.

    Construction verifies that archive_dir exists, that attack_data_archive.zip and metadata.yml
    exist inside it, and that the standalone metadata.yml is byte-identical to the copy embedded
    in the zip. metadata.yml is parsed once and cached on the instance.

    verify_path and get_data are the only public methods; reuse the same instance across many
    calls to them to avoid re-verifying and re-parsing metadata.yml on every call.

    require_attack_data_archive controls what happens if archive_dir, attack_data_archive.zip,
    or metadata.yml is missing: if True, construction raises ArchiveVerificationError; if False
    (the default), construction succeeds with the cache disabled, and verify_path/get_data
    resolve every HttpUrl via HEAD/GET requests instead. A present-but-inconsistent archive
    (standalone and embedded metadata.yml differing) always raises MetadataFilesDiffer,
    regardless of require_attack_data_archive.

    Every HttpUrl that misses the cache is recorded in missing_from_archive_log, keyed by
    url, as whichever of URL_GET/DOES_NOT_EXIST it resolved to.
    """

    model_config = ConfigDict(frozen=True)

    archive_dir: Path = Field(default_factory=default_archive_dir)
    check_existence_with_head_request: bool = False
    require_attack_data_archive: bool = False

    _metadata: Optional[Metadata] = PrivateAttr(default=None)
    _missing_from_archive_log: Dict[str, AttackDataProvenance] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: object) -> None:
        """Verify the archive folder/files, if present, are consistent, then cache parsed metadata.yml."""
        archive_dir = self.archive_dir

        if not archive_dir.is_dir():
            if self.require_attack_data_archive:
                raise ArchiveVerificationError(f"Archive folder not found: {archive_dir}")
            return

        zip_path = self._zip_path
        if not zip_path.is_file():
            if self.require_attack_data_archive:
                raise ArchiveVerificationError(f"Archive zip not found: {zip_path}")
            return

        yml_path = self._yml_path
        if not yml_path.is_file():
            if self.require_attack_data_archive:
                raise ArchiveVerificationError(f"Archive metadata not found: {yml_path}")
            return

        standalone_text = yml_path.read_text()

        with zipfile.ZipFile(zip_path) as zf:
            try:
                embedded_text = zf.read(METADATA_FILE_NAME).decode()
            except KeyError:
                raise ArchiveVerificationError(
                    f"{METADATA_FILE_NAME} not found inside {zip_path}"
                ) from None

        if standalone_text != embedded_text:
            line = _first_differing_line(standalone_text, embedded_text)
            raise MetadataFilesDiffer(
                f"{yml_path} and the {METADATA_FILE_NAME} embedded in {zip_path} differ, first at line {line}"
            )

        self._metadata = parse_metadata_yaml(standalone_text)

    @property
    def missing_from_archive_log(self) -> Mapping[str, AttackDataProvenance]:
        """Read-only view of every HttpUrl that has missed the cache so far, and how it resolved."""
        return MappingProxyType(self._missing_from_archive_log)

    @property
    def _zip_path(self) -> Path:
        """Path to attack_data_archive.zip inside archive_dir."""
        return self.archive_dir / ARCHIVE_FILE_NAME

    @property
    def _yml_path(self) -> Path:
        """Path to the standalone metadata.yml inside archive_dir."""
        return self.archive_dir / METADATA_FILE_NAME

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


class Options(BaseSettings):
    """CLI options for fetching one LFS file's bytes from the local attack_data_archive."""

    model_config = SettingsConfigDict(
        cli_prog_name="attack_data_archive_reader.py",
        cli_kebab_case=True,
        cli_shortcuts={"output": "o", "archive_dir": "d"},
    )

    url: CliPositionalArg[str] = Field(
        description="LFS download URL to look up under lfs-files in metadata.yml"
    )
    output: Optional[str] = Field(
        None, description="Write the file's bytes here instead of stdout"
    )
    archive_dir: Optional[str] = Field(
        None,
        description="Path to the attack_data_archive folder (default: alongside this repo's bin/ folder)",
    )
    resolve: CliImplicitFlag[bool] = Field(
        False,
        description="Only verify that the URL resolves (is in the cache, or reachable via a HEAD request); don't fetch its bytes",
    )
    check_existence_with_head_request: CliImplicitFlag[bool] = Field(
        False,
        description="When resolving a URL not in the cache, verify it with a HEAD request instead of failing immediately",
    )
    require_attack_data_archive: CliImplicitFlag[bool] = Field(
        False,
        description="Fail if the attack_data_archive folder is missing, instead of falling back to HEAD/GET requests for every URL",
    )

    def cli_cmd(self) -> None:
        """Fetch the requested LFS file's bytes and write them to --output or stdout, or just verify it resolves."""
        try:
            kwargs = {"archive_dir": Path(self.archive_dir)} if self.archive_dir else {}
            resolver = AttackDataArchiveResolver(
                check_existence_with_head_request=self.check_existence_with_head_request,
                require_attack_data_archive=self.require_attack_data_archive,
                **kwargs,
            )

            if self.resolve:
                provenance = resolver.verify_path(self.url)
                print(f"Resolved ({provenance}): {self.url}")
                return

            data, provenance = resolver.get_data(self.url)
        except ArchiveVerificationError as exc:
            sys.exit(f"Error: {exc}")

        if self.output:
            Path(self.output).write_bytes(data)
            print(f"Wrote {len(data):,} bytes ({provenance}) to {self.output}")
        else:
            sys.stdout.buffer.write(data)


if __name__ == "__main__":
    CliApp.run(Options)
