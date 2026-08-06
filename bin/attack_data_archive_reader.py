#!/usr/bin/env python3
"""
Fetch a single LFS-tracked dataset file's bytes out of the local attack_data_archive/
folder produced by build_dataset_archive.py.

AttackDataArchiveResolver does the one-time verification (archive folder exists,
attack_data_archive.zip and metadata.yml exist inside it, and the standalone
metadata.yml matches the copy embedded in the zip) once, at construction. Reuse the
same instance across many calls to verify_lfs_file_existence / get_lfs_file_bytes
to avoid re-verifying and re-reading metadata.yml every time.

Given an LFS file's download URL (the key under lfs-files in metadata.yml),
verify_lfs_file_existence:
  1. Verifies the URL is a known LFS file in metadata.yml.
  2. Verifies that file's relative path is actually present in the zip.

get_lfs_file_bytes calls verify_lfs_file_existence, then returns that file's bytes.

Can be used as a CLI, or imported and used as a class (see AttackDataArchiveResolver).

Requires Python 3.14+ (zipfile.ZIP_ZSTANDARD support), pydantic, and pydantic-settings.
"""

import sys
import zipfile
from pathlib import Path
from typing import Optional

try:
    from pydantic import BaseModel, Field, PrivateAttr
    from pydantic_settings import BaseSettings, CliApp, CliPositionalArg, SettingsConfigDict
except ImportError as exc:
    sys.exit(f"Error: missing dependency ({exc}). Install with: pip install -r bin/requirements.txt")

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


def _first_differing_line(a: str, b: str) -> int:
    """Return the 1-indexed line number of the first line where a and b differ.

    If one text is a prefix of the other, returns the line just past the shorter text's end.
    """
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    for i, (a_line, b_line) in enumerate(zip(a_lines, b_lines), start=1):
        if a_line != b_line:
            return i
    return min(len(a_lines), len(b_lines)) + 1


def default_archive_dir() -> Path:
    """The attack_data_archive/ folder that build_dataset_archive.py writes, alongside this repo's bin/ folder."""
    return Path(__file__).resolve().parent.parent / OUTPUT_DIR_NAME


class AttackDataArchiveResolver(BaseModel):
    """Verifies the local attack_data_archive/ once, then resolves many LFS URLs against it cheaply.

    Construction verifies that archive_dir exists, that attack_data_archive.zip and metadata.yml
    exist inside it, and that the standalone metadata.yml is byte-identical to the copy embedded
    in the zip. metadata.yml is parsed once and cached on the instance.

    Reuse the same instance across many verify_lfs_file_existence / get_lfs_file_bytes calls to
    avoid re-verifying and re-parsing metadata.yml on every call.

    Raises ArchiveVerificationError if the folder or either file is missing, or
    MetadataFilesDiffer if the standalone and embedded metadata.yml contents differ.
    """

    archive_dir: Path = Field(default_factory=default_archive_dir)

    _metadata: Metadata = PrivateAttr()

    def model_post_init(self, __context: object) -> None:
        """Verify the archive folder/files exist and are consistent, then cache parsed metadata.yml."""
        archive_dir = self.archive_dir

        if not archive_dir.is_dir():
            raise ArchiveVerificationError(f"Archive folder not found: {archive_dir}")

        zip_path = self.zip_path
        if not zip_path.is_file():
            raise ArchiveVerificationError(f"Archive zip not found: {zip_path}")

        yml_path = self.yml_path
        if not yml_path.is_file():
            raise ArchiveVerificationError(f"Archive metadata not found: {yml_path}")

        standalone_text = yml_path.read_text()

        with zipfile.ZipFile(zip_path) as zf:
            try:
                embedded_text = zf.read(METADATA_FILE_NAME).decode()
            except KeyError:
                raise ArchiveVerificationError(f"{METADATA_FILE_NAME} not found inside {zip_path}") from None

        if standalone_text != embedded_text:
            line = _first_differing_line(standalone_text, embedded_text)
            raise MetadataFilesDiffer(
                f"{yml_path} and the {METADATA_FILE_NAME} embedded in {zip_path} differ, first at line {line}"
            )

        self._metadata = parse_metadata_yaml(standalone_text)

    @property
    def zip_path(self) -> Path:
        """Path to attack_data_archive.zip inside archive_dir."""
        return self.archive_dir / ARCHIVE_FILE_NAME

    @property
    def yml_path(self) -> Path:
        """Path to the standalone metadata.yml inside archive_dir."""
        return self.archive_dir / METADATA_FILE_NAME

    @property
    def metadata(self) -> Metadata:
        """The parsed metadata.yml, cached at construction time."""
        return self._metadata

    def verify_lfs_file_existence(self, url: str) -> str:
        """Verify url is a known LFS file in metadata.yml and that its file is present in the zip.

        Returns the file's relative path within the zip on success.

        Raises ArchiveVerificationError if the URL is not a known LFS file in metadata.yml,
        or the file it points to is missing from the zip.
        """
        entry = self._metadata.lfs_files.get(url)
        if entry is None:
            raise ArchiveVerificationError(f"URL not found in {METADATA_FILE_NAME}'s lfs-files: {url}")

        with zipfile.ZipFile(self.zip_path) as zf:
            if entry.relative_path not in zf.namelist():
                raise ArchiveVerificationError(
                    f"{entry.relative_path} is listed in {METADATA_FILE_NAME} but missing from {self.zip_path}"
                )

        return entry.relative_path

    def get_lfs_file_bytes(self, url: str) -> bytes:
        """Look up an LFS file by its download URL and return its bytes from the local archive."""
        relative_path = self.verify_lfs_file_existence(url)

        with zipfile.ZipFile(self.zip_path) as zf:
            return zf.read(relative_path)


class Options(BaseSettings):
    """CLI options for fetching one LFS file's bytes from the local attack_data_archive."""

    model_config = SettingsConfigDict(
        cli_prog_name="attack_data_archive_reader.py",
        cli_kebab_case=True,
        cli_shortcuts={"output": "o", "archive_dir": "d"},
    )

    url: CliPositionalArg[str] = Field(description="LFS download URL to look up under lfs-files in metadata.yml")
    output: Optional[str] = Field(None, description="Write the file's bytes here instead of stdout")
    archive_dir: Optional[str] = Field(
        None, description="Path to the attack_data_archive folder (default: alongside this repo's bin/ folder)"
    )

    def cli_cmd(self) -> None:
        """Fetch the requested LFS file's bytes and write them to --output or stdout."""
        try:
            kwargs = {"archive_dir": Path(self.archive_dir)} if self.archive_dir else {}
            resolver = AttackDataArchiveResolver(**kwargs)
            data = resolver.get_lfs_file_bytes(self.url)
        except ArchiveVerificationError as exc:
            sys.exit(f"Error: {exc}")

        if self.output:
            Path(self.output).write_bytes(data)
            print(f"Wrote {len(data):,} bytes to {self.output}")
        else:
            sys.stdout.buffer.write(data)


if __name__ == "__main__":
    CliApp.run(Options)
