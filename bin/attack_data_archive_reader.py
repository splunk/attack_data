#!/usr/bin/env python3
"""
Fetch a single LFS-tracked dataset file's bytes out of the local attack_data_archive/
folder produced by build_dataset_archive.py.

Given an LFS file's download URL (the key under lfs-files in metadata.yml), this:
  1. Verifies the attack_data_archive/ folder exists.
  2. Verifies attack_data_archive.zip and metadata.yml exist inside it.
  3. Parses metadata.yml.
  4. Verifies the URL is a known LFS file in metadata.yml.
  5. Verifies that file's relative path is actually present in the zip.
  6. Returns that file's bytes.

Can be used as a CLI, or imported and called as a function
(see get_lfs_file_bytes / load_metadata).

Requires Python 3.14+ (zipfile.ZIP_ZSTANDARD support), pydantic, and pydantic-settings.
"""

import sys
import zipfile
from pathlib import Path
from typing import Optional

try:
    from pydantic import Field
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


def default_archive_dir() -> Path:
    """The attack_data_archive/ folder that build_dataset_archive.py writes, alongside this repo's bin/ folder."""
    return Path(__file__).resolve().parent.parent / OUTPUT_DIR_NAME


def load_metadata(archive_dir: Path) -> Metadata:
    """Verify archive_dir and its zip/yml files exist, then parse and return metadata.yml.

    Raises ArchiveVerificationError if the folder or either file is missing.
    """
    if not archive_dir.is_dir():
        raise ArchiveVerificationError(f"Archive folder not found: {archive_dir}")

    zip_path = archive_dir / ARCHIVE_FILE_NAME
    if not zip_path.is_file():
        raise ArchiveVerificationError(f"Archive zip not found: {zip_path}")

    yml_path = archive_dir / METADATA_FILE_NAME
    if not yml_path.is_file():
        raise ArchiveVerificationError(f"Archive metadata not found: {yml_path}")

    return parse_metadata_yaml(yml_path.read_text())


def get_lfs_file_bytes(url: str, archive_dir: Optional[Path] = None) -> bytes:
    """Look up an LFS file by its download URL and return its bytes from the local archive.

    archive_dir defaults to the attack_data_archive/ folder alongside this repo's bin/ folder.

    Raises ArchiveVerificationError if the archive folder/files are missing, the URL is not
    a known LFS file in metadata.yml, or the file it points to is missing from the zip.
    """
    archive_dir = Path(archive_dir) if archive_dir is not None else default_archive_dir()
    metadata = load_metadata(archive_dir)

    entry = metadata.lfs_files.get(url)
    if entry is None:
        raise ArchiveVerificationError(f"URL not found in {METADATA_FILE_NAME}'s lfs-files: {url}")

    zip_path = archive_dir / ARCHIVE_FILE_NAME
    with zipfile.ZipFile(zip_path) as zf:
        if entry.relative_path not in zf.namelist():
            raise ArchiveVerificationError(
                f"{entry.relative_path} is listed in {METADATA_FILE_NAME} but missing from {zip_path}"
            )
        return zf.read(entry.relative_path)


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
            data = get_lfs_file_bytes(self.url, Path(self.archive_dir) if self.archive_dir else None)
        except ArchiveVerificationError as exc:
            sys.exit(f"Error: {exc}")

        if self.output:
            Path(self.output).write_bytes(data)
            print(f"Wrote {len(data):,} bytes to {self.output}")
        else:
            sys.stdout.buffer.write(data)


if __name__ == "__main__":
    CliApp.run(Options)
