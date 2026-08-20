#!/usr/bin/env python3
"""
Build a compressed (ZIP_ZSTANDARD) archive of the datasets/ folder.

The archive contains:
  - datasets/...   the datasets folder, unchanged
  - metadata.yml   generation info plus the LFS vs. non-LFS file listing

Output is always written to attack_data_archive/ (created if missing):
  - attack_data_archive/attack_data_archive.zip
  - attack_data_archive/metadata.yml   (the same metadata.yml, also
    written standalone alongside the archive)

Requires Python 3.14+ (zipfile.ZIP_ZSTANDARD support), pydantic, and pydantic-settings.
"""

import os
import re
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

try:
    from pydantic import Field
    from pydantic_settings import BaseSettings, CliApp, SettingsConfigDict
except ImportError as exc:
    sys.exit(f"Error: missing dependency ({exc}). Install with: pip install -r bin/requirements.txt")

from attack_data_models import (
    ARCHIVE_FILE_NAME,
    METADATA_FILE_NAME,
    OUTPUT_DIR_NAME,
    LfsFileEntry,
    Metadata,
    to_yaml,
)

REF_NAME = "master"


def run_git(args: List[str], cwd: "Path | str") -> str:
    """Run a git command in cwd and return its stripped stdout, raising CalledProcessError on failure."""
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def parse_github_owner_repo(remote_url: str) -> Tuple[str, str]:
    """Extract the (owner, repo) pair from a GitHub remote URL, in https or ssh form."""
    match = re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?/?$", remote_url)
    if not match:
        raise ValueError(f"Could not parse a GitHub owner/repo from remote URL: {remote_url}")
    return match.group(1), match.group(2)


def collect_last_updated(repo_root: Path) -> Dict[str, datetime]:
    """Map {relative_path: last commit datetime} for every file ever touched under datasets/."""
    raw = run_git(
        ["log", "--name-only", "--pretty=format:%x00%H%x01%cI", "--", "datasets"],
        cwd=repo_root,
    )
    last_updated: Dict[str, datetime] = {}
    for chunk in raw.split("\x00")[1:]:
        header, _, files_block = chunk.partition("\n")
        _commit_hash, _, date_str = header.partition("\x01")
        commit_dt = datetime.fromisoformat(date_str)
        for line in files_block.splitlines():
            line = line.strip()
            if line and line not in last_updated:
                # git log is newest-first, so the first hit for a path is its most recent commit.
                last_updated[line] = commit_dt
    return last_updated


def iter_dataset_files(datasets_dir: Path) -> Iterator[Path]:
    """Yield every regular file under datasets_dir, in sorted order."""
    for path in sorted(datasets_dir.rglob("*")):
        if path.is_file():
            yield path


def build_archive(
    repo_root: Path,
    datasets_dir: Path,
    output_dir: Path,
    compresslevel: int,
) -> Tuple[int, int, int, int]:
    """Write a ZIP_ZSTANDARD archive of datasets_dir plus metadata.yml into output_dir.

    metadata.yml is also written as a standalone file alongside the archive,
    in addition to being embedded in the archive.

    Returns (file_count, total_uncompressed_size_bytes, lfs_file_count, non_lfs_file_count).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / ARCHIVE_FILE_NAME

    owner, repo = parse_github_owner_repo(run_git(["remote", "get-url", "origin"], cwd=repo_root))
    git_hash = run_git(["rev-parse", "HEAD"], cwd=repo_root)

    lfs_paths = {
        line.strip()
        for line in run_git(["lfs", "ls-files", "-n"], cwd=repo_root).splitlines()
        if line.strip()
    }
    last_updated_map = collect_last_updated(repo_root)

    files = list(iter_dataset_files(datasets_dir))
    total_size = 0
    lfs_files: Dict[str, LfsFileEntry] = {}
    non_lfs_files: List[str] = []

    with zipfile.ZipFile(output_path, "w") as zf:
        for index, path in enumerate(files, start=1):
            rel = path.relative_to(repo_root).as_posix()  # e.g. datasets/foo/bar.log
            size = path.stat().st_size
            total_size += size

            zf.write(path, arcname=rel, compress_type=zipfile.ZIP_ZSTANDARD, compresslevel=compresslevel)

            if index % 100 == 0 or index == len(files):
                print(f"  added {index}/{len(files)} files...")

            if rel in lfs_paths:
                url = f"https://media.githubusercontent.com/media/{owner}/{repo}/{REF_NAME}/{rel}"
                lfs_files[url] = LfsFileEntry(
                    relative_path=rel,
                    uncompressed_size=size,
                    **{"last-updated": last_updated_map.get(rel)},
                )
            else:
                non_lfs_files.append(rel)

        metadata = Metadata(
            file_count=len(files),
            gitref=git_hash,
            github_url=f"https://github.com/{owner}/{repo}/tree/{REF_NAME}",
            total_uncompressed_size_bytes=total_size,
            **{"lfs-files": lfs_files, "non-lfs-files": non_lfs_files},
        )
        metadata_yaml = to_yaml(metadata)
        zf.writestr(METADATA_FILE_NAME, metadata_yaml)

    (output_dir / METADATA_FILE_NAME).write_text(metadata_yaml)

    return len(files), total_size, len(lfs_files), len(non_lfs_files)


class Options(BaseSettings):
    """CLI options for building the datasets archive."""

    model_config = SettingsConfigDict(
        cli_prog_name="build_dataset_archive.py",
        cli_kebab_case=True,
    )

    compresslevel: int = Field(9, description="Zstandard compression level (default: 9)")

    def cli_cmd(self) -> None:
        """Build the archive using the parsed CLI options and print a summary."""
        repo_root = Path(run_git(["rev-parse", "--show-toplevel"], cwd=os.getcwd())).resolve()
        datasets_dir = repo_root / "datasets"
        if not datasets_dir.is_dir():
            sys.exit(f"Error: {datasets_dir} does not exist")

        output_dir = repo_root / OUTPUT_DIR_NAME

        file_count, total_size, lfs_count, non_lfs_count = build_archive(
            repo_root, datasets_dir, output_dir, self.compresslevel
        )

        print(f"Wrote {output_dir / ARCHIVE_FILE_NAME}")
        print(f"Wrote {output_dir / METADATA_FILE_NAME}")
        print(f"  files:          {file_count} ({total_size:,} bytes uncompressed)")
        print(f"  lfs files:      {lfs_count}")
        print(f"  non-lfs files:  {non_lfs_count}")
        print(f"  ref:            {REF_NAME} (branch)")


if __name__ == "__main__":
    CliApp.run(Options)
