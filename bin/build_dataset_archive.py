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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Literal, Optional, Tuple

try:
    import yaml
    from pydantic import BaseModel, Field, field_serializer
    from pydantic_settings import BaseSettings, CliApp, SettingsConfigDict
except ImportError as exc:
    sys.exit(f"Error: missing dependency ({exc}). Install with: pip install -r bin/requirements.txt")

MIN_PYTHON = (3, 14)

OUTPUT_DIR_NAME = "attack_data_archive"
ARCHIVE_FILE_NAME = "attack_data_archive.zip"

if sys.version_info < MIN_PYTHON:
    sys.exit(
        f"Error: this script requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ "
        f"(zipfile.ZIP_ZSTANDARD support). Running {sys.version_info.major}.{sys.version_info.minor}."
    )


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


def determine_ref(
    repo_root: Path, ref_override: Optional[str], ref_type_override: Optional[str]
) -> Tuple[str, str]:
    """Resolve the (ref_name, ref_type) to embed in generated URLs.

    Preference order: an explicit override, then the GitHub Actions
    GITHUB_REF_NAME/GITHUB_REF_TYPE env vars, then the current local branch.
    """
    if ref_override:
        return ref_override, ref_type_override or "branch"

    ref_name = os.environ.get("GITHUB_REF_NAME")
    ref_type = os.environ.get("GITHUB_REF_TYPE")
    if ref_name and ref_type:
        return ref_name, ref_type

    try:
        branch = run_git(["symbolic-ref", "--short", "HEAD"], cwd=repo_root)
        if branch:
            return branch, "branch"
    except subprocess.CalledProcessError:
        pass

    raise RuntimeError(
        "Could not determine a branch/tag name for this checkout (HEAD is "
        "detached and GITHUB_REF_NAME is not set). Pass --ref/--ref-type explicitly."
    )


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
    ref_name: str,
    ref_type: str,
) -> Tuple[int, int, int, int]:
    """Write a ZIP_ZSTANDARD archive of datasets_dir plus metadata.yml into output_dir.

    metadata.yml is also written as a standalone file alongside the archive,
    in addition to being embedded in the archive.

    Returns (file_count, total_uncompressed_size_bytes, lfs_file_count, non_lfs_file_count).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / ARCHIVE_FILE_NAME

    owner, repo = parse_github_owner_repo(run_git(["remote", "get-url", "origin"], cwd=repo_root))
    ref_segment = "heads" if ref_type == "branch" else "tags"
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
                url = f"https://media.githubusercontent.com/media/{owner}/{repo}/refs/{ref_segment}/{ref_name}/{rel}"
                lfs_files[url] = LfsFileEntry(
                    relative_path=rel,
                    uncompressed_size=size,
                    **{"last-updated": last_updated_map.get(rel)},
                )
            else:
                non_lfs_files.append(rel)

        metadata = Metadata(
            generated_at_utc=datetime.now(timezone.utc),
            file_count=len(files),
            gitref=git_hash,
            github_url=f"https://github.com/{owner}/{repo}/tree/{ref_name}",
            total_uncompressed_size_bytes=total_size,
            **{"lfs-files": lfs_files, "non-lfs-files": non_lfs_files},
        )
        metadata_yaml = to_yaml(metadata)
        zf.writestr("metadata.yml", metadata_yaml)

    (output_dir / "metadata.yml").write_text(metadata_yaml)

    return len(files), total_size, len(lfs_files), len(non_lfs_files)


class Options(BaseSettings):
    """CLI options for building the datasets archive."""

    model_config = SettingsConfigDict(
        cli_prog_name="build_dataset_archive.py",
        cli_kebab_case=True,
    )

    compresslevel: int = Field(9, description="Zstandard compression level (default: 9)")
    ref: Optional[str] = Field(None, description="Override the git branch/tag name used to build GitHub URLs")
    ref_type: Optional[Literal["branch", "tag"]] = Field(
        None, description="Whether --ref is a branch or a tag (default: branch)"
    )

    def cli_cmd(self) -> None:
        """Build the archive using the parsed CLI options and print a summary."""
        repo_root = Path(run_git(["rev-parse", "--show-toplevel"], cwd=os.getcwd())).resolve()
        datasets_dir = repo_root / "datasets"
        if not datasets_dir.is_dir():
            sys.exit(f"Error: {datasets_dir} does not exist")

        output_dir = repo_root / OUTPUT_DIR_NAME
        ref_name, ref_type = determine_ref(repo_root, self.ref, self.ref_type)

        file_count, total_size, lfs_count, non_lfs_count = build_archive(
            repo_root, datasets_dir, output_dir, self.compresslevel, ref_name, ref_type
        )

        print(f"Wrote {output_dir / ARCHIVE_FILE_NAME}")
        print(f"Wrote {output_dir / 'metadata.yml'}")
        print(f"  files:          {file_count} ({total_size:,} bytes uncompressed)")
        print(f"  lfs files:      {lfs_count}")
        print(f"  non-lfs files:  {non_lfs_count}")
        print(f"  ref:            {ref_name} ({ref_type})")


if __name__ == "__main__":
    CliApp.run(Options)
