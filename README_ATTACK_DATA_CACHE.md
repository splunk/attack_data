# Attack Data Archive Cache

This directory holds a local snapshot produced by `bin/build_dataset_archive.py`:
a Zstandard-compressed archive of the `datasets/` folder from
[splunk/attack_data](https://github.com/splunk/attack_data), plus a
standalone metadata file describing exactly what went into it.

## Files

### `metadata.yml`
Describes the archive build and maps every file in it back to its source:

- `generated_at_utc` — when the archive was built
- `file_count` — total number of files included
- `gitref` — the exact commit hash the snapshot was built from
- `github_url` — link to the source branch/tag on GitHub
- `total_uncompressed_size_bytes` — combined size of all files before compression
- `lfs-files` — a map keyed by the file's Git LFS download URL
  (`media.githubusercontent.com/...`), with:
  - `relative_path` — path within `datasets/`
  - `uncompressed_size` — size in bytes
  - `last-updated` — timestamp of the most recent commit that touched the file
- `non-lfs-files` — a flat list of relative paths for files stored directly
  in git (not LFS-tracked)

Use the `lfs-files`/`non-lfs-files` sections to fetch an individual dataset
file directly from GitHub without downloading the full archive.

## Notes

- `metadata.yml` is also embedded inside the `.zip` archive itself, so it
  travels with it even if separated from this standalone copy.
- `gitref` pins the exact commit; re-running the build script against a
  later commit will produce different contents even if `datasets/` is
  otherwise unchanged (e.g. `last-updated` timestamps).
