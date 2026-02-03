# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TOTAL-REPLAY is a Python CLI tool by Splunk Threat Research Team for replaying attack data and test logs from Splunk Security Content and Splunk Attack Data projects. It automates detection testing by replaying relevant attack data based on detection metadata (names, GUIDs, MITRE ATT&CK IDs, analytic stories).

## Development Setup

```bash
poetry shell
poetry install
```

**Requirements:** Python 3.13+

**Environment Variables (required):**
- `SPLUNK_HOST` - Splunk server IP/hostname
- `SPLUNK_HEC_TOKEN` - HTTP Event Collector authentication token

## Running the Tool

```bash
# By detection name (also searches .yml filenames)
python3 total_replay.py -n '7zip CommandLine To SMB Share Path, CMLUA Or CMSTPLUA UAC Bypass'

# By MITRE ATT&CK technique ID
python3 total_replay.py -tid 'T1021, T1020, T1537'

# By detection GUID
python3 total_replay.py -g '01d29b48-ff6f-11eb-b81e-acde48001123'

# By analytic story
python3 total_replay.py -as 'AgentTesla, Remcos'

# From file with mixed metadata (greedy mode)
python3 total_replay.py -fgr './test/test_names.txt'

# Replay from local cache (skip re-downloading)
python3 total_replay.py -ld './output/2025-12-12/guid/replayed_yaml_cache'

# Specify custom index (default: "test")
python3 total_replay.py -i main -tid 'T1071'
```

File-based inputs also available: `-fn` (names), `-ftid` (technique IDs), `-fg` (GUIDs), `-fas` (analytic stories).

## Architecture

**Entry Point:** `total_replay.py` - Typer CLI that parses input, delegates to UtilityHelper

**Core Logic:** `utility/utility_helper.py` - UtilityHelper class handles:
- `search_security_content()` - Walks security_content/detections to find matching YAML files
- `download_via_attack_data()` - Downloads attack data via `git lfs pull --include=<path>`
- `send_data_to_splunk()` - POSTs events to Splunk HEC (port 8088, HTTPS)
- `normalized_file_args()` - Regex categorization of file inputs into metadata types

**Data Flow:**
1. Parse CLI input and categorize by type (detection names, GUIDs, technique IDs, analytic stories)
2. Walk security_content detections folder, match YAML files by field
3. Extract `attack_data` URLs from matched detection YAML
4. Download data via Git LFS from attack_data repo
5. Generate YAML cache with metadata in `output/<date>/<marker_uid>/replayed_yaml_cache/`
6. Send events to Splunk HEC

## Configuration

Edit `configuration/config.yml`:
```yaml
settings:
  security_content_detection_path: ~/security_content/detections
  attack_data_dir_path: ~/attack_data
  debug_print: False  # Toggle verbose output
```

## Input File Format

File inputs support mixed metadata. The tool uses regex to auto-categorize:
- YAML filenames: `^[a-z0-9_]+(?:\.yml)?$`
- GUIDs: UUID format
- Technique IDs: `T\d{4}(?:\.\d{3})?`
- Detection names/analytic stories: Remaining alphanumeric entries
- Lines starting with `#` are skipped

See `test/test_names.txt` for examples.
