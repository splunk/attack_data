#!/usr/bin/env python3

import os
import sys
import argparse
import glob
import uuid
import urllib
import requests
from urllib3 import disable_warnings
import yaml
from pathlib import Path


def load_environment_variables():
    """Load required environment variables for Splunk connection."""
    required_vars = ['SPLUNK_HOST', 'SPLUNK_HEC_TOKEN']
    env_vars = {}
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"Environment variable {var} is required but not set")
        env_vars[var.lower().replace('splunk_', '')] = value
    return env_vars


def find_data_yml_files(folder_path):
    """Find all YAML files recursively in folder and subfolders."""
    data_yml_files = []
    folder_path = Path(folder_path)

    # Use pathlib to recursively find all .yml and .yaml files
    for yml_file in folder_path.rglob("*.yml"):
        data_yml_files.append(str(yml_file))
    for yaml_file in folder_path.rglob("*.yaml"):
        data_yml_files.append(str(yaml_file))

    if not data_yml_files:
        print(f"Warning: No YAML files found in {folder_path}")
    else:
        print(f"Found {len(data_yml_files)} YAML files")

    return data_yml_files


def parse_data_yml(yml_file_path):
    """Parse a YAML file and extract dataset information."""
    try:
        with open(yml_file_path, 'r') as file:
            data = yaml.safe_load(file)

        # Extract required fields
        file_id = data.get('id', str(uuid.uuid4()))
        datasets = data.get('datasets', [])

        # Extract default metadata from YAML file
        default_index = data.get('index', 'attack_data')  # Default to attack_data index
        default_source = data.get('source', 'attack_data')
        default_sourcetype = data.get('sourcetype', '_json')

        # Return tuple of (id, datasets_list, default_metadata)
        return file_id, datasets, {
            'index': default_index,
            'source': default_source,
            'sourcetype': default_sourcetype
        }

    except Exception as e:
        print(f"Error parsing {yml_file_path}: {e}")
        return None, [], {}


def find_data_files(folder_path):
    """Find all data files in the specified folder (supports .log, .json, .txt)."""
    files = []
    for ext in ("*.log", "*.json", "*.txt"):
        files.extend(glob.glob(os.path.join(folder_path, ext)))
    if not files:
        print(f"Warning: No data files found in {folder_path}")
    return files


def send_data_to_splunk(file_path, splunk_host, hec_token, event_host_uuid,
                        index="test", source="test", sourcetype="test"):
    """Send a data file to Splunk HEC."""
    disable_warnings()
    hec_channel = str(uuid.uuid4())
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "X-Splunk-Request-Channel": hec_channel,
    }
    url_params = {
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "host": event_host_uuid,
    }
    url = urllib.parse.urljoin(
        f"https://{splunk_host}:8088",
        "services/collector/raw"
    )
    with open(file_path, "rb") as datafile:
        try:
            res = requests.post(
                url,
                params=url_params,
                data=datafile.read(),
                allow_redirects=True,
                headers=headers,
                verify=False,
            )
            res.raise_for_status()
            print(f":white_check_mark: Sent {file_path} to Splunk HEC")
        except Exception as e:
            print(f":x: Error sending {file_path} to Splunk HEC: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Replay datasets from YAML files to Splunk via HTTP Event Collector (HEC). "
                    "All metadata (source, sourcetype, index) is read from the YAML files.",
        epilog="""
Environment Variables Required:
  SPLUNK_HOST      - Splunk server hostname/IP
  SPLUNK_HEC_TOKEN - Splunk HEC token

Example usage:
  # Replay from specific YAML files
  python replay.py datasets/attack_techniques/T1003.003/atomic_red_team/atomic_red_team.yml
  python replay.py file1.yml file2.yml file3.yml

  # Replay from directories (finds all YAML files)
  python replay.py datasets/attack_techniques/T1003.003/
  python replay.py datasets/attack_techniques/T1003.003/ datasets/attack_techniques/T1005/

Environment setup:
  export SPLUNK_HOST="192.168.1.100"
  export SPLUNK_HEC_TOKEN="your-hec-token"

This script will:
1. Process YAML files directly or find all YAML files in specified directories
2. Parse each YAML file to extract all metadata (source, sourcetype, index, etc.)
3. Replay each dataset using the metadata from the YAML file
4. Use the id field from YAML file as the host field for Splunk events
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'paths',
        nargs='+',
        help='Paths to YAML files or directories containing YAML files'
    )
    parser.add_argument(
        '--index-override',
        help='Override the index specified in YAML files (optional)'
    )
    parser.add_argument(
        '--source-override',
        help='Override the source specified in YAML files (optional)'
    )
    parser.add_argument(
        '--sourcetype-override',
        help='Override the sourcetype specified in YAML files (optional)'
    )
    parser.add_argument(
        '--host-uuid',
        help='UUID to use as the host field for Splunk events '
             '(uses id from YAML file if not provided)'
    )
    args = parser.parse_args()

    try:
        env_vars = load_environment_variables()
        splunk_host = env_vars['host']
        hec_token = env_vars['hec_token']

        # Collect all YAML files from paths (files or directories)
        all_yaml_files = []
        for path in args.paths:
            path_obj = Path(path)

            if path_obj.is_file():
                # Direct YAML file
                if path_obj.suffix.lower() in ['.yml', '.yaml']:
                    all_yaml_files.append(str(path_obj))
                else:
                    print(f"Warning: {path} is not a YAML file, skipping")
            elif path_obj.is_dir():
                # Directory - find YAML files
                yaml_files = find_data_yml_files(str(path_obj))
                all_yaml_files.extend(yaml_files)
            else:
                print(f"Warning: {path} does not exist, skipping")

        if not all_yaml_files:
            print("No YAML files found to process")
            sys.exit(1)

        print(f"Found {len(all_yaml_files)} YAML files to process")

        # Process each YAML file
        for yml_file in all_yaml_files:
            print(f"\nProcessing {yml_file}...")
            file_id, datasets, defaults = parse_data_yml(yml_file)

            if not file_id or not datasets:
                print(f"Skipping {yml_file} - no valid data found")
                continue

            # Use the id from YAML file as host field (unless user provided one)
            event_host_uuid = args.host_uuid or file_id
            print(f"Using host UUID: {event_host_uuid}")

            # Process each dataset in the YAML file
            for dataset in datasets:
                dataset_name = dataset.get('name', 'unknown')
                dataset_path = dataset.get('path', '')

                # Use dataset-specific metadata, fall back to YAML defaults
                dataset_source = (args.source_override or
                                  dataset.get('source') or
                                  defaults.get('source', 'attack_data'))
                dataset_sourcetype = (args.sourcetype_override or
                                      dataset.get('sourcetype') or
                                      defaults.get('sourcetype', '_json'))
                dataset_index = (args.index_override or
                                 dataset.get('index') or
                                 defaults.get('index', 'attack_data'))

                if not dataset_path:
                    print(f"Warning: No path specified for dataset "
                          f"'{dataset_name}', skipping")
                    continue

                # Handle relative paths - relative to attack_data root
                if dataset_path.startswith('/datasets/'):
                    # Convert to absolute path based on project structure
                    current_path = Path(yml_file).parent
                    base_dir = current_path

                    # Walk up to find attack_data root
                    while (base_dir.name != 'attack_data' and
                           base_dir.parent != base_dir):
                        base_dir = base_dir.parent

                    if base_dir.name == 'attack_data':
                        full_path = base_dir / dataset_path.lstrip('/')
                    else:
                        # Fallback: assume current working directory structure
                        full_path = Path.cwd() / dataset_path.lstrip('/')
                else:
                    # Assume relative to yml file location
                    yml_dir = Path(yml_file).parent
                    full_path = yml_dir / dataset_path

                if not full_path.exists():
                    print(f"Warning: Dataset file not found: {full_path}")
                    continue

                print(f"  Sending dataset '{dataset_name}' from {full_path}")
                print(f"    index: {dataset_index}")
                print(f"    source: {dataset_source}")
                print(f"    sourcetype: {dataset_sourcetype}")

                send_data_to_splunk(
                    file_path=str(full_path),
                    splunk_host=splunk_host,
                    hec_token=hec_token,
                    event_host_uuid=event_host_uuid,
                    index=dataset_index,
                    source=dataset_source,
                    sourcetype=dataset_sourcetype,
                )

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
