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
    """Find all data.yml files recursively in folder and subfolders."""
    data_yml_files = []
    folder_path = Path(folder_path)

    # Use pathlib to recursively find all data.yml files
    for yml_file in folder_path.rglob("data.yml"):
        data_yml_files.append(str(yml_file))

    if not data_yml_files:
        print(f"Warning: No data.yml files found in {folder_path}")
    else:
        print(f"Found {len(data_yml_files)} data.yml files")

    return data_yml_files


def parse_data_yml(yml_file_path):
    """Parse a data.yml file and extract dataset information."""
    try:
        with open(yml_file_path, 'r') as file:
            data = yaml.safe_load(file)

        # Extract required fields
        file_id = data.get('id', str(uuid.uuid4()))
        datasets = data.get('datasets', [])

        # Return tuple of (id, datasets_list)
        return file_id, datasets

    except Exception as e:
        print(f"Error parsing {yml_file_path}: {e}")
        return None, []


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
        description="Recursively find and replay datasets from data.yml files "
                    "to Splunk via HTTP Event Collector (HEC)",
        epilog="""
Environment Variables Required:
  SPLUNK_HOST      - Splunk server hostname/IP
  SPLUNK_HEC_TOKEN - Splunk HEC token

Example usage:
  python replay_all.py /path/to/datasets/folder
  python replay_all.py datasets/attack_techniques --host-uuid 12345678-abcd-efgh
  export SPLUNK_HOST="192.168.1.100"
  export SPLUNK_HEC_TOKEN="your-hec-token"

This script will:
1. Recursively find all data.yml files in the specified directory
2. Parse each data.yml file to extract dataset information
3. Replay each dataset using the source and sourcetype from the yml file
4. Use the id field from data.yml as the host field for Splunk events
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'path',
        help='Path to a directory containing data.yml files '
             '(searches recursively)'
    )
    parser.add_argument(
        '--source',
        default='test',
        help='Source field for Splunk events (default: test)'
    )
    parser.add_argument(
        '--sourcetype',
        default='test',
        help='Sourcetype field for Splunk events (default: test)'
    )
    parser.add_argument(
        '--index',
        default='test',
        help='Splunk index to send events to (default: test)'
    )
    parser.add_argument(
        '--host-uuid',
        help='UUID to use as the host field for Splunk events '
             '(generates random UUID if not provided)'
    )
    args = parser.parse_args()

    try:
        env_vars = load_environment_variables()
        splunk_host = env_vars['host']
        hec_token = env_vars['hec_token']

        if not os.path.isdir(args.path):
            print(f"Error: {args.path} is not a valid directory")
            sys.exit(1)

        # Find all data.yml files recursively
        data_yml_files = find_data_yml_files(args.path)

        if not data_yml_files:
            print(f"No data.yml files found in {args.path}")
            sys.exit(1)

        # Process each data.yml file
        for yml_file in data_yml_files:
            print(f"\nProcessing {yml_file}...")
            file_id, datasets = parse_data_yml(yml_file)

            if not file_id or not datasets:
                print(f"Skipping {yml_file} - no valid data found")
                continue

            # Use the id from data.yml as host field (unless user provided one)
            event_host_uuid = args.host_uuid or file_id
            print(f"Using host UUID: {event_host_uuid}")

            # Process each dataset in the data.yml file
            for dataset in datasets:
                dataset_name = dataset.get('name', 'unknown')
                dataset_path = dataset.get('path', '')
                dataset_source = dataset.get('source', args.source)
                dataset_sourcetype = dataset.get('sourcetype', args.sourcetype)

                if not dataset_path:
                    print(f"Warning: No path specified for dataset "
                          f"'{dataset_name}', skipping")
                    continue

                # Handle relative paths - relative to attack_data root
                if dataset_path.startswith('/datasets/'):
                    # Convert to absolute path based on project structure
                    if Path(args.path).name == 'datasets':
                        base_dir = Path(args.path).parent
                    else:
                        base_dir = Path(args.path)
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
                print(f"    source: {dataset_source}")
                print(f"    sourcetype: {dataset_sourcetype}")

                send_data_to_splunk(
                    file_path=str(full_path),
                    splunk_host=splunk_host,
                    hec_token=hec_token,
                    event_host_uuid=event_host_uuid,
                    index=args.index,
                    source=dataset_source,
                    sourcetype=dataset_sourcetype,
                )

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
