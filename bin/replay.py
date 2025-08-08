#!/usr/bin/env python3

import os
import sys
import argparse
import glob
import uuid
import urllib
import requests
from urllib3 import disable_warnings


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


def find_data_files(folder_path):
    """Find all data files in the specified folder (supports .log, .json, .txt)."""
    files = []
    for ext in ("*.log", "*.json", "*.txt"):
        files.extend(glob.glob(os.path.join(folder_path, ext)))
    if not files:
        print(f"Warning: No data files found in {folder_path}")
    return files


def send_data_to_splunk(file_path, splunk_host, hec_token, event_host_uuid,
                        index="test", source="test", sourcetype="test",
                        verify_ssl=False):
    """Send a data file to Splunk HEC."""
    if not verify_ssl:
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
                verify=verify_ssl,
            )
            res.raise_for_status()
            print(f":white_check_mark: Sent {file_path} to Splunk HEC")
        except Exception as e:
            print(f":x: Error sending {file_path} to Splunk HEC: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Replay data files to Splunk via HTTP Event Collector (HEC)",
        epilog="""
Environment Variables Required:
  SPLUNK_HOST      - Splunk server hostname/IP
  SPLUNK_HEC_TOKEN - Splunk HEC token

Example usage:
  python replay.py /path/to/data/folder
  python replay.py /path/to/data/file.log --host-uuid 12345678-abcd-efgh
  export SPLUNK_HOST="192.168.1.100"
  export SPLUNK_HEC_TOKEN="your-hec-token"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'path',
        help='Path to a data file or folder containing data files'
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
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL verification for Splunk HEC'
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

        # Generate UUID for host field if not provided
        event_host_uuid = args.host_uuid or str(uuid.uuid4())
        print(f"Using host UUID: {event_host_uuid}")

        if os.path.isdir(args.path):
            files = find_data_files(args.path)
        elif os.path.isfile(args.path):
            files = [args.path]
        else:
            print(f"Error: {args.path} is not a valid file or directory")
            sys.exit(1)

        for file_path in files:
            send_data_to_splunk(
                file_path=file_path,
                splunk_host=splunk_host,
                hec_token=hec_token,
                event_host_uuid=event_host_uuid,
                index=args.index,
                source=args.source,
                sourcetype=args.sourcetype,
                verify_ssl=not args.no_verify_ssl,
            )

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
