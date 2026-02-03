"""
author: Claude Code
description: A utility tool to run SPL queries from security content detection YAML files against Splunk
and output results to a JSONL file.

Splunk connection settings can be configured in two ways:

1. Config file (configuration/config.yml):
   splunk:
     host: "your-splunk-server"
     username: "admin"
     password: "your-password"

2. Environment variables (override config file values):
   - SPLUNK_HOST: Splunk server IP/hostname
   - SPLUNK_USERNAME: Splunk username for REST API authentication
   - SPLUNK_PASSWORD: Splunk password for REST API authentication
"""

import typer
import os
import sys
import yaml
import json
import requests
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init
from urllib3 import disable_warnings
from dotenv import load_dotenv

# Initialize colorama
init()

# Disable SSL warnings
disable_warnings()

# Load environment variables from .env file
load_dotenv()


class ColorPrint:
    """Simple color print utility"""
    @staticmethod
    def print_info_fg(msg):
        print(Fore.GREEN + msg + Style.RESET_ALL)

    @staticmethod
    def print_error_fg(msg):
        print(Fore.RED + msg + Style.RESET_ALL)

    @staticmethod
    def print_warning_fg(msg):
        print(Fore.YELLOW + msg + Style.RESET_ALL)

    @staticmethod
    def print_success_fg(msg):
        print(Fore.CYAN + msg + Style.RESET_ALL)

    @staticmethod
    def print_cyan_fg(msg):
        print(Fore.CYAN + msg + Style.RESET_ALL)


class DetectionRunner:
    """Class to run SPL queries from detection YAML files"""

    def __init__(self):
        self.curdir = os.path.dirname(os.path.abspath(__file__))
        self.config = self.load_config()

    def normalized_args_tolist(self, input_args: str) -> list:
        """Convert comma-separated string to list"""
        return [i.strip() for i in input_args.split(',')]

    def load_config(self) -> dict:
        """Load configuration from config.yml"""
        config_path = os.path.join(self.curdir, "configuration", "config.yml")
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
                if config is None:
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Configuration file is empty: {config_path}")
                    return {}
                return config
        except FileNotFoundError:
            ColorPrint.print_error_fg(f"[-][. ERROR]: Configuration file not found: {config_path}")
            return {}
        except yaml.YAMLError as e:
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to parse configuration file: {e}")
            return {}

    def read_config_settings(self, setting_field: str) -> str:
        """Read a specific setting from config"""
        if not self.config:
            return None
        return self.config.get("settings", {}).get(setting_field)

    def load_splunk_config(self) -> dict:
        """Load Splunk connection settings from config file and/or environment variables.

        Environment variables take precedence over config file values.
        """
        ColorPrint.print_info_fg("[+][.  INFO]: ... Loading Splunk connection settings ...")

        # First, try to load from config file
        splunk_config = self.config.get("splunk", {})

        settings = {
            "host": splunk_config.get("host", ""),
            "username": splunk_config.get("username", ""),
            "password": splunk_config.get("password", "")
        }

        # Environment variables override config file values
        env_mappings = {
            "SPLUNK_HOST": "host",
            "SPLUNK_USERNAME": "username",
            "SPLUNK_PASSWORD": "password"
        }

        for env_var, key in env_mappings.items():
            env_value = os.environ.get(env_var)
            if env_value:
                settings[key] = env_value
                ColorPrint.print_info_fg(f"[+][.  INFO]: ... Using {env_var} from environment variable")

        # Check for missing required settings
        missing = [k for k, v in settings.items() if not v]

        if missing:
            ColorPrint.print_error_fg(f"[-][. ERROR]: Missing Splunk settings: {', '.join(missing)}")
            ColorPrint.print_error_fg("[-][. ERROR]: Set values in config.yml or use environment variables:")
            ColorPrint.print_error_fg("[-][. ERROR]:   SPLUNK_HOST, SPLUNK_USERNAME, SPLUNK_PASSWORD")
            return None

        ColorPrint.print_success_fg("[+][SUCCESS]: ... Splunk connection settings loaded successfully")
        return settings

    def read_yaml_file(self, file_path: str) -> dict:
        """Read and parse a YAML file"""
        try:
            with open(file_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            return None

    def get_all_yaml_files(self) -> list:
        """Get all YAML files from security content detections directory"""
        security_content_dir_path = self.read_config_settings("security_content_detection_path")
        if security_content_dir_path is None:
            ColorPrint.print_error_fg("[-][. ERROR]: Failed to read security_content_detection_path from config")
            return []

        expanded_path = os.path.expanduser(security_content_dir_path)
        if not os.path.isdir(expanded_path):
            ColorPrint.print_error_fg(f"[-][. ERROR]: Detection directory does not exist: {expanded_path}")
            return []

        all_yaml_files = []
        for root, dirs, files in os.walk(expanded_path):
            if "deprecated" in dirs:
                dirs.remove("deprecated")
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    all_yaml_files.append(os.path.join(root, file))

        return all_yaml_files

    def filter_by_name(self, yaml_files: list, names: list) -> list:
        """Filter YAML files by detection name or filename"""
        filtered = []
        names_lower = [n.lower() for n in names]

        for file_path in yaml_files:
            file_name = os.path.basename(file_path).replace(".yml", "").replace(".yaml", "")

            # Check filename match
            if file_name.lower() in names_lower:
                filtered.append(file_path)
                continue

            # Check detection name in YAML
            yaml_data = self.read_yaml_file(file_path)
            if yaml_data and yaml_data.get("name", "").lower() in names_lower:
                filtered.append(file_path)

        return filtered

    def filter_by_technique_id(self, yaml_files: list, technique_ids: list) -> list:
        """Filter YAML files by MITRE ATT&CK technique ID"""
        filtered = []
        tids_lower = [t.lower() for t in technique_ids]

        for file_path in yaml_files:
            yaml_data = self.read_yaml_file(file_path)
            if yaml_data:
                mitre_ids = yaml_data.get("tags", {}).get("mitre_attack_id", [])
                if mitre_ids:
                    for mid in mitre_ids:
                        if mid.lower() in tids_lower:
                            filtered.append(file_path)
                            break

        return filtered

    def filter_by_guid(self, yaml_files: list, guids: list) -> list:
        """Filter YAML files by detection GUID"""
        filtered = []
        guids_lower = [g.lower() for g in guids]

        for file_path in yaml_files:
            yaml_data = self.read_yaml_file(file_path)
            if yaml_data:
                detection_id = yaml_data.get("id", "").lower()
                if detection_id in guids_lower:
                    filtered.append(file_path)

        return filtered

    def filter_by_analytic_story(self, yaml_files: list, stories: list) -> list:
        """Filter YAML files by analytic story"""
        filtered = []
        stories_lower = [s.lower() for s in stories]

        for file_path in yaml_files:
            yaml_data = self.read_yaml_file(file_path)
            if yaml_data:
                analytic_stories = yaml_data.get("tags", {}).get("analytic_story", [])
                if analytic_stories:
                    for story in analytic_stories:
                        if story.lower() in stories_lower:
                            filtered.append(file_path)
                            break

        return filtered

    def run_splunk_search(self, splunk_host: str, username: str, password: str,
                          spl_query: str, earliest_time: str = "-24h", latest_time: str = "now") -> dict:
        """Run an SPL query on Splunk and return results"""

        # Create search job
        search_url = f"https://{splunk_host}:8089/services/search/jobs"

        search_data = {
            "search": f"search {spl_query}" if not spl_query.strip().startswith("|") else spl_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json"
        }

        max_retries = 3
        retry_delay = 30

        for attempt in range(1, max_retries + 1):
            try:
                # Create the search job
                response = requests.post(
                    search_url,
                    data=search_data,
                    auth=(username, password),
                    verify=False,
                    timeout=60
                )
                response.raise_for_status()

                job_response = response.json()
                job_sid = job_response.get("sid")

                if not job_sid:
                    return {"error": "Failed to get search job SID", "results": []}

                # Poll for job completion
                job_status_url = f"https://{splunk_host}:8089/services/search/jobs/{job_sid}"

                while True:
                    status_response = requests.get(
                        job_status_url,
                        params={"output_mode": "json"},
                        auth=(username, password),
                        verify=False,
                        timeout=60
                    )
                    status_response.raise_for_status()

                    status_data = status_response.json()
                    dispatch_state = status_data.get("entry", [{}])[0].get("content", {}).get("dispatchState", "")

                    if dispatch_state == "DONE":
                        break
                    elif dispatch_state == "FAILED":
                        return {"error": "Search job failed", "results": []}

                    time.sleep(2)

                # Get results
                results_url = f"https://{splunk_host}:8089/services/search/jobs/{job_sid}/results"
                results_response = requests.get(
                    results_url,
                    params={"output_mode": "json", "count": 0},
                    auth=(username, password),
                    verify=False,
                    timeout=120
                )
                results_response.raise_for_status()

                results_data = results_response.json()
                return {"error": None, "results": results_data.get("results", [])}

            except requests.exceptions.Timeout as e:
                if attempt < max_retries:
                    ColorPrint.print_warning_fg(f"[!][WARNING]: Request timed out (attempt {attempt}/{max_retries}). Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    return {"error": f"Request timed out after {max_retries} attempts: {e}", "results": []}
            except requests.exceptions.ConnectionError as e:
                return {"error": f"Connection error: {e}", "results": []}
            except requests.exceptions.HTTPError as e:
                return {"error": f"HTTP error: {e.response.status_code} - {e.response.text}", "results": []}
            except Exception as e:
                return {"error": f"Unexpected error: {e}", "results": []}

        return {"error": "Max retries exceeded", "results": []}

    def process_detections(self, yaml_files: list, output_file: str, earliest_time: str, latest_time: str) -> None:
        """Process detection YAML files and run their SPL queries"""

        ColorPrint.print_cyan_fg("\n" + "=" * 80)
        ColorPrint.print_cyan_fg("  DETECTION RUNNER - Running SPL queries from Security Content")
        ColorPrint.print_cyan_fg("=" * 80 + "\n")

        # Load Splunk connection settings
        splunk_settings = self.load_splunk_config()
        if not splunk_settings:
            return

        splunk_host = splunk_settings['host']
        username = splunk_settings['username']
        password = splunk_settings['password']

        if not yaml_files:
            ColorPrint.print_error_fg("[-][. ERROR]: No YAML files to process")
            return

        total_files = len(yaml_files)
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {total_files} YAML files to process")

        # Process each file and write results to JSONL
        processed = 0
        skipped = 0
        errors = 0

        with open(output_file, "w") as out_f:
            for ctr, file_path in enumerate(yaml_files):
                ColorPrint.print_info_fg(f"[+][.  INFO]: ... Processing {ctr+1}/{total_files}: {file_path}")

                yaml_data = self.read_yaml_file(file_path)
                if yaml_data is None:
                    ColorPrint.print_warning_fg(f"[!][WARNING]: ... Skipping invalid YAML file: {file_path}")
                    skipped += 1
                    continue

                # Extract required fields
                file_name = os.path.basename(file_path)
                description = yaml_data.get("description", "No description available")
                spl_query = yaml_data.get("search", None)

                if not spl_query:
                    ColorPrint.print_warning_fg(f"[!][WARNING]: ... No SPL query found in: {file_name}")
                    skipped += 1
                    continue

                ColorPrint.print_info_fg(f"[+][.  INFO]: ... Running SPL query for: {yaml_data.get('name', file_name)}")

                # Build the exact query that will be sent to Splunk
                exact_query = f"search {spl_query}" if not spl_query.strip().startswith("|") else spl_query
                ColorPrint.print_info_fg(f"[+][.  INFO]: ... SPL Query: {exact_query}")

                # Run the SPL query
                search_result = self.run_splunk_search(
                    splunk_host, username, password,
                    spl_query, earliest_time, latest_time
                )

                if search_result["error"]:
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Query failed: {search_result['error']}")
                    errors += 1
                else:
                    ColorPrint.print_success_fg(f"[+][SUCCESS]: ... Got {len(search_result['results'])} results")
                    processed += 1

                # Create output record
                output_record = {
                    "file_name": file_name,
                    "description": description,
                    "spl_query": spl_query,
                    "results": search_result["results"],
                    "error": search_result["error"]
                }

                # Write to JSONL
                out_f.write(json.dumps(output_record) + "\n")

        ColorPrint.print_cyan_fg("\n" + "=" * 80)
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Processing complete!")
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Total files: {total_files}")
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Processed: {processed}")
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Skipped: {skipped}")
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Errors: {errors}")
        ColorPrint.print_success_fg(f"[+][SUCCESS]: ... Results written to: {output_file}")
        ColorPrint.print_cyan_fg("=" * 80 + "\n")


def main():
    app = typer.Typer()

    @app.command()
    def run(
        detection_name: str = typer.Option(
            None, "--name", "-n",
            help="Comma-separated list of detection names or YAML filenames.\n\n<e.g. python3 run_detections.py -n 'Windows Remote Services, CMLUA Or CMSTPLUA UAC Bypass'>"
        ),
        technique_id: str = typer.Option(
            None, "--technique_id", "-tid",
            help="Comma-separated list of MITRE ATT&CK technique IDs.\n\n<e.g. python3 run_detections.py -tid 'T1021, T1020, T1537'>"
        ),
        guid: str = typer.Option(
            None, "--guid", "-g",
            help="Comma-separated list of detection GUIDs.\n\n<e.g. python3 run_detections.py -g '01d29b48-ff6f-11eb-b81e-acde48001123'>"
        ),
        analytic_story: str = typer.Option(
            None, "--analytic_story", "-as",
            help="Comma-separated list of analytic stories.\n\n<e.g. python3 run_detections.py -as 'AgentTesla, Remcos'>"
        ),
        all_detections: bool = typer.Option(
            False, "--all", "-a",
            help="Run SPL queries for ALL detection YAML files.\n\n<e.g. python3 run_detections.py --all>"
        ),
        output_file: str = typer.Option(
            "detection_results.jsonl",
            "--output", "-o",
            help="Output JSONL file path for results"
        ),
        earliest_time: str = typer.Option(
            "0",
            "--earliest", "-e",
            help="Earliest time for SPL search (e.g., 0 for all time, -24h, -7d, 2024-01-01T00:00:00)"
        ),
        latest_time: str = typer.Option(
            "now",
            "--latest", "-l",
            help="Latest time for SPL search (e.g., now, -1h, 2024-01-01T23:59:59)"
        ),
    ):
        """
        Run SPL queries from security content detection YAML files against Splunk.

        Splunk connection can be configured via config.yml or environment variables.
        Environment variables (SPLUNK_HOST, SPLUNK_USERNAME, SPLUNK_PASSWORD) override config file.

        Examples:
            python3 run_detections.py --all
            python3 run_detections.py -n 'Windows Remote Services'
            python3 run_detections.py -tid 'T1021, T1059'
            python3 run_detections.py -as 'AgentTesla' --output results.jsonl
        """
        runner = DetectionRunner()

        # Get all YAML files first
        all_yaml_files = runner.get_all_yaml_files()
        if not all_yaml_files:
            return

        yaml_files_to_process = []

        if detection_name:
            ColorPrint.print_info_fg("[+][.  INFO]: ... Filtering by detection name ...")
            names = runner.normalized_args_tolist(detection_name)
            yaml_files_to_process = runner.filter_by_name(all_yaml_files, names)
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {len(yaml_files_to_process)} matching detections")

        elif technique_id:
            ColorPrint.print_info_fg("[+][.  INFO]: ... Filtering by MITRE ATT&CK technique ID ...")
            tids = runner.normalized_args_tolist(technique_id)
            yaml_files_to_process = runner.filter_by_technique_id(all_yaml_files, tids)
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {len(yaml_files_to_process)} matching detections")

        elif guid:
            ColorPrint.print_info_fg("[+][.  INFO]: ... Filtering by detection GUID ...")
            guids = runner.normalized_args_tolist(guid)
            yaml_files_to_process = runner.filter_by_guid(all_yaml_files, guids)
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {len(yaml_files_to_process)} matching detections")

        elif analytic_story:
            ColorPrint.print_info_fg("[+][.  INFO]: ... Filtering by analytic story ...")
            stories = runner.normalized_args_tolist(analytic_story)
            yaml_files_to_process = runner.filter_by_analytic_story(all_yaml_files, stories)
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {len(yaml_files_to_process)} matching detections")

        elif all_detections:
            ColorPrint.print_info_fg("[+][.  INFO]: ... Processing ALL detection YAML files ...")
            yaml_files_to_process = all_yaml_files

        else:
            ColorPrint.print_error_fg("[-][. ERROR]: No filter specified. Use --all for all detections, or filter by --name, --technique_id, --guid, or --analytic_story")
            return

        if not yaml_files_to_process:
            ColorPrint.print_error_fg("[-][. ERROR]: No matching detections found")
            return

        runner.process_detections(yaml_files_to_process, output_file, earliest_time, latest_time)

    app()


if __name__ == "__main__":
    main()
