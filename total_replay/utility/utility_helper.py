"""
author: Teoderick Contreras
description: a utility class for several helper functions for echo-attack utility tool:
 - analytic story
 - detection name
 - detection guid id
 - Mitre attack Technique ID
 - detection name list in a file
"""

import os
import sys
import yaml
import platform
import logging
from pathlib import Path
from colorama import Fore, Back, Style, init
import datetime
import json
import requests
import subprocess
import time
import typer
import uuid
import re
import urllib
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, unquote
from urllib3 import disable_warnings
from utility.color_print import ColorPrint
import json

# Configure module-level logger
logger = logging.getLogger(__name__)

class UtilityHelper:

    def __init__(self):
        self.curdir = os.getcwd()
        self.config_file_path = os.path.join(self.curdir, "configuration", "config.yml")
        self.home_path = Path.home()
        self.processed_attack_data_uuid = []
        self.header_val = ""
        return
    
    def get_header_val(self):
        return self.header_val
    #############################################
    ### config helper functions
    #############################################
    def get_config_file_path(self)->str:
        return self.config_file_path 
    
    def load_config(self)->str:
        config_path = self.get_config_file_path()
        try:
            with open(config_path, "r") as file:
                config = yaml.safe_load(file)
                if config is None:
                    logger.error(f"Configuration file is empty: {config_path}")
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Configuration file is empty: {config_path}")
                    return {}
                return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Configuration file not found: {config_path}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse configuration file: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to parse configuration file: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error loading configuration: {e}", exc_info=True)
            ColorPrint.print_error_fg(f"[-][. ERROR]: Unexpected error loading configuration: {e}")
            return {}

    def read_config_settings(self, setting_field:str, key_tag="settings")->str:
        cfg = self.load_config()
        if not cfg:
            logger.error("Failed to load configuration")
            return None
        try:
            config_field = cfg[key_tag][setting_field]
            return config_field
        except KeyError:
            logger.error(f"Configuration key not found: {key_tag}.{setting_field}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Configuration key not found: {key_tag}.{setting_field}")
            return None
    
    #############################################
    ### helper functions
    #############################################
    def clear_screen(self)->None:
        """Clear the console screen based on the operating system."""
        if platform.system() == "Windows":
            os.system("cls")   ## Windows
        else:
            os.system("clear") ## macOS/Linux

        return
    
    def get_time_stamps(self)->str:
        """get the current timestamps"""
        timestamps = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return
    
    def show_banner(self)->None:

        banner = r"""
                 ________________
                |'-.--._ _________:
                |  /    |  __    __\   
                | |  _  | [\_\= [\_\_         ████████╗ ██████╗ ████████╗ █████╗ ██╗      ██████╗ ███████╗██████╗ ██╗      █████╗ ██╗   ██╗    ██╗ ██╗
                | |.' '. \...........|        ╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║      ██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝    ╚██╗╚██╗ 
                | ( <)  ||: █ █ █ █ :|_          ██║   ██║   ██║   ██║   ███████║██║█████╗██████╔╝█████╗  ██████╔╝██║     ███████║ ╚████╔╝      ╚██╗╚██╗
                \ '._.'█| :.....: |_(o █ █       ██║   ██║   ██║   ██║   ██╔══██║██║╚════╝██╔══██╗██╔══╝  ██╔═══╝ ██║     ██╔══██║  ╚██╔╝       ██╔╝██╔╝
                '-\_   \ .------./               ██║   ╚██████╔╝   ██║   ██║  ██║███████╗ ██║  ██║███████╗██║     ███████╗██║  ██║   ██║       ██╔╝██╔╝ 
                _   \   ||.---.||  _             ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝ ╚═╝ 
                / \  '-._|/|x~~|x | \        
                / \  '-._|/|x~~|x | \         by: @tccontre18 - Splunk Threat Research Team [STRT]
                (| []=.--[===[()]===[) |      ███████████████████████████████████████████████████████████████████████████████████████████████████████████═╗ 
                <\_/  \_______/ _.' /_/.       ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝
                ///            (_/_/.         
                |\\            [\\.              
                ||:|           | I|
                :/\:            ([])
                ([])             [|
                ||              |\_
                _/_\_            [ -'-.__
        snd <]   \>            \_____.>
                \__/          ___Br3akp0int_]

        """ 
        self.clear_screen()

        ColorPrint.print_cyan_fg(banner)

        return
    
    def header_divider(self, header:str, tag:str="...")->str:
        timestamp = f"[ {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ]==> [+][. TOTAL-REPLAY: {tag}]: ..."
        header_div = f"""
 ╔══════════════════════════════════════════════════════════════════ [ {header} ] ══════════════════════════════════════════════════════════════════
 ║
 ╚═{timestamp}
    """
        return header_div

    def footer_divider(self,footer:str):
        timestamp = f"[ {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ]==> [+][.    END]: ..."

        footer_div = f"""
 ╔═{timestamp}
 ╚══════════════════════════════════════════════════════════════════ [ {footer} ] ═══════════════════════════════════════════════════════════════════
    """
        return footer_div
    
    def load_environment_variables(self)->dict:
        """Load required environment variables for Splunk connection."""
        ColorPrint.print_info_fg("[+][.  INFO]: ... Checking SPLUNK HOST and HEC_TOKEN ENV VARIABLE ...")
        logger.debug("Loading environment variables for Splunk connection")
        required_vars = ['SPLUNK_HOST', 'SPLUNK_HEC_TOKEN']
        env_vars = {}
        missing_vars = []
        for var in required_vars:
            value = os.environ.get(var)
            if not value:
                missing_vars.append(var)
            else:
                env_vars[var.lower().replace('splunk_', '')] = value

        if missing_vars:
            error_msg = f"Required environment variable(s) not set: {', '.join(missing_vars)}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            ColorPrint.print_error_fg("[-][. ERROR]: Please set SPLUNK_HOST and SPLUNK_HEC_TOKEN environment variables")
            return {}

        logger.debug("Environment variables loaded successfully")
        return env_vars

    def normalized_args_tolist(self, input_args:str)->list:
        return [i.strip() for i in input_args.split(',')] 

    def parse_needed_detection_name(self, normalized_args_list:list)->list:
        """Parse and find detection YAML files by filename."""
        logger.debug(f"Parsing detection names: {normalized_args_list}")

        ColorPrint.print_info_fg(f'[+][.  INFO]: ... Enumerating detection .yml file name ... []')
        security_content_dir_path = self.read_config_settings("security_content_detection_path")

        if security_content_dir_path is None:
            logger.error("Failed to read security_content_detection_path from config")
            return []

        expanded_path = os.path.expanduser(security_content_dir_path)
        if not os.path.isdir(expanded_path):
            error_msg = f"The security content folder path is invalid or does not exist: {expanded_path}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[+][. ERROR]: {error_msg}")
            return []

        search_count = 0
        search_found_list = []
        found_flag = False
        needed_replay_yaml_field = {}

        for roots, dirs, files in os.walk(expanded_path):

            ### skip deprecated directories
            if dirs == "deprecated":
                continue

            if found_flag:
                break

            ### enumerate the files in the directory
            for file in files:

                if file.lower() in [fn.lower() for fn in normalized_args_list]:
                    logger.info(f"Found matching detection file: {file}")
                    ColorPrint.print_success_fg(f"[+][SUCCESS]: ... SEARCH FOUND -> [ {file} ]")
                    file_path = os.path.join(roots, file)

                    yaml_data = self.read_yaml_file(file_path)

                    ### check if file content is empty or invalid
                    if yaml_data is None:
                        logger.warning(f"Skipping empty or invalid YAML file: {file_path}")
                        ColorPrint.print_warning_fg(f"[!][WARNING]: ... Skipping empty or invalid YAML file: {file_path}")
                        continue
                    needed_replay_yaml_field = self.create_metadata_cache(yaml_data, file_path)
                    search_found_list.append(needed_replay_yaml_field)

                    search_count += 1
                    if search_count == len(normalized_args_list):
                        found_flag = True
                        break

        logger.info(f"Total filtered detections found: {len(search_found_list)}")
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Total filtered detections: {len(search_found_list)} ")

        if len(search_found_list) < len(normalized_args_list):
            not_found_count = len(normalized_args_list) - len(search_found_list)
            logger.warning(f"{not_found_count} detection(s) were not found")

        return search_found_list
    
    def process_replay_attack_data_by_file_name(self, tag:str, normalized_args_list:list, index_value:str, generated_guid:str)->None:
        """main function in replaying attack data base on Splunk detection filename"""

        ColorPrint.print_cyan_fg(self.header_divider("TOTAl-REPLAY-ACTIVATED", tag))

        search_found_list=[]
        search_found_list = self.parse_needed_detection_name(normalized_args_list)
       
        ### generate uid for caching purposes of replay data

        for ctr, needed_replay_yaml_field in enumerate(search_found_list):

            ### get the attack data url link
            if "attack_data_link" in needed_replay_yaml_field:
                attack_data_link = needed_replay_yaml_field["attack_data_link"]
            else:
                continue

            ### generate replay yaml output folder
            output_base_dir = os.path.join(self.curdir, self.read_config_settings('output_dir_name'))
            self.generate_output_dir(output_base_dir)
            
            attack_data_timestamp_dir_path = os.path.join(output_base_dir, datetime.date.today().strftime("%Y-%m-%d"))
            escu_detection_guid = needed_replay_yaml_field['id']

            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Downloading attack data for: {needed_replay_yaml_field['name']} ... item:{ctr+1}")
            logger.debug(f"Downloading attack data for: {needed_replay_yaml_field['name']}")

            attack_datasets_full_path, attack_datasets_path = self.download_via_attack_data(attack_data_link, attack_data_timestamp_dir_path, generated_guid)

            # Check if download was successful
            if attack_datasets_full_path is None or attack_datasets_path is None:
                logger.error(f"Failed to download attack data for: {needed_replay_yaml_field['name']}")
                ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to download attack data for: {needed_replay_yaml_field['name']}")
                continue

            ### update the total-replay cache yaml file
            needed_replay_yaml_field['attack_data_output_file_path'] = attack_datasets_full_path


            needed_replay_yaml_field = self.locate_associated_attack_data_yaml_file(attack_data_link, attack_datasets_path, needed_replay_yaml_field)
            if not needed_replay_yaml_field:
                logger.error("Failed to locate associated YAML file for attack data")
                continue

            ### dropped the replay yaml cache
            replayed_yaml_cache_dir = self.read_config_settings('replayed_yaml_cache_dir_name')
            if not replayed_yaml_cache_dir:
                logger.error("Failed to read replayed_yaml_cache_dir_name from config")
                continue

            replayed_yaml_cache_path = os.path.join(attack_data_timestamp_dir_path, generated_guid, replayed_yaml_cache_dir)
            self.generate_output_dir(replayed_yaml_cache_path)

            cache_replay_yaml_name = self.read_config_settings('cache_replay_yaml_name')
            if not cache_replay_yaml_name:
                logger.error("Failed to read cache_replay_yaml_name from config")
                continue

            cache_replay_yaml_file_path = os.path.join(replayed_yaml_cache_path, needed_replay_yaml_field['id'] + "_" + cache_replay_yaml_name)
            self.dump_yaml_file(cache_replay_yaml_file_path, needed_replay_yaml_field)

            ### comment me if you dont want to see the replay_cache yml file
            if self.read_config_settings('debug_print'):
                ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("TOTAL-REPLAY CACHE YAML FILE", tag))
                ColorPrint.print_yellow_fg(Style.DIM + f"[+] ... \n{json.dumps(needed_replay_yaml_field, indent=4)}")
                ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("TOTAL-REPLAY CACHE YAML FILE"))

            self.processed_attack_data_uuid.append(needed_replay_yaml_field['attack_data_uuid'])


            try:
                result = self.attack_data_replay_cmd(needed_replay_yaml_field, index_value)
                if not result:
                    logger.warning(f"Attack data replay returned failure for: {needed_replay_yaml_field['name']}")
            except Exception as e:
                logger.error(f"Attack Data Replay Exception for {needed_replay_yaml_field['name']}: {e}", exc_info=True)
                ColorPrint.print_error_fg(f"[-][. ERROR]: Attack Data Replay Exception: {e}")


            ColorPrint.print_magenta_fg("\n[+]" + "█" * 160 + "\n")

        ColorPrint.print_cyan_fg(self.footer_divider("TOTAl-REPLAY-ACTIVATED"))

        return
    
    def dump_yaml_file(self, file_path:str, data:dict)->bool:
        """Write data to a YAML file."""
        logger.debug(f"Writing YAML cache file: {file_path}")
        try:
            with open(file_path, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            logger.debug(f"Successfully wrote YAML file: {file_path}")
            return True
        except IOError as e:
            logger.error(f"Failed to write YAML file {file_path}: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to write YAML file: {e}")
            return False
        except yaml.YAMLError as e:
            logger.error(f"YAML serialization error for {file_path}: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: YAML serialization error: {e}")
            return False

    def generate_output_dir(self, dir_name:str)->bool:
        """generate the base output folder for total-replay cache data"""

        ### if not exist create output directory
        if not os.path.isdir(dir_name):
            try:
                os.makedirs(dir_name, exist_ok=True)
                logger.debug(f"Created output directory: {dir_name}")
                ColorPrint.print_success_fg(f"[+][SUCCESS]: ... {dir_name} folder created!")
            except OSError as e:
                logger.error(f"Failed to create output directory {dir_name}: {e}")
                ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to create directory: {e}")
                return False
        return True
            
    def download_via_attack_data(self, attack_data_link:str, attack_data_timestamp_dir_path:str, generated_guid:str)->tuple:
        """download needed raw attack data via attack data feature"""
        logger.debug(f"Downloading attack data from: {attack_data_link}")

        ### generate a unique guid folder path
        guid_dir_path = os.path.join(attack_data_timestamp_dir_path, generated_guid)
        self.generate_output_dir(guid_dir_path)

        ### verify if the string contain url scheme
        p = urlparse(attack_data_link)
        if not p.scheme or not p.netloc:
            error_msg = f"Unsupported GitHub URL format: {attack_data_link}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            raise ValueError(f"[-][. ERROR]: ... {error_msg}")

        try:
            m, datasets_path = str(p.path).split("master/")
        except ValueError:
            error_msg = f"URL does not contain expected 'master/' path segment: {attack_data_link}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return (None, None)

        ### locate the attack_data path in config
        attack_data_dir = self.read_config_settings('attack_data_dir_path')
        if attack_data_dir is None:
            logger.error("Failed to read attack_data_dir_path from configuration")
            return (None, None)

        expanded_attack_data_dir = os.path.expanduser(attack_data_dir)
        if not os.path.isdir(expanded_attack_data_dir):
            error_msg = f"The attack data folder path in config is invalid or does not exist: {expanded_attack_data_dir}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[+][. ERROR]: {error_msg}")
            return (None, None)

        attack_datasets_full_path = os.path.join(expanded_attack_data_dir, datasets_path)
        if os.path.isfile(attack_datasets_full_path):
            logger.info(f"Attack data already exists, skipping download: {attack_datasets_full_path}")
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Attack data at: {attack_datasets_full_path} already exists. Download skipped.")
            return (attack_datasets_full_path, datasets_path)

        # Find the Git repository root
        try:
            repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to find Git repository root: {e}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return (None, None)
        except FileNotFoundError:
            error_msg = "Git command not found. Please ensure Git is installed and in PATH."
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return (None, None)

        git_lfs_cmd = ["git", "lfs", "pull", f"--include={datasets_path}"]
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... command: {' '.join(git_lfs_cmd)}")
        logger.debug(f"Executing Git LFS command: {' '.join(git_lfs_cmd)}")

        ### execute the git command process
        try:
            result = subprocess.run(git_lfs_cmd, check=True, cwd=repo_root, capture_output=True, text=True)
            logger.info(f"Successfully downloaded attack data: {datasets_path}")
            ColorPrint.print_success_fg(f"[+][SUCCESS]: ... Git Command succeeded! attack data: {datasets_path} ==> downloaded successfully!")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git LFS pull failed - Exit code: {e.returncode}, Stdout: {e.stdout}, Stderr: {e.stderr}")
            ColorPrint.print_error_fg("[-][. ERROR]: ... Git LFS command failed!")
            ColorPrint.print_error_fg(f"[-][. ERROR]: ... Exit code: {e.returncode}")
            if e.stdout:
                ColorPrint.print_error_fg(f"[-][. ERROR]: ... Stdout: {e.stdout}")
            if e.stderr:
                ColorPrint.print_error_fg(f"[-][. ERROR]: ... Stderr: {e.stderr}")
            return (None, None)
        except FileNotFoundError:
            error_msg = "Git LFS command not found. Please ensure Git LFS is installed."
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return (None, None)

        return (attack_datasets_full_path, datasets_path)
     

    def read_yaml_file(self, file_path:str)->dict:
        """Read a YAML file and return its content as a dictionary."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            ColorPrint.print_error_fg(f"[!] [ERROR]: File not found: {file_path}")
            return None
        except PermissionError:
            ColorPrint.print_error_fg(f"[!] [STATUS]: error ... permission denied: {file_path}")
            return None
        except yaml.YAMLError as e:
            ColorPrint.print_error_fg(f"[!] [ERROR]: Error reading YAML file {file_path}: {e}")
            return None

    def locate_associated_attack_data_yaml_file(self, attack_data_link:str, attack_datasets_path:str, needed_yaml_field_cache:dict)->dict:
        """Locate and parse the YAML file associated with attack data."""
        logger.debug(f"Locating associated YAML file for: {attack_data_link}")

        ### check and parsed the yml file associated with the attack data
        try:
            yml_name = os.path.basename(os.path.dirname(unquote(urlparse(attack_data_link).path)))
        except Exception as e:
            logger.error(f"Failed to parse attack data link URL: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to parse attack data link: {e}")
            return {}

        ### locate the attack_data path in config
        attack_data_dir = self.read_config_settings('attack_data_dir_path')
        if attack_data_dir is None:
            logger.error("Failed to read attack_data_dir_path from config")
            return {}

        expanded_attack_data_dir = os.path.expanduser(attack_data_dir)
        if not os.path.isdir(expanded_attack_data_dir):
            error_msg = f"The attack data folder path is invalid or does not exist: {expanded_attack_data_dir}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[+][. ERROR]: {error_msg}")
            return {}

        attack_data_full_dir_path = os.path.join(expanded_attack_data_dir, os.path.dirname(attack_datasets_path))

        if not os.path.isdir(attack_data_full_dir_path):
            error_msg = f"Attack data directory not found: {attack_data_full_dir_path}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return {}

        ### enumerate all yaml file inside the attack data folder base on the attack_data_link in escu
        try:
            dir_contents = os.listdir(attack_data_full_dir_path)
        except OSError as e:
            logger.error(f"Failed to list directory {attack_data_full_dir_path}: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to list directory: {e}")
            return {}

        for file in dir_contents:
            if file.endswith((".yml", ".yaml")):
                yml_file_path = os.path.join(attack_data_full_dir_path, file)
                attack_data_yaml_buff = self.read_yaml_file(yml_file_path)

                if attack_data_yaml_buff is None:
                    logger.debug(f"Skipping invalid YAML file: {yml_file_path}")
                    continue

                ### this is to support the old and new attack data yaml format
                datasets = attack_data_yaml_buff.get("datasets", [])
                dataset = attack_data_yaml_buff.get("dataset", "")

                has_new_format = (
                    isinstance(datasets, list)
                    and len(datasets) > 0
                    and attack_datasets_path in datasets[0].get("path", "")
                )

                has_old_format = (
                    (isinstance(dataset, str) and attack_datasets_path in dataset)
                    or (isinstance(dataset, list) and dataset and attack_datasets_path in dataset[0])
                )

                if yml_name in file or has_new_format or has_old_format:

                    needed_yaml_field_cache['attack_data_yml_file_path'] = yml_file_path
                    attack_id = attack_data_yaml_buff.get("id")
                    if attack_id:
                        needed_yaml_field_cache['attack_data_uuid'] = attack_data_yaml_buff['id']
                        logger.info(f"Found associated YAML file: {file}")
                        ColorPrint.print_success_fg(f"[+][SUCCESS]: ... {file} ==> associated yml file extracted successfully")
                        return needed_yaml_field_cache
                    else:
                        logger.warning(f"YAML file {file} missing 'id' field")
                        ColorPrint.print_warning_fg(f"[!][WARNING]: ... attack_data yaml field: [uuid] => not found in {file}!")

        # This runs ONLY if the loop never hits 'return' or 'break'
        logger.error(f"No matching YAML file found for attack data: {attack_datasets_path}")
        ColorPrint.print_error_fg("[-][. ERROR]: ... No matching YAML file was found during iteration!")
        return {}

    def create_metadata_cache(self, yaml_data: yaml, file_path: str = None) -> dict:
        """Create a metadata cache from the YAML data."""

        needed_replay_yaml_field = {
            "name": yaml_data.get("name", "Unknown"),
            "id": yaml_data.get("id", "Unknown"),
            "mitre_attack_id": yaml_data.get("tags", {}).get("mitre_attack_id", "Unknown"),
            "analytic_story": yaml_data.get("tags", {}).get("analytic_story", "Unknown"),
            "description": yaml_data.get("description", "No description available"),
            "file_path": file_path if file_path else "Unknown"
        }

        # Checking for 'tests' key for handling 'attack_data' yaml field
        if "tests" in yaml_data:

            # Check if 'attack_data' is present and not empty
            if yaml_data["tests"]:
                test = yaml_data["tests"][0]  # First test in the list

                # Check for 'attack_data' key and that it's not empty
                if "attack_data" in test and test["attack_data"]:
                    attack_data = test["attack_data"][0]  # Assuming it's a list with at least one entry

                    # Adding the 'attack_data' fields to the cache dictionary
                    needed_replay_yaml_field["attack_data_link"] = attack_data.get("data", "N/A")
                    needed_replay_yaml_field["attack_data_source"] = attack_data.get("source", "N/A")
                    needed_replay_yaml_field["attack_data_sourcetype"] = attack_data.get("sourcetype", "N/A")

                else:
                    ColorPrint.print_warning_fg("[!][WARNING]: ... attack_data is empty or missing in the first test")
            else:
                ColorPrint.print_warning_fg("[!][WARNING]: ... no tests available in the YAML")
        else:
            ColorPrint.print_warning_fg("[!][WARNING]: ... no tests field in YAML data")

        return needed_replay_yaml_field
    
    def send_data_to_splunk(self, file_path, splunk_host, hec_token, event_host_uuid, index="test", source="test", sourcetype="test"):
        """Send a data file to Splunk HEC."""
        logger.debug(f"Preparing to send data to Splunk - file: {file_path}, host: {splunk_host}, index: {index}")
        disable_warnings()

        # Validate file exists
        if not os.path.isfile(file_path):
            error_msg = f"Data file not found: {file_path}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return False

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
        if self.read_config_settings('debug_print'):
            ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("ATTACK DATA REPLAY SUMMARY"))
            name_value = os.path.basename(file_path).split(".")[0]
            ColorPrint.print_yellow_fg(Style.DIM + f"[+][.  INFO]: ... Sending dataset '{name_value}' from {file_path}")
            ColorPrint.print_yellow_fg(Style.DIM + f"[+][.  INFO]: ... index: {index}")
            ColorPrint.print_yellow_fg(Style.DIM + f"[+][.  INFO]: ... source: {source}")
            ColorPrint.print_yellow_fg(Style.DIM + f"[+][.  INFO]: ... sourcetype: {sourcetype}")
            ColorPrint.print_yellow_fg(Style.DIM + f"[+][.  INFO]: ... uuid: {event_host_uuid}")
            ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("ATTACK DATA REPLAY SUMMARY"))

        max_retries = 3
        retry_delay = 30  # seconds

        try:
            with open(file_path, "rb") as datafile:
                data = datafile.read()
                if not data:
                    logger.warning(f"Data file is empty: {file_path}")
                    ColorPrint.print_warning_fg(f"[!][WARNING]: Data file is empty: {file_path}")

                for attempt in range(1, max_retries + 1):
                    try:
                        res = requests.post(
                            url,
                            params=url_params,
                            data=data,
                            allow_redirects=True,
                            headers=headers,
                            verify=False,
                            timeout=300
                        )
                        res.raise_for_status()
                        logger.info(f"Successfully sent data to Splunk HEC: {file_path}")
                        ColorPrint.print_success_fg(f"[+][SUCCESS]: ... Sent {file_path} to Splunk HEC")
                        return True
                    except requests.exceptions.ConnectionError as e:
                        error_msg = f"Failed to connect to Splunk HEC at {splunk_host}:8088 - {e}"
                        logger.error(error_msg)
                        ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
                        return False
                    except requests.exceptions.Timeout as e:
                        if attempt < max_retries:
                            logger.warning(f"Request to Splunk HEC timed out (attempt {attempt}/{max_retries}). Retrying in {retry_delay} seconds...")
                            ColorPrint.print_warning_fg(f"[!][WARNING]: Request timed out (attempt {attempt}/{max_retries}). Retrying in {retry_delay} seconds...")
                            time.sleep(retry_delay)
                        else:
                            error_msg = f"Request to Splunk HEC timed out after {max_retries} attempts: {e}"
                            logger.error(error_msg)
                            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
                            return False
                    except requests.exceptions.HTTPError as e:
                        error_msg = f"HTTP error from Splunk HEC: {e.response.status_code} - {e.response.text}"
                        logger.error(error_msg)
                        ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
                        return False
                    except requests.exceptions.RequestException as e:
                        error_msg = f"Error sending data to Splunk HEC: {e}"
                        logger.error(error_msg)
                        ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
                        return False
        except IOError as e:
            error_msg = f"Failed to read data file {file_path}: {e}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return False

    def attack_data_replay_cmd(self, needed_replay_yaml_field:dict, index_value:str)->bool:
        """main function in replaying attack data in splunk server"""
        logger.debug(f"Starting attack data replay for detection: {needed_replay_yaml_field.get('name', 'Unknown')}")

        env_var = self.load_environment_variables()
        if not env_var:
            logger.error("Cannot replay attack data: environment variables not set")
            return False

        try:
            splunk_host = env_var['host']
            hec_token = env_var['hec_token']
        except KeyError as e:
            logger.error(f"Missing required environment variable key: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Missing required environment variable: {e}")
            return False

        # Validate required fields in the yaml cache
        required_fields = ['attack_data_output_file_path', 'attack_data_source', 'attack_data_sourcetype',
                          'attack_data_uuid', 'attack_data_yml_file_path']
        missing_fields = [f for f in required_fields if f not in needed_replay_yaml_field]
        if missing_fields:
            logger.error(f"Missing required fields in replay data: {', '.join(missing_fields)}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Missing required fields: {', '.join(missing_fields)}")
            return False

        attack_data_file_path = needed_replay_yaml_field['attack_data_output_file_path']
        attack_data_source = needed_replay_yaml_field['attack_data_source']
        attack_data_source_type = needed_replay_yaml_field['attack_data_sourcetype']
        attack_data_uuid = needed_replay_yaml_field['attack_data_uuid']
        attack_data_yml_file_path = needed_replay_yaml_field['attack_data_yml_file_path']

        # Validate attack data file exists
        if not attack_data_file_path or not os.path.isfile(attack_data_file_path):
            logger.error(f"Attack data file not found: {attack_data_file_path}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Attack data file not found: {attack_data_file_path}")
            return False

        attack_data_dir = self.read_config_settings('attack_data_dir_path')
        if attack_data_dir and not os.path.isdir(os.path.expanduser(attack_data_dir)):
            logger.error(f"The attack data folder path in config is invalid or does not exist: {attack_data_dir}")
            ColorPrint.print_error_fg("[-][. ERROR]: ... The attack data folder path in config is invalid or does not exist.")
            return False

        try:
            result = self.send_data_to_splunk(attack_data_file_path, splunk_host, hec_token, attack_data_uuid,
                                              index_value, attack_data_source, attack_data_source_type)
            if result:
                logger.info(f"Successfully replayed attack data for: {needed_replay_yaml_field.get('name', 'Unknown')}")
            return result
        except Exception as e:
            logger.error(f"Error replaying attack data: {e}", exc_info=True)
            ColorPrint.print_error_fg(f"[-][. ERROR]: Error replaying attack data: {e}")
            return False


    def process_replay_all_detections(self, index_value: str, generated_guid: str) -> None:
        """Replay attack data for ALL detection YAML files in security content"""
        tag = "all_detections"

        ColorPrint.print_cyan_fg(self.header_divider("TOTAl-REPLAY-ACTIVATED", tag))

        security_content_dir_path = self.read_config_settings("security_content_detection_path")
        if security_content_dir_path is None:
            ColorPrint.print_error_fg("[-][. ERROR]: Failed to read security_content_detection_path from config")
            return

        expanded_path = os.path.expanduser(security_content_dir_path)
        if not os.path.isdir(expanded_path):
            ColorPrint.print_error_fg(f"[-][. ERROR]: The security content folder path is invalid or does not exist: {expanded_path}")
            return

        # Collect all YAML files first
        all_yaml_files = []
        for root, dirs, files in os.walk(expanded_path):
            if "deprecated" in dirs:
                dirs.remove("deprecated")  # Skip deprecated folder
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    all_yaml_files.append(os.path.join(root, file))

        total_files = len(all_yaml_files)
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Found {total_files} YAML files to process")

        for ctr, file_path in enumerate(all_yaml_files):
            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Processing {ctr+1}/{total_files}: {file_path}")

            yaml_data = self.read_yaml_file(file_path)
            if yaml_data is None:
                ColorPrint.print_warning_fg(f"[!][WARNING]: ... Skipping empty or invalid YAML file: {file_path}")
                continue

            needed_replay_yaml_field = self.create_metadata_cache(yaml_data, file_path)

            # Check if attack_data_link exists
            if "attack_data_link" not in needed_replay_yaml_field or needed_replay_yaml_field["attack_data_link"] == "N/A":
                continue

            attack_data_link = needed_replay_yaml_field["attack_data_link"]

            # Generate replay yaml output folder
            output_dir_name = self.read_config_settings('output_dir_name')
            if not output_dir_name:
                ColorPrint.print_error_fg("[-][. ERROR]: Failed to read output_dir_name from config")
                continue

            output_base_dir = os.path.join(self.curdir, output_dir_name)
            self.generate_output_dir(output_base_dir)

            attack_data_timestamp_dir_path = os.path.join(output_base_dir, datetime.date.today().strftime("%Y-%m-%d"))

            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Downloading attack data for: {needed_replay_yaml_field['name']}")

            attack_datasets_full_path, attack_datasets_path = self.download_via_attack_data(attack_data_link, attack_data_timestamp_dir_path, generated_guid)

            # Check if download was successful
            if attack_datasets_full_path is None or attack_datasets_path is None:
                ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to download attack data for: {needed_replay_yaml_field['name']}")
                continue

            # Update the total-replay cache yaml file
            needed_replay_yaml_field['attack_data_output_file_path'] = attack_datasets_full_path
            needed_replay_yaml_field = self.locate_associated_attack_data_yaml_file(attack_data_link, attack_datasets_path, needed_replay_yaml_field)
            if not needed_replay_yaml_field:
                ColorPrint.print_error_fg("[-][. ERROR]: Failed to locate associated YAML file for attack data")
                continue

            # Dropped the replay yaml cache
            replayed_yaml_cache_dir = self.read_config_settings('replayed_yaml_cache_dir_name')
            if not replayed_yaml_cache_dir:
                ColorPrint.print_error_fg("[-][. ERROR]: Failed to read replayed_yaml_cache_dir_name from config")
                continue

            replayed_yaml_cache_path = os.path.join(attack_data_timestamp_dir_path, generated_guid, replayed_yaml_cache_dir)
            self.generate_output_dir(replayed_yaml_cache_path)

            cache_replay_yaml_name = self.read_config_settings('cache_replay_yaml_name')
            if not cache_replay_yaml_name:
                ColorPrint.print_error_fg("[-][. ERROR]: Failed to read cache_replay_yaml_name from config")
                continue

            cache_replay_yaml_file_path = os.path.join(replayed_yaml_cache_path, needed_replay_yaml_field['id'] + "_" + cache_replay_yaml_name)
            self.dump_yaml_file(cache_replay_yaml_file_path, needed_replay_yaml_field)

            if self.read_config_settings('debug_print'):
                ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("TOTAL-REPLAY CACHE YAML FILE", tag))
                ColorPrint.print_yellow_fg(Style.DIM + f"[+] ... \n{json.dumps(needed_replay_yaml_field, indent=4)}")
                ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("TOTAL-REPLAY CACHE YAML FILE"))

            self.processed_attack_data_uuid.append(needed_replay_yaml_field['attack_data_uuid'])

            try:
                result = self.attack_data_replay_cmd(needed_replay_yaml_field, index_value)
                if not result:
                    ColorPrint.print_warning_fg(f"[!][WARNING]: Attack data replay returned failure for: {needed_replay_yaml_field['name']}")
            except Exception as e:
                ColorPrint.print_error_fg(f"[-][. ERROR]: Attack Data Replay Exception: {e}")

            ColorPrint.print_magenta_fg("\n[+]" + "█" * 160 + "\n")

        ColorPrint.print_cyan_fg(self.footer_divider("TOTAl-REPLAY-ACTIVATED"))
        ColorPrint.print_info_fg(f"[+][.  INFO]: ... Completed processing all {total_files} detection files")

    def process_replay_attack_data(self, tag:str, normalized_args_list:list, index_value:str, generated_guid:str)->None:
        """main function in replaying attack data using ESCU metadata"""
        logger.info(f"Starting replay for {len(normalized_args_list)} items with tag: {tag}")

        ColorPrint.print_cyan_fg(self.header_divider("TOTAl-REPLAY-ACTIVATED", tag))


        search_found_list = []
        for field_name in normalized_args_list:

            ### skipped if the inputted string has file extension or not a .yml file
            if field_name.endswith(".yml"):
                logger.debug(f"Skipping .yml extension in field name: {field_name}")
                continue

            needed_replay_yaml_field = {}
            search_found_list = self.search_security_content(tag, field_name)

            if not search_found_list:
                logger.warning(f"No matching detections found for: {field_name}")
                continue

            ColorPrint.print_info_fg(f"[+][.  INFO]: ... Total filtered detections: {len(search_found_list)} ")
            logger.info(f"Found {len(search_found_list)} detections for: {field_name}")


            for ctr, needed_replay_yaml_field in enumerate(search_found_list):
                ColorPrint.print_info_fg(f"[+][.  INFO]: ... Processing detection {ctr+1}/{len(search_found_list)}: {needed_replay_yaml_field.get('file_path', 'Unknown')}")

                ### get the attack data url link
                if "attack_data_link" in needed_replay_yaml_field:
                    attack_data_link = needed_replay_yaml_field["attack_data_link"]
                else:
                    logger.warning(f"No attack_data_link found for detection: {needed_replay_yaml_field.get('name', 'Unknown')}")
                    continue

                ### generate replay yaml output folder
                output_dir_name = self.read_config_settings('output_dir_name')
                if not output_dir_name:
                    logger.error("Failed to read output_dir_name from config")
                    continue

                output_base_dir = os.path.join(self.curdir, output_dir_name)
                self.generate_output_dir(output_base_dir)

                attack_data_timestamp_dir_path = os.path.join(output_base_dir, datetime.date.today().strftime("%Y-%m-%d"))
                escu_detection_guid = needed_replay_yaml_field['id']

                ColorPrint.print_info_fg(f"[+][.  INFO]: ... Downloading attack data for: {needed_replay_yaml_field['name']} ... item:{ctr+1}")
                logger.debug(f"Downloading attack data for: {needed_replay_yaml_field['name']}")

                attack_datasets_full_path, attack_datasets_path = self.download_via_attack_data(attack_data_link, attack_data_timestamp_dir_path, generated_guid)

                # Check if download was successful
                if attack_datasets_full_path is None or attack_datasets_path is None:
                    logger.error(f"Failed to download attack data for: {needed_replay_yaml_field['name']}")
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to download attack data for: {needed_replay_yaml_field['name']}")
                    continue

                ### update the total-replay cache yaml file
                needed_replay_yaml_field['attack_data_output_file_path'] = attack_datasets_full_path
                needed_replay_yaml_field = self.locate_associated_attack_data_yaml_file(attack_data_link, attack_datasets_path, needed_replay_yaml_field)
                if not needed_replay_yaml_field:
                    logger.error("Failed to locate associated YAML file for attack data")
                    continue

                ### dropped the replay yaml cache
                replayed_yaml_cache_dir = self.read_config_settings('replayed_yaml_cache_dir_name')
                if not replayed_yaml_cache_dir:
                    logger.error("Failed to read replayed_yaml_cache_dir_name from config")
                    continue

                replayed_yaml_cache_path = os.path.join(attack_data_timestamp_dir_path, generated_guid, replayed_yaml_cache_dir)
                self.generate_output_dir(replayed_yaml_cache_path)

                cache_replay_yaml_name = self.read_config_settings('cache_replay_yaml_name')
                if not cache_replay_yaml_name:
                    logger.error("Failed to read cache_replay_yaml_name from config")
                    continue

                cache_replay_yaml_file_path = os.path.join(replayed_yaml_cache_path, needed_replay_yaml_field['id'] + "_" + cache_replay_yaml_name)
                self.dump_yaml_file(cache_replay_yaml_file_path, needed_replay_yaml_field)

                ### comment me if you dont want to see the replay_cache yml file
                if self.read_config_settings('debug_print'):
                    ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("TOTAL-REPLAY CACHE YAML FILE", tag))
                    ColorPrint.print_yellow_fg(Style.DIM + f"[+] ... \n{json.dumps(needed_replay_yaml_field, indent=4)}")
                    ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("TOTAL-REPLAY CACHE YAML FILE"))


                self.processed_attack_data_uuid.append(needed_replay_yaml_field['attack_data_uuid'])

                try:
                    result = self.attack_data_replay_cmd(needed_replay_yaml_field, index_value)
                    if not result:
                        logger.warning(f"Attack data replay returned failure for: {needed_replay_yaml_field['name']}")
                except Exception as e:
                    logger.error(f"Attack Data Replay Exception for {needed_replay_yaml_field['name']}: {e}", exc_info=True)
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Attack Data Replay Exception: {e}")

                ColorPrint.print_magenta_fg("\n[+]" + "█" * 160 + "\n")

        ColorPrint.print_cyan_fg(self.footer_divider("TOTAl-REPLAY-ACTIVATED"))


        return

    def search_security_content(self, key_name: str, field_name:str)->list:
        """Function in parsing Splunk Security Content Repo"""
        logger.debug(f"Searching security content for key={key_name}, field={field_name}")

        ColorPrint.print_info_fg(f'[+][.  INFO]: ... processing => [ {field_name} ]')

        search_found_list = []

        found_flag = False

        needed_replay_yaml_field = {}
        security_content_dir_path = self.read_config_settings("security_content_detection_path")

        if security_content_dir_path is None:
            logger.error("Failed to read security_content_detection_path from config")
            return []

        expanded_path = os.path.expanduser(security_content_dir_path)
        if not os.path.isdir(expanded_path):
            error_msg = f"The security content folder path is invalid or does not exist: {expanded_path}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[+][. ERROR]: {error_msg}")
            return []

        for root, dirs, files in os.walk(expanded_path):
            ## skip deprecated folder
            if dirs == "deprecated":
                continue
            ## break the loop once we found the needed field value
            if found_flag:
                break

            for file in files:

                if file.endswith((".yaml",".yml")):
                    file_path = os.path.join(root, file)

                    yaml_data = self.read_yaml_file(file_path)

                    ### check if file content is empty or invalid
                    if yaml_data is None:
                        logger.debug(f"Skipping empty or invalid YAML file: {file_path}")
                        continue

                    if self.check_needed_yaml_field(key_name, field_name, yaml_data):
                        if key_name != "mitre_attack_id" and key_name != "analytic_story":
                            found_flag = True

                        needed_replay_yaml_field = self.create_metadata_cache(yaml_data, file_path)
                        search_found_list.append(needed_replay_yaml_field)
                        logger.debug(f"Found matching detection: {yaml_data.get('name', 'Unknown')}")

        logger.debug(f"Search complete. Found {len(search_found_list)} matches for {field_name}")
        return search_found_list

    def check_needed_yaml_field(self, yaml_key_name:str, field_name:str, yaml_data:yaml)->bool:
        """Function for checking needed yaml fields per search type"""
        if yaml_key_name == "name":
            if yaml_data.get(yaml_key_name).lower() == field_name.lower():
                ColorPrint.print_success_fg(f"[+][SUCCESS]: ... found -> [ {yaml_data.get(yaml_key_name)} ]")
                return True
            
        elif yaml_key_name == "mitre_attack_id":
            if yaml_data['tags']:
                if "mitre_attack_id" in yaml_data['tags']:
                    if field_name.lower() in [i.lower() for i in yaml_data['tags']['mitre_attack_id']]:
                        return True
                    
        elif yaml_key_name == "analytic_story":
            if yaml_data['tags']:
                if "analytic_story" in yaml_data['tags']:
                    if field_name.lower() in [i.lower() for i in yaml_data['tags']['analytic_story']]:
                        return True

        elif yaml_key_name == "id":
            if yaml_data.get(yaml_key_name).lower() == field_name.lower():
                ColorPrint.print_success_fg(f"[+][SUCCESS]: ... found -> [ {yaml_data.get(yaml_key_name)} ]")
                return True

        return False
    
    def normalized_file_args(self, file_path:str)->dict:
        """segregate string by possible Splunk Security content yaml field via regex"""
        ColorPrint.print_info_fg("[+][.  INFO]: ... segregating the file data ...")
        logger.debug(f"Processing file for categorization: {file_path}")

        # Validate file exists
        if not os.path.isfile(file_path):
            logger.error(f"Input file not found: {file_path}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Input file not found: {file_path}")
            return {}

        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
        except IOError as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: Failed to read file: {e}")
            return {}
        except UnicodeDecodeError as e:
            logger.error(f"File encoding error for {file_path}: {e}")
            ColorPrint.print_error_fg(f"[-][. ERROR]: File encoding error: {e}")
            return {}

        # Filter out empty lines and comments
        filter_line = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]

        if not filter_line:
            logger.warning(f"No valid entries found in file: {file_path}")
            ColorPrint.print_warning_fg(f"[!][WARNING]: No valid entries found in file: {file_path}")
            return {}

        logger.debug(f"Found {len(filter_line)} non-empty lines to categorize")

        segregate = defaultdict(list)
        regex_patterns = {
            "detection_filename": r"^[a-z0-9_]+(?:\.yml)?$",
            "guid": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            "mitre_attack_tid": r"^T\d{4}(?:\.\d{3})?$",
            "detection_and_analytic_story_name": r"^[A-Za-z0-9\s\-]+$"
            }

        unmatched_count = 0
        for item in filter_line:
            found_category = False
            for category, pattern in regex_patterns.items():
                if re.fullmatch(pattern, item): # fullmatch ensures the entire string matches the pattern
                    segregate[category].append(item)
                    found_category = True

            if not found_category:
                unmatched_count += 1
                logger.warning(f"No category matched for item: {item}")
                ColorPrint.print_warning_fg(f"[!][WARNING]: ... {item} - No category matched.")

        if unmatched_count > 0:
            logger.warning(f"Total unmatched items: {unmatched_count}")

        ### remove guid and technique id catched by generic regex detection__and_analytic_story_name
        if 'detection_and_analytic_story_name' in segregate and ("guid" in segregate or "mitre_attack_tid" in segregate):
            removed_list = []
            for v in segregate['detection_and_analytic_story_name']:
                if 'guid' in segregate and v in segregate['guid']:
                    removed_list.append(v)
                if 'mitre_attack_tid' in segregate and v in segregate['mitre_attack_tid']:
                    removed_list.append(v)
            for r in removed_list:
                segregate['detection_and_analytic_story_name'].remove(r)

        regular_dict = dict(segregate)
        beautified_json_string = json.dumps(regular_dict, indent=4)

        # Log categorization summary
        for category, items in regular_dict.items():
            logger.debug(f"Category '{category}': {len(items)} items")

        ### comment me if you dont want to see the replay_cache yml file
        if self.read_config_settings('debug_print'):
            ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("STRING CATEGORIZATION"))
            ColorPrint.print_yellow_fg(Style.DIM + f"[+] ... \n{beautified_json_string}")
            ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("STRING CATEGORIZATION"))

        return segregate
    
    def process_local_yaml_cache(self, local_replayed_yaml_dir_path:str, index_value:str)->bool:
        """Process local YAML cache files for replaying attack data."""
        logger.info(f"Processing local YAML cache from: {local_replayed_yaml_dir_path}")

        if not os.path.isdir(local_replayed_yaml_dir_path):
            error_msg = f"Local cache directory not found or is not a directory: {local_replayed_yaml_dir_path}"
            logger.error(error_msg)
            ColorPrint.print_error_fg(f"[-][. ERROR]: {error_msg}")
            return False

        yaml_files_found = 0
        yaml_files_processed = 0
        yaml_files_failed = 0

        for root, dirs, files in os.walk(local_replayed_yaml_dir_path):
            for ctr, file in enumerate(files):
                if not file.endswith((".yaml", ".yml")):
                    continue

                yaml_files_found += 1
                ColorPrint.print_info_fg(f'[+][.  INFO]: ... Processing {ctr+1} => [ {file} ]')
                file_path = os.path.join(root, file)
                logger.debug(f"Processing YAML cache file: {file_path}")

                yaml_data = self.read_yaml_file(file_path)

                if yaml_data is None:
                    logger.error(f"Skipping empty or invalid YAML file: {file_path}")
                    ColorPrint.print_error_fg(f"[-][. ERROR]: ... Skipping empty or invalid YAML file: {file_path}")
                    yaml_files_failed += 1
                    continue

                # Validate required fields
                if 'attack_data_uuid' not in yaml_data:
                    logger.error(f"Missing 'attack_data_uuid' in YAML file: {file_path}")
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Missing 'attack_data_uuid' in: {file_path}")
                    yaml_files_failed += 1
                    continue

                ### comment me if you dont want to see the replay_cache yml file
                if self.read_config_settings('debug_print'):
                    ColorPrint.print_yellow_fg(Style.DIM + self.header_divider("TOTAL-REPLAY CACHE YAML FILE", "local cache"))
                    ColorPrint.print_yellow_fg(Style.DIM + f"[+] ... \n{json.dumps(yaml_data, indent=4)}")
                    ColorPrint.print_yellow_fg(Style.DIM + self.footer_divider("TOTAL-REPLAY CACHE YAML FILE"))

                self.processed_attack_data_uuid.append(yaml_data['attack_data_uuid'])

                try:
                    result = self.attack_data_replay_cmd(yaml_data, index_value)
                    if result:
                        yaml_files_processed += 1
                    else:
                        yaml_files_failed += 1
                except Exception as e:
                    logger.error(f"Exception during attack data replay for {file_path}: {e}", exc_info=True)
                    ColorPrint.print_error_fg(f"[-][. ERROR]: Attack Data Replay Exception for {file}: {e}")
                    yaml_files_failed += 1

                ColorPrint.print_magenta_fg("\n[+]" + "█" * 160 + "\n")

        # Log summary
        logger.info(f"Local cache processing complete - Found: {yaml_files_found}, Processed: {yaml_files_processed}, Failed: {yaml_files_failed}")
        if yaml_files_found == 0:
            logger.warning(f"No YAML files found in: {local_replayed_yaml_dir_path}")
            ColorPrint.print_warning_fg(f"[!][WARNING]: No YAML files found in: {local_replayed_yaml_dir_path}")

        return yaml_files_failed == 0