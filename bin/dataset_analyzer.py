#!/usr/bin/env python3
"""
Dataset Analyzer for Attack Data Repository

This script analyzes datasets in the attack_data repository and categorizes them
based on filename patterns and content types. It recursively searches through
directories to find data files and creates data.yml files in the same directories
as the data files.

Features:
- Recursive analysis of all directories containing data files (default behavior)
- Analyze a specific folder and its subdirectories
- Generic directory structure support (not tied to specific naming conventions)
- Automatic categorization based on filename patterns and content detection
- Automatic creation of data.yml files in directories containing data files
- Summary report generation

Usage Examples:
  # Analyze all directories recursively
  python dataset_analyzer.py

  # Analyze a specific directory and its subdirectories
  python dataset_analyzer.py --folder datasets/attack_techniques/T1003.001

  # Analyze a specific folder (malware, honeypots, etc.)
  python dataset_analyzer.py --folder datasets/malware

  # Use custom base path
  python dataset_analyzer.py --base-path /path/to/data

Author: Generated for attack_data repository analysis
"""

import re
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    import yaml
except ImportError:
    print("Warning: PyYAML not installed. Install with: pip install PyYAML")
    yaml = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DatasetInfo:
    """Information about a dataset file"""
    name: str
    path: str
    sourcetype: str
    source: Optional[str] = None


@dataclass
class CategoryRule:
    """Rule for categorizing datasets"""
    pattern: str
    sourcetype: str
    source: Optional[str] = None
    content_check: Optional[str] = None
    description: str = ""


class DatasetAnalyzer:
    """Analyzes and categorizes datasets in the attack_data repository"""

    def __init__(self, base_path: str = "datasets"):
        self.base_path = Path(base_path)
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> List[CategoryRule]:
        """Initialize categorization rules based on common patterns"""
        return [
            # Windows Event Logs - XML format
            CategoryRule(
                pattern=r".*windows-sysmon.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                content_check="xml",
                description="Windows Sysmon logs in XML format"
            ),
            CategoryRule(
                pattern=r".*sysmon.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                content_check="xml",
                description="Sysmon logs in XML format"
            ),
            CategoryRule(
                pattern=r".*windows-security.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:Security",
                content_check="xml",
                description="Windows Security Event logs in XML format"
            ),
            CategoryRule(
                pattern=r".*windows-system.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:System",
                content_check="xml",
                description="Windows System Event logs in XML format"
            ),
            CategoryRule(
                pattern=r".*windows-powershell.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
                content_check="xml",
                description="Windows PowerShell logs in XML format"
            ),
            CategoryRule(
                pattern=r".*windows-application.*\.log$",
                sourcetype="XmlWinEventLog",
                source="XmlWinEventLog:Application",
                content_check="xml",
                description="Windows Application Event logs in XML format"
            ),

            # CrowdStrike Falcon
            CategoryRule(
                pattern=r".*crowdstrike.*\.log$",
                sourcetype="crowdstrike:events:sensor",
                content_check="json",
                description="CrowdStrike Falcon sensor events"
            ),
            CategoryRule(
                pattern=r".*falcon.*\.log$",
                sourcetype="crowdstrike:events:sensor",
                content_check="json",
                description="CrowdStrike Falcon sensor events"
            ),

            # Linux/Unix logs
            CategoryRule(
                pattern=r".*syslog.*\.log$",
                sourcetype="syslog",
                source="syslog",
                description="Linux/Unix syslog files"
            ),
            CategoryRule(
                pattern=r".*auth.*\.log$",
                sourcetype="linux_secure",
                source="linux_secure",
                description="Linux authentication logs"
            ),
            CategoryRule(
                pattern=r".*secure.*\.log$",
                sourcetype="linux_secure",
                source="linux_secure",
                description="Linux secure logs"
            ),

            # Network and Firewall logs
            CategoryRule(
                pattern=r".*firewall.*\.log$",
                sourcetype="firewall",
                description="Firewall logs"
            ),
            CategoryRule(
                pattern=r".*palo.*alto.*\.log$",
                sourcetype="pan:traffic",
                description="Palo Alto firewall logs"
            ),
            CategoryRule(
                pattern=r".*cisco.*\.log$",
                sourcetype="cisco:asa",
                description="Cisco network device logs"
            ),

            # Web server logs
            CategoryRule(
                pattern=r".*access.*\.log$",
                sourcetype="access_combined",
                description="Web server access logs"
            ),
            CategoryRule(
                pattern=r".*apache.*\.log$",
                sourcetype="access_combined",
                description="Apache web server logs"
            ),
            CategoryRule(
                pattern=r".*nginx.*\.log$",
                sourcetype="nginx:plus:access",
                description="Nginx web server logs"
            ),
            CategoryRule(
                pattern=r".*iis.*\.log$",
                sourcetype="iis",
                description="IIS web server logs"
            ),

            # Cloud and container logs
            CategoryRule(
                pattern=r".*aws.*\.log$",
                sourcetype="aws:cloudtrail",
                description="AWS CloudTrail logs"
            ),
            CategoryRule(
                pattern=r".*azure.*\.log$",
                sourcetype="azure:monitor:aad",
                description="Azure activity logs"
            ),
            CategoryRule(
                pattern=r".*docker.*\.log$",
                sourcetype="docker",
                description="Docker container logs"
            ),
            CategoryRule(
                pattern=r".*kubernetes.*\.log$",
                sourcetype="kube:container",
                description="Kubernetes container logs"
            ),

            # Database logs
            CategoryRule(
                pattern=r".*mysql.*\.log$",
                sourcetype="mysql:error",
                description="MySQL database logs"
            ),
            CategoryRule(
                pattern=r".*postgres.*\.log$",
                sourcetype="postgresql",
                description="PostgreSQL database logs"
            ),
            CategoryRule(
                pattern=r".*mssql.*\.log$",
                sourcetype="mssql:errorlog",
                description="Microsoft SQL Server logs"
            ),

            # Application logs
            CategoryRule(
                pattern=r".*exchange.*\.log$",
                sourcetype="MSExchange:Management",
                description="Microsoft Exchange logs"
            ),
            CategoryRule(
                pattern=r".*sharepoint.*\.log$",
                sourcetype="sharepoint:uls",
                description="SharePoint logs"
            ),
            CategoryRule(
                pattern=r".*jboss.*\.log$",
                sourcetype="jboss",
                description="JBoss application server logs"
            ),
            CategoryRule(
                pattern=r".*tomcat.*\.log$",
                sourcetype="catalina",
                description="Apache Tomcat logs"
            ),

            # JSON format logs (generic)
            CategoryRule(
                pattern=r".*\.json\.log$",
                sourcetype="json",
                content_check="json",
                description="JSON formatted logs"
            ),

            # CSV format logs
            CategoryRule(
                pattern=r".*\.csv\.log$",
                sourcetype="csv",
                description="CSV formatted logs"
            ),
            CategoryRule(
                pattern=r".*\.csv$",
                sourcetype="csv",
                description="CSV data files"
            ),

            # Text files
            CategoryRule(
                pattern=r".*\.txt$",
                sourcetype="text",
                description="Plain text files"
            ),

            # Generic log file fallback
            CategoryRule(
                pattern=r".*\.log$",
                sourcetype="generic_log",
                description="Generic log files"
            )
        ]

    def _detect_content_type(self, file_path: Path) -> str:
        """Detect the content type of a file by examining its contents"""
        try:
            # Read first few lines to determine format
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = []
                for i, line in enumerate(f):
                    if i >= 10:  # Read first 10 lines
                        break
                    first_lines.append(line.strip())

                content = '\n'.join(first_lines)

                # Check for XML (Windows Event Log format)
                if ('<Event xmlns=' in content or
                        ('<Event ' in content and 'xmlns=' in content)):
                    return 'xml'

                # Check for JSON
                if (content.startswith('{') or
                        any(line.startswith('{') for line in first_lines)):
                    return 'json'

                # Check for CSV
                if ',' in content and len(first_lines) > 1:
                    # Simple heuristic: if most lines have similar comma count
                    comma_counts = [line.count(',') for line in first_lines
                                    if line]
                    if comma_counts and len(set(comma_counts)) <= 2:
                        return 'csv'

                return 'text'

        except Exception as e:
            logger.warning(f"Could not detect content type for {file_path}: {e}")
            return 'unknown'

    def _apply_rules(self, file_path: Path) -> Optional[
        Tuple[str, Optional[str], bool]
    ]:
        """Apply categorization rules and return (sourcetype, source, is_specific_rule)"""
        filename = file_path.name.lower()
        content_type = self._detect_content_type(file_path)

        for i, rule in enumerate(self.rules):
            if re.match(rule.pattern.lower(), filename):
                # If rule has content check, verify it matches
                if rule.content_check and rule.content_check != content_type:
                    continue

                # Check if this is the generic log fallback rule (last rule)
                is_specific_rule = i < len(self.rules) - 1
                
                logger.debug(
                    f"Applied rule '{rule.description}' to {filename} "
                    f"(specific: {is_specific_rule})"
                )
                return rule.sourcetype, rule.source, is_specific_rule

        logger.warning(f"No matching rule found for {filename}")
        return None

    def _is_data_file(self, file_path: Path) -> bool:
        """Check if a file is a data file (not .yml or .zip)"""
        excluded_extensions = {'.yml', '.yaml', '.zip', '.tar', '.gz',
                               '.rar', '.7z'}
        return file_path.suffix.lower() not in excluded_extensions

    def _find_datasets(self, technique_path: Path) -> List[Path]:
        """Find all dataset files in a technique directory"""
        datasets = []

        for item in technique_path.rglob('*'):
            if item.is_file() and self._is_data_file(item):
                datasets.append(item)

        return datasets

    def _get_mitre_technique(self, technique_path: Path) -> str:
        """Extract MITRE technique ID from path"""
        # Extract technique ID from path like "datasets/attack_techniques/T1003.001/..."
        parts = technique_path.parts
        for part in parts:
            if part.startswith('T') and ('.' in part or part[1:].isdigit()):
                return part
        return "unknown"

    def _generate_dataset_info(
        self, datasets: List[Path], base_path: Path
    ) -> Tuple[List[DatasetInfo], List[Dict]]:
        """Generate dataset information with categorization and track ignored files"""
        dataset_infos = []
        ignored_files = []

        for dataset_path in datasets:
            # Create relative path from base directory
            try:
                relative_path = dataset_path.relative_to(base_path.parent)
                web_path = f"/datasets/{relative_path.as_posix()}"
            except ValueError:
                # Fallback if relative path fails
                web_path = f"/datasets/{dataset_path.name}"

            # Apply categorization rules
            result = self._apply_rules(dataset_path)
            if result:
                sourcetype, source, is_specific_rule = result

                if is_specific_rule:
                    # Only include files that match specific rules
                    dataset_info = DatasetInfo(
                        name=dataset_path.name,
                        path=web_path,
                        sourcetype=sourcetype,
                        source=source
                    )
                    dataset_infos.append(dataset_info)
                    logger.info(f"Categorized {dataset_path.name} as {sourcetype}")
                else:
                    # Track files that only match generic fallback rules
                    ignored_files.append({
                        'name': dataset_path.name,
                        'path': web_path,
                        'sourcetype': sourcetype,
                        'reason': 'generic_fallback_rule'
                    })
                    logger.info(
                        f"Ignored {dataset_path.name} (generic rule: {sourcetype})"
                    )
            else:
                # Track files that don't match any rule
                ignored_files.append({
                    'name': dataset_path.name,
                    'path': web_path,
                    'sourcetype': 'unknown',
                    'reason': 'no_matching_rule'
                })
                logger.error(f"Could not categorize {dataset_path.name}")

        return dataset_infos, ignored_files

    def analyze_technique_directory(self, technique_path: Path) -> Optional[Dict]:
        """Analyze a single technique directory and generate YAML structure"""
        if not technique_path.is_dir():
            return None

        datasets = self._find_datasets(technique_path)
        if not datasets:
            logger.info(f"No datasets found in {technique_path}")
            return None

        dataset_infos, ignored_files = self._generate_dataset_info(
            datasets, self.base_path
        )
        
        # Store ignored files for summary reporting
        if not hasattr(self, '_ignored_files'):
            self._ignored_files = []
        self._ignored_files.extend(ignored_files)
        
        if not dataset_infos:
            logger.warning(f"No categorizable datasets found in {technique_path}")
            return None

        # Extract technique information
        mitre_technique = self._get_mitre_technique(technique_path)

        # Generate YAML structure
        yaml_data = {
            'author': 'Generated by dataset_analyzer.py',
            'id': (f'generated-{mitre_technique.lower()}-'
                   f'{datetime.now().strftime("%Y%m%d")}'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'description': (f'Automatically categorized datasets for technique '
                            f'{mitre_technique}'),
            'environment': 'attack_range',
            'mitre_technique': [mitre_technique],
            'datasets': []
        }

        # Add dataset entries
        for dataset_info in dataset_infos:
            dataset_entry = {
                'name': dataset_info.name.replace('.log', '').replace('.', '-'),
                'path': dataset_info.path,
                'sourcetype': dataset_info.sourcetype
            }

            if dataset_info.source:
                dataset_entry['source'] = dataset_info.source

            yaml_data['datasets'].append(dataset_entry)

        return yaml_data

    def analyze_specific_folder(self, folder_path: str) -> Dict[str, Dict]:
        """Analyze a specific folder recursively and return results"""
        results = {}
        target_path = Path(folder_path)
        
        if not target_path.exists():
            logger.error(f"Folder not found: {target_path}")
            return results
            
        if not target_path.is_dir():
            logger.error(f"Path is not a directory: {target_path}")
            return results
            
        logger.info(f"Analyzing specific folder: {target_path}")
        
        # Initialize ignored files tracking
        self._ignored_files = []
        
        # Store the analysis base path for later use in creating data.yml files
        self._analysis_base_path = target_path.resolve()
        
        # Find all directories that contain data files within the target path
        data_directories = self._find_directories_with_data(target_path)
        
        if not data_directories:
            logger.warning(f"No directories with data files found in {target_path}")
            return results
            
        logger.info(f"Found {len(data_directories)} directories containing data files")

        for data_dir in data_directories:
            logger.info(f"Analyzing {data_dir}...")
            yaml_data = self._analyze_data_directory(data_dir)
            
            if yaml_data:
                # Store the actual directory path in the yaml_data for later use
                yaml_data['_source_directory'] = str(data_dir.resolve())
                
                # Use relative path from target_path as key for uniqueness
                try:
                    rel_path = data_dir.relative_to(target_path)
                    results[str(rel_path)] = yaml_data
                except ValueError:
                    # Fallback if relative path fails
                    results[data_dir.name] = yaml_data
                logger.info(f"Successfully analyzed {data_dir}")
            else:
                logger.info(f"No analyzable data in {data_dir}")
        
        return results

    def _find_directories_with_data(self, base_path: Path) -> List[Path]:
        """Find all directories that contain data files (recursively)"""
        data_directories = []
        
        # First, check if the base_path itself contains data files
        has_data_files = False
        for file_item in base_path.iterdir():
            if file_item.is_file() and self._is_data_file(file_item):
                has_data_files = True
                break
        
        if has_data_files:
            data_directories.append(base_path)
        
        # Then use rglob to find subdirectories that contain data files
        for item in base_path.rglob('*'):
            if item.is_dir():
                # Check if this directory contains any data files (non-recursive check)
                has_data_files = False
                for file_item in item.iterdir():
                    if file_item.is_file() and self._is_data_file(file_item):
                        has_data_files = True
                        break
                
                if has_data_files:
                    data_directories.append(item)
                
        return data_directories

    def _analyze_data_directory(self, data_dir: Path) -> Optional[Dict]:
        """Analyze a directory containing data files"""
        if not data_dir.is_dir():
            return None

        # Find data files in this specific directory (not recursive)
        datasets = []
        for item in data_dir.iterdir():
            if item.is_file() and self._is_data_file(item):
                datasets.append(item)

        if not datasets:
            logger.info(f"No data files found in {data_dir}")
            return None

        dataset_infos, ignored_files = self._generate_dataset_info(datasets, data_dir)
        
        # Store ignored files for summary reporting
        if not hasattr(self, '_ignored_files'):
            self._ignored_files = []
        self._ignored_files.extend(ignored_files)
        
        if not dataset_infos:
            logger.warning(f"No categorizable datasets found in {data_dir}")
            return None

        # Generate YAML structure for data directory
        try:
            relative_path = data_dir.relative_to(self.base_path)
            directory_str = str(relative_path)
        except ValueError:
            # Fallback if relative path fails (e.g., when target is outside base_path)
            relative_path = data_dir
            directory_str = str(data_dir.name)
        
        # Extract MITRE technique from directory path
        mitre_technique = self._get_mitre_technique(data_dir)
        
        yaml_data = {
            'author': 'Generated by dataset_analyzer.py',
            'id': (f'generated-{data_dir.name.lower()}-'
                   f'{datetime.now().strftime("%Y%m%d")}'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'description': (f'Automatically categorized datasets in directory '
                            f'{directory_str}'),
            'environment': 'attack_range',
            'directory': directory_str,
            'mitre_technique': [mitre_technique],
            'datasets': []
        }

        # Add dataset entries
        for dataset_info in dataset_infos:
            dataset_entry = {
                'name': dataset_info.name.replace('.log', '').replace('.', '-'),
                'path': dataset_info.path,
                'sourcetype': dataset_info.sourcetype
            }

            if dataset_info.source:
                dataset_entry['source'] = dataset_info.source

            yaml_data['datasets'].append(dataset_entry)

        return yaml_data

    def analyze_generic_directory(self, directory_path: Path) -> Optional[Dict]:
        """Analyze a generic directory that doesn't follow technique naming"""
        if not directory_path.is_dir():
            return None

        datasets = self._find_datasets(directory_path)
        if not datasets:
            logger.info(f"No datasets found in {directory_path}")
            return None

        dataset_infos, ignored_files = self._generate_dataset_info(
            datasets, directory_path
        )
        
        # Store ignored files for summary reporting
        if not hasattr(self, '_ignored_files'):
            self._ignored_files = []
        self._ignored_files.extend(ignored_files)
        
        if not dataset_infos:
            logger.warning(f"No categorizable datasets found in {directory_path}")
            return None

        # Generate YAML structure for generic directory
        # Extract MITRE technique from directory path
        mitre_technique = self._get_mitre_technique(directory_path)
        
        yaml_data = {
            'author': 'Generated by dataset_analyzer.py',
            'id': (f'generated-{directory_path.name.lower()}-'
                   f'{datetime.now().strftime("%Y%m%d")}'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'description': (f'Automatically categorized datasets in directory '
                            f'{directory_path.name}'),
            'environment': 'attack_range',
            'directory': directory_path.name,
            'mitre_technique': [mitre_technique],
            'datasets': []
        }

        # Add dataset entries
        for dataset_info in dataset_infos:
            dataset_entry = {
                'name': dataset_info.name.replace('.log', '').replace('.', '-'),
                'path': dataset_info.path,
                'sourcetype': dataset_info.sourcetype
            }

            if dataset_info.source:
                dataset_entry['source'] = dataset_info.source

            yaml_data['datasets'].append(dataset_entry)

        return yaml_data

    def analyze_all_directories(self) -> Dict[str, Dict]:
        """Analyze all directories recursively and return results"""
        results = {}

        if not self.base_path.exists():
            logger.error(f"Base path not found: {self.base_path}")
            return results

        logger.info(f"Starting recursive analysis from: {self.base_path}")
        
        # Initialize ignored files tracking
        self._ignored_files = []
        
        # Find all directories that contain data files
        data_directories = self._find_directories_with_data(self.base_path)
        
        logger.info(f"Found {len(data_directories)} directories containing data files")

        for data_dir in data_directories:
            logger.info(f"Analyzing {data_dir}...")
            yaml_data = self._analyze_data_directory(data_dir)

            if yaml_data:
                # Store the actual directory path in the yaml_data for later use
                yaml_data['_source_directory'] = str(data_dir.resolve())
                
                # Use relative path as key for uniqueness
                rel_path = data_dir.relative_to(self.base_path)
                results[str(rel_path)] = yaml_data
                logger.info(f"Successfully analyzed {data_dir}")
            else:
                logger.info(f"No analyzable data in {data_dir}")

        return results

    def create_data_yaml_files(self, results: Dict[str, Dict]):
        """Create data.yml files in the same directories as the datasets"""
        if yaml is None:
            logger.error("PyYAML not available. Cannot create data.yml files.")
            return

        for directory_key, yaml_data in results.items():
            if 'datasets' not in yaml_data or not yaml_data['datasets']:
                continue
                
            # Check if we have the actual source directory stored
            if '_source_directory' in yaml_data:
                directory_path = Path(yaml_data['_source_directory'])
                
                # Remove the internal metadata before saving
                yaml_data_clean = yaml_data.copy()
                del yaml_data_clean['_source_directory']
                
                if directory_path.exists() and directory_path.is_dir():
                    data_yml_path = directory_path / "data.yml"
                    try:
                        with open(data_yml_path, 'w', encoding='utf-8') as f:
                            yaml.dump(yaml_data_clean, f, default_flow_style=False,
                                      allow_unicode=True, sort_keys=False)
                        logger.info(f"Created data.yml in {directory_path}")
                    except Exception as e:
                        logger.error(f"Failed to create data.yml in {directory_path}: "
                                     f"{e}")
                else:
                    logger.warning(f"Source directory does not exist: {directory_path}")
                continue
                
            # Fallback to the old method for backward compatibility
            first_dataset = yaml_data['datasets'][0]
            dataset_path = first_dataset.get('path', '')
            
            if dataset_path.startswith('/datasets/'):
                # Convert web path to local path
                local_path = dataset_path[10:]  # Remove '/datasets/' prefix
                full_file_path = self.base_path / local_path
                directory_path = full_file_path.parent
                
                if directory_path.exists() and directory_path.is_dir():
                    data_yml_path = directory_path / "data.yml"
                    try:
                        with open(data_yml_path, 'w', encoding='utf-8') as f:
                            yaml.dump(yaml_data, f, default_flow_style=False,
                                      allow_unicode=True, sort_keys=False)
                        logger.info(f"Created data.yml in {directory_path}")
                    except Exception as e:
                        logger.error(f"Failed to create data.yml in {directory_path}: "
                                     f"{e}")
                else:
                    logger.warning(f"Directory does not exist: {directory_path}")
            else:
                logger.warning(f"Invalid dataset path format: {dataset_path}")

    def _find_technique_directory(self, technique_id: str) -> Optional[Path]:
        """Find the directory path for a given technique ID"""
        attack_techniques_path = self.base_path / "attack_techniques"
        technique_path = attack_techniques_path / technique_id
        
        if technique_path.exists() and technique_path.is_dir():
            return technique_path
        return None

    def _find_generic_directory(self, directory_name: str,
                                yaml_data: Dict) -> Optional[Path]:
        """Find a generic directory based on dataset paths"""
        if 'datasets' not in yaml_data or not yaml_data['datasets']:
            return None
        
        # Get the first dataset path and extract the directory
        first_dataset = yaml_data['datasets'][0]
        dataset_path = first_dataset.get('path', '')
        
        # Convert web path back to local path
        if dataset_path.startswith('/datasets/'):
            local_path = dataset_path[10:]  # Remove '/datasets/' prefix
            full_path = self.base_path / local_path
            
            # Get the directory containing the file
            directory_path = full_path.parent
            if directory_path.exists() and directory_path.is_dir():
                return directory_path
        
        return None

    def _create_data_yml_from_paths(self, base_directory: Path, yaml_data: Dict):
        """Create data.yml files based on dataset paths"""
        if 'datasets' not in yaml_data:
            return
        
        # Group datasets by their directory
        datasets_by_dir = {}
        
        for dataset in yaml_data['datasets']:
            dataset_path = dataset.get('path', '')
            if dataset_path.startswith('/datasets/'):
                local_path = dataset_path[10:]  # Remove '/datasets/' prefix
                full_path = self.base_path / local_path
                dataset_dir = full_path.parent
                
                if dataset_dir not in datasets_by_dir:
                    datasets_by_dir[dataset_dir] = []
                datasets_by_dir[dataset_dir].append(dataset)
        
        # Create data.yml in each directory that has datasets
        for directory, datasets in datasets_by_dir.items():
            if directory.exists() and directory.is_dir():
                dir_yaml_data = yaml_data.copy()
                dir_yaml_data['datasets'] = datasets
                self._create_data_yml_in_directory(directory, dir_yaml_data)

    def _find_subdirs_with_datasets(self, technique_path: Path) -> List[Path]:
        """Find subdirectories that contain dataset files"""
        subdirs_with_datasets = []
        
        for item in technique_path.iterdir():
            if item.is_dir():
                # Check if this subdirectory contains dataset files
                datasets = self._find_datasets(item)
                if datasets:
                    subdirs_with_datasets.append(item)
        
        return subdirs_with_datasets

    def _get_datasets_for_directory(self, directory: Path,
                                    yaml_data: Dict) -> List[Dict]:
        """Get datasets that belong to a specific directory"""
        directory_datasets = []
        dir_name = directory.name
        
        for dataset in yaml_data['datasets']:
            # Check if the dataset path contains this directory name
            if f"/{dir_name}/" in dataset['path']:
                directory_datasets.append(dataset)
        
        return directory_datasets

    def _create_data_yml_in_directory(self, directory: Path, yaml_data: Dict):
        """Create a data.yml file in the specified directory"""
        data_yml_path = directory / "data.yml"
        
        try:
            with open(data_yml_path, 'w', encoding='utf-8') as f:
                yaml.dump(yaml_data, f, default_flow_style=False,
                          allow_unicode=True, sort_keys=False)
            
            logger.info(f"Created data.yml in {directory}")
            
        except Exception as e:
            logger.error(f"Failed to create data.yml in {directory}: {e}")

    def generate_summary_report(self, results: Dict[str, Dict]) -> str:
        """Generate a summary report of the analysis"""
        total_techniques = len(results)
        total_datasets = sum(len(data['datasets']) for data in results.values())

        # Count sourcetypes for included datasets
        sourcetype_counts = {}
        for data in results.values():
            for dataset in data['datasets']:
                sourcetype = dataset['sourcetype']
                sourcetype_counts[sourcetype] = (
                    sourcetype_counts.get(sourcetype, 0) + 1
                )

        # Count ignored files
        ignored_files = getattr(self, '_ignored_files', [])
        total_ignored = len(ignored_files)
        ignored_sourcetype_counts = {}
        
        for ignored_file in ignored_files:
            sourcetype = ignored_file['sourcetype']
            ignored_sourcetype_counts[sourcetype] = (
                ignored_sourcetype_counts.get(sourcetype, 0) + 1
            )

        report = f"""
Dataset Analysis Summary Report
==============================

Total Techniques Analyzed: {total_techniques}
Total Datasets Categorized: {total_datasets}
Total Files Ignored: {total_ignored}

Sourcetype Distribution (Included in data.yml):
{'-' * 50}
"""

        for sourcetype, count in sorted(sourcetype_counts.items(),
                                        key=lambda x: x[1], reverse=True):
            report += f"{sourcetype:<40} {count:>6}\n"

        if ignored_files:
            report += f"\nIgnored Files (Generic/No Rules):\n{'-' * 50}\n"
            for sourcetype, count in sorted(ignored_sourcetype_counts.items(),
                                            key=lambda x: x[1], reverse=True):
                report += f"{sourcetype:<40} {count:>6}\n"
            
            report += f"\nIgnored File Details:\n{'-' * 50}\n"
            for ignored_file in ignored_files:
                reason = ignored_file['reason'].replace('_', ' ').title()
                report += f"{ignored_file['name']:<50} {reason}\n"

        report += f"\n{'-' * 50}\n"
        report += (f"Report generated on: "
                   f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        return report


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Dataset Analyzer for Attack Data Repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all directories recursively (creates data.yml files automatically)
  python dataset_analyzer.py

  # Analyze a specific directory and its subdirectories
  python dataset_analyzer.py --folder datasets/attack_techniques/T1003.001

  # Analyze any custom folder
  python dataset_analyzer.py --folder /path/to/custom/folder

  # Use custom base path
  python dataset_analyzer.py --base-path /path/to/data
        """
    )
    
    parser.add_argument(
        "--folder", "-f",
        type=str,
        help="Specific folder to analyze (default: analyze all directories recursively)"
    )
    
    parser.add_argument(
        "--base-path", "-b",
        type=str,
        default="datasets",
        help="Base path for the datasets directory (default: datasets)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser.parse_args()


def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("Dataset Analyzer for Attack Data Repository")
    print("=" * 50)

    # Initialize analyzer with custom base path if provided
    analyzer = DatasetAnalyzer(base_path=args.base_path)

    # Determine analysis mode
    if args.folder:
        # Analyze specific folder
        print(f"Starting analysis of specific folder: {args.folder}")
        results = analyzer.analyze_specific_folder(args.folder)
        analysis_type = "folder"
    else:
        # Analyze all directories (default behavior)
        print("Starting analysis of all directories...")
        results = analyzer.analyze_all_directories()
        analysis_type = "all directories"

    if not results:
        print(f"No results found for {analysis_type}. "
              f"Please check the path and directory structure.")
        return

    # Create data.yml files in dataset directories
    print("\nCreating data.yml files in dataset directories...")
    analyzer.create_data_yaml_files(results)

    # Generate and save summary report
    report = analyzer.generate_summary_report(results)
    print(report)

    # Save report to file
    report_filename = (f"dataset_analysis_report_"
                       f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report)

    print("Analysis complete!")
    print(f"- Summary report saved to: {report_filename}")
    print("- data.yml files created in dataset directories")
    
    if args.folder:
        print(f"- Analyzed folder: {args.folder}")
    else:
        print(f"- Analyzed {len(results)} directories with data files")


if __name__ == "__main__":
    main()