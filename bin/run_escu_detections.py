#!/usr/bin/env python3

"""
Splunk ESCU Detection Runner

This script clones the Splunk security_content repository and runs all ESCU detections
against a Splunk instance. It parses detection YAML files and executes the searches
via Splunk's REST API.

Author: Attack Data Team
Dependencies: See requirements.txt
"""

import os
import sys
import argparse
import yaml
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

import splunklib.client as client
import splunklib.results as results
from git import Repo
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('escu_detections.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SecurityContentManager:
    """Manages the security_content repository operations."""
    
    def __init__(self, repo_path: str = "./security_content"):
        self.repo_path = Path(repo_path)
        self.repo_url = "https://github.com/splunk/security_content.git"
        
    def clone_or_update_repo(self) -> bool:
        """Clone or update the security_content repository."""
        try:
            if self.repo_path.exists() and (self.repo_path / ".git").exists():
                logger.info(f"Updating existing repository at {self.repo_path}")
                repo = Repo(self.repo_path)
                origin = repo.remotes.origin
                origin.pull()
                logger.info("Repository updated successfully")
            else:
                logger.info(f"Cloning repository to {self.repo_path}")
                self.repo_path.parent.mkdir(parents=True, exist_ok=True)
                Repo.clone_from(self.repo_url, self.repo_path)
                logger.info("Repository cloned successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to clone/update repository: {e}")
            return False
    
    def find_detection_files(self) -> List[Path]:
        """Find all detection YAML files in the repository."""
        detections_dir = self.repo_path / "detections"
        if not detections_dir.exists():
            logger.error(f"Detections directory not found: {detections_dir}")
            return []
        
        detection_files = []
        for yaml_file in detections_dir.rglob("*.yml"):
            detection_files.append(yaml_file)
        
        logger.info(f"Found {len(detection_files)} detection files")
        return detection_files


class DetectionParser:
    """Parses detection YAML files and extracts relevant information."""
    
    @staticmethod
    def parse_detection_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a detection YAML file and extract detection information."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                detection_data = yaml.safe_load(f)
            
            if not detection_data:
                logger.warning(f"Empty detection file: {file_path}")
                return None
            
            # Validate required fields
            required_fields = ['name', 'search', 'type']
            for field in required_fields:
                if field not in detection_data:
                    logger.warning(f"Missing required field '{field}' in {file_path}")
                    return None
            
            # Extract key information
            detection = {
                'file_path': str(file_path),
                'name': detection_data.get('name', ''),
                'id': detection_data.get('id', ''),
                'description': detection_data.get('description', ''),
                'search': detection_data.get('search', ''),
                'type': detection_data.get('type', ''),
                'data_source': detection_data.get('data_source', []),
                'mitre_attack_id': detection_data.get('tags', {}).get('mitre_attack_id', []),
                'analytic_story': detection_data.get('tags', {}).get('analytic_story', []),
                'asset_type': detection_data.get('tags', {}).get('asset_type', ''),
                'security_domain': detection_data.get('tags', {}).get('security_domain', ''),
                'risk_score': detection_data.get('rba', {}).get('risk_objects', []),
                'status': detection_data.get('status', 'unknown')
            }
            
            return detection
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return None


class SplunkConnector:
    """Handles connection and search execution with Splunk."""
    
    def __init__(self, host: str, port: int, username: str, password: str, 
                 verify_ssl: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.service = None
        
    def connect(self) -> bool:
        """Establish connection to Splunk."""
        try:
            self.service = client.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                verify=self.verify_ssl
            )
            logger.info(f"Successfully connected to Splunk at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {e}")
            return False
    
    def run_search(self, search_query: str, earliest_time: str = "-24h", 
                   latest_time: str = "now", max_results: int = 1000) -> Dict[str, Any]:
        """Execute a search query on Splunk."""
        if not self.service:
            raise Exception("Not connected to Splunk")
        
        try:
            # Prepare search parameters
            search_kwargs = {
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'max_count': max_results,
                'output_mode': 'json'
            }
            
            # Execute the search
            logger.debug(f"Executing search: {search_query[:100]}...")
            job = self.service.jobs.create(search_query, **search_kwargs)
            
            # Wait for the job to complete
            while not job.is_done():
                time.sleep(0.5)
            
            # Get results
            results_stream = job.results(output_mode='json')
            results_data = results.JSONResultsReader(results_stream)
            
            search_results = []
            for result in results_data:
                if isinstance(result, dict):
                    search_results.append(result)
            
            # Get job statistics
            job_stats = {
                'result_count': len(search_results),
                'scan_count': job.content.get('scanCount', 0),
                'event_count': job.content.get('eventCount', 0),
                'run_duration': job.content.get('runDuration', 0),
                'is_finalized': job.content.get('isFinalized', False),
                'dispatch_state': job.content.get('dispatchState', 'UNKNOWN')
            }
            
            return {
                'success': True,
                'results': search_results,
                'stats': job_stats,
                'message': f"Search completed successfully with {len(search_results)} results"
            }
            
        except Exception as e:
            logger.error(f"Search execution failed: {e}")
            return {
                'success': False,
                'results': [],
                'stats': {},
                'message': f"Search failed: {str(e)}"
            }


class ESCUDetectionRunner:
    """Main class for running ESCU detections."""
    
    def __init__(self, splunk_host: str, splunk_port: int, splunk_username: str,
                 splunk_password: str, repo_path: str = "./security_content",
                 verify_ssl: bool = False):
        self.repo_manager = SecurityContentManager(repo_path)
        self.splunk = SplunkConnector(splunk_host, splunk_port, splunk_username, 
                                    splunk_password, verify_ssl)
        self.results = []
        
    def setup(self) -> bool:
        """Setup the environment and connections."""
        logger.info("Setting up ESCU Detection Runner...")
        
        # Clone/update repository
        if not self.repo_manager.clone_or_update_repo():
            return False
        
        # Connect to Splunk
        if not self.splunk.connect():
            return False
        
        logger.info("Setup completed successfully")
        return True
    
    def run_all_detections(self, detection_filter: Optional[Dict[str, Any]] = None,
                          earliest_time: str = "-24h", latest_time: str = "now",
                          max_results: int = 1000, parallel: bool = False) -> List[Dict[str, Any]]:
        """Run all detection searches and collect results."""
        
        # Find detection files
        detection_files = self.repo_manager.find_detection_files()
        if not detection_files:
            logger.error("No detection files found")
            return []
        
        # Parse detections
        detections = []
        logger.info("Parsing detection files...")
        for file_path in tqdm(detection_files, desc="Parsing detections"):
            detection = DetectionParser.parse_detection_file(file_path)
            if detection:
                # Apply filters if provided
                if detection_filter:
                    if self._should_include_detection(detection, detection_filter):
                        detections.append(detection)
                else:
                    detections.append(detection)
        
        logger.info(f"Parsed {len(detections)} valid detections")
        
        # Execute detections
        results = []
        logger.info("Executing detections...")
        
        for detection in tqdm(detections, desc="Running detections"):
            try:
                start_time = time.time()
                
                # Execute the search
                search_result = self.splunk.run_search(
                    detection['search'],
                    earliest_time=earliest_time,
                    latest_time=latest_time,
                    max_results=max_results
                )
                
                execution_time = time.time() - start_time
                
                # Compile result
                result = {
                    'detection_name': detection['name'],
                    'detection_id': detection['id'],
                    'detection_type': detection['type'],
                    'file_path': detection['file_path'],
                    'execution_time': execution_time,
                    'timestamp': datetime.now().isoformat(),
                    'search_query': detection['search'],
                    'mitre_attack_id': detection['mitre_attack_id'],
                    'analytic_story': detection['analytic_story'],
                    'success': search_result['success'],
                    'result_count': search_result['stats'].get('result_count', 0),
                    'event_count': search_result['stats'].get('event_count', 0),
                    'scan_count': search_result['stats'].get('scan_count', 0),
                    'message': search_result['message'],
                    'results_preview': search_result['results'][:5] if search_result['results'] else []
                }
                
                results.append(result)
                
                # Log result
                status_color = Fore.GREEN if search_result['success'] else Fore.RED
                logger.info(f"{status_color}Detection: {detection['name']} - "
                          f"Results: {result['result_count']} - "
                          f"Time: {execution_time:.2f}s{Style.RESET_ALL}")
                
            except Exception as e:
                logger.error(f"Failed to execute detection {detection['name']}: {e}")
                results.append({
                    'detection_name': detection['name'],
                    'detection_id': detection['id'],
                    'success': False,
                    'message': f"Execution failed: {str(e)}",
                    'timestamp': datetime.now().isoformat()
                })
        
        self.results = results
        return results
    
    def _should_include_detection(self, detection: Dict[str, Any], 
                                filters: Dict[str, Any]) -> bool:
        """Check if detection should be included based on filters."""
        
        # Filter by type
        if 'type' in filters and detection['type'] not in filters['type']:
            return False
        
        # Filter by MITRE ATT&CK ID
        if 'mitre_attack_id' in filters:
            if not any(attack_id in detection['mitre_attack_id'] 
                      for attack_id in filters['mitre_attack_id']):
                return False
        
        # Filter by analytic story
        if 'analytic_story' in filters:
            if not any(story in detection['analytic_story'] 
                      for story in filters['analytic_story']):
                return False
        
        # Filter by security domain
        if 'security_domain' in filters:
            if detection['security_domain'] not in filters['security_domain']:
                return False
        
        # Filter by status
        if 'status' in filters:
            if detection['status'] not in filters['status']:
                return False
        
        return True
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate a comprehensive report of detection results."""
        if not self.results:
            return "No results to report"
        
        # Calculate statistics
        total_detections = len(self.results)
        successful_detections = sum(1 for r in self.results if r['success'])
        failed_detections = total_detections - successful_detections
        total_results = sum(r.get('result_count', 0) for r in self.results)
        
        # Group by MITRE ATT&CK
        mitre_stats = {}
        for result in self.results:
            for attack_id in result.get('mitre_attack_id', []):
                if attack_id not in mitre_stats:
                    mitre_stats[attack_id] = {'total': 0, 'with_results': 0}
                mitre_stats[attack_id]['total'] += 1
                if result.get('result_count', 0) > 0:
                    mitre_stats[attack_id]['with_results'] += 1
        
        # Generate report
        report_lines = [
            "=" * 80,
            "SPLUNK ESCU DETECTION EXECUTION REPORT",
            "=" * 80,
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "SUMMARY:",
            f"  Total Detections Executed: {total_detections}",
            f"  Successful Executions: {successful_detections}",
            f"  Failed Executions: {failed_detections}",
            f"  Success Rate: {(successful_detections/total_detections)*100:.1f}%",
            f"  Total Results Found: {total_results}",
            "",
            "TOP MITRE ATT&CK TECHNIQUES BY RESULTS:",
        ]
        
        # Sort MITRE techniques by results
        sorted_mitre = sorted(mitre_stats.items(), 
                            key=lambda x: x[1]['with_results'], reverse=True)
        
        for attack_id, stats in sorted_mitre[:10]:
            report_lines.append(f"  {attack_id}: {stats['with_results']}/{stats['total']} detections with results")
        
        report_lines.extend([
            "",
            "DETECTIONS WITH RESULTS:",
        ])
        
        # Show detections that found results
        detections_with_results = [r for r in self.results if r.get('result_count', 0) > 0]
        detections_with_results.sort(key=lambda x: x.get('result_count', 0), reverse=True)
        
        for result in detections_with_results[:20]:  # Top 20
            report_lines.append(f"  {result['detection_name']}: {result['result_count']} results")
        
        if len(detections_with_results) > 20:
            report_lines.append(f"  ... and {len(detections_with_results) - 20} more")
        
        report_lines.extend([
            "",
            "FAILED DETECTIONS:",
        ])
        
        failed_results = [r for r in self.results if not r['success']]
        for result in failed_results[:10]:  # Show first 10 failures
            report_lines.append(f"  {result['detection_name']}: {result.get('message', 'Unknown error')}")
        
        if len(failed_results) > 10:
            report_lines.append(f"  ... and {len(failed_results) - 10} more failures")
        
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            logger.info(f"Report saved to {output_file}")
        
        return report_text
    
    def export_results(self, output_file: str = "escu_results.json"):
        """Export detailed results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"Detailed results exported to {output_file}")


def load_environment_variables():
    """Load required environment variables for Splunk connection."""
    required_vars = ['SPLUNK_HOST', 'SPLUNK_USERNAME', 'SPLUNK_PASSWORD']
    env_vars = {}
    
    for var in required_vars:
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"Environment variable {var} is required but not set")
        env_vars[var.lower().replace('splunk_', '')] = value
    
    # Optional variables with defaults
    env_vars['port'] = int(os.environ.get('SPLUNK_PORT', '8089'))
    env_vars['verify_ssl'] = os.environ.get('SPLUNK_VERIFY_SSL', 'false').lower() == 'true'
    
    return env_vars


def main():
    parser = argparse.ArgumentParser(
        description="Run all Splunk ESCU detections from security_content repository",
        epilog="""
Environment Variables Required:
  SPLUNK_HOST      - Splunk server hostname/IP
  SPLUNK_USERNAME  - Splunk username
  SPLUNK_PASSWORD  - Splunk password
  SPLUNK_PORT      - Splunk management port (default: 8089)
  SPLUNK_VERIFY_SSL - Verify SSL certificates (default: false)

Example usage:
  export SPLUNK_HOST="192.168.1.100"
  export SPLUNK_USERNAME="admin"
  export SPLUNK_PASSWORD="changeme"
  python run_escu_detections.py --time-range "-7d,now"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        '--repo-path',
        default='./security_content',
        help='Path to clone/find security_content repository (default: ./security_content)'
    )
    
    parser.add_argument(
        '--time-range',
        default='-24h,now',
        help='Time range for searches in format "earliest,latest" (default: -24h,now)'
    )
    
    parser.add_argument(
        '--max-results',
        type=int,
        default=1000,
        help='Maximum results per detection (default: 1000)'
    )
    
    parser.add_argument(
        '--filter-type',
        nargs='+',
        help='Filter detections by type (e.g., TTP Hunting Correlation)'
    )
    
    parser.add_argument(
        '--filter-mitre',
        nargs='+',
        help='Filter detections by MITRE ATT&CK ID (e.g., T1003 T1059)'
    )
    
    parser.add_argument(
        '--filter-status',
        nargs='+',
        default=['production'],
        help='Filter detections by status (default: production)'
    )
    
    parser.add_argument(
        '--output-report',
        default='escu_detection_report.txt',
        help='Output file for summary report (default: escu_detection_report.txt)'
    )
    
    parser.add_argument(
        '--output-json',
        default='escu_detection_results.json',
        help='Output file for detailed JSON results (default: escu_detection_results.json)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load environment variables
        env_vars = load_environment_variables()
        
        # Parse time range
        time_parts = args.time_range.split(',')
        if len(time_parts) != 2:
            raise ValueError("Time range must be in format 'earliest,latest'")
        earliest_time, latest_time = time_parts
        
        # Create filters
        filters = {}
        if args.filter_type:
            filters['type'] = args.filter_type
        if args.filter_mitre:
            filters['mitre_attack_id'] = args.filter_mitre
        if args.filter_status:
            filters['status'] = args.filter_status
        
        # Initialize runner
        runner = ESCUDetectionRunner(
            splunk_host=env_vars['host'],
            splunk_port=env_vars['port'],
            splunk_username=env_vars['username'],
            splunk_password=env_vars['password'],
            repo_path=args.repo_path,
            verify_ssl=env_vars['verify_ssl']
        )
        
        # Setup environment
        if not runner.setup():
            logger.error("Setup failed")
            sys.exit(1)
        
        # Run detections
        logger.info("Starting detection execution...")
        results = runner.run_all_detections(
            detection_filter=filters if filters else None,
            earliest_time=earliest_time,
            latest_time=latest_time,
            max_results=args.max_results
        )
        
        # Generate reports
        logger.info("Generating reports...")
        report = runner.generate_report(args.output_report)
        print(report)
        
        runner.export_results(args.output_json)
        
        logger.info(f"Detection execution completed. Processed {len(results)} detections.")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
