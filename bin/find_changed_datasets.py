#!/usr/bin/env python3
"""
Script to identify changed or added YAML dataset files for replay.
This script simplifies the bash logic from the GitHub Actions workflow.
"""

import sys
import argparse
import subprocess
from pathlib import Path


def run_git_command(cmd):
    """Run a git command and return the output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {cmd}")
        print(f"Error: {e.stderr}")
        return ""


def find_changed_files(base_sha, head_sha):
    """Find files that changed between two commits."""
    if not base_sha or not head_sha:
        print("Error: Both base and head SHA are required")
        return []

    cmd = f"git diff --name-only {base_sha}...{head_sha}"
    output = run_git_command(cmd)

    if not output:
        return []

    # Filter for files in datasets directory
    changed_files = []
    for line in output.split('\n'):
        if line.strip() and line.startswith('datasets/'):
            changed_files.append(line.strip())

    return changed_files


def find_yaml_files_in_directories(changed_files):
    """Find directories containing YAML files from changed files."""
    yaml_dirs = set()

    for file_path in changed_files:
        # Get the directory containing the changed file
        current_dir = Path(file_path).parent

        # Walk up the directory tree to find YAML files
        while current_dir != Path("datasets") and current_dir != Path("."):
            # Check if this directory contains YAML files
            yaml_files = (list(current_dir.glob("*.yml")) +
                         list(current_dir.glob("*.yaml")))

            if yaml_files:
                yaml_dirs.add(str(current_dir))
                break

            current_dir = current_dir.parent

    return sorted(yaml_dirs)


def find_all_yaml_files(directories):
    """Find all YAML files in the given directories."""
    yaml_files = []

    for dir_path in directories:
        dir_path = Path(dir_path)
        if dir_path.exists() and dir_path.is_dir():
            # Find YAML files in this directory (not recursive)
            yaml_files.extend(dir_path.glob("*.yml"))
            yaml_files.extend(dir_path.glob("*.yaml"))

    return [str(f) for f in sorted(yaml_files)]


def main():
    parser = argparse.ArgumentParser(
        description="Find changed dataset YAML files for replay",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find changes between two commits
  python find_changed_datasets.py --base-sha abc123 --head-sha def456

  # Find changes in current branch vs main
  python find_changed_datasets.py --compare-branch main

  # List all YAML files in a specific directory
  python find_changed_datasets.py --directory datasets/attack_techniques/T1003.003

Output formats:
  --output directories  : Print directories containing YAML files (default)
  --output files        : Print individual YAML file paths
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--base-sha',
        help='Base commit SHA to compare from'
    )
    group.add_argument(
        '--compare-branch',
        help='Compare current HEAD against this branch (e.g., main, origin/main)'
    )
    group.add_argument(
        '--directory',
        help='Specific directory to find YAML files in'
    )

    parser.add_argument(
        '--head-sha',
        help='Head commit SHA to compare to (defaults to HEAD if using --base-sha)'
    )
    parser.add_argument(
        '--output',
        choices=['directories', 'files'],
        default='directories',
        help='Output format: directories or individual files'
    )
    
    args = parser.parse_args()
    
    try:
        if args.directory:
            # Direct directory mode
            if not Path(args.directory).exists():
                print(f"Error: Directory {args.directory} does not exist")
                sys.exit(1)
            
            if args.output == 'files':
                yaml_files = find_all_yaml_files([args.directory])
                for f in yaml_files:
                    print(f)
            else:
                if find_all_yaml_files([args.directory]):
                    print(args.directory)
        
        elif args.compare_branch:
            # Compare against a branch
            head_sha = run_git_command("git rev-parse HEAD")
            base_sha = run_git_command(f"git merge-base HEAD {args.compare_branch}")
            
            if not head_sha or not base_sha:
                print("Error: Could not determine commit SHAs")
                sys.exit(1)
            
            changed_files = find_changed_files(base_sha, head_sha)
            if not changed_files:
                print("No dataset files changed")
                sys.exit(0)
            
            print(f"Changed files: {len(changed_files)}", file=sys.stderr)
            for f in changed_files:
                print(f"  {f}", file=sys.stderr)
            
            yaml_dirs = find_yaml_files_in_directories(changed_files)
            
            if args.output == 'files':
                yaml_files = find_all_yaml_files(yaml_dirs)
                for f in yaml_files:
                    print(f)
            else:
                for d in yaml_dirs:
                    print(d)
        
        else:
            # Base/head SHA mode
            head_sha = args.head_sha or run_git_command("git rev-parse HEAD")
            
            changed_files = find_changed_files(args.base_sha, head_sha)
            if not changed_files:
                print("No dataset files changed")
                sys.exit(0)
            
            print(f"Changed files: {len(changed_files)}", file=sys.stderr)
            for f in changed_files:
                print(f"  {f}", file=sys.stderr)
            
            yaml_dirs = find_yaml_files_in_directories(changed_files)
            
            if args.output == 'files':
                yaml_files = find_all_yaml_files(yaml_dirs)
                for f in yaml_files:
                    print(f)
            else:
                for d in yaml_dirs:
                    print(d)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
