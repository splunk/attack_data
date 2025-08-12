#!/usr/bin/env python3
"""
Script to analyze folders recursively and rename data.yml files.

When a folder contains:
- A data.yml file
- Another yml file with a different name

The script will:
1. Copy metadata (author, id, date, description) from the other yml file to data.yml
2. Remove the other yml file
3. Rename data.yml to match the folder name (folder_name.yml)
"""

import argparse
import logging
import yaml
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def find_yml_files(directory: Path) -> List[Path]:
    """Find all yml/yaml files in a directory (not recursive)."""
    yml_files = []
    for file_path in directory.iterdir():
        if file_path.is_file() and file_path.suffix.lower() in ['.yml', '.yaml']:
            yml_files.append(file_path)
    return yml_files


def load_yaml_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load and parse a YAML file.

    Returns:
        Dictionary containing the YAML data, or None if there was an error
    """
    logger = logging.getLogger(__name__)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading YAML file {file_path}: {e}")
        return None


def save_yaml_file(file_path: Path, data: Dict[str, Any]) -> bool:
    """
    Save data to a YAML file.

    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                      allow_unicode=True)
        return True
    except Exception as e:
        logger.error(f"Error saving YAML file {file_path}: {e}")
        return False


def copy_metadata_fields(source_data: Dict[str, Any], target_data: Dict[str, Any]) \
        -> Dict[str, Any]:
    """
    Copy metadata fields (author, id, date, description) from source to target.

    Args:
        source_data: YAML data from the other yml file
        target_data: YAML data from data.yml file

    Returns:
        Updated target data with copied metadata
    """
    logger = logging.getLogger(__name__)
    metadata_fields = ['author', 'id', 'date', 'description']

    updated_data = target_data.copy()

    for field in metadata_fields:
        if field in source_data:
            old_value = updated_data.get(field, 'N/A')
            new_value = source_data[field]
            logger.info(f"Copying {field}: '{old_value}' -> '{new_value}'")
            updated_data[field] = new_value
        else:
            logger.warning(f"Field '{field}' not found in source file")

    return updated_data


def analyze_directory(directory: Path) -> Optional[Tuple[Path, List[Path]]]:
    """
    Analyze a directory for data.yml and other yml files.

    Returns:
        Tuple of (data_yml_path, other_yml_files) if conditions are met, None otherwise
    """
    yml_files = find_yml_files(directory)

    if len(yml_files) < 2:
        return None

    data_yml = None
    other_yml_files = []

    for yml_file in yml_files:
        if yml_file.name.lower() == 'data.yml':
            data_yml = yml_file
        else:
            other_yml_files.append(yml_file)

    # Return only if we have data.yml and at least one other yml file
    if data_yml and other_yml_files:
        return (data_yml, other_yml_files)

    return None


def process_directory(directory: Path, dry_run: bool = False) -> bool:
    """
    Process a directory that meets our criteria.

    Args:
        directory: The directory to process
        dry_run: If True, only log what would be done without actually doing it

    Returns:
        True if processing was successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    result = analyze_directory(directory)
    if not result:
        return False

    data_yml, other_yml_files = result
    folder_name = directory.name
    new_yml_name = f"{folder_name}.yml"
    new_yml_path = directory / new_yml_name

    logger.info(f"Processing directory: {directory}")
    logger.info(f"Found data.yml: {data_yml}")
    logger.info(f"Found other yml files: {[str(f) for f in other_yml_files]}")

    try:
        # Step 1: Copy metadata from other yml files to data.yml
        data_yml_content = load_yaml_file(data_yml)
        if not data_yml_content:
            logger.error(f"Failed to load data.yml: {data_yml}")
            return False

        # Process each other yml file and copy metadata
        for other_yml in other_yml_files:
            other_yml_content = load_yaml_file(other_yml)
            if other_yml_content:
                logger.info(f"Copying metadata from {other_yml.name} to data.yml")
                data_yml_content = copy_metadata_fields(
                    other_yml_content, data_yml_content)
            else:
                logger.warning(f"Failed to load other yml file: {other_yml}")

        # Save the updated data.yml
        if dry_run:
            logger.info("[DRY RUN] Would update data.yml with copied metadata")
        else:
            logger.info("Updating data.yml with copied metadata")
            if not save_yaml_file(data_yml, data_yml_content):
                logger.error(f"Failed to save updated data.yml: {data_yml}")
                return False

        # Step 2: Remove other yml files
        for other_yml in other_yml_files:
            if dry_run:
                logger.info(f"[DRY RUN] Would remove: {other_yml}")
            else:
                logger.info(f"Removing: {other_yml}")
                other_yml.unlink()

        # Step 3: Rename data.yml to folder name
        if dry_run:
            logger.info(f"[DRY RUN] Would rename {data_yml} to {new_yml_path}")
        else:
            logger.info(f"Renaming {data_yml} to {new_yml_path}")
            data_yml.rename(new_yml_path)

        logger.info(f"Successfully processed directory: {directory}")
        return True

    except Exception as e:
        logger.error(f"Error processing directory {directory}: {e}")
        return False


def scan_directory_recursive(root_directory: Path, dry_run: bool = False) -> \
        Tuple[int, int]:
    """
    Recursively scan directories and process them.

    Returns:
        Tuple of (directories_processed, errors_encountered)
    """
    logger = logging.getLogger(__name__)
    processed_count = 0
    error_count = 0

    logger.info(f"Starting recursive scan of: {root_directory}")

    # Walk through all directories recursively
    for current_dir in root_directory.rglob('*'):
        if current_dir.is_dir():
            logger.debug(f"Checking directory: {current_dir}")

            try:
                if process_directory(current_dir, dry_run):
                    processed_count += 1
            except Exception as e:
                logger.error(f"Unexpected error processing {current_dir}: {e}")
                error_count += 1

    return processed_count, error_count


def main():
    """Main function to handle command line arguments and execute the script."""
    parser = argparse.ArgumentParser(
        description="Recursively analyze folders and rename data.yml files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rename_data.py /path/to/folder
  python rename_data.py /path/to/folder --dry-run
  python rename_data.py /path/to/folder --verbose
        """
    )
    parser.add_argument(
        'folder',
        type=str,
        help='Path to the root folder to analyze'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without actually making changes'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Validate input folder
    root_path = Path(args.folder).resolve()
    if not root_path.exists():
        logger.error(f"Error: The specified folder does not exist: {root_path}")
        return 1

    if not root_path.is_dir():
        logger.error(f"Error: The specified path is not a directory: {root_path}")
        return 1

    logger.info(f"Analyzing folder: {root_path}")
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")

    # Process the directories
    try:
        processed_count, error_count = scan_directory_recursive(root_path, args.dry_run)

        logger.info("Scan completed!")
        logger.info(f"Directories processed: {processed_count}")
        if error_count > 0:
            logger.warning(f"Errors encountered: {error_count}")

        return 0 if error_count == 0 else 1

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
