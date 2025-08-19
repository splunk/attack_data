#!/usr/bin/env python3
"""
YAML Dataset Validation Script

This script validates YAML files in the specified directory against a
predefined JSON schema.
All dataset YAML files must conform to the specified structure with mandatory fields.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

import yaml
from jsonschema import validate, ValidationError, draft7_format_checker


def load_yaml_schema() -> Dict[str, Any]:
    """
    Load and return the JSON schema for validating YAML dataset files.
    
    Returns:
        Dict containing the JSON schema definition
        
    Raises:
        FileNotFoundError: If schema file doesn't exist
        json.JSONDecodeError: If schema file is invalid JSON
    """
    # Get the schema file path relative to the script location
    script_dir = Path(__file__).parent
    schema_path = script_dir / 'dataset_schema.json'
    
    try:
        with open(schema_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in schema file {schema_path}: {e}")


def validate_uuid(uuid_string: str) -> bool:
    """
    Validate that a string is a properly formatted UUID.
    
    Args:
        uuid_string: String to validate as UUID
        
    Returns:
        True if valid UUID, False otherwise
    """
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False


def validate_date(date_string: str) -> bool:
    """
    Validate that a string is a properly formatted date (YYYY-MM-DD).
    
    Args:
        date_string: String to validate as date
        
    Returns:
        True if valid date, False otherwise
    """
    try:
        datetime.strptime(date_string, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def load_yaml_file(file_path: Path) -> Dict[str, Any]:
    """
    Load and parse a YAML file.
    
    Args:
        file_path: Path to the YAML file
        
    Returns:
        Parsed YAML content as dictionary
        
    Raises:
        yaml.YAMLError: If YAML parsing fails
        FileNotFoundError: If file doesn't exist
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"YAML parsing error in {file_path}: {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")


def validate_yaml_file(file_path: Path, schema: Dict[str, Any]) -> List[str]:
    """
    Validate a single YAML file against the schema.
    
    Args:
        file_path: Path to the YAML file to validate
        schema: JSON schema to validate against
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    try:
        # Load YAML content
        yaml_content = load_yaml_file(file_path)
        
        # Validate against JSON schema
        validate(yaml_content, schema, format_checker=draft7_format_checker)
        
        # Additional custom validations
        if 'id' in yaml_content and not validate_uuid(yaml_content['id']):
            errors.append(f"Invalid UUID format for 'id': {yaml_content['id']}")
            
        if 'date' in yaml_content and not validate_date(yaml_content['date']):
            errors.append(
                f"Invalid date format for 'date': {yaml_content['date']} "
                f"(expected YYYY-MM-DD)"
            )
            
    except ValidationError as e:
        errors.append(f"Schema validation error: {e.message}")
        if e.absolute_path:
            errors.append(f"  Path: {' -> '.join(str(p) for p in e.absolute_path)}")
    except yaml.YAMLError as e:
        errors.append(f"YAML parsing error: {e}")
    except FileNotFoundError as e:
        errors.append(f"File error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    
    return errors


def find_yaml_files(input_dir: Path) -> List[Path]:
    """
    Find all YAML files in the specified directory.
    
    Args:
        input_dir: Path to the directory to search for YAML files
        
    Returns:
        List of paths to YAML files
    """
    yaml_files = []
    
    # Look for .yml and .yaml files recursively
    for pattern in ['**/*.yml', '**/*.yaml']:
        yaml_files.extend(input_dir.glob(pattern))
    
    # Exclude template files and files with 'old' in the name
    yaml_files = [
        f for f in yaml_files 
        if not f.name.startswith('TEMPLATE') and 'old' not in f.name.lower()
    ]
    
    return sorted(yaml_files)


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Validate YAML files against a predefined JSON schema.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Validate files in default 'datasets' dir (failures only)
  %(prog)s -v                 # Validate with verbose output (show all files)
  %(prog)s /path/to/data      # Validate files in a specific directory
  %(prog)s ../other_datasets  # Validate files in a relative path
        """
    )
    
    parser.add_argument(
        'input_folder',
        nargs='?',
        default='datasets',
        help='Directory to search for YAML files (default: datasets)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show validation results for all files (default: only show failures)'
    )
    
    return parser.parse_args()


def main():
    """
    Main function to validate all YAML files in the specified directory.
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    # Get the project root directory and input directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    
    # Handle input folder path (can be relative or absolute)
    if Path(args.input_folder).is_absolute():
        input_dir = Path(args.input_folder)
    else:
        input_dir = project_root / args.input_folder
    
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}")
        sys.exit(1)
    
    if not input_dir.is_dir():
        print(f"Error: Input path is not a directory: {input_dir}")
        sys.exit(1)
    
    print(f"Validating YAML files in: {input_dir}")
    
    # Load the JSON schema
    try:
        schema = load_yaml_schema()
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading schema: {e}")
        sys.exit(1)
    
    # Find all YAML files
    yaml_files = find_yaml_files(input_dir)
    
    if not yaml_files:
        print(f"No YAML files found in the input directory: {input_dir}")
        return
    
    print(f"Found {len(yaml_files)} YAML files to validate...")
    if args.verbose:
        print("-" * 60)
    
    total_files = len(yaml_files)
    valid_files = 0
    invalid_files = 0
    failed_validations = []  # Track failed files and their errors
    
    # Validate each file
    for yaml_file in yaml_files:
        # Try to get relative path from project root, fallback to input_dir
        try:
            relative_path = yaml_file.relative_to(project_root)
        except ValueError:
            relative_path = yaml_file.relative_to(input_dir)
        
        errors = validate_yaml_file(yaml_file, schema)
        
        if errors:
            invalid_files += 1
            # Always show failures
            print(f"\n❌ INVALID: {relative_path}")
            print(f"   {len(errors)} error(s):")
            for error in errors:
                print(f"  • {error}")
            # Store failed validation details
            failed_validations.append((relative_path, errors))
        else:
            valid_files += 1
            # Only show valid files in verbose mode
            if args.verbose:
                print(f"\n✅ VALID: {relative_path}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total files processed: {total_files}")
    print(f"Valid files: {valid_files}")
    print(f"Invalid files: {invalid_files}")
    
    if invalid_files > 0:
        print(f"\n❌ {invalid_files} file(s) failed validation!")
        
        # In verbose mode, also print detailed failed validations at the end
        if args.verbose and failed_validations:
            print("\n" + "=" * 60)
            print("FAILED VALIDATIONS SUMMARY")
            print("=" * 60)
            for file_path, errors in failed_validations:
                print(f"\n📁 {file_path}")
                print("-" * 40)
                for i, error in enumerate(errors, 1):
                    print(f"{i}. {error}")
        
        sys.exit(1)
    else:
        print("\n✅ All files passed validation!")


if __name__ == "__main__":
    main()
