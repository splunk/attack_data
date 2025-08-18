# Attack Data Validation Workflows

This document explains the GitHub Actions workflows that automatically validate attack data YAML files on every pull request and push to ensure data quality and consistency.

## Overview

The validation system consists of four main workflows that work together to ensure all attack data meets the required schema and quality standards:

1. **validate-pr.yml** - Full validation on all PRs
2. **validate-changed-files.yml** - Optimized validation for only changed files
3. **validate-push.yml** - Validation on pushes to main branches
4. **required-checks.yml** - Status checks and YAML linting

## Workflows Description

### 1. Validate Attack Data on PR (`validate-pr.yml`)

**Triggers:** Pull requests to `master` or `main` branches
**Purpose:** Comprehensive validation of all dataset YAML files

**Features:**
- Runs on PR open, synchronize, and reopen events
- Validates all YAML files in the `datasets/` directory
- Uses the validation script at `bin/validate.py`
- Comments on PR with success/failure status
- Only triggers when relevant files are changed

**Path filters:**
- `datasets/**/*.yml`
- `datasets/**/*.yaml`
- `bin/validate.py`
- `bin/dataset_schema.json`
- `bin/requirements.txt`

### 2. Validate Changed Attack Data Files (`validate-changed-files.yml`)

**Triggers:** Pull requests to `master` or `main` branches
**Purpose:** Fast validation of only changed YAML files

**Features:**
- Optimized for performance - only validates changed files
- Uses `tj-actions/changed-files` to detect modifications
- Provides detailed feedback on which files passed/failed
- Automatically skips if no YAML files were changed
- Comments on PR with detailed results

**Benefits:**
- Faster execution for large repositories
- Clear visibility into which specific files have issues
- Reduces CI/CD time for PRs with few changes

### 3. Validate Attack Data on Push (`validate-push.yml`)

**Triggers:** Pushes to `master` or `main` branches
**Purpose:** Safety net to catch validation failures that reach main branches

**Features:**
- Validates all dataset files after merge
- Creates GitHub issues automatically if validation fails
- Provides detailed error reporting
- Labels issues with appropriate tags for triage

**Issue Creation:**
- Creates issues labeled with `bug`, `validation-failure`, `high-priority`
- Includes commit hash and workflow run links
- Provides action items for resolution

### 4. Required Status Checks (`required-checks.yml`)

**Triggers:** Pull requests to `master` or `main` branches
**Purpose:** Enforce validation requirements and provide additional checks

**Features:**
- Basic YAML syntax linting with `yamllint`
- Status check requirement enforcement
- Configuration for branch protection rules

## Setup Instructions

### 1. Branch Protection Rules

To enforce these validations, configure branch protection rules in your GitHub repository:

1. Go to **Settings** → **Branches**
2. Add a rule for your main branch (`master` or `main`)
3. Enable **Require status checks to pass before merging**
4. Add these required status checks:
   - `validate-attack-data` (from validate-pr.yml)
   - `validate-changed-files` (from validate-changed-files.yml)
   - `validation-status` (from required-checks.yml)
   - `yaml-lint` (from required-checks.yml)

### 2. Repository Secrets

No additional secrets are required for the validation workflows. They use the default `GITHUB_TOKEN` for commenting on PRs and creating issues.

### 3. Dependencies

The workflows automatically install Python dependencies from `bin/requirements.txt`:
- `pyyaml`
- `jsonschema`
- Other dependencies as needed

## Validation Rules

The validation process checks:

### Schema Validation
- All YAML files must conform to the JSON schema in `bin/dataset_schema.json`
- Required fields must be present and properly formatted
- Data types must match schema specifications

### Custom Validations
- **UUID Format**: The `id` field must be a valid UUID
- **Date Format**: The `date` field must follow YYYY-MM-DD format
- **File Naming**: Template files and files with 'old' in the name are excluded

### YAML Syntax
- Valid YAML syntax
- Proper indentation (2 spaces)
- Line length limits (120 characters)
- Consistent formatting

## Workflow Outputs

### Success Scenarios
- ✅ PR comments indicating successful validation
- ✅ Green status checks in PR interface
- ✅ Detailed file-by-file validation results

### Failure Scenarios
- ❌ PR comments with error details
- ❌ Failed status checks blocking merge
- 🚨 Automatic issue creation for main branch failures
- 📝 Detailed error logs in workflow runs

## Troubleshooting

### Common Issues

1. **Schema Validation Errors**
   - Check that all required fields are present
   - Verify field data types match schema
   - Ensure proper YAML formatting

2. **UUID Format Errors**
   - Generate valid UUIDs using tools like `uuidgen`
   - Ensure no extra characters or formatting

3. **Date Format Errors**
   - Use YYYY-MM-DD format (e.g., 2024-01-15)
   - Avoid time components or other formats

4. **YAML Syntax Errors**
   - Use a YAML validator or linter
   - Check indentation (use spaces, not tabs)
   - Verify string quoting when needed

### Debugging Workflows

1. **Check Workflow Logs**
   - Go to Actions tab in GitHub
   - Click on the failed workflow run
   - Review step-by-step execution logs

2. **Local Testing**
   ```bash
   cd bin
   python validate.py ../datasets
   ```

3. **File-Specific Testing**
   ```bash
   cd bin
   python validate.py path/to/specific/file.yml
   ```

## Best Practices

### For Contributors

1. **Test Locally First**
   - Run validation script before pushing
   - Use the same schema and validation rules

2. **Keep Changes Small**
   - Smaller PRs are easier to validate and review
   - Changed-files workflow provides faster feedback

3. **Follow Schema Requirements**
   - Always include required fields
   - Use proper data types and formats
   - Reference schema documentation

### For Maintainers

1. **Monitor Validation Health**
   - Review failed workflows regularly
   - Update schema as requirements evolve
   - Keep dependencies updated

2. **Branch Protection**
   - Enforce status checks on main branches
   - Require reviews in addition to validation
   - Consider additional quality gates

3. **Issue Triage**
   - Address validation failures on main branches quickly
   - Create hotfix procedures for critical issues
   - Maintain schema documentation

## Files Structure

```
.github/
├── workflows/
│   ├── validate-pr.yml                 # Full PR validation
│   ├── validate-changed-files.yml      # Changed files validation
│   ├── validate-push.yml               # Push validation
│   └── required-checks.yml             # Status checks & linting
└── VALIDATION_WORKFLOWS.md             # This documentation

bin/
├── validate.py                         # Main validation script
├── dataset_schema.json                 # JSON schema definition
└── requirements.txt                    # Python dependencies

datasets/                               # Attack data files
└── **/*.yml, **/*.yaml                # Files to validate
```

## Support

For issues with validation workflows:

1. Check this documentation first
2. Review workflow logs in GitHub Actions
3. Test validation locally using the `validate.py` script
4. Create an issue if problems persist

For schema-related questions:
- Review `bin/dataset_schema.json`
- Check existing valid examples in `datasets/`
- Refer to attack data documentation

