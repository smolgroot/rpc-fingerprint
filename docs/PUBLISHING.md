# Publishing Guide

This repository includes an automated publishing script (`publish.sh`) to streamline the process of releasing new versions to PyPI.

## Prerequisites

Before using the publish script, ensure you have:

1. **PyPI Account**: Register at [pypi.org](https://pypi.org) and [test.pypi.org](https://test.pypi.org)
2. **API Tokens**: Configure PyPI API tokens for authentication
3. **Git Repository**: Initialized git repository for version tagging
4. **Virtual Environment**: Activated Python virtual environment with required dependencies

## Setup Authentication

### PyPI API Tokens

1. Generate API tokens:
   - Production PyPI: https://pypi.org/manage/account/token/
   - Test PyPI: https://test.pypi.org/manage/account/token/

2. Configure authentication in `~/.pypirc`:
```ini
[distutils]
index-servers = 
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-your-api-token-here

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-your-test-api-token-here
```

## Usage

### Basic Usage

```bash
# Patch version bump (1.0.0 -> 1.0.1) and publish to PyPI
./publish.sh

# Minor version bump (1.0.0 -> 1.1.0)
./publish.sh minor

# Major version bump (1.0.0 -> 2.0.0)
./publish.sh major
```

### Test Publishing

```bash
# Test with Test PyPI first
./publish.sh patch --test

# Dry run to see what would happen
./publish.sh --dry-run

# Combine options
./publish.sh minor --test --dry-run
```

### Available Options

- `patch|minor|major`: Version increment type (default: patch)
- `--test`: Upload to Test PyPI instead of production PyPI
- `--dry-run`: Show what would be done without executing
- `--help`: Display help message

## What the Script Does

The publish script automates the following steps:

1. **Validation**: Checks for required tools and dependencies
2. **Testing**: Runs test suite (if available)
3. **Cleanup**: Removes old build artifacts
4. **Version Bump**: Updates version in `setup.py` and `pyproject.toml`
5. **Build**: Creates source and wheel distributions
6. **Validation**: Checks package integrity with twine
7. **Upload**: Publishes to PyPI (with confirmation for production)
8. **Git Operations**: Commits version changes and creates git tag

## Version Management

The script automatically increments versions based on semantic versioning:

- **Patch** (1.0.0 → 1.0.1): Bug fixes, small improvements
- **Minor** (1.0.0 → 1.1.0): New features, backwards compatible
- **Major** (1.0.0 → 2.0.0): Breaking changes, API changes

## Safety Features

- **Dry Run Mode**: Test the process without making changes
- **Test PyPI**: Validate packages on test repository first
- **Confirmation**: Prompts before uploading to production PyPI
- **Validation**: Checks package integrity before upload
- **Git Integration**: Automatic tagging and commit tracking

## Example Workflow

1. **Development**: Make changes and commit to git
2. **Test**: Run dry run to validate process
   ```bash
   ./publish.sh --dry-run
   ```
3. **Test Publish**: Upload to Test PyPI
   ```bash
   ./publish.sh patch --test
   ```
4. **Validate**: Install and test from Test PyPI
   ```bash
   pip install --index-url https://test.pypi.org/simple/ ethereum-rpc-fingerprinter
   ```
5. **Production**: Publish to production PyPI
   ```bash
   ./publish.sh patch
   ```
6. **Git**: Push tags and changes
   ```bash
   git push && git push --tags
   ```

## Troubleshooting

### Common Issues

1. **Authentication Error**: Ensure PyPI tokens are correctly configured
2. **Package Already Exists**: Version already published, increment version
3. **Build Errors**: Check package configuration and dependencies
4. **Git Issues**: Ensure repository is clean and up to date

### Manual Recovery

If the script fails partway through:

1. **Reset Version**: Manually revert version changes in files
2. **Clean Build**: Remove `dist/`, `build/`, `*.egg-info/` directories
3. **Git Reset**: Remove uncommitted changes or tags if needed
4. **Retry**: Run the script again

## Security Notes

- Never commit PyPI tokens to version control
- Use environment variables or secure credential storage
- Review packages before uploading to production
- Test thoroughly on Test PyPI first
- Keep backup of working versions

## Files Modified

The script modifies these files during publishing:

- `setup.py`: Version string
- `pyproject.toml`: Version string
- Git repository: Commits and tags

Backup important changes before running the script.
