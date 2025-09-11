#!/bin/bash
# publish.sh - Automated PyPI publishing script for ethereum-rpc-fingerprinter
# Usage: ./publish.sh [patch|minor|major] [--test]

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERSION_TYPE="patch"
TEST_PYPI=false
DRY_RUN=false

# Help function
show_help() {
    echo "Usage: $0 [VERSION_TYPE] [OPTIONS]"
    echo ""
    echo "VERSION_TYPE:"
    echo "  patch    Increment patch version (1.0.0 -> 1.0.1) [default]"
    echo "  minor    Increment minor version (1.0.0 -> 1.1.0)"
    echo "  major    Increment major version (1.0.0 -> 2.0.0)"
    echo ""
    echo "OPTIONS:"
    echo "  --test     Upload to test.pypi.org instead of pypi.org"
    echo "  --dry-run  Show what would be done without actually doing it"
    echo "  --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Bump patch version and publish to PyPI"
    echo "  $0 minor             # Bump minor version and publish to PyPI"
    echo "  $0 patch --test      # Bump patch version and publish to Test PyPI"
    echo "  $0 --dry-run         # Show what would be done"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        patch|minor|major)
            VERSION_TYPE="$1"
            shift
            ;;
        --test)
            TEST_PYPI=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Function to print colored output
print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get current version from setup.py
get_current_version() {
    python -c "
import re
with open('setup.py', 'r') as f:
    content = f.read()
    match = re.search(r'version=\"([^\"]+)\"', content)
    if match:
        print(match.group(1))
    else:
        print('1.0.0')
"
}

# Function to increment version
increment_version() {
    local current_version=$1
    local version_type=$2
    
    python -c "
import sys
version = '$current_version'.split('.')
major, minor, patch = int(version[0]), int(version[1]), int(version[2])

if '$version_type' == 'major':
    major += 1
    minor = 0
    patch = 0
elif '$version_type' == 'minor':
    minor += 1
    patch = 0
elif '$version_type' == 'patch':
    patch += 1

print(f'{major}.{minor}.{patch}')
"
}

# Function to update version in files
update_version() {
    local new_version=$1
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would update version to $new_version in setup.py and pyproject.toml"
        return
    fi
    
    # Update setup.py
    sed -i.bak "s/version=\"[^\"]*\"/version=\"$new_version\"/" setup.py
    
    # Update pyproject.toml
    sed -i.bak "s/version = \"[^\"]*\"/version = \"$new_version\"/" pyproject.toml
    
    # Remove backup files
    rm -f setup.py.bak pyproject.toml.bak
    
    print_success "Updated version to $new_version"
}

# Function to run tests
run_tests() {
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would run tests"
        return
    fi
    
    print_step "Running tests..."
    
    # Check if pytest is available
    if command -v pytest &> /dev/null; then
        if [[ -f "test_fingerprinter.py" ]]; then
            python -m pytest test_fingerprinter.py -v
        else
            print_warning "No test files found, skipping tests"
        fi
    else
        print_warning "pytest not found, skipping tests"
    fi
}

# Function to clean build directories
clean_build() {
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would clean build directories"
        return
    fi
    
    print_step "Cleaning build directories..."
    rm -rf build/ dist/ *.egg-info/
    print_success "Build directories cleaned"
}

# Function to build package
build_package() {
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would build package"
        return
    fi
    
    print_step "Building package..."
    python -m build
    print_success "Package built successfully"
}

# Function to check package
check_package() {
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would check package with twine"
        return
    fi
    
    print_step "Checking package..."
    python -m twine check dist/*
    print_success "Package check passed"
}

# Function to upload to PyPI
upload_package() {
    local new_version=$1
    
    if [[ "$DRY_RUN" == "true" ]]; then
        if [[ "$TEST_PYPI" == "true" ]]; then
            print_warning "DRY RUN: Would upload to Test PyPI"
        else
            print_warning "DRY RUN: Would upload to PyPI"
        fi
        return
    fi
    
    if [[ "$TEST_PYPI" == "true" ]]; then
        print_step "Uploading to Test PyPI..."
        python -m twine upload --repository testpypi dist/* --verbose
        print_success "Package uploaded to Test PyPI"
        echo -e "${YELLOW}Test with: pip install --index-url https://test.pypi.org/simple/ ethereum-rpc-fingerprinter==$new_version${NC}"
    else
        print_step "Uploading to PyPI..."
        echo -e "${YELLOW}This will upload to the PRODUCTION PyPI. Continue? (y/N)${NC}"
        read -r confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            python -m twine upload --repository pypi dist/* --verbose
            print_success "Package uploaded to PyPI"
            echo -e "${GREEN}Install with: pip install ethereum-rpc-fingerprinter==$new_version${NC}"
        else
            print_warning "Upload cancelled"
            exit 0
        fi
    fi
}

# Function to commit and tag version
commit_and_tag() {
    local new_version=$1
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_warning "DRY RUN: Would commit and tag version v$new_version"
        return
    fi
    
    # Check if git repo exists
    if [[ ! -d ".git" ]]; then
        print_warning "Not a git repository, skipping commit and tag"
        return
    fi
    
    print_step "Committing and tagging version v$new_version..."
    
    # Add changed files
    git add setup.py pyproject.toml
    
    # Check if there are changes to commit
    if git diff --cached --quiet; then
        print_warning "No changes to commit"
    else
        git commit -m "Bump version to $new_version"
        print_success "Changes committed"
    fi
    
    # Create tag
    git tag -a "v$new_version" -m "Release version $new_version"
    print_success "Tagged version v$new_version"
    
    echo -e "${YELLOW}Don't forget to push: git push && git push --tags${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Ethereum RPC Fingerprinter Publisher${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Check requirements
    print_step "Checking requirements..."
    
    # Check Python
    if ! command -v python &> /dev/null; then
        print_error "python is required but not installed"
        exit 1
    fi
    
    # Check required packages
    for pkg in build twine; do
        if ! python -c "import $pkg" &> /dev/null; then
            print_error "Python package '$pkg' is required. Install with: pip install $pkg"
            exit 1
        fi
    done
    
    # Get current version
    current_version=$(get_current_version)
    new_version=$(increment_version "$current_version" "$VERSION_TYPE")
    
    echo -e "Current version: ${YELLOW}$current_version${NC}"
    echo -e "New version:     ${GREEN}$new_version${NC}"
    echo -e "Version type:    ${BLUE}$VERSION_TYPE${NC}"
    
    if [[ "$TEST_PYPI" == "true" ]]; then
        echo -e "Target:          ${YELLOW}Test PyPI${NC}"
    else
        echo -e "Target:          ${GREEN}Production PyPI${NC}"
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "Mode:            ${YELLOW}DRY RUN${NC}"
    fi
    
    echo ""
    
    # Confirmation
    if [[ "$DRY_RUN" == "false" ]]; then
        echo -e "${YELLOW}Continue? (y/N)${NC}"
        read -r confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            print_warning "Cancelled"
            exit 0
        fi
    fi
    
    # Execute steps
    run_tests
    clean_build
    update_version "$new_version"
    build_package
    check_package
    upload_package "$new_version"
    commit_and_tag "$new_version"
    
    echo ""
    print_success "Publishing completed successfully!"
    
    if [[ "$DRY_RUN" == "false" && "$TEST_PYPI" == "false" ]]; then
        echo ""
        echo -e "${GREEN}Package is now available at: https://pypi.org/project/ethereum-rpc-fingerprinter/${NC}"
        echo -e "${GREEN}Install with: pip install ethereum-rpc-fingerprinter==$new_version${NC}"
    fi
}

# Run main function
main "$@"
