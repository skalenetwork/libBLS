#!/bin/bash

# Script to calculate the next PyPI version based on existing versions.
# Usage: ./calculate_version_pypi.sh <package_name> <base_version> <branch>

PACKAGE_NAME=$1
BASE_VERSION=$2
BRANCH=$3

if [ -z "$PACKAGE_NAME" ]; then
    echo "Error: Package name is not provided."
    exit 1
fi

if [ -z "$BASE_VERSION" ]; then
    echo "Error: Base version is not provided."
    exit 1
fi

if [ -z "$BRANCH" ]; then
    echo "Error: Branch name is not provided."
    exit 1
fi

# If on stable branch, just return the base version (stripped of pre-release suffixes if any)
if [ "$BRANCH" = "stable" ]; then
    echo "$BASE_VERSION"
    exit 0
fi

# Determine the pre-release label
LABEL="dev"
if [ "$BRANCH" = "beta" ]; then
    LABEL="rc"
elif [ "$BRANCH" = "develop" ]; then
    LABEL="dev"
fi

# Fetch existing versions from PyPI
# We use the JSON API: https://pypi.org/pypi/<package>/json
REGISTRY_URL="https://pypi.org/pypi/${PACKAGE_NAME}/json"
EXISTING_VERSIONS=$(curl -s -L "${REGISTRY_URL}" | jq -r '.releases | keys | .[]' 2>/dev/null)

# Loop to find the next available version
for (( VERSION_NUMBER=0; ; VERSION_NUMBER++ )); do
    # PEP 440 compliant pre-release version: 1.2.3.dev0, 1.2.3rc1, etc.
    # Note: 'dev' versions normally use dot separator or not: 1.2.3.dev0 or 1.2.3dev0
    # We will use dot notation for clarity: BASE.devN or BASE.rcN
    
    if [ "$LABEL" = "dev" ]; then
        RESULT_VERSION="${BASE_VERSION}.dev${VERSION_NUMBER}"
    else
        RESULT_VERSION="${BASE_VERSION}${LABEL}${VERSION_NUMBER}"
    fi

    echo "$EXISTING_VERSIONS" | grep -q "^${RESULT_VERSION}$"
    if [ $? -ne 0 ]; then
        # Version not found in existing versions
        echo "$RESULT_VERSION"
        break
    fi
done
