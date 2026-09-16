#!/bin/bash
set -euo pipefail

BASE_REF="${1:-stable}"
REQUIRE_BUMP="${2:-true}"

if [ ! -f "VERSION.txt" ]; then
    echo "::error::VERSION.txt not found in current directory!"
    exit 1
fi

TARGET_VERSION=$(tr -d '[:space:]' < VERSION.txt)
BASE_VERSION=$(git show "origin/${BASE_REF}:VERSION.txt" 2>/dev/null | tr -d '[:space:]' || echo "")

echo "Target version: '${TARGET_VERSION}'"
echo "Base version (${BASE_REF}): '${BASE_VERSION}'"
echo "Require bump (strictly greater): '${REQUIRE_BUMP}'"

# Validate SemVer format: MAJOR.MINOR.PATCH (e.g. 1.2.3)
if ! [[ "${TARGET_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "::error::VERSION.txt '${TARGET_VERSION}' is invalid! Expected format: MAJOR.MINOR.PATCH (e.g. 1.2.3)"
    exit 1
fi

if [ -n "${BASE_VERSION}" ] && [[ "${BASE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if [ "${REQUIRE_BUMP}" = "true" ] || [ "${REQUIRE_BUMP}" = "1" ]; then
        # Strict mode (stable): Must be strictly greater, cannot be equal
        if [ "${TARGET_VERSION}" = "${BASE_VERSION}" ]; then
            echo "::error::VERSION.txt must be updated before merging into ${BASE_REF}! Base branch already has version ${BASE_VERSION}."
            exit 1
        fi
        HIGHER_VERSION=$(printf '%s\n%s\n' "${BASE_VERSION}" "${TARGET_VERSION}" | sort -V | tail -n1)
        if [ "${HIGHER_VERSION}" != "${TARGET_VERSION}" ]; then
            echo "::error::New version ${TARGET_VERSION} must be strictly greater than ${BASE_VERSION}!"
            exit 1
        fi
    else
        # Non-strict mode (beta): Can be equal or higher, but NEVER lower (no downgrades)
        HIGHER_VERSION=$(printf '%s\n%s\n' "${BASE_VERSION}" "${TARGET_VERSION}" | sort -V | tail -n1)
        if [ "${HIGHER_VERSION}" != "${TARGET_VERSION}" ]; then
            echo "::error::Version regression detected! Target version ${TARGET_VERSION} cannot be lower than base branch version ${BASE_VERSION}."
            exit 1
        fi
    fi
fi

# If bump is required (e.g. for stable), check that tag does not already exist
if [ "${REQUIRE_BUMP}" = "true" ] || [ "${REQUIRE_BUMP}" = "1" ]; then
    git fetch --tags
    if git show-ref --tags --quiet --verify "refs/tags/${TARGET_VERSION}" \
        || git show-ref --tags --quiet --verify "refs/tags/v${TARGET_VERSION}"; then
        echo "::error::Tag ${TARGET_VERSION} (or v${TARGET_VERSION}) already exists in repository tags! Please use a new version."
        exit 1
    fi
fi

echo "Version check passed: ${TARGET_VERSION} is valid SemVer and satisfies branch constraints."
