#!/bin/bash

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

if [ "$BRANCH" = "stable" ]
then
    echo "$VERSION"
    exit 0
fi

LABEL="develop"
if [ "$BRANCH" = "beta" ]
then
    LABEL="beta"
fi

for (( VERSION_NUMBER=0; ; VERSION_NUMBER<1000; VERSION_NUMBER++ )); do
    RESULT_VERSION="${BASE_VERSION}-${LABEL}.${VERSION_NUMBER}"
    echo "Checking version: $RESULT_VERSION"
    if ! npm view "$PACKAGE_NAME@$RESULT_VERSION" > /dev/null 2>&1; then
        echo "$RESULT_VERSION" | tr / -
        break
    fi
    sleep 0.1
done

# If the loop reaches its limit, exit with an error
if [ $VERSION_NUMBER -eq 1000 ]; then
    echo "Error: Could not find a unique version after 1000 attempts."
    exit 1
fi