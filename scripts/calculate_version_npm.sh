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

if [ "$BRANCH" = "master" ]
then
    echo "$VERSION"
    exit 0
fi

LABEL="develop"
if [ "$BRANCH" = "stable" ]
then
    LABEL="stable"
elif [ "$BRANCH" = "beta" ]
then
    LABEL="beta"
fi

for (( VERSION_NUMBER=0; ; VERSION_NUMBER++ )); do
    RESULT_VERSION="${BASE_VERSION}-${LABEL}.${VERSION_NUMBER}"
    if ! npm view "$PACKAGE_NAME@$RESULT_VERSION" > /dev/null 2>&1; then
        echo "$RESULT_VERSION" | tr / -
        break
    fi
done