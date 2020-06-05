#!/bin/bash

VERSION=$(cat VERSION)
USAGE_MSG='Usage: BRANCH=[BRANCH] calculate_version.sh'

if [ -z "$BRANCH" ]
then
      echo "A branch is not set."
      exit 1
fi

if [ -z "$VERSION" ]
then
      echo "The base version is not set."
      exit 1
fi

git fetch --tags

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

for (( VERSION_NUMBER=0; ; VERSION_NUMBER++ ))
do
    RESULT_VERSION="$VERSION-$LABEL.$VERSION_NUMBER"
    if ! [[ $(git tag -l | grep $RESULT_VERSION) ]]; then
        echo "$RESULT_VERSION" | tr / -
        break
    fi
done
