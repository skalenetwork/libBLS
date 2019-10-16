#!/bin/bash

CWD="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

set -e

for i in {1..1000}
do
  python3.6 $CWD/test.py
  if [[ $? -ne 0 ]] ; then
    exit 1
  fi
done

echo ================ test passed successfully ===============
