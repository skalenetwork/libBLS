#!/bin/bash

CWD="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

python3.6 $CWD/setup.py build
if [[ $? -ne 0 ]] ; then
  exit 1
fi
# or even simply run: setup.py build
echo ================ module built =============
ldd ./build/lib.linux-x86_64-3.6/dkgpython.cpython-36m-x86_64-linux-gnu.so
mv ./build/lib.linux-x86_64-3.6/dkgpython.cpython-36m-x86_64-linux-gnu.so dkgpython.so
echo ================ setup done ===============
