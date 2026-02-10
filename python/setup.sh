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

echo ================ building skale_te ===============
# Note: This assumes libskale_te_python.so has been built in ../build/ via cmake
python3 $CWD/setup_te.py install --user
if [[ $? -ne 0 ]] ; then
  echo "Error installing skale_te. Ensure you have built the C++ library (make skale_te_python)"
  exit 1
fi
echo ================ setup skale_te done =============
