#!/bin/bash

CWD="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

echo ================ building t-encrypt ===============
# Note: This assumes libt_encrypt_python.so has been built in ../build/ via cmake
python3 $CWD/setup_t_encrypt.py install --user
if [[ $? -ne 0 ]] ; then
  echo "Error installing t-encrypt. Ensure you have built the C++ library (make t_encrypt_python)"
  exit 1
fi
echo ================ setup t-encrypt done =============
