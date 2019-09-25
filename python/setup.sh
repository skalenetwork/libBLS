#!/bin/bash
python3 setup.py build
# or even simply run: setup.py build
echo ================ module built =============
ldd ./build/lib.linux-x86_64-3.6/dkgpython.cpython-36m-x86_64-linux-gnu.so
mv ./build/lib.linux-x86_64-3.6/dkgpython.cpython-36m-x86_64-linux-gnu.so dkgpython.so
echo ================ setup done ===============
