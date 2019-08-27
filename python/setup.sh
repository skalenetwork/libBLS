#!/bin/bash
python3 setup.py build
# or even simply run: setup.py build
echo ================ module built =============
ldd ./build/lib.linux-x86_64-3.5/dkgpython.cpython-35m-x86_64-linux-gnu.so
echo ================ setup done ===============

