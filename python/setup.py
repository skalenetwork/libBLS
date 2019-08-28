#!/usr/bin/env python3
# encoding: utf-8

import os
from distutils.core import setup, Extension

strCompilerCommonFlagsSuffix = " -fpermissive -fPIC -std=c++11 -Wno-error=parentheses -Wno-error=char-subscripts"
os.environ["CC" ] = "gcc-7" + strCompilerCommonFlagsSuffix
os.environ["CXX"] = "g++-7" + strCompilerCommonFlagsSuffix
os.environ["LD" ] = "ld" + strCompilerCommonFlagsSuffix

dkgpython_module = Extension('dkgpython',
                             sources = ['dkgpython.cpp'],
                             include_dirs = ['..', '../bls', '../dkg', '../third_party',
                             '../libff', '../deps/include', '../mpir'],
                             library_dirs = ['../build', '../deps/lib', '../build/deps/lib',
                             '../build/libff/libff'],
                             libraries = ['bls', 'ff', 'gmpxx', 'gmp']
                             )

setup(name = 'dkgpython',
      version = '0.1.0',
      description = 'dkgpython module written in C++',
      #include_dirs = [ '..', '../bls', '../dkg', '../third_party', '../deps/include' ],
      #library_dirs = [ '../deps/lib' ],
      #libraries = [ 'bls', 'dkg' ],
      ext_modules = [dkgpython_module]
      )
