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
                             '../libff', '../mpir'],
                             library_dirs = ['../build', '../deps/lib', '../build/deps/lib',
                             '../build/libff/libff'],
                             libraries = ['bls', 'ff', 'gmpxx', 'gmp']
                             )

setup(name = 'libdkgpython',
      version = '0.1.0',
      description = 'dkgpython module written in C++',
      ext_modules = [dkgpython_module]
      )
