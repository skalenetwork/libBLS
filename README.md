# libBLS: a C++ library for BLS Threshold Signatures
 
A mathematical library written in C++ that supports BLS threshold signatures and Distributed Key Generation (DKG).

The libBLS library is developed by SKALE Labs and uses SCIPR-LAB's libff (see Libraries below).

# Overview
libBLS is a C++ library for BLS signatures and DKG that supports both threshold signatures and multi-signatures. 

The signature process proceeds in 3 steps:

1. Key generation
2. Signing
3. Verification

libBLS uses the alt_bn128 elliptic curve.

## Installation Requirements

libBLS has been built and tested on Ubuntu and Mac.

Make sure that the following libraries are installed:
1. Boost verison >= 1.65.1
2. OpenSSL version >= 1.1.1

## Building from source on Mac
Configure the project build with the following commands.
```
cmake -H. -Bbuild                               # Configure the project and create a build directory.
cmake --build build -- -j$(sysctl -n hw.ncpu)   # Build all default targets using all cores.
```

## Building from source on Ubuntu
Ensure that the required packages are installed by executing:
```sudo apt-get update```
```sudo apt-get install -y cmake build-essential automake```

Configure the project build with the following commands.
```
cmake -H. -Bbuild                   # Configure the project and create a build directory.
cmake --build build -- -j$(nproc)   # Build all default targets using all cores.
```

### Import the library
```
#include <bls/bls.h>
#include <dkg/dkg.h>
```

### Run tests
```
./build/test_dkg
./build/test_bls
./build/test_threshold
./build/bls_unit_test                           # run all unit tests
./build/bls_unit_test --list_content            # show all test cases
./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case
```

## How to use the BLS algorithm
1. Create an instance of class bls with input parameters t, and n; where n = number of participants in your group and t is a threshold number for your case.
2. Generate keys with DKG algorithm (if you want to use Threshold algorithm) or running the function KeyGeneration (if you want to use MultiSignature algorithm or singleBLS)
3. Create a hash of the message you want ot sign by running the function Hashing (by default we use the SHA256 hash function, but you can replace this with any other hash function. Be sure to be careful with respect to security.)
4. Sign the hashed message by running Signing (if you are doing Threshold algorithm, you have to generate common signature by running SignatureRecover after it)
5. Verify a signature by running the function Verification.

## Libraries
- [libff by SCIPR-LAB](http://www.scipr-lab.org/)

# License

Copyright (c) 2018 SKALE Labs, Inc. and contributors.
