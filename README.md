# libBLS: a C++ library for BLS Threshold Signatures
 
A mathematical library written in C++ that supports BLS threshold signatures and Distributed Key Generation (DKG).

The libBLS library is developed by SKALE Labs and uses SCIPR-LAB's libff (see Libraries below).

# Overview
libBLS is a C++ library for BLS signatures and DKG that supports both threshold signatures and multi-signatures. 

The signature process proceeds in 4 steps:

1. Key generation
2. Hashing
3. Signing
4. Verification

libBLS uses the alt_bn128 (Barreto-Naehrig curve) elliptic curve to be compatible with Ethereum's cryptography and provides 128 bits of security.

## Perfomance Specifications

libBLS allows to sign about 3000 messages per second on a single thread(Intel® Core™ i3-4160 CPU @ 3.60GHz).
However, for our solution we have implemented constant time signing (0.01 sec for sign) to avoid timing attacks.

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
./build/dkg_unit_test                           # run all dkg unit tests
./build/bls_unit_test                           # run all bls unit tests
./build/bls_unit_test --list_content            # show all test cases
./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case
```

## How to use the BLS algorithm
1. Create an instance of class bls with input parameters t, and n; where n is a number of participants in your group and t is a threshold number for your case.
```
signatures::bls bls_instance = signatures::bls(t, n);
```
2. Generate keys with DKG algorithm (if you want to use Threshold algorithm) or running the function KeyGeneration (if you want to use MultiSignature algorithm or singleBLS)
```
libff::alt_bn128_Fr secret_key = key_generated_by_dkg;
libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();
```
or
```
std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> keys = bls_instance.KeyGeneration();
```
3. Create a hash of the message you want ot sign by running the function Hashing (by default we use the SHA256 hash function, but you can replace this with any other hash function. Be sure to be careful with respect to security.)
```
libff::alt_bn128_G1 hash = bls_instance.Hashing(message);
```
4. Sign the hashed message by running Signing (if you are doing Threshold algorithm, you have to generate common signature by running SignatureRecover after it)
```
libff::alt_bn128_G1 signature = bls_instance.Signing(hash, secret_key);
```
5. Verify a signature by running the function Verification.
```
assert(bls_instance.Verification(hash, signature, public_key) == true);
```

## Libraries
- [libff by SCIPR-LAB](http://www.scipr-lab.org/)

# License

Copyright (c) 2018 SKALE Labs, Inc. and contributors.
