# libBLS: a C++ library for BLS Threshold Signatures

[![Build Status](https://travis-ci.com/skalelabs/libBLS.svg?token=GpDGXHqy9kTj5H5cyHGS&branch=develop)](https://travis-ci.com/skalelabs/libBLS) [![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

A mathematical library written in C++ that supports BLS threshold signatures and Distributed Key Generation (DKG).

This libBLS library is developed by SKALE Labs and uses SCIPR-LAB's libff (see Libraries below).

## An important note about production readiness

This libBLS library is still in active development and therefore should be regarded as _alpha software_. The development is still subject to security hardening, further testing, and breaking changes.  **This library has not yet been reviewed or audited for security.**

## Overview

libBLS is a C++ library for [BLS signatures](https://doi.org/10.1007%2F3-540-45682-1_30) and [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) that supports both threshold signatures and multi-signatures. 

The signature process proceeds in 4 steps:

1.  Key generation
2.  Hashing
3.  Signing
4.  Verification

libBLS uses the alt_bn128 (Barreto-Naehrig curve) elliptic curve to be compatible with [Ethereum's cryptography](https://ethereum.github.io/yellowpaper/paper.pdf) and provides 128 bits of security. Also, it provides opportunity to generate secret keys with DKG algorithm that supports the same curve. 

libBLS for the most part corresponds to [BLS signature standard](https://tools.ietf.org/html/draft-boneh-bls-signature-00). This work is still in progress and is going to be improved in the next couple of months.

## Perfomance Specifications

libBLS allows to sign about 3000 messages per second on a single thread (Intel® Core™ i3-4160 CPU @ 3.60GHz). However, for our solution we have implemented constant time signing (0.01 sec for sign) to avoid timing attacks.

## Installation Requirements

libBLS has been built and tested on Ubuntu and Mac.

GitHub is used to maintain this source code. Clone this repository by:

    git clone --recurse-submodules https://github.com/skalelabs/libBLS.git
    cd libBLS

⚠️ Note: Because this repository depends on an additional submodule, it is important to pass`--recurse-submodules` to the `git clone` command to automatically initialize and update the submodule.

If you have already cloned the repository and forgot to pass `--recurse-submodules`, then simply execute `git submodule update --init`.

## Building from source on Mac

Ensure that the following required packages are installed:

-   Boost version >= 1.65.1
-   OpenSSL version >= 1.1.1

Configure the project build with the following commands.

    # Configure the project and create a build directory.
    cmake -H. -Bbuild

    # Build all default targets using all cores.
    cmake --build build -- -j$(sysctl -n hw.ncpu)

## Building from source on Ubuntu

Ensure that the required packages are installed by executing:

    sudo apt-get update
    sudo apt-get install -y cmake\
        build-essential\
        automake\
        libprocps-dev\
        libboost-all-dev\
        libgmp3-dev\
        libssl-dev

Configure the project build with the following commands.

    # Configure the project and create a build directory.
    cmake -H. -Bbuild

    # Build all default targets using all cores.
    cmake --build build -- -j$(nproc)

### Include the library

    #include <bls/bls.h>
    #include <dkg/dkg.h>

### Run tests

    ./build/dkg_unit_test                           # run all dkg unit tests
    ./build/bls_unit_test                           # run all bls unit tests
    ./build/bls_unit_test --list_content            # show all test cases
    ./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case

## How to use the BLS algorithm

1.  Create an instance of class Bls with input parameters t, and n; where n is a number of participants in your group and t is a threshold number for your case.


    signatures::bls bls_instance = signatures::bls(t, n);

2.  Generate keys with DKG algorithm (if you want to use Threshold algorithm) or running the function KeyGeneration (if you want to use MultiSignature algorithm or singleBLS)


    libff::alt_bn128_Fr secret_key = key_generated_by_dkg;
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

or

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> keys = bls_instance.KeyGeneration();

3.  Create a hash of the message you want ot sign by running the function Hashing (by default we use the SHA256 hash function, but you can replace this with any other hash function. Be sure to be careful with respect to security.)


    libff::alt_bn128_G1 hash = bls_instance.Hashing(message);

4.  Sign the hashed message by running Signing (if you are doing Threshold algorithm, you have to generate common signature by running SignatureRecover after it)


    libff::alt_bn128_G1 signature = bls_instance.Signing(hash, secret_key);

5.  Verify a signature by running the function Verification.


    assert(bls_instance.Verification(message, signature, public_key) == true);

## Libraries

-   [libff by SCIPR-LAB](http://www.scipr-lab.org/)

## Contributing

**If you have any questions please ask our development community on [Discord](https://discord.gg/vvUtWJB).**

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

Otherwise see our [CONTRIBUTING.md](.github/CONTRIBUTING.md) for more information.

# License

![GitHub](https://img.shields.io/github/license/skalelabs/libbls.svg)

Copyright (C) 2018-present SKALE Labs
