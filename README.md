# libBLS: a C++ library for BLS Threshold Signatures

[![Build Status](https://travis-ci.com/skalenetwork/libBLS.svg?token=GpDGXHqy9kTj5H5cyHGS&branch=develop)](https://travis-ci.com/skalenetwork/libBLS) [![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

A mathematical library written in C++ that supports BLS threshold signatures, Distributed Key Generation (DKG) and Threshold Encryption (TE).

This libBLS library is developed by SKALE Labs and uses SCIPR-LAB's libff and PBC library by Ben Lynn (see Libraries below).

## An important note about production readiness

This libBLS library is still in active development and therefore should be regarded as _alpha software_. The development is still subject to security hardening, further testing, and breaking changes.  **This library has not yet been reviewed or audited for security.**

## Overview

libBLS is a C++ library for [BLS signatures](https://doi.org/10.1007%2F3-540-45682-1_30) and [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) that supports both threshold signatures and multi-signatures. Also it supports [Threshold Encryption](https://doi.org/10.1109/GLOCOM.2003.1258486).

The signature process proceeds in 4 steps:

1.  Key generation
2.  Hashing
3.  Signing
4.  Verification

libBLS uses the alt_bn128 (Barreto-Naehrig curve) elliptic curve to be compatible with [Ethereum's cryptography](https://ethereum.github.io/yellowpaper/paper.pdf) and provides 128 bits of security. Also, it provides opportunity to generate secret keys with DKG algorithm that supports the same curve. 

libBLS for the most part corresponds to [BLS signature standard](https://tools.ietf.org/html/draft-boneh-bls-signature-00). This work is still in progress and is going to be improved in the next couple of months.

Encryption process is running running as follows:

1.  Key generation
2.  Encryption
3.  Decryption
4.  Verifying and combining shares

You can learn more about the algebraic structures used in this algorithm in [Ben Lynn’s PhD Dissertation](https://crypto.stanford.edu/pbc/thesis.html). libBLS uses the TYPE A curve for symmetric billinear pairing.

## Perfomance Specifications

libBLS allows to sign about 3000 messages per second on a single thread (Intel® Core™ i3-4160 CPU @ 3.60GHz). However, for our solution we have implemented constant time signing (0.01 sec for sign) to avoid timing attacks.

## Installation Requirements

libBLS has been built and tested on Ubuntu and Mac.

GitHub is used to maintain this source code. Clone this repository by:

    git clone --recurse-submodules https://github.com/skalenetwork/libBLS.git
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

For BLS signatures:

```cpp
    #include <bls/bls.h>
    #include <dkg/dkg.h>
```

For pbc library:

```cpp
    #include "pbc/pbc.h"
```

For TE algorithm:

```cpp
    #include <dkg/dkg_te.h>
    #include <threshold_encryption/threshold_encryption.h>
```

### Run tests

```bash
    ./build/dkg_unit_test                           # run all dkg unit tests
    ./build/bls_unit_test                           # run all bls unit tests
    ./build/bls_unit_test --list_content            # show all test cases
    ./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case
    ./build/threshold_encryption/dkg_te_unit_test   # run all dkg tests corresponds to the algebraic structures used in TE algroithm
    ./build/threshold_encryption/te_unit_test       # run all te tests
```

## How to use the BLS algorithm

1.  Create an instance of class Bls with input parameters t, and n; where n is a number of participants in your group and t is a threshold number for your case.

```cpp
    signatures::bls bls_instance = signatures::bls(t, n);
```

2.  Generate keys with DKG algorithm (if you want to use Threshold algorithm) or running the function KeyGeneration (if you want to use MultiSignature algorithm or singleBLS)

```cpp
    libff::alt_bn128_Fr secret_key = key_generated_by_dkg;
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();
```

or

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> keys = bls_instance.KeyGeneration();

3.  Create a hash of the message you want to sign by running the function Hashing (by default we use the SHA256 hash function, but you can replace this with any other hash function. Be sure to be careful with respect to security.)

```cpp
    libff::alt_bn128_G1 hash = bls_instance.Hashing(message);
```

4.  Sign the hashed message by running Signing (if you are doing Threshold algorithm, you have to generate common signature by running SignatureRecover after it)

```cpp
    libff::alt_bn128_G1 signature = bls_instance.Signing(hash, secret_key
```

5.  Verify a signature by running the function Verification.

```cpp
    assert(bls_instance.Verification(message, signature, public_key) == true);
```

## How to use the TE algorithm

1.  Create an istance of class TE with input parameters t, and n; where n is a number of participants in your group and t is a threshold number for your case.

```cpp
    encryption::TE te_instance = encryption::TE(t, n);
```

2.  Encrypt a plaintext  `message`  by running

```cpp
    auto ciphertext = te_instance.Encrypt(message, public_key);
```

3.  Decrypt recieved ciphertext by running

```cpp
    te_instance.Decrypt(decrypted, ciphertext, secret_key); // decrypted value is stored in `decrypted`.
```

4.  Verify decrypted ciphertext by running

```cpp
    assert(te_instance.Verify(ciphertext, decrypted, public_key));
```

5.  If decrypted value is verified then you can get encrypted plaintext by running

```cpp
    std::vector<std::pair<encryption::element_wrapper, size_t>> shares;
    std::string res = te_instance.CombineShares(ciphertext, shares); // `res` is equal to `message`
```

## Libraries

-   [libff by SCIPR-LAB](http://www.scipr-lab.org/)
-   [pbc by Ben Lynn](https://crypto.stanford.edu/pbc/)

## Contributing

**If you have any questions please ask our development community on [Discord](https://discord.gg/vvUtWJB).**

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

Otherwise see our [CONTRIBUTING.md](.github/CONTRIBUTING.md) for more information.

## License

[![License](https://img.shields.io/github/license/skalenetwork/libbls.svg)](LICENSE)

Copyright (C) 2018-present SKALE Labs
