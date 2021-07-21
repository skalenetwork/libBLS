# libBLS: a C++ library for BLS Threshold Signatures

[![Build and test libBLS](https://github.com/skalenetwork/libBLS/actions/workflows/test.yml/badge.svg)](https://github.com/skalenetwork/libBLS/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/skalenetwork/libBLS/branch/develop/graph/badge.svg)](https://codecov.io/gh/skalenetwork/libBLS)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3745/badge)](https://bestpractices.coreinfrastructure.org/projects/3745)
[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

A mathematical library written in C++ that supports BLS threshold signatures, Distributed Key Generation (DKG) and Threshold Encryption (TE).

This libBLS library is developed by SKALE Labs and uses SCIPR-LAB's libff and PBC library by Ben Lynn (see Libraries below).

## An important note about production readiness

This libBLS library is still in active development and therefore should be regarded as _alpha software_. The development is still subject to security hardening, further testing, and breaking changes.  **This library has not yet been reviewed or audited for security.** Please see [SECURITY.md](SECURITY.md) for reporting policies.

## Overview

libBLS is a C++ library for [BLS signatures](https://doi.org/10.1007%2F3-540-45682-1_30) and [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) that supports both threshold signatures and multi-signatures. Also it supports [Threshold Encryption](https://doi.org/10.1109/GLOCOM.2003.1258486).

The signature process proceeds in 4 steps:

1.  Key generation
2.  Hashing
3.  Signing
4.  Verification

libBLS uses the alt_bn128 (Barreto-Naehrig curve) elliptic curve to be compatible with [Ethereum's cryptography](https://ethereum.github.io/yellowpaper/paper.pdf) and provides 128 bits of security. Also, it provides opportunity to generate secret keys with DKG algorithm that supports the same curve.

libBLS for the most part corresponds to [BLS signature standard](https://tools.ietf.org/html/draft-boneh-bls-signature-00). This work is still in progress and is going to be improved in the next couple of months.

Encryption process is running as follows:

1.  Key generation
2.  Encryption
3.  Decryption
4.  Verifying and combining shares

You can learn more about the algebraic structures used in this algorithm in [Ben Lynn’s PhD Dissertation](https://crypto.stanford.edu/pbc/thesis.html). libBLS uses a modified [Ben Lynn's pbc library](https://github.com/skalenetwork/pbc) with memory corruption bug fixed and the TYPE A curve for symmetric bilinear pairing.

## Performance Specifications

libBLS allows to sign about 3000 messages per second on a single thread (Intel® Core™ i3-4160 CPU @ 3.60GHz). However, for our solution we have implemented constant time signing (0.01 sec for sign) to avoid timing attacks.

## Installation Requirements

libBLS has been built and tested on Ubuntu and Mac.

GitHub is used to maintain this source code. Clone this repository by:

```shell
git clone https://github.com/skalenetwork/libBLS.git
cd libBLS
```

## Building Dependencies

Ensure that required packages listed below are installed.

Build libBLS's dependencies by:

```shell
cd deps
bash ./build.sh
cd ..
```

## Building from source on Mac

```shell
brew install flex bison libtool automake cmake pkg-config yasm
# Configure the project and create a build directory.
cmake -H. -Bbuild

# Build all default targets using all cores.
cmake --build build -- -j$(sysctl -n hw.ncpu)
```

## Building from source on Ubuntu

Ensure that the required packages are installed by executing:

```shell
sudo apt-get update
sudo apt-get install -y automake cmake build-essential libprocps-dev libtool\
                        pkg-config yasm texinfo autoconf flex bison clang-format-6.0
```

Configure the project build with the following commands.

```shell
# Configure the project and create a build directory.
cmake -H. -Bbuild

# Build all default targets using all cores.
cmake --build build -- -j$(nproc)
```

### Include the library

```cpp
#include <libBLS.h>
```

### Documentation

See [docs](docs) for libBLS documentation.

## Libraries

-   [libff by SCIPR-LAB](http://www.scipr-lab.org/)
-   [pbc by Ben Lynn](https://crypto.stanford.edu/pbc/) with modifications from SKALE Labs

## Contributing

**If you have any questions please ask the development community on [Discord](https://discord.gg/vvUtWJB).**

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

Otherwise see our [CONTRIBUTING.md](.github/CONTRIBUTING.md) for more information.

## License

[![License](https://img.shields.io/github/license/skalenetwork/libbls.svg)](LICENSE)

Copyright (C) 2018-present SKALE Labs
