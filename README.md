# libBLS: a C++ library for BLS Threshold Signatures

[![Build and test libBLS](https://github.com/skalenetwork/libBLS/actions/workflows/test.yml/badge.svg)](https://github.com/skalenetwork/libBLS/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/skalenetwork/libBLS/branch/develop/graph/badge.svg)](https://codecov.io/gh/skalenetwork/libBLS)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3745/badge)](https://bestpractices.coreinfrastructure.org/projects/3745)
[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.com/invite/gM5XBy6)

A mathematical library written in C++ that supports BLS threshold signatures, Distributed Key Generation (DKG) and Threshold Encryption (TE).

This library is developed by SKALE Labs. Its current algebra backend is
[MCL](https://github.com/herumi/mcl), with GMP used for arbitrary-precision
integer support.

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

libBls uses the same alt_bn128 curve for threshold encryption as for BLS signatures. 

## Performance Specifications

libBLS allows to sign about 3000 messages per second on a single thread (Intel® Core™ i3-4160 CPU @ 3.60GHz). However, for our solution we have implemented constant time signing (0.01 sec for sign) to avoid timing attacks.

## Installation Requirements

libBLS has been built and tested on Ubuntu and macOS. The supported toolchains
are GCC/G++ 11 or newer on Linux and Apple Clang on macOS. CMake and the
platform packages listed below are also required.

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
brew install libtool automake cmake pkg-config yasm
# Configure the project and create a build directory.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build all default targets using all cores.
cmake --build build -- -j$(sysctl -n hw.ncpu)
```

## Building from source on Ubuntu

Ensure that the required packages are installed by executing:

```shell
sudo apt-get update
sudo apt-get install -y automake cmake build-essential libgnutls28-dev libtool\
                        pkg-config yasm texinfo autoconf clang-format-14
```

Configure the project build with the following commands.

```shell
# Configure the project and create a build directory.
cmake -S . -B build

# Build all default targets using all cores.
cmake --build build --parallel $(nproc)
```

### Run the tests

```shell
ctest --test-dir build --output-on-failure
```

For more details on running individual test binaries, benchmarks, and AddressSanitizer (ASan) builds, see [Running Tests, Benchmarks & ASan](docs/usage/testing.md).

To build without optional tests and benchmarks:

```shell
cmake -S . -B build \
    -DLIBBLS_BUILD_TESTS=OFF \
    -DLIBBLS_BUILD_BENCHMARKS=OFF
cmake --build build --parallel
```

### Include the library

```cpp
#include <libBLS.h>
```

### Documentation

See the [documentation index](docs/index.md) for an overview, or jump directly
to the [usage guide](docs/usage/usage-index.md),
[threshold signatures](docs/usage/using-threshold-signatures.md),
[distributed key generation](docs/usage/using-distributed-key-generation.md),
or [threshold encryption](docs/usage/using-threshold-encryption.md).

## Libraries

-   [MCL by herumi](https://github.com/herumi/mcl)
-   [GMP](https://gmplib.org/)

## Contributing

**If you have any questions please ask the development community on [Discord](https://discord.gg/vvUtWJB).**

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

Otherwise see our [CONTRIBUTING.md](.github/CONTRIBUTING.md) for more information.

## License

[![License](https://img.shields.io/github/license/skalenetwork/libbls.svg)](LICENSE)

Copyright (C) 2018-present SKALE Labs
