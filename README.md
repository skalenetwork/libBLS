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

```bash
git clone --recurse-submodules https://github.com/skalenetwork/libBLS.git
cd libBLS
```

⚠️ Note: Because this repository depends on an additional submodule, it is important to pass`--recurse-submodules` to the `git clone` command to automatically initialize and update the submodule.

If you have already cloned the repository and forgot to pass `--recurse-submodules`, then simply execute `git submodule update --init`.

## Building from source on Mac

Ensure that the following required packages are installed:

-   Boost version >= 1.65.1
-   OpenSSL version >= 1.1.1

Configure the project build with the following commands.

```bash
# Configure the project and create a build directory.
cmake -H. -Bbuild

# Build all default targets using all cores.
cmake --build build -- -j$(sysctl -n hw.ncpu)
```

## Building from source on Ubuntu

Ensure that the required packages are installed by executing:

```bash
sudo apt-get update
sudo apt-get install -y cmake\
    build-essential\
    automake\
    libprocps-dev\
    libboost-all-dev\
    libgmp3-dev\
    libssl-dev\
    flex\
    bison
```

Configure the project build with the following commands.

```bash
# Configure the project and create a build directory.
cmake -H. -Bbuild

# Build all default targets using all cores.
cmake --build build -- -j$(nproc)
```

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

```cpp
std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> keys = bls_instance.KeyGeneration();
```

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

## Classes for BLS threshold signatures

**BLSPrivateKeyShare** - class for private key for each participant. Has methods _sign_ and _signWithHelper_ to sign hashed message.

**BLSPrivateKey** - class for common private key

**BLSPublicKeyShare** - class for public key for each participant. Has methods _VerifySig_ and _VerifySigWithHelper_ to Verify piece of signature.

**BLSPublicKey** - class for common public key. Has method _VerifySig_ for verifying common signature.

**BLSSigShare** - class for a piece of common signature.

**BLSSigShareSet** - class for set of pieces of signature. Has methods _Add_ (to add a piece of signature) and _merge_ ( to get common signature, if enough pieces of signature added)

**BLSSignature** - class for common signature.

All these classes (except BLSSigShareSet) can be created from shared_ptr to string(or to vector of strings)  and converted to shared_ptr to string(or to vector of strings) with the method _toString()_.

## How to use BLS threshold signatures

1. Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t <= n).

2. Generate private keys. You may use DKG.
   For test you can use

```cpp
std::shared_ptr<std::pair<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> std::shared_ptr<BLSPublicKey> > > keys = BLSPrivateKeyShare::generateSampleKeys(t, n);
```
You will get a pair, which first component is shared_ptr to vector of private keys, and second component is shared_ptr to common public key;

3. Hash the message you want to sign. Hash should be ```std::array<uint8_t, 32> ```

4. Sign the hashed message with each private key(which is an instance of PrivateKeyShare). You will get piece of signature (shared_ptr to BLSSigShare instance)

If you need to be compatible with Ethereum

```cpp
 std::shared_ptr<BLSSigShare> sigShare_ptr = key.signWithHelper(hash_ptr, signer_index);
```
where key is an instance of BLSPrivateKeyShare, hash_ptr is shared_ptr to std::array<uint8_t, 32>, signer index is an index of a participant whose key is used to sign

If you are not using Ethereum then for each key call

```cpp
std::shared_ptr<BLSSigShare> sigShare_ptr = key.sign(hash_ptr, signer_index)
```
where key is an instance of BLSPrivateKeyShare, hash_ptr is shared_ptr to std::array<uint8_t, 32>, signer index is an index of a participant whose key is used to sign

5. Create an instance of BLSSigShareSet.
```cpp
BLSSigShareSet SigSet(t,n);
```
Add shared_ptr to pieces of signature ( BLSSigShare instances ) to BLSSigShareSet.
```cpp
SigSet.add(sigShare_ptr1);
```
If you have enough pieces you will be able to merge them and to get common signature(shared_ptr to BLSSignature instance)
```cpp
std::shared_ptr<BLSSignature> signature_ptr = SigSet.merge();
```

6. Verify common signature with common public key

If you need to be compatible with Ethereum
```cpp
 assert( publicKey.VerifySigWithHelper(hash_ptr, signature_ptr, t, n);
```

If you need not to be compatible with Ethereum
```cpp
 assert( publicKey.VerifySig(hash_ptr, signature_ptr, t, n );
```
Here is an example of BLS threshold signatures algorithm with t = 3, n = 4.

```cpp

  size_t num_all = 4;
  size_t num_signed = 3;

  std::vector<size_t> participants(num_all);
  for (size_t i = 0; i < num_signed; ++i) participants.at(i) = i + 1; //set participants indices 1,2,3

  std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> Skeys = BLSPrivateKeyShare::generateSampleKeys(
  num_signed, num_all)->first;

  std::default_random_engine rand_gen((unsigned int) time(0));
  std::array<uint8_t, 32> hash_byte_arr;
  for ( size_t i = 0; i < 32 ; i++){        //generate random hash
    hash_byte_arr.at(i) = rand_gen() % 255;
  }
  std::shared_ptr< std::array<uint8_t, 32> > hash_ptr = std::make_shared< std::array<uint8_t, 32> >(hash_byte_arr);

  BLSSigShareSet sigSet(num_signed, num_all);

  for (size_t i = 0; i < num_signed; ++i) {
    std::shared_ptr<BLSPrivateKeyShare> skey = Skeys->at(i);
    std::shared_ptr<BLSSigShare> sigShare = skey->sign(hash_ptr, participants.at(i)); // sign with private key of each participant
    sigSet.addSigShare(sigShare);
  }

  std::shared_ptr<BLSSignature> common_sig_ptr = sigSet.merge();                                                //create common signature
  BLSPrivateKey common_skey(Skeys, std::make_shared<std::vector<size_t >>(participants), num_signed,
                                          num_all);                                          //create common private key from private keys of each participant
  BLSPublicKey common_pkey(*(common_skey.getPrivateKey()), num_signed, num_all);   //create common public key from common private key
  assert(common_pkey.VerifySig(hash_ptr, common_sig_ptr, num_signed, num_all));    // verify common signature with common public key
```

## [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) for BLS threshold signatures algorithm

1. Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t <= n).

2. Each participant of DKG creates an instance of DKGBLSWrapper class with parameters t and n;
```cpp
 DKGBLSWrapper dkg_obj(t, n);
```
When created DKGBLSWrapper generates secret polynomial, but if you want you can set your own one with the method _setDKGSecret_

3. Each participant generates a vector of public shares coefficients and broadcasts it.
```cpp
std::shared_ptr < std::vector <encryption::element_wrapper>>  public_shares = dkg_obj.createDKGPublicShares();
```

4.  Each participant generates vector of secret shares coefficients. And sends to j-th participant j-th component of secret shares coefficients vector.
```cpp
 std::shared_ptr < std::vector <encryption::element_wrapper>>  private_shares = dkg_obj.createDKGSecretShares();
```

5. Each participant verifies that for data recieved other participants  secret share matches vector of public shares
```cpp
  assert(dkg_obj. VerifyDKGShare( signerIndex, secret_share, public_shares_vector));
```
where public_shares_vector is shared_ptr to vector of public shares, signerIndex is index of participant from which secret and public shares were recieved.

6. If verification passed each participant may create private key from secret shares that it recieved
```cpp
   BLSPrivateKeyShare privateKeyShare = dkg_obj.CreateBLSPrivateKeyShare(secret_shares_vector);
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
