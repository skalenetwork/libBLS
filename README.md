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

```cpp
#include <libBLS.h>
```

### Run tests

```bash
./build/dkg_unit_test                           # run all dkg unit tests
./build/bls_test                                # run all bls tests
./build/bls_unit_test                           # run all bls unit tests
./build/bls_unit_test --list_content            # show all test cases
./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case
./build/threshold_encryption/dkg_te_unit_test   # run all dkg tests corresponds to the algebraic structures used in TE algroithm
./build/threshold_encryption/te_unit_test       # run all te unit tests
./build/threshold_encryption/te_test            # run all te tests
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

2. Generate private keys. Create common public key. You may use DKG.
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

## Classes for Threshold Encryption

**TEPrivateKey** - class for common private key

**TEPublicKey** - class for common public key. Has method _encrypt_ to encrypt message. (Message length should be 64) .

*TEPrivateKeyShare** - class for private key for each participant. Has method _decrypt_ to decrypt CipherText and to get part of decrypted message.

**TEPublicKeyShare** - class for public key for each participant. Has methods _Verify_ to verify if given CipherText matches given dectypted piece of message.

**TEDecryptSet** - class for set of decrypted pieces of message. Has methods _addDecrypt_ (to add a piece of decrypted message) and _merge_ to get decrypted message ( if enough pieces are added).

All these classes (except TEDecryptSet) can be created from shared_ptr to string(or to vector of strings)  and converted to shared_ptr to string(or to vector of strings) with the method _toString()_.

## How to use  Threshold encryption

1. Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t <= n).

2. Generate private key for each participant. Create common public key. You may use DKG.
For test you can use

```cpp
std::pair<std::shared_ptr<std::vector<std::shared_ptr<TEPrivateKeyShare>>>, std::shared_ptr<TEPublicKey>> keys =TEPrivateKeyShare::generateSampleKeys(t, n);
```
You will get a pair, which first component is shared_ptr to vector of private keys, and second component is shared_ptr to common public key;

3. Create public key from private key for each participant.
```cpp
 TEPrivateKeyShare privateKeyShare = *keys.first->at(i);
 TEPublicKeyShare publicKeyShare ( privateKeyShare, t, n);
```
where i is index of participant.

 ```
4. Decrypt message with common public key. Message length should be 64.
 ```cpp
 TEPublic publicKey = *keys.second;
 encryption::Ciphertext cipher = publicKey.encrypt(message_ptr);
```
 Where message_ptr is shared_ptr to string, cipher is encrypted message.

5. Get pieces of decrypted message with private key of each participant and cipher got in step 4. Verify every piece with public key of corresponding participant.
 ```cpp
  encryption::element_wrapper piece = privateKey.decrypt(cipher);
  assert ( publicKeyShare.Verify(cipher, piece) ) ;
  ```
6. Create DecryptSet and add to it each piece of decrypted message.
 ```cpp
   TEDecryptSet decrSet(t, n);
   decrSet.addDecrypt(signerIndex, piece_ptr);
```
where piece_ptr is shared_ptr to piece, signerIndex is an index of a participant, which created this piece.

7. If you have enough pieces you will be able to merge them and to get decrypted message.
```cpp
std::string message = decrSet.merge();
```

## [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) algorithm for BLS threshold signatures  and Threshols Encryption

1. Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t <= n).

2. Each participant of DKG creates an instance of dkg class with parameters t and n;
For BLS
```cpp
 DKGBLSWrapper dkg_obj(t, n);
```
For TE
```cpp
 DKGTEWrapper dkg_obj(t, n);
```
When created dkg_obj generates secret polynomial, but if you want you can set your own one with the method _setDKGSecret_

3. Each participant generates a vector of public shares coefficients and broadcasts it.

For BLS
```cpp
std::shared_ptr < std::vector <libff::alt_bn128_G2>>  public_shares = dkg_obj.createDKGPublicShares();
```
For TE
```cpp
std::shared_ptr < std::vector <encryption::element_wrapper>>  public_shares = dkg_obj.createDKGPublicShares();
```

4.  Each participant generates vector of secret shares coefficients. And sends to j-th participant j-th component of secret shares coefficients vector. ( j = 1 .. n and not equal to current participant index).

For BLS
```cpp
 std::shared_ptr < std::vector <libff::alt_bn128_Fr>>  private_shares = dkg_obj.createDKGSecretShares();
```
For TE
```cpp
 std::shared_ptr < std::vector <encryption::element_wrapper>>  private_shares = dkg_obj.createDKGSecretShares();
```

5. Each participant verifies that for data recieved other participants  secret share matches vector of public shares
```cpp
  assert(dkg_obj. VerifyDKGShare( signerIndex, secret_share, public_shares_vector));
```
where public_shares_vector is shared_ptr to vector of public shares, signerIndex is index of participant from which secret and public shares were recieved.

6. If verification passed each participant may create private key from secret shares that it recieved

For BLS
```cpp
   BLSPrivateKeyShare privateKeyShare = dkg_obj.CreateBLSPrivateKeyShare(secret_shares_vector);
```
For TE
```cpp
   TEPrivateKeyShare privateKeyShare = dkg_obj.CreateTEPrivateKeyShare(secret_shares_vector);
```
Also in DKGTEWrapper there is a static function that creates common public key
```cpp
   TEPublicKey publicKey = DKGTEWrapper::CreateTEPublicKey( public_shares_all, t, n);
```
where public_shares_all is shared_ptr to matrix of all public shares ( its type is std::shared_ptr<std::vector<std::vector<encryption::element_wrapper>>>).

Here is an example of Threshold Encryption algorythm with DKG simulation for t = 3, n =4
```cpp
        size_t num_signed = 3;
        size_t num_all = 4;
        std::vector<std::vector<encryption::element_wrapper>> secret_shares_all; // matrix of all secret shares
        std::vector<std::vector<encryption::element_wrapper>> public_shares_all; //// matrix of all public shares
        std::vector<DKGTEWrapper> dkgs; // instances of DKGTEWrapper for each participant
        std::vector<TEPrivateKeyShare> skeys; // private keys of participants
        std::vector<TEPublicKeyShare> pkeys;  // public keys of participants

        for (size_t i = 0; i < num_all; i++) {
          DKGTEWrapper dkg_wrap(num_signed, num_all);
          dkgs.push_back(dkg_wrap);
          std::shared_ptr<std::vector<encryption::element_wrapper>> secret_shares_ptr = dkg_wrap.createDKGSecretShares(); // create secret shares for each participant
          std::shared_ptr<std::vector<encryption::element_wrapper>> public_shares_ptr = dkg_wrap.createDKGPublicShares(); // create pulic shares for each participant
          secret_shares_all.push_back(*secret_shares_ptr);
          public_shares_all.push_back(*public_shares_ptr);
        }


        for (size_t i = 0; i < num_all; i++)      // Verifying shares for each participant
          for (size_t j = 0; j < num_all; j++) {
            BOOST_REQUIRE(dkgs.at(i).VerifyDKGShare(j, secret_shares_all.at(i).at(j),
                    std::make_shared<std::vector<encryption::element_wrapper>>( public_shares_all.at(i))));
          }

        std::vector<std::vector<encryption::element_wrapper>> secret_key_shares;

        for (size_t i = 0; i < num_all; i++) {          // collect got secret shares in a vector
          std::vector<encryption::element_wrapper> secret_key_contribution;
          for (size_t j = 0; j < num_all; j++) {
            secret_key_contribution.push_back(secret_shares_all.at(j).at(i));
          }
          secret_key_shares.push_back(secret_key_contribution);
        }

        for (size_t i = 0; i < num_all; i++) {
          TEPrivateKeyShare pkey_share = dkgs.at(i).CreateTEPrivateKeyShare(i + 1,
                                                                            std::make_shared<std::vector<encryption::element_wrapper>>(
                                                                                    secret_key_shares.at(i)));
          skeys.push_back(pkey_share);
          pkeys.push_back(TEPublicKeyShare(pkey_share, num_signed, num_all));
        }

        TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(std::make_shared< std::vector<std::vector<encryption::element_wrapper>>>(public_shares_all), num_signed, num_all);

        std::string message;    // Generating random message
        size_t msg_length = 64;
        for (size_t length = 0; length < msg_length; ++length) {
          message += char(rand_gen() % 128);
        }

        std::shared_ptr msg_ptr = std::make_shared<std::string>(message);
        encryption::Ciphertext cypher = common_public.encrypt(msg_ptr);

        size_t ind4del = rand_gen() % secret_shares_all.size(); // removing 1 random participant ( because only 3 of 4 will participate)
        auto pos4del = secret_shares_all.begin();
        advance(pos4del, ind4del);
        secret_shares_all.erase(pos4del);
        auto pos2 = public_shares_all.begin();
        advance(pos2, ind4del);
        public_shares_all.erase(pos2);

        TEDecryptSet decr_set(num_signed, num_all);
        for (size_t i = 0; i < num_signed; i++) {
          encryption::element_wrapper decrypt = skeys.at(i).decrypt(cypher);
          assert(pkeys.at(i).Verify(cypher, decrypt.el_));
          std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
          decr_set.addDecrypt(skeys.at(i).getSignerIndex(), decr_ptr);
        }

        std::string message_decrypted = decr_set.merge(cypher);
      }
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
