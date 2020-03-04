# Using Threshold Signatures

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

## Classes for BLS threshold signatures

**BLSPrivateKeyShare** - class for private key for each participant. Has methods _sign_ and _signWithHelper_ to sign hashed message.

**BLSPrivateKey** - class for common private key

**BLSPublicKeyShare** - class for public key for each participant. Has methods _VerifySig_ and _VerifySigWithHelper_ to Verify a piece of signature.

**BLSPublicKey** - class for common public key. Has method _VerifySig_ and _VerifySigWithHelper_ for verifying common signature.

**BLSSigShare** - class for a piece of common signature.

**BLSSigShareSet** - class for a set of pieces of signature. Has methods _Add_ (to add a piece of signature) and _merge_ ( to get common signature, if enough pieces of signature added)

**BLSSignature** - class for common signature.

All these classes (except BLSSigShareSet) can be created from shared_ptr to string(or to vector of strings)  and converted to shared_ptr to string(or to vector of strings) with the method \_toString()_.

## How to use BLS threshold signatures

1.  Choose total number of participants in your group (n), give an index to each participant and choose a threshold number (t) for your case. (t &lt;= n).

2.  Generate private keys. Create common public key. You may use DKG.
    For test you can use

```cpp
std::shared_ptr<std::pair
<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>, std::shared_ptr<BLSPublicKey>>> keys =
                                                            BLSPrivateKeyShare::generateSampleKeys(t, n);
```

You will get a pair, which first component is shared_ptr to vector of private keys, and second component is shared_ptr to common public key;

3.  Hash the message you want to sign. Hash should be `std::array<uint8_t, 32> `
4.  Sign the hashed message with each private key(which is an instance of PrivateKeyShare). You will get a piece of signature (shared_ptr to BLSSigShare instance)

If you need to be compatible with Ethereum

```cpp
std::shared_ptr<BLSSigShare> sigShare_ptr = key.signWithHelper(hash_ptr, signer_index);
```

where key is an instance of BLSPrivateKeyShare, hash_ptr is shared_ptr to std::array&lt;uint8_t, 32>, signer index is an index of a participant whose key is used to sign

If you are not using Ethereum then for each key call

```cpp
std::shared_ptr<BLSSigShare> sigShare_ptr = key.sign(hash_ptr, signer_index)
```

where key is an instance of BLSPrivateKeyShare, hash_ptr is shared_ptr to std::array&lt;uint8_t, 32>, signer index is an index of a participant whose key is used to sign

5.  Create an instance of BLSSigShareSet.

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

6.  Verify common signature with common public key

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

std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> Skeys =
                                    LSPrivateKeyShare::generateSampleKeys(num_signed, num_all)->first;

std::default_random_engine rand_gen((unsigned int) time(0));
std::array<uint8_t, 32> hash_byte_arr;
for ( size_t i = 0; i < 32 ; i++){        //generate random hash
  hash_byte_arr.at(i) = rand_gen() % 255;
}
std::shared_ptr<std::array<uint8_t, 32>> hash_ptr =
                                          std::make_shared< std::array<uint8_t, 32> >(hash_byte_arr);

BLSSigShareSet sigSet(num_signed, num_all);

for (size_t i = 0; i < num_signed; ++i) {
  std::shared_ptr<BLSPrivateKeyShare> skey = Skeys->at(i);

  // sign with private key of each participant
  std::shared_ptr<BLSSigShare> sigShare = skey->sign(hash_ptr, participants.at(i));

  sigSet.addSigShare(sigShare);
}

std::shared_ptr<BLSSignature> common_sig_ptr = sigSet.merge();         //create common signature

//create common private key from private keys of each participant
BLSPrivateKey common_skey
  (Skeys, std::make_shared<std::vector<size_t>>(participants), num_signed, num_all);

//create common public key from common private key
BLSPublicKey common_pkey(*(common_skey.getPrivateKey()), num_signed, num_all);

  // verify common signature with common public key
assert(common_pkey.VerifySig(hash_ptr, common_sig_ptr, num_signed, num_all));

```
