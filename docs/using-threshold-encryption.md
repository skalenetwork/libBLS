# Using Threshold Encryption

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

## Classes for Threshold Encryption

**TEPrivateKey** - Class that holds the common private key

**TEPublicKey** - Class that holds the common public key. 

**TEPrivateKeyShare** - Class that holds private key for each participant.

**TEPublicKeyShare** - Class that holds public key for each participant.

**TEDecryptionShare** - Class that holds a decryption share. Is used together with **TEDecryptSet** to combine several shares.

**TEDecryptSet** - Class that holds a set of decrypted pieces of message. Has methods _addDecryptShare_ (to add a piece of decrypted message - represented by the class **TEDecryptionShare**).

Most of the above classes (except for **TEDecryptSet**) allow building from string representation, as well as converting the object to string.

Some also allow convertion from/to byte representation.

## How to use Threshold encryption

### 1. Key Creation

1.1.  Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t &lt;= n).

1.2.  Generate private key for each participant. Create a common private key, and a common public key from the common private key. You may use DKG. 

```cpp
// common_skey is a raw libff::alt_bn128_Fr
libBLS::TEPrivateKey commonPrivate( common_skey );
libBLS::TEPublicKey commonPublic( commonPrivate );
```

1.3.  Create public key share from private key share for each participant.

```cpp
(...)
for ( size_t i = 0; i < n; i++ ) {
    // skeys is a vector of raw libff::alt_bn128_Fr types
    secretKeys.emplace_back( libBLS::TEPrivateKeyShare( skeys[i], i + 1, t, n ) );
    publicKeys.emplace_back( libBLS::TEPublicKeyShare( secretKeys[i] ) );
}
```

Where i is the index of each participant.

Please refer to `test/utils.cpp`, function `generateKeys` for an example of the process of generating all necessary keys.

### 2. Encryption / Decryption

2.1.  After having all keys generated, encrypt a message using the common public key.

```cpp
libBLS::ThresholdEncryption::encrypt(message, common_public);
```

This call returns a `Ciphertext` , which includes the ciphered *AES-256* key, as well as the ciphered data encoded in bytes.

2.2.    Each party should create a `TEDecryptSet` to be used later on to merge the received `TEDecryptionShare`.

```cpp
libBLS::TEDecryptSet decrypt_set(n, t);
```

2.3  Each party, upon receiving the ciphertext, may optionally **validate** the encryption, and then **partially decrypts it**. This last step returns a `TEDecryptionShare`.

```cpp
// Validation
try {
    libBLS::ThresholdEncryption::validateEncryption(ciphertext);
    libBLS::TEDecryptionShare share = libBLS::ThresholdEncryption::partialDecrypt(ciphertext, private_key_share);
} catch( error ) {
    ...
}
```

2.4.  Upon having a new `TEDecryptionShare`, each party should add it to their own `TEDecryptSet`

```cpp
decrypt_set.addDecryptShare(share);
```

2.5. Once enough shares have been gathered, the `DecryptSet` can be merged.

```cpp
if (decrypt_set.canMerge()) {
   libBLS::AES256Key key = libBLS::ThresholdEncryption::combineShares(ciphertext, decrypt_set);
}
```

As an optional step, the resulting key from the combined shares can also be validated:

```cpp
try {
    libBLS::ThresholdEncryption::validateCombinedDecryption(ciphertext, aes_key, common_public);
} catch( error ) {
    ...
}
```

2.6.  Finally decrypt the ciphertext using the deciphered aes 256 key

```cpp
auto data = libBLS::ThresholdEncryption::decrypt(cyphertext, aesKey);
```
