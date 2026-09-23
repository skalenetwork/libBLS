# Using Threshold Encryption

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

## Classes for Threshold Encryption

**TEPrivateKey** - Class that holds a common private key for a centralized setup. In a DKG
setup, participants keep their individual `TEPrivateKeyShare`; the common secret is not
reconstructed.

**TEPublicKey** - Class that holds the common public key. 

**TEPrivateKeyShare** - Class that holds private key for each participant.

**TEPublicKeyShare** - Class that holds public key for each participant.

**TEDecryptionShare** - Class that holds a decryption share. Is used together with **TEDecryptSet** to combine several shares.

**TEDecryptSet** - Class that collects validated **TEDecryptionShare** values. Its
`addValidatedDecryptShare` method adds a share that the caller has already validated.

Most of the above classes (except for **TEDecryptSet**) allow building from string representation, as well as converting the object to string.

Some also allow conversion to and from byte representations.

## How to use Threshold encryption

### 1. Key Creation

1.1. Choose a total of `n` participants, assign each participant a unique **1-based index** (`1 <= index <= n`), and choose a threshold `t` such that `1 <= t <= n`. Note: index `0` is invalid in libBLS threshold schemes and will be rejected.

1.2.  For a distributed setup, use DKG to create one `TEPrivateKeyShare` per participant and a
common `TEPublicKey`. Each participant keeps its private share. DKG does not require participants to
reconstruct a common private key. See the [distributed key generation guide](using-distributed-key-generation.md)
for the share-generation and verification flow. The guide covers the library-side calculations;
communication between participants is application-specific.

1.3.  Each participant can derive its `TEPublicKeyShare` from its private share:

```cpp
libBLS::TEPublicKeyShare public_key_share( private_key_share );
```

For test setups that need a complete sample key set, see `generateKeys` in `test/utils.cpp`.

### 2. Encryption / Decryption

2.1.  After having all keys generated, encrypt a message using the common public key. You can optionally supply associated data (AAD) for both threshold encryption and AES-GCM via `EncryptMetaData`.

```cpp
// message is a std::vector<uint8_t>; common_public is a TEPublicKey.
libBLS::EncryptMetaData metaData;
// Optional TE AAD: verified during validateEncryption and share validation
// metaData.associatedDataTE = std::vector<uint8_t>{ ... };
// Optional AES-GCM AAD: authenticated during AES decryption
// metaData.associatedDataAesGcm = std::vector<uint8_t>{ ... };

libBLS::Ciphertext ciphertext =
    libBLS::ThresholdEncryption::encrypt( message, common_public, metaData );
```

This call returns a `Ciphertext`, which includes the ciphered *AES-256* key (`ciphertext.keys`) as well as the authenticated payload bytes (`ciphertext.data`). If encrypting for multiple recipient public keys, pass a `std::vector<libBLS::TEPublicKey>` to generate one `CipheredKey` per recipient.

2.2.    Each party creates a `TEDecryptSet` to collect and combine received `TEDecryptionShare` values.

```cpp
libBLS::TEDecryptSet decrypt_set( t, n );
```

2.3. Before producing a decryption share, validate the received ciphered key. Then partially decrypt it using your private key share to produce a `TEDecryptionShare`.

```cpp
const libBLS::CipheredKey& ciphered_key = ciphertext.keys.at( 0 );
const std::vector<uint8_t>* aad_te_ptr =
    metaData.associatedDataTE ? &metaData.associatedDataTE.value() : nullptr;

// Validates proof elements (U, V, W) in the ciphered key
libBLS::ThresholdEncryption::validateEncryption( ciphered_key, aad_te_ptr );

libBLS::TEDecryptionShare share =
    libBLS::ThresholdEncryption::partialDecrypt( ciphered_key, private_key_share );
```

2.4.  Before adding a received `TEDecryptionShare`, validate it against the
corresponding ciphertext, the sender's public-key share, and any TE AAD. For multiple shares, use
`validateDecryptionSharesBatch` (or the parallel variant) and retain only entries
whose result is `true`. `TEDecryptSet` assumes that shares added to it have already
passed this cryptographic validation.

```cpp
libBLS::ThresholdEncryption::validateDecryptionShare(
    ciphered_key, share, public_key_share, aad_te_ptr );
decrypt_set.addValidatedDecryptShare( share );
```

`validateDecryptionShare` throws if the share is invalid. Add it only if validation succeeds.

2.5. Check that enough shares have been collected (at least `t`), then combine them to recover the AES-256 key:

```cpp
if ( decrypt_set.canMerge() ) {
    libBLS::AES256Key aes_key =
        libBLS::ThresholdEncryption::combineValidatedShares( ciphered_key, decrypt_set );
}
```

2.6. Decrypt the payload using the recovered AES-256 key:

```cpp
const auto& aad_aes = metaData.associatedDataAesGcm;
std::vector<uint8_t> data =
    libBLS::ThresholdEncryption::decrypt( ciphertext, aes_key, aad_aes );
```

#### Recommended: Combined Validation and Decryption in One Step

In production systems, calling `validateCombinedDecryption` and `decrypt` in sequence causes the AES payload to be deciphered twice. Use `validateAndDecrypt` to perform verification and payload decryption in a single, more performant pass:

```cpp
try {
    std::vector<uint8_t> data = libBLS::ThresholdEncryption::validateAndDecrypt(
        ciphertext, aes_key, common_public, metaData.associatedDataAesGcm );
} catch ( const std::exception& e ) {
    // Handle corrupted ciphertext, key tampering, or validation failure
}
```

### 3. Serialization and Network Transfer

Classes can be converted to and from bytes or strings for RPC and wire transport:

```cpp
// Serializing Ciphertext
std::vector<uint8_t> wire_bytes = ciphertext.toBytes();
libBLS::Ciphertext restored_ct = libBLS::Ciphertext::fromBytes( wire_bytes );

// Serializing TEDecryptionShare
std::string share_hex = share.toString();
size_t signer_index = share.getSignerIndex();
libBLS::TEDecryptionShare restored_share( share_hex, signer_index );
```

### 4. High-Performance Batch APIs

Threshold operations (pairing checks and Lagrange interpolation) are computationally intensive. For high-throughput services and consensus nodes, libBLS provides batch and parallel APIs:

- **Key Validation:** `validateEncryptionBatch` and `validateEncryptionBatchParallel`
- **Share Verification:** `validateDecryptionSharesBatch` and `validateDecryptionSharesBatchParallel`
- **Reconstruction:** `combineValidatedSharesBatch` and `combineValidatedSharesBatchParallel`
- **Decryption Validation:** `validateCombinedDecryptionBatch` and `validateCombinedDecryptionBatchParallel`
