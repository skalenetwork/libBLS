# Using Threshold Encryption

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

## Classes for Threshold Encryption

**TEPrivateKey** - class for common private key

**TEPublicKey** - class for common public key. Has method _encrypt_ to encrypt the message. (Message length should be 64) .

**TEPrivateKeyShare** - class for private key for each participant. Has method _decrypt_ to decrypt CipherText and to get a part of decrypted message.

**TEPublicKeyShare** - class for public key for each participant. Has methods _Verify_ to verify if given CipherText matches given decrypted piece of message.

**TEDecryptSet** - class for set of decrypted pieces of message. Has methods _addDecrypt_ (to add a piece of decrypted message) and _merge_ to get a decrypted message ( if enough pieces are added).

All these classes (except TEDecryptSet) can be created from shared_ptr to string(or to vector of strings)  and converted to shared_ptr to string(or to vector of strings) with the method \_toString()_.

## How to use Threshold encryption

1.  Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t &lt;= n).

2.  Generate private key for each participant. Create common public key. You may use DKG.
    For test you can use

```cpp
std::pair
<std::shared_ptr<std::vector<std::shared_ptr<TEPrivateKeyShare>>>, std::shared_ptr<TEPublicKey>> keys =
                                                             TEPrivateKeyShare::generateSampleKeys(t, n);
```

You will get a pair, which first component is shared_ptr to a vector of private keys, and second component is shared_ptr to common public key;

3.  Create public key from private key for each participant.

```cpp
TEPrivateKeyShare privateKeyShare = *keys.first->at(i);
TEPublicKeyShare publicKeyShare ( privateKeyShare, t, n);
```

where i is an index of a participant.

4.  Decrypt message with common public key. Message length should be 64.

```cpp
TEPublic publicKey = *keys.second;
encryption::Ciphertext cipher = publicKey.encrypt(message_ptr);
```

 Where message_ptr is shared_ptr to string, cipher is encrypted message.

5.  Get pieces of decrypted message with private key of each participant and cipher got in step 4. Verify every piece with public key of corresponding participant.

```cpp
encryption::element_wrapper piece = privateKey.decrypt(cipher);
assert ( publicKeyShare.Verify(cipher, piece) ) ;
```

6.  Create DecryptSet and add to it each piece of decrypted message.

```cpp
TEDecryptSet decrSet(t, n);
decrSet.addDecrypt(signerIndex, piece_ptr);
```

where piece_ptr is shared_ptr to piece, signerIndex is an index of a participant, which created this piece.

7.  If you have enough pieces you will be able to merge them and to get decrypted message.

```cpp
std::string message = decrSet.merge();
```
