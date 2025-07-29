# Threshold Encryption

This document explains the complete encryption flow when using threshold encryption (TE). We first explain the base idea using a single public key, and later on we introduce the use of two public keys. The approach combines symmetric encryption for performance with threshold encryption for secure key encapsulation.

> The support for two keys is necessary for certain scenarios, such as key rotation in a committee of nodes managing the TE public key. When the set of nodes responsible for threshold decryption changes, a new public key must be generated. During the rotation period, it may be required to encrypt data under both the old and new keys to maintain continuity. This approach allows ciphertexts to be decrypted by either key set, ensuring seamless transition and backward compatibility until the rotation is fully completed.

# 1. Full Encryption Flow (Single Key)

The process is designed to:

1. Encrypt the plaintext using a randomly generated AES key (symmetric encryption).
2. Securely encrypt the AES key using threshold encryption with a TE common public key.
3. Construct a ciphertext that contains both the encrypted AES key and the encrypted payload.

---

## Overview of the Process

<img src="../../diagrams/te-full-flow.svg" alt="Diagram" style="width: 100%; max-width: 1200px;" />

<br>
<br>


The diagram depicts the internal steps involved in building the ciphertext. The steps occur on the client side and assume the availability of:
- A plaintext message `T`
- A TE common public key `Y₁` (e.g., shared by a server or group of key holders)

### Inputs

- `T`: The plaintext message to be encrypted.
- `Y₁`: A public key used for threshold encryption.

---

## Encryption Steps
### 1. Generate Secrets

As a first step, two cryptographic secrets are generated:

- A **random AES key `m`**: Used for symmetric encryption of the message.
- A **random number `r`**: Used as part of the threshold encryption input to ensure semantic security.



### 2. Encrypt the Plaintext with AES

The message `T` is concatenated with the random number `r`, forming `T || r`. This is done so that, after decrypting the original key `m` through Threshold Decryption, and decrypting also `T` using `m`, we can get `r`, and use it to validate the decryption - i.e, **validate the decrypted data against the threshold encrypted key**.

This combined input is encrypted using AES in GCM mode:

\( C = GCM_m(T || r)  \)


Where:

- `m` is the randomly generated AES key
- `GCMₘ` is the AES-GCM encryption function keyed with `m`
- `C` is the resulting ciphertext, which includes authentication data

This step is performed for efficiency, as symmetric encryption is significantly faster than asymmetric alternatives.


### 3. Encrypt the AES Key with Threshold Encryption

The AES key `m` is encrypted using threshold encryption with public key `Y₁` and random number `r`:

\( K_1 = TE(m, r, Y_1) \)


Where:

- `TE` is the threshold encryption function ([explained here](./1-threshold-encryption.md))
- `Y₁` is the network's TE common public key
- `K₁` is the encrypted AES key (also referred to as a `CipheredKey`)

Threshold encryption ensures that decryption will require access to the corresponding secret share(s), depending on the system’s threshold configuration.


### 4. Construct the Final Ciphertext

The final ciphertext consists of:

- The encrypted AES key `K₁`
- The AES-encrypted message `C`

This is serialized as:

\( Ciphertext = [Keys Size] || K₁ || C \)

The diagram reflects this with the final output structure shown on the right-hand side.

#### Example Field Sizes (for 1 Key)

| Field       | Size (bytes)     |
|-------------|------------------|
| Keys Size   | 1                |
| K₁          | 224              |
| C           | Varies           |

`Keys Size` specifies the number of keys appended. Currently we support only either `1` or `2` keys. The size of `K₁` is always fixed at 224 bytes. The size of `C` depends on the length of the plaintext and the AES-GCM overhead.


# 1.2 Full Encryption Flow (Two Keys)

The flow for 2 keys is mostly the same as when using a single key. The only difference is that we now also threshold encrypt the second key, and append it to the ciphertext.

Meaning that we reuse the same  AESKey `m` as well as the random secret `r` for both Threshold Encryptions, and only change the public common key inputted to each of the processes.

This will still result in different `CipheredKey` struct outputs, which will then be concatenated, and be part of the final `Ciphertext`.

The following diagram shows the entire process uing 2 keys, and also depicts the TE process in the bottom half, for ease of reference:


<img src="../../diagrams/te-full-flow-full.svg" alt="Diagram" style="width: 100%; max-width: 1200px;" />

<br>

---

# 2. Decryption (soon)

---

# 3. Validation (soon)
