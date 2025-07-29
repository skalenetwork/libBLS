# Threshold Encryption

Threshold encryption (TE) is a form of public key encryption in which the decryption key is distributed across multiple parties. A message can only be decrypted if a threshold number of parties collaborate. This technique ensures both **confidentiality** and **fault tolerance** in cryptographic systems, especially in distributed environments.

This document explains the **encryption** phase of the threshold encryption process, focusing on the generation of a *CipheredKey* object from a message, a public key, and a random scalar.

---

# 1. Encryption


The encryption function takes the following inputs:

- `m`: The input message (e.g., an AES key).
- `Y = x⋅P`: A public key (G2 point) where `x` is a private scalar and `P` is a known generator.
- `r`: A random scalar (ephemeral secret).

The output is a `CipheredKey` structure containing three components: `V`, `W`, and `U`.

---

## Encryption Diagram

Below is a visual representation of the encryption process:

<img src="../../diagrams/threshold-encryption.svg" alt="Diagram" style="width: 100%; max-width: 800px;" />


---

## Step-by-Step Breakdown

### 1. Compute `V`

We start by computing:

\( V = G(r ⋅ Y) ⊕ m \)

- `r ⋅ Y` produces a shared secret using the public key.
- `G(⋅)` is a key derivation function that maps a group element to a symmetric key.
- `⊕ m` is a bitwise XOR between the derived key and the plaintext message `m`.

### 2. Compute `U`

The ephemeral public component:

\( U = r ⋅ P \)


This is needed by decryptors to reconstruct the shared secret via pairing-based operations.

### 3. Compute `W`

To protect integrity or bind `V` and `U` together:

\( W = r ⋅ H(U, V) \)


Where `H(U, V)` is a hash-to-curve function that outputs a point in the G1 group. `W` is used later during the **decryption** and **verification** phase to prove consistency.

---

## Output: `CipheredKey`

The output of the encryption process is the `CipheredKey` struct, composed of the following fields:

| Field | Type     | Size (bytes) |
|-------|----------|--------------|
| `V`   | Bytes    | 32           |
| `W`   | G1 point | 64           |
| `U`   | G2 point | 128          |

This tuple forms the encrypted representation of the message `m`. Only a valid quorum of decryptors (holding key shares) will be able to recover the original message.

---

# 2. Decryption (soon)

---

# 3. Validation (soon)

---

## Next Steps

Although the threshold encryption is powerful, it is slow for large messages. So it is best to use it alongside symmetric cryptography. This allows to benefit from symmetric cryptography speed as well as threshold cryptographie's security.

This more robust process is explained in [here](./2-te-full-flow.md).

