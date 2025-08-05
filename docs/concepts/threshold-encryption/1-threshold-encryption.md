# Threshold Encryption

Threshold encryption (TE) is a form of public key encryption in which the decryption key is distributed across multiple parties. A message can only be decrypted if a threshold number of parties collaborate. This technique ensures both **confidentiality** and **fault tolerance** in cryptographic systems, especially in distributed environments.

This document starts by explaining the **encryption** phase of the threshold encryption process, focusing on the generation of a `CipheredKey` object from a message, a public key, and a random scalar.

Then we explain the **decryption** process in order to retrieve the original plaintext.

Finally we explain how **validation** happens in the different stages of the encryption-decryption process such that any node can validate the correctness of the data it is using for the threshold encryption process.

> **Note:** This process assumes the [DKG](../distributed-key-generation/dkg.md) procedure was already executed, and each node is already in posession of its `PrivateKeyShare` as well as its `PublicKeyShare`.

---

# 1. Encryption

Below is a visual representation of the generic encryption process, which will be used as reference in the `step-by-step breakdown` section:

<img src="../../diagrams/threshold-encryption.svg" alt="Diagram" style="width: 100%; max-width: 800px;" />

<br>

The process takes `3` inputs:
- `m` - Plaintext message. Must be exactly `32` bytes. For our use case, this message will be an `AES256` key, which is exactly `32` bytes. We explain why we use an `AES256` key in [te-full-flow.md](./2-te-full-flow.md).
- `Y = x⋅P` - A public key (G2 point), generated from the respective private key share `x`, where `P` is a known generator.
- `r`: A random scalar (ephemeral secret).

And it generates a single output - A `CipheredKey` struct that is always `224` bytes long, and includes `V`, `W` and `U` fields.

---

## Step-by-Step Breakdown

### 1. Compute `V`

We start by computing:

```
V = G(r ⋅ Y) ⊕ m
```

- `r ⋅ Y` is a scalar multiplication over the elliptic curve, producing a secret point using the common public key `Y` and the secret scalar `r`.
- `G(⋅)` is a cryptographic hash function that maps the elliptic curve point to a fixed-length byte array.
- `⊕ m` denotes a bitwise XOR between the derived key and the plaintext message `m`.

The result `V` is 32 bytes and constitutes the encrypted (masked) version of the key. `V` can only be computed or reversed if the scalar `r` is known. Without knowledge of `r`, no party can recover `m` from `V`.

The security of this construction relies on two cryptographic hardness assumptions:
1. **One-wayness of hash functions**: Given `A = G(x)`, it is computationally infeasible to recover `x` from `A`.
2. **Elliptic Curve Discrete Logarithm Problem (ECDLP)**: Given a point `A = r ⋅ Y` and the public key `Y`, it is computationally infeasible to determine the scalar `r`.

These properties ensure that even if an adversary knows `V` and `Y`, they cannot recover the plaintext `m` without the original random scalar `r`.

### 2. Compute `U`

The ephemeral public component derived from the random scalar:

```
U = r ⋅ P
```

The value `U` is essential for enabling decryption: it is used by decrypting nodes to reconstruct the shared secret via pairing-based operations. This mechanism allows the sender to transmit a masked message without revealing `r`, while still enabling the authorized parties to recover it collaboratively.

### 3. Compute `W`

A binding value used for integrity verification:

```
W = r ⋅ H(U, V)
```

Here, `H(U, V)` is a hash-to-curve function that maps the tuple `(U, V)` to a point in the elliptic curve group. The resulting `W` value acts as a cryptographic commitment, binding together the ephemeral component `U` and the encrypted key `V`.

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

# 2. Decryption

The main goal of the decryption process is to **discover the secret used to encrypt the original plaintext** - `r * Y`. If we discover this value, we can run `G( r * Y)` and `xor` it aganinst the ciphertext to recover the original plaintext.
 
The following diagram (**Diagram 2**) shows the communication process to be able to decipher the ciphertext, used as reference for the following 2 subsections:

<img src="../../diagrams/te-decryption.svg" alt="Diagram" style="width: 100%; max-width: 1200px;" />

This section will focus on the **Deciphering** part of the diagram. The ciphering part is already explained in the previous section.

## 2.1 Computing Decryption Shares

Each node uses its private key share to compute a **partial decryption share** (`DecryptShare` in the diagram) from the ciphertext. This share is then broadcast into the network such that each node eventually gets enough shares from all other nodes, so that they can be merged into the original plaintext.
The share computation is shown in detail in the diagram below:

<img src="../../diagrams/decrypt-share-computation.svg" alt="Diagram" style="width: 100%; max-width: 1200px;" />

The process uses 2 inputs:
- `U` field from `Ciphertext`
- `s` - Private key share. 

Each node computes:
```
D = s ⋅ U
```

And broadcasts this value to all other nodes.
Recall that `U = r ⋅ P`. Thus `D = s ⋅ U = s⋅(r⋅P) = r⋅(s⋅P) = r⋅Y`

## 2.2 Merging Decryption Shares

Each node waits to receive a supermajority (t >= 2/3) of `DecryptShares` from other nodes. Once enough shares were received, each node merges them. The merging process is shown below:

<img src="../../diagrams/merge-shares.svg" alt="Diagram" style="width: 100%; max-width: 1200px;" />

---

# 3. Validation (soon)

---

## Next Steps

Although the threshold encryption is powerful, it is slow for large messages. So it is best to use it alongside symmetric cryptography. This allows to benefit from symmetric cryptography speed as well as threshold cryptographie's security.

This more robust process is explained in [here](./2-te-full-flow.md).

