# Documentation Overview

This set of documents describes the core logic and workflows implemented in the system.

## Prerequisites

The reader is expected to have basic familiarity with the following concepts:

- Cyclic groups and finite fields  
- Polynomial arithmetic  
- Elliptic curve cryptography (ECC)
- Core cryptographic principles, including:
  - Symmetric and asymmetric encryption  
  - Key exchange mechanisms  

## Threshold Encryption

- [High Level Client Integration Flow](./threshold-encryption/3-full-client-flow.md)  
  Explains the client role in the full process. Includes detailes about data structures used, but provides little detail on the underlying processes. Good if you just need to know the basics.

- [Threshold Encryption: Full Flow](./threshold-encryption/2-te-full-flow.md)  
  End-to-end description of the API-exposed threshold encryption process involving key generation, encryption, and decryption. Includes all process details of all stages. Does not include details on the underlying mathematics. Good if you need to know how the entire process works, and how threshold encryption is used.

- [How Threshold Encryption Works](./threshold-encryption/1-threshold-encryption.md)  
  Introduction to the core principles and structure of the threshold encryption scheme. INcludes details on the underlying mathematics. Good if you need to know how it works under the hood.

- [Validation Optimizations](./threshold-encryption/4-optimizations.md)  
  Explains optimizations implemented to speedup validation steps.

## Distributed Key Generation (DKG)

- [Distributed Key Generation Protocol](./distributed-key-generation/dkg.md)  
  Description of the collaborative key generation protocol, ensuring no single participant holds the full private key. Includes mathematical details. Also includes communication steps. Good if you need to know either communication steps or the details.
