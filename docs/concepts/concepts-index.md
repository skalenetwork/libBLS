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

- [Basic Threshold Encryption](./threshold-encryption/1-threshold-encryption.md)  
  Introduction to the core principles and structure of the threshold encryption scheme.

- [Threshold Encryption: Full Flow](./threshold-encryption/2-te-full-flow.md)  
  End-to-end description of the API-exposed threshold encryption process involving key generation, encryption, and decryption.

- [Client Integration Flow](./threshold-encryption/3-full-client-flow.md)  
  Explains the client-side responsibilities and flow for interacting with the threshold encryption system.

## Distributed Key Generation (DKG)

- [Distributed Key Generation Protocol](./distributed-key-generation/dkg.md)  
  Description of the collaborative key generation protocol, ensuring no single participant holds the full private key.
