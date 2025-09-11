# Threshold Encryption

#### Test Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 15    |
| Total signers (n)    | 22    |
| Message size (bytes) | 256   |
| Runs                 | 1000   |

#### Results

| Result Metric                            | Libff (ms) | MCL (ms) | MCL - batches (ms)      | 
| ---------------------------------------- | --------- | --------- | ----------------------- |
| Average encryption time                  | 13.82     | 3.08      | 2.3                     |
| Avg. validation encryption time          | 13.92     | 1.95      | 1.03                    |
| Avg. partial decryption time             | 22.10     | 3.95      | 0.92                    |
| Avg. validation decryption share time    | 443.07    | 66.68     | 3.77                    |
| Avg. combine shares time                 | 29.41     | 3.46      | 1.16                    |
| Avg. validation combined decryption time | 4.52      | 0.83      | 0.13                    |
| Avg. decryption time                     | 2.33      | 0.69      | 0.002                   |
| Avg. full cycle time                     | 529.18    | 80.63     | 9.31                    |

- Full cycle speedup: **56.8x**
- All but encryption speedup: **73.5x**
- Decryption share validation speedup: **117.5x**

| Result Metric  (1k Txns)                  | MCL - batches (seconds) | 
| ----------------------------------------  | ----------------------- |
| Total encryption time                     | 2.1                     |
| Total validation encryption time          | 0.97                    |
| Total partial decryption time             | 0.47                    |
| Total validation decryption share time    | 2.1                     |
| Total combine shares time                 | 0.69                    |
| Total validation combined decryption time | 0.11                    |
| Total decryption time                     | 0.004                   |
| Total full cycle time                     | 6.5                     |

- Libff would have taken 529 seconds.
- MCL takes 6.7

- Full cycle speedup: **79x**
- All but encryption speedup: **112x**
- Decryption share validation speedup: **210x**

---

# BLS

#### Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 15    |
| Total signers (n)    | 22    |
| Runs                 | 100   |

#### Results

| Result Metric                            | Libff (ms) | MCL (ms) |
| ---------------------------------------- | --------- | --------- |
| Avg. partial signature time              | 10.4205   | 10.2508   |
| Avg. signature merge time                | 3.18792   | 1.06128   |
| Avg. adding signature share time         | 0.0801542 | 0.0868283 |
| Avg. signature verification time         | 13.7209   | 2.05368   |
| Avg. full cycle time                     | 27.4095   | 13.4526   |