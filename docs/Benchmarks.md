# Threshold Encryption

#### Test Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 15    |
| Total signers (n)    | 22    |
| Message size (bytes) | 256   |
| Runs                 | 100   |

#### Results

| Result Metric                            | Libff (ms) | MCL (ms) | MCL Optimizations 1 & 2 (ms) | MCL prev. Opt. + Batching (ms) | MCL prev. Opt. + Vectorization (ms) |
| ---------------------------------------- | --------- | --------- | ---------------------------  | -------------------------      | ----------------------------------- |
| Average encryption time                  | 12.75     | 3.23      | 2.72                         | 1.90                           | 2.07
| Avg. validation encryption time          | 15.52     | 2.05      | 1.08                         | 0.84                           | 0.92
| Avg. partial decryption time             | 24.93     | 4.17      | 3.15                         | 0.75                           | 0.82
| Avg. validation decryption share time    | 425.42    | 76.54     | 35.39                        | 11.36                          | 6.11
| Avg. combine shares time                 | 27.24     | 3.66      | 1.76                         | 1.26                           | 1.38
| Avg. validation combined decryption time | 4.14      | 0.89      | 0.16                         | 0.10                           | 0.11
| Avg. decryption time                     | 2.10      | 0.73      | 0.003                        | 0.002                          | 0.002
| Avg. full cycle time                     | 512.11    | 91.26     | 43.77                        | 16.22                          | 11.5


---

# BLS

#### Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 15     |
| Total signers (n)    | 22     |
| Runs                 | 100  |

#### Results

| Result Metric                            | Libff (ms) | MCL (ms) |
| ---------------------------------------- | --------- | --------- |
| Avg. partial signature time              | 10.4205   | 10.2508   |
| Avg. signature merge time                | 3.18792   | 1.06128   |
| Avg. adding signature share time         | 0.0801542 | 0.0868283 |
| Avg. signature verification time         | 13.7209   | 2.05368   |
| Avg. full cycle time                     | 27.4095   | 13.4526   |