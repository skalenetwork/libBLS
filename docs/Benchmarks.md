# Threshold Encryption

#### Test Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 15    |
| Total signers (n)    | 22    |
| Message size (bytes) | 256   |
| Runs                 | 1000   |

#### Results

| Result Metric                            | Libff (ms) | MCL (ms) | MCL Optimizations 1 & 2 (ms) | MCL prev. Opt. + Batching (ms) | MCL prev. Opt. + optimistic validation |
| ---------------------------------------- | --------- | --------- | ---------------------------  | -------------------------      | ----------------------------------- |
| Average encryption time                  | 12.75     | 3.23      | 1.92                         | 2.16                           | 2.3
| Avg. validation encryption time          | 15.52     | 2.05      | 0.86                         | 0.96                           | 1.03
| Avg. partial decryption time             | 24.93     | 4.17      | 0.76                         | 0.86                           | 0.92
| Avg. validation decryption share time    | 425.42    | 76.54     | 23.57                        | 13.02                          | 3.77
| Avg. combine shares time                 | 27.24     | 3.66      | 1.27                         | 1.09                           | 1.16
| Avg. validation combined decryption time | 4.14      | 0.89      | 0.11                         | 0.12                           | 0.13
| Avg. decryption time                     | 2.10      | 0.73      | 0.002                        | 0.002                          | 0.002
| Avg. full cycle time                     | 512.11    | 91.26     | 28.48                        | 18.19                          | 9.31


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