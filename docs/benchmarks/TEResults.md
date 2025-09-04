# Test Inputs

| Input Parameter      | Value |
| -------------------- | ----- |
| Required signers (t) | 3     |
| Total signers (n)    | 5     |
| Message size (bytes) | 256   |
| Runs                 | 1000  |

# LIBFF

| Result Metric                            | Time (ms) |
| ---------------------------------------- | --------- |
| Average encryption time                  | 15.8389   |
| Avg. validation encryption time          | 16.0224   |
| Avg. partial decryption time             | 25.5238   |
| Avg. validation decryption share time    | 101.87    |
| Avg. combine shares time                 | 18.4758   |
| Avg. validation combined decryption time | 5.19379   |
| Avg. decryption time                     | 2.69803   |
| Avg. full cycle time                     | 185.662   |

# MCL

| Result Metric                            | Time (ms) |
| ---------------------------------------- | --------- |
| Average encryption time                  | 3.21066   |
| Avg. validation encryption time          | 2.05783   |
| Avg. partial decryption time             | 4.1533    |
| Avg. validation decryption share time    | 14.021    |
| Avg. combine shares time                 | 2.20417   |
| Avg. validation combined decryption time | 0.858861  |
| Avg. decryption time                     | 0.729269  |
| Avg. full cycle time                     | 27.2351   |