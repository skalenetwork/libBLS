# Run tests

```bash
./build/dkg_unit_test                           # run all dkg unit tests
./build/bls_test                                # run all bls tests
./build/bls_unit_test                           # run all bls unit tests
./build/bls_unit_test --list_content            # show all test cases
./build/bls_unit_test -t libBLS/<TestCaseName>  # run single test case
./build/threshold_encryption/dkg_te_unit_test   # run all dkg tests corresponds to the algebraic
                                                # structures used in TE algorithm
./build/threshold_encryption/te_unit_test       # run all te unit tests
./build/threshold_encryption/te_test            # run all te tests
```
