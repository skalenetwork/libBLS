## Tests

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

## Benchmarks

### Running benchmarks

```bash
# You can pass args to the bench
./build/benchmarks/te_bench -- --rounds 1000
```

### Adding benchmarks

1. Add new .cpp file under `./benchmarks`
2. Add it to `./benchmarks/CMakeLists.txt`
3. Edit expected input params if needed from global param list in `bench_util.hpp`

### Results

You can previous benchmark result [here](./benchmarks/main.md)

