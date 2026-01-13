# Tests

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

# Benchmarks

### Running benchmarks

| Argument      | Description                        | Example Value | Default Value |
|---------------|------------------------------------|-------------- | ------------- |
| `--n`         | Total number of nodes              | `22`          | 5             |
| `--t`         | Required number of nodes (t<n)     | `15`          | 3             |
| `--numTxs`    | Number of transactions to process  | `1000`        | 1             |
| `--msg`       | Message size in bytes              | `1000`        | 256           |

```bash
# Override numTxs, n and t args
./build/benchmarks/bench_te -- --numTxs 1000 --n 22 --t 15
# runs with all default args
./build/benchmarks/bench_bls
```

### Adding benchmarks

1. Add new .cpp file under `./benchmarks`
2. Add it to `./benchmarks/CMakeLists.txt`
3. Edit expected input params if needed from global param list in `bench_util.hpp`

### Results

You can previous benchmark result [here](./benchmarks/main.md)

# Memory Leak Analysis

The project is also configured to allow running with address sanitizer to check for memory leaks:
```bash
cmake -H. -Bbuild -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug

cmake --build build -- -j$(nproc)
```

This sets up address sanitizer for all binaries produced (including tests, except for emscripten) + all libraries built (te, backend, bls)

External dependencies must be configured individually in the `deps/build.sh` script, by adding the following flags to the cmake command:
```bash
-DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
-DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
-DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
-DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
```
