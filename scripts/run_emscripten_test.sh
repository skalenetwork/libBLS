#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Usage: ./run_emscripten_test.sh <build_dir>
BUILD_DIR=${1:-build_em}  # Default to build_em if not provided
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ABS_BUILD_DIR="$ROOT_DIR/$BUILD_DIR"

# Prepare the build directory
cp "$ROOT_DIR/tools/generate_bls_keys" "$ABS_BUILD_DIR/"
cp "$ROOT_DIR/tools/decrypt_message" "$ABS_BUILD_DIR/"
cp "$ROOT_DIR/test/test.js" "$ABS_BUILD_DIR/"
cp "$ABS_BUILD_DIR/threshold_encryption/encrypt."* "$ABS_BUILD_DIR/"
cd "$ABS_BUILD_DIR/"

# Number of times to run the test block
RUNS=50

for i in $(seq 1 $RUNS); do
    echo "=== Run $i ==="
    # Run the test block
    ./generate_bls_keys
    MESSAGE=$(cat message.txt)
    PUBLIC_BLS_KEY=$(cat bls_public_key.txt)
    node test.js $PUBLIC_BLS_KEY $MESSAGE > encrypted_data.txt
    ./decrypt_message

    # Clean up temp files generated in $ABS_BUILD_DIR/
    rm -f message.txt bls_public_key.txt encrypted_data.txt
done
