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
cp "$ROOT_DIR/test/test2Keys.js" "$ABS_BUILD_DIR/"
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
    SECRET_KEY=$(cat secret_key.txt)
    
    # Occasionally pass AAD parameters (every 3rd run)
    if [ $((i % 3)) -eq 0 ]; then
        # Generate 20 or 32 byte hex strings for AAD
        AAD_LENGTH=$((RANDOM % 2))
        if [ $AAD_LENGTH -eq 0 ]; then
            # 20 bytes
            AAD_AES=$(openssl rand -hex 20)
            AAD_TE=$(openssl rand -hex 20)
        else
            # 32 bytes
            AAD_AES=$(openssl rand -hex 32)
            AAD_TE=$(openssl rand -hex 32)
        fi
        node test.js $PUBLIC_BLS_KEY $MESSAGE $AAD_AES $AAD_TE > encrypted_data.txt
        ENCRYPTED_DATA=$(cat encrypted_data.txt)
        ./decrypt_message "$ENCRYPTED_DATA" "$SECRET_KEY" "$MESSAGE" 0 "$AAD_AES" "$AAD_TE"
    else
        node test.js $PUBLIC_BLS_KEY $MESSAGE > encrypted_data.txt
        ENCRYPTED_DATA=$(cat encrypted_data.txt)
        ./decrypt_message "$ENCRYPTED_DATA" "$SECRET_KEY" "$MESSAGE" 0
    fi

    # Clean up temp files generated in $ABS_BUILD_DIR/
    rm -f message.txt bls_public_key.txt encrypted_data.txt

    ./generate_bls_keys
    MESSAGE=$(cat message.txt)
    FIRST_PUBLIC_BLS_KEY=$(cat bls_public_key.txt)
    FIRST_SECRET_BLS_KEY=$(cat secret_key.txt)
    ./generate_bls_keys
    SECOND_PUBLIC_BLS_KEY=$(cat bls_public_key.txt)
    SECOND_SECRET_BLS_KEY=$(cat secret_key.txt)
    
    # Randomly pick index 0 or 1
    RANDOM_INDEX=$((RANDOM % 2))
    if [ $RANDOM_INDEX -eq 0 ]; then
        SECRET_KEY_TO_USE=$FIRST_SECRET_BLS_KEY
    else
        SECRET_KEY_TO_USE=$SECOND_SECRET_BLS_KEY
    fi
    
    # Occasionally pass AAD parameters (every 3rd run)
    if [ $((i % 3)) -eq 0 ]; then
        # Generate 20 or 32 byte hex strings for AAD
        AAD_LENGTH=$((RANDOM % 2))
        if [ $AAD_LENGTH -eq 0 ]; then
            # 20 bytes
            AAD_AES=$(openssl rand -hex 20)
            AAD_TE=$(openssl rand -hex 20)
        else
            # 32 bytes
            AAD_AES=$(openssl rand -hex 32)
            AAD_TE=$(openssl rand -hex 32)
        fi
        node test2Keys.js $FIRST_PUBLIC_BLS_KEY $SECOND_PUBLIC_BLS_KEY $MESSAGE $AAD_AES $AAD_TE > encrypted_data.txt
        ENCRYPTED_DATA=$(cat encrypted_data.txt)
        ./decrypt_message "$ENCRYPTED_DATA" "$SECRET_KEY_TO_USE" "$MESSAGE" "$RANDOM_INDEX" "$AAD_AES" "$AAD_TE"
    else
        node test2Keys.js $FIRST_PUBLIC_BLS_KEY $SECOND_PUBLIC_BLS_KEY $MESSAGE > encrypted_data.txt
        ENCRYPTED_DATA=$(cat encrypted_data.txt)
        ./decrypt_message "$ENCRYPTED_DATA" "$SECRET_KEY_TO_USE" "$MESSAGE" "$RANDOM_INDEX"
    fi
done
