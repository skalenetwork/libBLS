#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_DIR="$(dirname "$DIR")"
WORK_DIR="$PROJECT_DIR"/build
echo "$WORK_DIR"
cd "$WORK_DIR"

DATA_FILE=data.txt
SIGNATURE_FILE=signature.txt
RANDOM_HASH_STR="9ebe2b024baa072bb02f1df851a88900"

calculate_hash() {
    HASH_FILE=hash.json
    touch "$HASH_FILE"
    JSON_STRING=$( jq -n \
                  --arg msg "$RANDOM_HASH_STR" \
                  '{message: $msg}' )
    echo "$JSON_STRING" > "$HASH_FILE"
    ./hash_g1 --t 11 --n 16
}

run_tools_test_with_individual_keys() {
    individual_dkg_keys="./dkg_glue --t 11 --n 16"
    for i in {0..15}
    do
        individual_dkg_keys=""$individual_dkg_keys" --input data_for_"$i"-th_participant.json"
        ./dkg_keygen --t 11 --n 16 --j "$i"
    done
    echo "Generated individual dkg keys"
    $individual_dkg_keys
    echo "Generated individual bls keys"
    
    calculate_hash
    echo "Calculated hash"

    touch "$DATA_FILE"
    echo "$RANDOM_HASH_STR" > "$DATA_FILE"

    for i in {0..15}
    do
        SIGNATURE="signature"$i".json"
        ./sign_bls --t 11 --n 16 --j "$i" --key "BLS_keys" --input "$DATA_FILE" --output "$SIGNATURE"
        ./verify_bls --t 11 --n 16 --j "$i" --input "$SIGNATURE"
    done
    echo "Completed individual signatures and verified them"
    
    individual_signatures="./bls_glue --t 11 --n 16 "
    for i in {0..10}
    do
        SIGNATURE="signature"$i".json"
        individual_signatures="$individual_signatures --input $SIGNATURE"
    done
    $individual_signatures --output "$SIGNATURE_FILE"
    echo "Generated common bls signature"
    
    ./verify_bls --t 11 --n 16 --input "$SIGNATURE_FILE"
    echo "Verified common bls signature"
}

run_tools_test_with_common_keys() {
    ./dkg_keygen --t 11 --n 16
    echo "Generated individual bls keys"
    
    calculate_hash
    echo "Calculated hash"

    touch "$DATA_FILE"
    echo "$RANDOM_HASH_STR" > "$DATA_FILE"

    ./sign_bls --t 11 --n 16 --key BLS_keys --input "$DATA_FILE" --output "$SIGNATURE_FILE"
    echo "Generated common bls signature"

    ./verify_bls --t 11 --n 16 --input "$SIGNATURE_FILE"
    echo "Verified common bls signature"

    ./generate_key_system --t 11 --n 16 --output output.json
}

clean() {
    rm data_for_*
    rm BLS_keys*
    rm hash.json g1.json
    rm common_public_key.json
    rm signature*.json
    rm "$SIGNATURE_FILE" "$DATA_FILE"
}

run_tools_test_with_individual_keys

clean

run_tools_test_with_common_keys
