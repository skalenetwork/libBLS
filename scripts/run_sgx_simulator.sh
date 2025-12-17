#!/usr/bin/env bash

set -e

: "${SGX_WALLET_TAG?Need to set SGX_WALLET_TAG}"

SGX_WALLET_IMAGE_NAME=skalenetwork/sgxwallet_sim:$SGX_WALLET_TAG
SGX_WALLET_CONTAINER_NAME=sgx_simulator

docker rm -f $SGX_WALLET_CONTAINER_NAME || true
docker pull $SGX_WALLET_IMAGE_NAME

# The default entrypoint (start.sh) runs check_firewall.py before starting sgxwallet.
# check_firewall.py uses Tor to verify that sgxwallet ports aren't exposed to the internet.
# However, Tor connectivity is blocked in GitHub Actions, causing the script to hang indefinitely.
# Workaround: Use a custom entrypoint that skips check_firewall.py and starts sgxwallet directly.
docker run -d -p 1026-1031:1026-1031 --name $SGX_WALLET_CONTAINER_NAME \
  --entrypoint /bin/bash $SGX_WALLET_IMAGE_NAME \
  -c "source /opt/intel/sgxsdk/environment && cd /usr/src/sdk && ./sgxwallet -y -n"
