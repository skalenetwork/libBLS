#!/usr/bin/env bash

set -e

: "${SGX_WALLET_TAG?Need to set SGX_WALLET_TAG}"

SGX_WALLET_IMAGE_NAME=skalenetwork/sgxwallet_sim:$SGX_WALLET_TAG
SGX_WALLET_CONTAINER_NAME=sgx_simulator

docker rm -f $SGX_WALLET_CONTAINER_NAME || true
docker pull $SGX_WALLET_IMAGE_NAME

# Skip check_firewall.py which uses Tor (blocked in CI) by using custom entrypoint
docker run -d -p 1026-1031:1026-1031 --name $SGX_WALLET_CONTAINER_NAME \
  --entrypoint /bin/bash $SGX_WALLET_IMAGE_NAME \
  -c "source /opt/intel/sgxsdk/environment && cd /usr/src/sdk && ./sgxwallet -y -n"
