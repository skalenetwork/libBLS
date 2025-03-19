/*
Copyright (C) 2021- SKALE Labs

This file is part of libBLS.

libBLS is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libBLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with libBLS. If not, see <https://www.gnu.org/licenses/>.

@file te_sample_sgx.cpp
@author Oleh Nikolaiev
@date 2021
*/

#include <cstdlib>

#include <jsonrpccpp/client/client.h>
#include <jsonrpccpp/client/connectors/httpclient.h>

#include <bls/bls.h>
#include <dkg/dkg.h>
#include <threshold_encryption/ThresholdEncryption.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>
#include <chrono>

#define TIMER( variable, code_block )                                                   \
    auto start_##variable = std::chrono::high_resolution_clock::now();                  \
    code_block auto end_##variable = std::chrono::high_resolution_clock::now();         \
    auto duration_##variable = std::chrono::duration_cast< std::chrono::microseconds >( \
        end_##variable - start_##variable )                                             \
                                   .count();                                            \
    variable += duration_##variable;

struct keys {
    TEPublicKey common_public;
    TEPrivateKey common_private;
    std::vector< TEPrivateKeyShare > secret_keys;
    std::vector< TEPublicKeyShare > public_keys;
};

void importBLSKeys( const std::vector< TEPrivateKeyShare >& secret_keys, const std::string& sgx_url,
    const std::string& dkg_rand_id );

keys generateKeys( size_t t, size_t n, const std::string& sgx_url, const std::string& dkg_rand_id );

std::vector< TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& key_name, const std::string& sgx_url, const size_t signerIndex );

std::pair< std::vector< std::string >, std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const TEPublicKey& common_public_key, size_t n_messages_batch );


int64_t total_time = 0;
int64_t total_time_building_request = 0;
int64_t total_time_awaiting_resp = 0;
int64_t total_time_parsing_resp = 0;

int main() {
    size_t t;
    size_t n;
    std::string sgxwallet_url;
    size_t n_messages_batch;
    size_t n_batches;

    if ( const char* env_t = std::getenv( "t" ) ) {
        t = std::stoi( env_t );
    } else {
        t = 11;
    }

    if ( const char* env_n = std::getenv( "n" ) ) {
        n = std::stoi( env_n );
    } else {
        n = 16;
    }

    if ( const char* env_url = std::getenv( "SGXWALLET_URL" ) ) {
        sgxwallet_url = std::string( env_url );
    } else {
        sgxwallet_url = "http://127.0.0.1:1029";
    }

    if ( const char* env_n_messages_batch = std::getenv( "N_MESSAGES_BATCH" ) ) {
        n_messages_batch = std::stoi( env_n_messages_batch );
    } else {
        n_messages_batch = 100;
    }

    if ( const char* env_batch_size = std::getenv( "N_BATCHES" ) ) {
        n_batches = std::stoi( env_batch_size );
    } else {
        n_batches = 1;
    }

    // generate random dkg id - have different key names for each run
    auto now = std::chrono::system_clock::now();
    auto now_ms =
        std::chrono::duration_cast< std::chrono::milliseconds >( now.time_since_epoch() ).count();
    auto dkg_rand_id = std::to_string( now_ms );

    keys keys = generateKeys( t, n, sgxwallet_url, dkg_rand_id );


    for ( size_t i = 0; i < n_batches; ++i ) {
        auto [plaintexts, ciphertexts] =
            cipherRandomMessageBatch( keys.common_public, n_messages_batch );

        std::vector< TEDecryptSet > decription_sets( n_messages_batch, TEDecryptSet( t, n ) );

        // For each node - request decryption shares for current batch
        for ( size_t node_id = 0; node_id < n; ++node_id ) {
            // node id should start from 1
            size_t actual_node_id = node_id + 1;

            std::string bls_key_name =
                "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:" + std::to_string( actual_node_id ) +
                ":DKG_ID:" + dkg_rand_id;


            std::vector< TEDecryptionShare > batched_decryption_shares =
                getDecryptionShares( ciphertexts, bls_key_name, sgxwallet_url, actual_node_id );

            // verify all shares
            for ( size_t msg = 0; msg < batched_decryption_shares.size(); ++msg ) {
                assert( ThresholdEncryption::validateDecryptionShare( ciphertexts[msg]->key,
                    batched_decryption_shares[msg], keys.public_keys[node_id] ) );

                decription_sets[msg].addDecryptShare( batched_decryption_shares[msg] );
            }
        }

        // combine shares from each individual message on the batch
        for ( size_t msg = 0; msg < n_messages_batch; ++msg ) {
            std::string decrypted_msg =
                ThresholdEncryption::combineShares( *ciphertexts[msg], decription_sets[msg] );
            ThresholdEncryption::validateCombinedDecryption(
                *ciphertexts[msg], decrypted_msg, keys.common_public );
        }
    }

    float elapsed_time = total_time / ( float ) 1'000'000;  // convert to seconds
    std::cout << "Total time: " << elapsed_time << " seconds" << std::endl;
    std::cout << "Throughput / node: " << ( n_messages_batch * n_batches * n ) / elapsed_time
              << " seconds" << std::endl;
    return 0;
}

std::pair< std::vector< std::string >, std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const TEPublicKey& common_public_key, size_t n_messages_batch ) {
    std::vector< std::string > plaintexts;
    std::vector< std::shared_ptr< libBLS::Ciphertext > > ciphertexts;

    // create the batch of messages
    for ( size_t j = 0; j < n_messages_batch; ++j ) {
        std::string plaintext;
        // build random messages of random sizes up to 800 characters
        size_t msg_length = rand() % 800;
        for ( size_t length = 0; length < msg_length; ++length ) {
            plaintext += char( rand() % 128 );
        }
        plaintexts.push_back( plaintext );

        // build corresponding ciphertexts
        auto encrypted_string = ThresholdEncryption::encrypt( plaintext, common_public_key );
        ciphertexts.push_back( encrypted_string.ciphertext );
    }
    return { std::move( plaintexts ), std::move( ciphertexts ) };
}

void importBLSKeys( const std::vector< TEPrivateKeyShare >& secret_keys, const std::string& sgx_url,
    const std::string& dkg_rand_id ) {
    jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgx_url );
    jsonrpc::Client sgxClient( *jsonRpcClient );

    for ( size_t i = 0; i < secret_keys.size(); ++i ) {
        Json::Value p;
        p["keyShare"] = secret_keys[i].toStringHex();
        p["keyShareName"] = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:" + std::to_string( i + 1 ) +
                            ":DKG_ID:" + dkg_rand_id;

        Json::Value result = sgxClient.CallMethod( "importBLSKeyShare", p );
    }

    delete jsonRpcClient;
}

keys generateKeys(
    size_t t, size_t n, const std::string& sgx_url, const std::string& dkg_rand_id ) {
    libBLS::Dkg dkg_te( t, n );

    std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();

    libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

    libff::alt_bn128_Fr common_skey = dkg_te.PolynomialValue( poly, zero_el );

    TEPrivateKey common_private( common_skey, t, n );

    TEPublicKey common_public( common_private );

    std::vector< libff::alt_bn128_Fr > skeys = dkg_te.SecretKeyContribution( poly );
    std::vector< TEPrivateKeyShare > secret_keys;
    std::vector< TEPublicKeyShare > public_keys;
    for ( size_t i = 0; i < n; i++ ) {
        secret_keys.emplace_back( TEPrivateKeyShare( skeys[i], i + 1, t, n ) );
        public_keys.emplace_back( TEPublicKeyShare( secret_keys[i] ) );
    }

    importBLSKeys( secret_keys, sgx_url, dkg_rand_id );

    return { common_public, common_private, secret_keys, public_keys };
}

std::vector< TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& key_name, const std::string& sgx_url, const size_t signerIndex ) {
    Json::Value p;
    p["blsKeyName"] = key_name;

    Json::Value batch;
    // batch.reserve( 256 * ciphertexts.size());
    for ( size_t i = 0; i < ciphertexts.size(); i++ ) {
        std::shared_ptr< libBLS::Ciphertext > ciphertext = ciphertexts[i];
        ThresholdEncryption::validateEncryption( ciphertexts[i]->key );
        batch.append( ciphertext->getPublicDecryptionValue() );
    }

    TIMER(
        total_time, p["publicDecryptionValues"] = batch;
        jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgx_url );
        jsonRpcClient->SetTimeout( 1000000 ); jsonrpc::Client sgxClient( *jsonRpcClient );

        Json::Value result = sgxClient.CallMethod( "getDecryptionShares", p );

        delete jsonRpcClient;

        std::vector< TEDecryptionShare > ret_values;

        for ( size_t i = 0; i < ciphertexts.size(); i++ ) {
            int i_int = ( int ) i;
            ret_values.push_back(
                TEDecryptionShare( signerIndex, result["decryptionShares"][i_int].asCString() ) );
        } );

    return ret_values;
}