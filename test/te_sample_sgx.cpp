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

#include "utils.h"
#include <bls/bls.h>
#include <dkg/dkg.h>
#include <threshold_encryption/ThresholdEncryption.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>
#include <chrono>

void importBLSKeys( const std::vector< libBLS::TEPrivateKeyShare >& secretKeys,
    const std::string& sgxUrl, const std::string& dkgRandId );

std::vector< libBLS::TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& keyName, const std::string& sgxUrl, const size_t signerIndex,
    const size_t keyIndex = 0 );

std::pair< std::vector< std::vector< uint8_t > >,
    std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const libBLS::TEPublicKey& commonPublicKey, size_t nMessagesBatch );


int64_t totalTime = 0;

int main() {
    size_t t;
    size_t n;
    std::string sgxWalletUrl;
    size_t nMessagesBatch;
    size_t nBatches;

    if ( const char* envT = std::getenv( "t" ) ) {
        t = std::stoi( envT );
    } else {
        t = 11;
    }

    if ( const char* env_n = std::getenv( "n" ) ) {
        n = std::stoi( env_n );
    } else {
        n = 16;
    }

    if ( const char* envUrl = std::getenv( "SGXWALLET_URL" ) ) {
        sgxWalletUrl = std::string( envUrl );
    } else {
        sgxWalletUrl = "http://127.0.0.1:1029";
    }

    if ( const char* envNmessagesBatch = std::getenv( "N_MESSAGES_BATCH" ) ) {
        nMessagesBatch = std::stoi( envNmessagesBatch );
    } else {
        nMessagesBatch = 100;
    }

    if ( const char* envBatchSize = std::getenv( "N_BATCHES" ) ) {
        nBatches = std::stoi( envBatchSize );
    } else {
        nBatches = 1;
    }

    // generate random dkg id - have different key names for each run
    auto now = std::chrono::system_clock::now();
    auto now_ms =
        std::chrono::duration_cast< std::chrono::milliseconds >( now.time_since_epoch() ).count();
    auto dkgRandId = std::to_string( now_ms );

    const keys keys = generateKeys( t, n );
    importBLSKeys( keys.secretKeys, sgxWalletUrl, dkgRandId );


    for ( size_t i = 0; i < nBatches; ++i ) {
        auto [plaintexts, ciphertexts] =
            cipherRandomMessageBatch( keys.commonPublic, nMessagesBatch );

        std::vector< libBLS::TEDecryptSet > decription_sets(
            nMessagesBatch, libBLS::TEDecryptSet( t, n ) );

        // For each node - request decryption shares for current batch
        for ( size_t nodeId = 0; nodeId < n; ++nodeId ) {
            // node id should start from 1
            size_t actualNodeId = nodeId + 1;

            std::string bls_key_name =
                "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:" + std::to_string( actualNodeId ) +
                ":DKG_ID:" + dkgRandId;

            std::vector< libBLS::TEDecryptionShare > batchedDecryptionShares =
                getDecryptionShares( ciphertexts, bls_key_name, sgxWalletUrl, actualNodeId, 0 );

            // verify all shares
            for ( size_t msg = 0; msg < batchedDecryptionShares.size(); ++msg ) {
                for ( const auto& cipheredkey : ciphertexts[msg]->getKeys() ) {
                    libBLS::ThresholdEncryption::validateDecryptionShare(
                        cipheredkey, batchedDecryptionShares[msg], keys.publicKeys[nodeId] );
                }

                decription_sets[msg].addDecryptShare( batchedDecryptionShares[msg] );
            }
        }

        // combine shares from each individual message on the batch
        for ( size_t msg = 0; msg < nMessagesBatch; ++msg ) {
            for ( const auto& cipheredkey : ciphertexts[msg]->getKeys() ) {
                libBLS::AES256Key decipheredKey =
                    libBLS::ThresholdEncryption::combineShares( cipheredkey, decription_sets[msg] );
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    *ciphertexts[msg], decipheredKey, keys.commonPublic );
                std::vector< uint8_t > decipheredMsg =
                    libBLS::ThresholdEncryption::decrypt( *ciphertexts[msg], decipheredKey );

                assert( decipheredMsg == plaintexts[msg] );
            }
        }
    }

    float elapsedTime = totalTime / ( float ) 1'000'000;  // convert to seconds
    std::cout << "Total time: " << elapsedTime << " seconds" << std::endl;
    std::cout << "Throughput / node: " << ( nMessagesBatch * nBatches * n ) / elapsedTime
              << " seconds" << std::endl;
    return 0;
}

std::pair< std::vector< std::vector< uint8_t > >,
    std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const libBLS::TEPublicKey& commonPublicKey, size_t nMessagesBatch ) {
    std::vector< std::vector< uint8_t > > plaintexts;
    std::vector< std::shared_ptr< libBLS::Ciphertext > > ciphertexts;

    // create the batch of messages
    for ( size_t j = 0; j < nMessagesBatch; ++j ) {
        std::vector< uint8_t > plaintext;
        // build random messages of random sizes up to 800 characters
        size_t msgLength = rand() % 800;
        for ( size_t length = 0; length < msgLength; ++length ) {
            plaintext.push_back( rand() % 256 );
        }
        plaintexts.push_back( plaintext );

        // build corresponding ciphertexts
        auto encrypted_data = libBLS::ThresholdEncryption::encrypt( plaintext, commonPublicKey );
        ciphertexts.push_back( std::make_shared< libBLS::Ciphertext >( encrypted_data ) );
    }
    return { std::move( plaintexts ), std::move( ciphertexts ) };
}

void importBLSKeys( const std::vector< libBLS::TEPrivateKeyShare >& secretKeys,
    const std::string& sgxUrl, const std::string& dkgRandId ) {
    jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgxUrl );
    jsonrpc::Client sgxClient( *jsonRpcClient );

    for ( size_t i = 0; i < secretKeys.size(); ++i ) {
        Json::Value p;
        p["keyShare"] = secretKeys[i].toStringHex();
        p["keyShareName"] = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:" + std::to_string( i + 1 ) +
                            ":DKG_ID:" + dkgRandId;

        Json::Value result = sgxClient.CallMethod( "importBLSKeyShare", p );
    }

    delete jsonRpcClient;
}

std::vector< libBLS::TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& keyName, const std::string& sgxUrl, const size_t signerIndex,
    const size_t keyIndex ) {
    Json::Value p;
    p["blsKeyName"] = keyName;

    Json::Value batch;
    // batch.reserve( 256 * ciphertexts.size());
    for ( size_t i = 0; i < ciphertexts.size(); i++ ) {
        std::shared_ptr< libBLS::Ciphertext > ciphertext = ciphertexts[i];
        libBLS::CipheredKey cipheredKey = ciphertexts[i]->getKeys()[keyIndex];
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey );
        batch.append( cipheredKey.getDecryptionShareInput() );
    }

    TIMER(
        totalTime, p["publicDecryptionValues"] = batch;
        jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgxUrl );
        jsonRpcClient->SetTimeout( 1000000 ); jsonrpc::Client sgxClient( *jsonRpcClient );

        Json::Value result = sgxClient.CallMethod( "getDecryptionShares", p );

        delete jsonRpcClient;

        std::vector< libBLS::TEDecryptionShare > ret_values;

        for ( size_t i = 0; i < ciphertexts.size(); i++ ) {
            int i_int = ( int ) i;
            ret_values.push_back( libBLS::TEDecryptionShare(
                result["decryptionShares"][i_int].asCString(), signerIndex ) );
        } );

    return ret_values;
}
