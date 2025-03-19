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
    TEPublicKey commonPublic;
    TEPrivateKey commonPrivate;
    std::vector< TEPrivateKeyShare > secretKeys;
    std::vector< TEPublicKeyShare > publicKeys;
};

void importBLSKeys( const std::vector< TEPrivateKeyShare >& secretKeys, const std::string& sgxUrl,
    const std::string& dkgRandId );

keys generateKeys( size_t t, size_t n, const std::string& sgxUrl, const std::string& dkgRandId );

std::vector< TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& keyName, const std::string& sgxUrl, const size_t signerIndex );

std::pair< std::vector< std::string >, std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const TEPublicKey& commonPublicKey, size_t nMessagesBatch );


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

    if ( const char* envUrl = std::getenv( "sgxWalletUrl" ) ) {
        sgxWalletUrl = std::string( envUrl );
    } else {
        sgxWalletUrl = "http://127.0.0.1:1029";
    }

    if ( const char* envNmessagesBatch = std::getenv( "nMessagesBatch" ) ) {
        nMessagesBatch = std::stoi( envNmessagesBatch );
    } else {
        nMessagesBatch = 100;
    }

    if ( const char* envBatchSize = std::getenv( "nBatches" ) ) {
        nBatches = std::stoi( envBatchSize );
    } else {
        nBatches = 1;
    }

    // generate random dkg id - have different key names for each run
    auto now = std::chrono::system_clock::now();
    auto now_ms =
        std::chrono::duration_cast< std::chrono::milliseconds >( now.time_since_epoch() ).count();
    auto dkgRandId = std::to_string( now_ms );

    keys keys = generateKeys( t, n, sgxWalletUrl, dkgRandId );


    for ( size_t i = 0; i < nBatches; ++i ) {
        auto [plaintexts, ciphertexts] =
            cipherRandomMessageBatch( keys.commonPublic, nMessagesBatch );

        std::vector< TEDecryptSet > decription_sets( nMessagesBatch, TEDecryptSet( t, n ) );

        // For each node - request decryption shares for current batch
        for ( size_t nodeId = 0; nodeId < n; ++nodeId ) {
            // node id should start from 1
            size_t actualNodeId = nodeId + 1;

            std::string bls_key_name =
                "BLS_KEY:SCHAIN_ID:123456789:nodeId:" + std::to_string( actualNodeId ) +
                ":DKG_ID:" + dkgRandId;


            std::vector< TEDecryptionShare > batchedDecryptionShares =
                getDecryptionShares( ciphertexts, bls_key_name, sgxWalletUrl, actualNodeId );

            // verify all shares
            for ( size_t msg = 0; msg < batchedDecryptionShares.size(); ++msg ) {
                assert( ThresholdEncryption::validateDecryptionShare( ciphertexts[msg]->key,
                    batchedDecryptionShares[msg], keys.publicKeys[nodeId] ) );

                decription_sets[msg].addDecryptShare( batchedDecryptionShares[msg] );
            }
        }

        // combine shares from each individual message on the batch
        for ( size_t msg = 0; msg < nMessagesBatch; ++msg ) {
            std::string decrypted_msg =
                ThresholdEncryption::combineShares( *ciphertexts[msg], decription_sets[msg] );
            ThresholdEncryption::validateCombinedDecryption(
                *ciphertexts[msg], decrypted_msg, keys.commonPublic );
        }
    }

    float elapsedTime = totalTime / ( float ) 1'000'000;  // convert to seconds
    std::cout << "Total time: " << elapsedTime << " seconds" << std::endl;
    std::cout << "Throughput / node: " << ( nMessagesBatch * nBatches * n ) / elapsedTime
              << " seconds" << std::endl;
    return 0;
}

std::pair< std::vector< std::string >, std::vector< std::shared_ptr< libBLS::Ciphertext > > >
cipherRandomMessageBatch( const TEPublicKey& commonPublicKey, size_t nMessagesBatch ) {
    std::vector< std::string > plaintexts;
    std::vector< std::shared_ptr< libBLS::Ciphertext > > ciphertexts;

    // create the batch of messages
    for ( size_t j = 0; j < nMessagesBatch; ++j ) {
        std::string plaintext;
        // build random messages of random sizes up to 800 characters
        size_t msgLength = rand() % 800;
        for ( size_t length = 0; length < msgLength; ++length ) {
            plaintext += char( rand() % 128 );
        }
        plaintexts.push_back( plaintext );

        // build corresponding ciphertexts
        auto encrypted_string = ThresholdEncryption::encrypt( plaintext, commonPublicKey );
        ciphertexts.push_back( encrypted_string.ciphertext );
    }
    return { std::move( plaintexts ), std::move( ciphertexts ) };
}

void importBLSKeys( const std::vector< TEPrivateKeyShare >& secretKeys, const std::string& sgxUrl,
    const std::string& dkgRandId ) {
    jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgxUrl );
    jsonrpc::Client sgxClient( *jsonRpcClient );

    for ( size_t i = 0; i < secretKeys.size(); ++i ) {
        Json::Value p;
        p["keyShare"] = secretKeys[i].toStringHex();
        p["keyShareName"] = "BLS_KEY:SCHAIN_ID:123456789:nodeId:" + std::to_string( i + 1 ) +
                            ":DKG_ID:" + dkgRandId;

        Json::Value result = sgxClient.CallMethod( "importBLSKeyShare", p );
    }

    delete jsonRpcClient;
}

keys generateKeys( size_t t, size_t n, const std::string& sgxUrl, const std::string& dkgRandId ) {
    libBLS::Dkg dkgTe( t, n );

    std::vector< libff::alt_bn128_Fr > poly = dkgTe.GeneratePolynomial();

    libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

    libff::alt_bn128_Fr common_skey = dkgTe.PolynomialValue( poly, zero_el );

    TEPrivateKey commonPrivate( common_skey, t, n );

    TEPublicKey commonPublic( commonPrivate );

    std::vector< libff::alt_bn128_Fr > skeys = dkgTe.SecretKeyContribution( poly );
    std::vector< TEPrivateKeyShare > secretKeys;
    std::vector< TEPublicKeyShare > publicKeys;
    for ( size_t i = 0; i < n; i++ ) {
        secretKeys.emplace_back( TEPrivateKeyShare( skeys[i], i + 1, t, n ) );
        publicKeys.emplace_back( TEPublicKeyShare( secretKeys[i] ) );
    }

    importBLSKeys( secretKeys, sgxUrl, dkgRandId );

    return { commonPublic, commonPrivate, secretKeys, publicKeys };
}

std::vector< TEDecryptionShare > getDecryptionShares(
    const std::vector< std::shared_ptr< libBLS::Ciphertext > >& ciphertexts,
    const std::string& keyName, const std::string& sgxUrl, const size_t signerIndex ) {
    Json::Value p;
    p["blsKeyName"] = keyName;

    Json::Value batch;
    // batch.reserve( 256 * ciphertexts.size());
    for ( size_t i = 0; i < ciphertexts.size(); i++ ) {
        std::shared_ptr< libBLS::Ciphertext > ciphertext = ciphertexts[i];
        ThresholdEncryption::validateEncryption( ciphertexts[i]->key );
        batch.append( ciphertext->getPublicDecryptionValue() );
    }

    TIMER(
        totalTime, p["publicDecryptionValues"] = batch;
        jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgxUrl );
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