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
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>

void importBLSKeys(
    const std::vector< libff::alt_bn128_Fr >& secret_keys, const std::string& sgx_url ) {
    jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgx_url );
    jsonrpc::Client sgxClient( *jsonRpcClient );

    for ( size_t i = 0; i < secret_keys.size(); ++i ) {
        Json::Value p;
        p["keyShare"] = libBLS::ThresholdUtils::fieldElementToString( secret_keys[i], 16 );
        p["keyShareName"] = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:" + std::to_string( i );

        Json::Value result = sgxClient.CallMethod( "importBLSKeyShare", p );
    }

    delete jsonRpcClient;
}

std::vector< libff::alt_bn128_Fr > generateSecretKeys(
    size_t t, size_t n, const std::string& sgx_url ) {
    libBLS::Dkg dkg_instance = libBLS::Dkg( t, n );

    auto polynomial = dkg_instance.GeneratePolynomial();

    std::vector< libff::alt_bn128_Fr > secret_keys( n );
    for ( size_t i = 0; i < n; ++i ) {
        secret_keys[i] = dkg_instance.PolynomialValue( polynomial, i + 1 );
    }

    importBLSKeys( secret_keys, sgx_url );

    return secret_keys;
}

libff::alt_bn128_G2 getDecryptionShare( const libBLS::Ciphertext& ciphertext,
    const std::string& key_name, const std::string& sgx_url ) {
    libBLS::TE::checkCypher( ciphertext );

    libff::alt_bn128_G2 U = std::get< 0 >( ciphertext );

    U.to_affine_coordinates();
    auto u_splitted = libBLS::ThresholdUtils::G2ToString( U );
    std::string public_decryption_value = "";
    for ( size_t i = 0; i < u_splitted.size(); ++i ) {
        public_decryption_value += u_splitted[i];
        if ( i != u_splitted.size() - 1 ) {
            public_decryption_value += ":";
        }
    }

    std::string V = std::get< 1 >( ciphertext );

    libff::alt_bn128_G1 W = std::get< 2 >( ciphertext );

    libff::alt_bn128_G1 H = libBLS::TE::HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    if ( !res ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "cannot decrypt data" );
    }

    jsonrpc::HttpClient* jsonRpcClient = new jsonrpc::HttpClient( sgx_url );
    jsonrpc::Client sgxClient( *jsonRpcClient );

    Json::Value p;
    p["blsKeyName"] = key_name;
    p["publicDecryptionValue"] = public_decryption_value;

    Json::Value result = sgxClient.CallMethod( "getDecryptionShare", p );

    delete jsonRpcClient;

    libff::alt_bn128_G2 ret_val;
    ret_val.Z = libff::alt_bn128_Fq2::one();
    ret_val.X.c0 = libff::alt_bn128_Fq( result["decryptionShare"][0].asCString() );
    ret_val.X.c1 = libff::alt_bn128_Fq( result["decryptionShare"][1].asCString() );
    ret_val.Y.c0 = libff::alt_bn128_Fq( result["decryptionShare"][2].asCString() );
    ret_val.Y.c1 = libff::alt_bn128_Fq( result["decryptionShare"][3].asCString() );

    return ret_val;
}

int main() {
    size_t t;
    size_t n;
    std::string sgxwallet_url;
    std::string plaintext;

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

    if ( const char* env_message = std::getenv( "MESSAGE" ) ) {
        plaintext = std::string( env_message );
    } else {
        plaintext = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    }

    auto secret_keys = generateSecretKeys( t, n, sgxwallet_url );

    std::vector< libff::alt_bn128_G2 > public_keys( n );
    for ( size_t i = 0; i < n; ++i ) {
        public_keys[i] = secret_keys[i] * libff::alt_bn128_G2::one();
    }

    std::vector< size_t > idx( n );
    for ( size_t i = 0; i < n; ++i ) {
        idx[i] = i + 1;
    }
    auto lagrange_coeffs = libBLS::ThresholdUtils::LagrangeCoeffs( idx, t );

    libBLS::Bls bls_instance = libBLS::Bls( t, n );
    auto common_keys = bls_instance.KeysRecover( lagrange_coeffs, secret_keys );

    auto vector_coordinates = libBLS::ThresholdUtils::G2ToString( common_keys.second, 16 );

    std::string common_public_str = "";
    for ( auto& coord : vector_coordinates ) {
        while ( coord.size() < 64 ) {
            coord = "0" + coord;
        }
        common_public_str += coord;
    }

    auto encrypted_string = libBLS::TE::encryptMessage( plaintext, common_public_str );


    auto te_instance = libBLS::TE( t, n );

    auto ciphertext_with_aes = te_instance.aesCiphertextFromString( encrypted_string );

    auto ciphertext = ciphertext_with_aes.first;
    auto encrypted_message = ciphertext_with_aes.second;

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    for ( size_t i = 0; i < n; ++i ) {
        libff::alt_bn128_Fr secret_key = secret_keys[i];
        libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

        std::string bls_key_name =
            "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:" + std::to_string( i );

        libff::alt_bn128_G2 decryption_share =
            getDecryptionShare( ciphertext, bls_key_name, sgxwallet_url );

        assert( te_instance.Verify( ciphertext, decryption_share, public_key ) );

        shares.push_back( std::make_pair( decryption_share, size_t( i + 1 ) ) );
    }

    std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string decrypted_plaintext =
        libBLS::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    assert( decrypted_plaintext == plaintext );

    return 0;
}