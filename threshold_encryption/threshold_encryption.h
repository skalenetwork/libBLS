/*
Copyright (C) 2018-2019 SKALE Labs

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

@file threshold_encryption.h
@author Oleh Nikolaiev
@date 2019
*/

#pragma once

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <third_party/cryptlite/sha256.h>

#include <threshold_encryption/TEBase.h>
#include <tools/utils.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>


namespace libBLS {


struct CipheredKey {
    libff::alt_bn128_G2 U;
    std::string V;
    libff::alt_bn128_G1 W;

    bool operator==( const CipheredKey& other ) const {
        return ( U == other.U ) && ( V == other.V ) && ( W == other.W );
    }
};

struct Ciphertext {
    CipheredKey key;
    std::shared_ptr< std::vector< uint8_t > > data;

    bool operator==( const Ciphertext& other ) const {
        bool baseParams = key == other.key;
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }

    Ciphertext( const CipheredKey& _key, const std::vector< uint8_t >& _data )
        : key( _key ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {}

    /**
     * Converts U component of the key to string
     */
    std::string toStringU() {
        auto U = key.U; 
        U.to_affine_coordinates();
        auto u_splitted = ThresholdUtils::G2ToString( U );

        // convert to string
        std::string public_decryption_value;
        for ( size_t j = 0; j < u_splitted.size(); ++j ) {
            public_decryption_value += ThresholdUtils::convertDecToHex(u_splitted[j], 32);;
        }

        return public_decryption_value;
    }
};

class TE {
public:
    TE( const TEBase& base );

    TE( const size_t t, const size_t n );

    ~TE();

    static CipheredKey getCiphertext(
        const std::string& message, const libff::alt_bn128_G2& common_public );

    static Ciphertext encryptWithAES(
        const std::string& message, const libff::alt_bn128_G2& common_public );

    static std::string encryptMessage(
        const std::string& message, const std::string& common_public );

    static libff::alt_bn128_G2 getDecryptionShare(
        const CipheredKey& ciphertext, const libff::alt_bn128_Fr& secret_key );

    static libff::alt_bn128_G1 HashToGroup( const libff::alt_bn128_G2& U, const std::string& V,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static std::string Hash( const libff::alt_bn128_G2& Y,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static bool Verify( const CipheredKey& ciphertext, const libff::alt_bn128_G2& decryptionShare,
        const libff::alt_bn128_G2& public_key );

    std::string CombineShares( const CipheredKey& ciphertext,
        const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShare );

    std::vector< uint8_t > CombineSharesIntoAESKey(
        const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShare );

    static void checkCypher( const CipheredKey& cypher );

    static std::string aesCiphertextToString( const Ciphertext& cipher );

    static Ciphertext aesCiphertextFromString( const std::string& str );

    static CipheredKey ciphertextFromString( const std::string& str );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
