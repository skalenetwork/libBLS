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

constexpr size_t CYPHERTEXT_LENGTH = 64;

constexpr size_t RANDOM_SECRET_SIZE_BYTES = MAX_FIELD_ELEMENT_SIZE_BYTES;
using RandSecret = std::array< uint8_t, RANDOM_SECRET_SIZE_BYTES >;

/**
 * @brief Holds the AES key ciphered via
 * Thresgold Encryption
 */
struct CipheredKey {
    static constexpr size_t CIPHERED_KEY_SIZE_BYTES =
        G2_SIZE_BYTES + AES_256_KEY_SIZE_BYTES + G1_SIZE_BYTES;

    libff::alt_bn128_G2 U;
    AES256Key V;
    libff::alt_bn128_G1 W;

    CipheredKey() = default;
    CipheredKey( libff::alt_bn128_G2 _U, AES256Key _V, libff::alt_bn128_G1 _W )
        : U( _U ), V( std::move( _V ) ), W( _W ) {}

    bool operator==( const CipheredKey& other ) const {
        return ( U == other.U ) && ( V == other.V ) && ( W == other.W );
    }

    /**
     * @brief Converts CipheredKey to bytes
     * The byte format returned is: `[ U | V | W ]`
     * where `U` and `W` are elements of G2 and G1 groups respectively,
     * and `V` is a fixed size AES256Key.
     *
     * Final byte representation is always of fixed size.
     */
    std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > toBytes() const {
        std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > bytes;
        uint8_t* source = bytes.data();
        // set U component
        auto u_bytes = ThresholdUtils::G2ToBytes( U );
        std::memcpy( source, u_bytes.data(), u_bytes.size() );
        source += u_bytes.size();
        // set V commponent
        auto v_bytes = std::vector< uint8_t >( V.begin(), V.end() );
        std::memcpy( source, v_bytes.data(), v_bytes.size() );
        source += v_bytes.size();
        // set W component
        auto w_bytes = ThresholdUtils::G1ToBytes( W );
        std::memcpy( source, w_bytes.data(), w_bytes.size() );

        return bytes;
    }

    /**
     * @brief Converts bytes to CipheredKey
     */
    static CipheredKey fromBytes( std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > bytes ) {
        std::array< uint8_t, G2_SIZE_BYTES > u_bytes;
        std::array< uint8_t, AES_256_KEY_SIZE_BYTES > v_bytes;
        std::array< uint8_t, G1_SIZE_BYTES > w_bytes;

        uint8_t* offset = bytes.data();
        // Get U bytes
        std::memcpy( u_bytes.data(), offset, G2_SIZE_BYTES );
        offset += G2_SIZE_BYTES;
        // Get V bytes
        std::memcpy( v_bytes.data(), offset, AES_256_KEY_SIZE_BYTES );
        offset += AES_256_KEY_SIZE_BYTES;
        // Get W bytes
        std::memcpy( w_bytes.data(), offset, G1_SIZE_BYTES );

        // Convert to CipheredKey components
        libff::alt_bn128_G2 U = ThresholdUtils::bytesToG2( u_bytes );
        libff::alt_bn128_G1 W = ThresholdUtils::bytesToG1( w_bytes );

        return CipheredKey( U, v_bytes, W );
    }
};

/**
 * @brief Holds the ciphered AES key, as well as the data
 * ciphered with AES key.
 */
struct Ciphertext {
    CipheredKey key;

private:
    std::shared_ptr< std::vector< uint8_t > > data;

public:
    bool operator==( const Ciphertext& other ) const {
        bool baseParams = key == other.key;
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }

    Ciphertext() = default;

    Ciphertext( const CipheredKey& _key, const std::vector< uint8_t >& _data )
        : key( _key ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {}

    /**
     * Converts U component of the key to string
     */
    std::string getPublicDecryptionValue() {
        auto U = key.U;
        U.to_affine_coordinates();
        auto u_splitted = ThresholdUtils::G2ToString( U, BASE_HEXA );

        // convert to string
        std::string public_decryption_value;
        for ( size_t j = 0; j < u_splitted.size(); ++j ) {
            public_decryption_value += u_splitted[j];
        }

        return public_decryption_value;
    }


    const std::vector< uint8_t >& getData() const {
        if ( !data ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
        }
        return *data;
    }

    /**
     * @brief Converts Ciphertext to bytes
     * The byte format returned is: `[ key | data ]`
     *
     * where `data` can be of arbitrary size, and `key` is a fixed size.
     */
    const std::vector< uint8_t > toBytes() const {
        if ( !data ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
        }
        // get key bytes
        std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes = key.toBytes();
        // preallocate vec
        std::vector< uint8_t > bytes( CipheredKey::CIPHERED_KEY_SIZE_BYTES + data->size() );
        // Copy keyBytes into the first part of bytes
        std::copy( keyBytes.begin(), keyBytes.end(), bytes.begin() );
        // Copy data bytes after keyBytes
        std::copy( data->begin(), data->end(), bytes.begin() + keyBytes.size() );

        return bytes;
    }

    /**
     * @brief Converts bytes to Ciphertext
     */
    static Ciphertext fromBytes( std::vector< uint8_t >& bytes ) {
        // we require data field to have at least 1 byte
        if ( bytes.size() <= CipheredKey::CIPHERED_KEY_SIZE_BYTES ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is too short" );
        }

        // get key bytes
        std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes;
        std::copy(
            bytes.begin(), bytes.begin() + CipheredKey::CIPHERED_KEY_SIZE_BYTES, keyBytes.begin() );
        // get data bytes
        std::vector< uint8_t > data(
            bytes.begin() + CipheredKey::CIPHERED_KEY_SIZE_BYTES, bytes.end() );

        // get key structure
        CipheredKey key = CipheredKey::fromBytes( keyBytes );

        return Ciphertext( key, data );
    }
};

/**
 * @brief The result of the encryption process
 * Only accessible by the party that cyphers the text.
 * `random_secret` should never be shared.
 */
struct CipherResult {
    std::shared_ptr< Ciphertext > ciphertext;
    RandSecret random_secret;
};

struct CipheredKeyResult {
    std::shared_ptr< CipheredKey > ciphertext;
    RandSecret random_secret;
};

class TE {
public:
    TE( const TEBase& base );

    TE( const size_t t, const size_t n );

    ~TE();


    /**
     * @brief Encrypts a message using threshold encryption scheme
     *
     * Slow in comparison to encryptWithAES - Use only to cipher
     * AES key. Not the message itself
     *
     * @param message The message to encrypt
     * @param common_public The public key in G2 group
     * @return CipheredKey Triple (U,V,W) where:
     *         U is element of G2
     *         V is the encrypted message
     *         W is element of G1
     * @return string - random secret used for encryption. Mostly used for testing.
     *
     * @note This is an auxiliar function, used within `encryptWithAES`
     */
    static CipheredKeyResult getCiphertext(
        const AES256Key& key, const libff::alt_bn128_G2& commonPublic );

    static CipherResult encryptWithAES(
        const std::vector< uint8_t >& message, const libff::alt_bn128_G2& commonPublic );

    static std::pair< std::string, RandSecret > encryptMessage(
        const std::vector< uint8_t >& message, const std::string& common_public );

    static libff::alt_bn128_G2 getDecryptionShare(
        const CipheredKey& ciphertext, const libff::alt_bn128_Fr& secret_key );

    static libff::alt_bn128_G1 HashToGroup( const libff::alt_bn128_G2& U, const std::string& V,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static std::string Hash( const libff::alt_bn128_G2& Y,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static bool Verify( const CipheredKey& ciphertext, const libff::alt_bn128_G2& decryptionShare,
        const libff::alt_bn128_G2& public_key );

    AES256Key CombineShares( const CipheredKey& ciphertext,
        const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShare );

    std::vector< uint8_t > CombineSharesIntoAESKey(
        const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShare );

    static void checkCypher( const CipheredKey& cypher );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
