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

#include <openssl/rand.h>
#include <array>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <third_party/cryptlite/sha256.h>

#include "AesGcmCipher.h"
#include "TEBase.h"
#include "backends/algebra.hpp"
#include <tools/utils.h>

// TODO - remove this
#include <iostream>
#include "benchmarks/ScopedTimer.hpp"


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
        algebra::G2Point::SIZE_BYTES + AES_256_KEY_SIZE_BYTES + algebra::G1Point::SIZE_BYTES;

    algebra::G2Point U;
    AES256Key V;
    algebra::G1Point W;

public:
    CipheredKey() = default;
    CipheredKey( algebra::G2Point _U, AES256Key _V, algebra::G1Point _W, bool _validate = true )
        : U( _U ), V( std::move( _V ) ), W( _W ) {
        if ( _validate )
            validate();
    }

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
        auto u_bytes = U.toByteArray();
        std::memcpy( source, u_bytes.data(), u_bytes.size() );
        source += u_bytes.size();
        // set V commponent
        std::memcpy( source, V.data(), V.size() );
        source += V.size();
        // set W component
        auto w_bytes = W.toByteArray();
        std::memcpy( source, w_bytes.data(), w_bytes.size() );

        return bytes;
    }

    /**
     * @brief Converts bytes to CipheredKey
     */
    static CipheredKey fromBytes(
        std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > bytes, bool _validate = true ) {
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
        algebra::G2Point U = algebra::G2Point::fromBytes( u_bytes );
        algebra::G1Point W = algebra::G1Point::fromBytes( w_bytes );

        // constructor performs validation
        return CipheredKey( U, v_bytes, W, _validate );
    }

    /**
     * @brief Validates the CipheredKey
     * @throw NotWellFormed if the key is not well formed
     */
    void validate() const {
        W.validate();
        U.validate();
    }

    static CipheredKey random() {
        algebra::G2Point U = algebra::G2Point::random();
        AES256Key V;
        RAND_bytes( V.data(), V.size() );
        algebra::G1Point W = algebra::G1Point::random();
        return CipheredKey( U, V, W );
    }

    /**
     * Converts U component of the key to string
     */
    std::string getDecryptionShareInput() {
        U.toAffineCoordinates();
        U.validate();

        auto u_splitted = U.toStringArray( Base::HEXA );

        // convert to string
        std::string public_decryption_value;
        size_t total_size = 0;

        for ( const auto& part : u_splitted ) {
            total_size += part.size();
        }

        public_decryption_value.reserve( total_size );

        for ( const auto& part : u_splitted ) {
            public_decryption_value += part;
        }

        return public_decryption_value;
    }
};

/**
 * @brief Holds the ciphered AES keys (vector), as well as the data
 * ciphered with AES key.
 */
struct Ciphertext {
    std::vector< CipheredKey > keys;
    std::shared_ptr< std::vector< uint8_t > > data;

public:
    bool operator==( const Ciphertext& other ) const {
        bool baseParams = keys == other.keys;
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }

    Ciphertext() = default;

    Ciphertext( const std::vector< CipheredKey >& _keys, const std::vector< uint8_t >& _data,
        bool _validate = true )
        : keys( _keys ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    Ciphertext(
        const CipheredKey& _key, const std::vector< uint8_t >& _data, bool _validate = true )
        : keys( { _key } ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    // Constructor for exactly two keys
    Ciphertext( const CipheredKey& _key1, const CipheredKey& _key2,
        const std::vector< uint8_t >& _data, bool _validate = true )
        : keys( { _key1, _key2 } ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    const std::vector< uint8_t >& getData() const {
        if ( !data ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
        }
        return *data;
    }

    /**
     * @brief Converts Ciphertext to bytes
     * The byte format returned is: `[ num_keys | key1 | key2 | ... | data ]`
     *
     * where `data` can be of arbitrary size, each `key` is a fixed size,
     * and `num_keys` is a 1-byte integer indicating the number of keys.
     */
    const std::vector< uint8_t > toBytes() const {
        if ( !data ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
        }

        // Calculate total size needed
        size_t totalSize = sizeof( uint8_t ) +  // for number of keys
                           ( keys.size() * CipheredKey::CIPHERED_KEY_SIZE_BYTES ) +  // for all keys
                           data->size();                                             // for data

        std::vector< uint8_t > bytes;
        bytes.reserve( totalSize );

        // Add number of keys
        uint8_t numKeys = static_cast< uint8_t >( keys.size() );
        bytes.push_back( numKeys );

        // Add each key
        for ( const auto& key : keys ) {
            std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes = key.toBytes();
            bytes.insert( bytes.end(), keyBytes.begin(), keyBytes.end() );
        }

        // Add data
        bytes.insert( bytes.end(), data->begin(), data->end() );

        return bytes;
    }

    /**
     * @brief Converts bytes to Ciphertext
     */
    static Ciphertext fromBytes( std::vector< uint8_t >& bytes, bool _validate = true ) {
        // we require at least 1 byte for num_keys + one key + random secret + 1 byte for data
        if ( bytes.size() <=
             sizeof( uint8_t ) + CipheredKey::CIPHERED_KEY_SIZE_BYTES + RANDOM_SECRET_SIZE_BYTES ) {
            throw ThresholdUtils::IncorrectInput( "Cyphertext data is too short" );
        }

        size_t offset = 0;

        // Get number of keys
        uint8_t numKeys;
        std::memcpy( &numKeys, bytes.data() + offset, sizeof( uint8_t ) );
        offset += sizeof( uint8_t );

        if ( numKeys == 0 || numKeys > 2 )
            throw ThresholdUtils::IncorrectInput( "Ciphertext must contain exactly 1 or 2 keys" );

        // Check that the input matches the number of keys
        size_t expectedMinSize =
            sizeof( uint8_t ) + ( numKeys * CipheredKey::CIPHERED_KEY_SIZE_BYTES ) +
            RANDOM_SECRET_SIZE_BYTES + 1;  // +1 for at least 1 byte of actual data
        if ( bytes.size() < expectedMinSize )
            throw ThresholdUtils::IncorrectInput(
                "Cyphertext data is too short for specified number of keys" );

        // Extract keys
        std::vector< CipheredKey > keys;
        keys.reserve( numKeys );

        for ( size_t i = 0; i < numKeys; ++i ) {
            std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes;
            std::memcpy(
                keyBytes.data(), bytes.data() + offset, CipheredKey::CIPHERED_KEY_SIZE_BYTES );
            offset += CipheredKey::CIPHERED_KEY_SIZE_BYTES;

            // do not validate CipheredKey here
            // if validation is enabled, CipheredKey is validated in Ciphertext's constructor
            // otherwise we don't need validation at all
            keys.push_back( CipheredKey::fromBytes( keyBytes, false ) );
        }

        // Get data bytes
        std::vector< uint8_t > data( bytes.begin() + offset, bytes.end() );

        return Ciphertext( keys, data, _validate );
    }

    /**
     * @brief Validates the Ciphertext
     * @throw NotWellFormed if the it fails the validation
     */
    void validate() const {
        if ( keys.empty() || keys.size() > 2 )
            throw ThresholdUtils::IsNotWellFormed( "Ciphertext must contain exactly 1 or 2 keys" );

        for ( const auto& key : keys ) {
            key.validate();
        }

        if ( !data ) {
            throw ThresholdUtils::IsNotWellFormed( "Cyphertext data is not initialized" );
        }

        // actual data without random secret must be at least 1 byte long
        if ( data->size() <= RANDOM_SECRET_SIZE_BYTES ) {
            throw ThresholdUtils::IsNotWellFormed(
                "Cyphertext data is too short to hold random secret and at least 1 byte of data." );
        }
    }

    /**
     * @brief Returns the vector of keys in the Ciphertext
     */
    const std::vector< CipheredKey >& getKeys() const { return keys; }

    /**
     * @brief keeps only one key for validation and decryption
     * @param idx - index of the key to keep
     */
    void keepKey( size_t _idx ) {
        if ( _idx >= keys.size() || keys.size() != 2 )
            throw ThresholdUtils::IncorrectInput(
                "Key index is greater than number of the keys in ciphertext" );
        keys.erase( keys.begin() + ( keys.size() - _idx - 1 ) );
    }

    /**
     * @brief get a CipheredKey for validation and decryption
     * @throw IncorrectInput if there are 0 or 2 keys to choose
     */
    const CipheredKey& getTargetKey() const {
        if ( keys.size() != 1 )
            throw ThresholdUtils::IncorrectInput( "Cannot choose a target key" );
        return keys.front();
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
    std::vector< CipheredKey > ciphertext;
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
        const AES256Key& key, const algebra::G2Point& commonPublic );
    static CipheredKeyResult getCiphertext(
        const AES256Key& key, const std::vector< algebra::G2Point >& commonPublic );

    static CipherResult encryptWithAES(
        const std::vector< uint8_t >& message, const algebra::G2Point& commonPublic );
    static CipherResult encryptWithAES( const std::vector< uint8_t >& message,
        const std::vector< algebra::G2Point >& commonPublic );

    static std::pair< std::string, RandSecret > encryptMessage(
        const std::vector< uint8_t >& message, const std::string& commonPublic );
    static std::pair< std::string, RandSecret > encryptMessage(
        const std::vector< uint8_t >& message, const std::vector< std::string >& commonPublic );

    static algebra::G2Point getDecryptionShare(
        const CipheredKey& ciphertext, const algebra::FrScalar& secret_key );

    static algebra::G1Point HashToGroup( const algebra::G2Point& U, const std::string& V,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static std::string Hash( const algebra::G2Point& Y,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static bool Verify( const CipheredKey& ciphertext, const algebra::G2Point& decryptionShare,
        const algebra::G2Point& public_key );

    static std::vector< bool > VerifyBatch( const CipheredKey& ciphertext, 
        const std::vector< std::reference_wrapper< const algebra::G2Point > >& decryptionShares,
        const std::vector< std::reference_wrapper< const algebra::G2Point > >& publicKeys );

    AES256Key CombineShares( const CipheredKey& ciphertext,
        const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShare );

    std::vector< uint8_t > CombineSharesIntoAESKey(
        const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShare );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
