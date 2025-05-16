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
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file TECiphertext.h
  @author Sidnei Teixeira
  @date 2025
*/

#ifndef LIBBLS_TECIPHERTEXT_H
#define LIBBLS_TECIPHERTETX_H

#include <array>
#include <vector>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <tools/utils.h>

#include "threshold_encryption/AesGcmCipher.h"

namespace libBLS {

constexpr size_t CYPHERTEXT_LENGTH = 64;

constexpr size_t RANDOM_SECRET_SIZE_BYTES = MAX_FIELD_ELEMENT_SIZE_BYTES;
using RandSecret = std::array< uint8_t, RANDOM_SECRET_SIZE_BYTES >;

/**
 * @brief Holds the AES key ciphered via
 * Thresgold Encryption
 */
struct CipheredKey {
    static constexpr size_t SIZE_BYTES =
        G2_SIZE_BYTES + AES_256_KEY_SIZE_BYTES + G1_SIZE_BYTES;

    libff::alt_bn128_G2 U;
    AES256Key V;
    libff::alt_bn128_G1 W;

public:
    CipheredKey() = default;
    CipheredKey( libff::alt_bn128_G2 _U, AES256Key _V, libff::alt_bn128_G1 _W )
        : U( _U ), V( std::move( _V ) ), W( _W ) {
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
    std::array< uint8_t, SIZE_BYTES > toBytes() const;

    /**
     * @brief Converts bytes to CipheredKey
     */
    static CipheredKey fromBytes( std::array< uint8_t, SIZE_BYTES > bytes );

    /**
     * @brief Validates the CipheredKey
     * @throw NotWellFormed if the key is not well formed
     */
    void validate() const;

    static CipheredKey random();
};

/**
 * @brief Holds the ciphered AES key, as well as the data
 * ciphered with AES key.
 */
struct Ciphertext {
    CipheredKey key;
    std::shared_ptr< std::vector< uint8_t > > data;

public:
    Ciphertext() = default;

    Ciphertext( const CipheredKey& _key, const std::vector< uint8_t >& _data )
        : key( _key ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        validate();
    }

    /**
     * @brief Converts U component of the key to string
     */
    std::string getPublicDecryptionValue();


    const std::vector< uint8_t >& getData() const;

    /**
     * @brief Converts Ciphertext to bytes
     * The byte format returned is: `[ key | data ]`
     *
     * where `data` can be of arbitrary size, and `key` is a fixed size.
     */
    const std::vector< uint8_t > toBytes() const;

    /**
     * @brief Converts bytes to Ciphertext
     */
    static Ciphertext fromBytes( std::vector< uint8_t >& bytes );

    /**
     * @brief Validates the Ciphertext
     * @throw NotWellFormed if the it fails the validation
     */
    void validate() const;


    bool operator==( const Ciphertext& other ) const {
        bool baseParams = key == other.key;
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }
};

}

#endif