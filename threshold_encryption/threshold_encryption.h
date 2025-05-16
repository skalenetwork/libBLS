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
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <third_party/cryptlite/sha256.h>

#include "AesGcmCipher.h"
#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TECiphertext.h>
#include <tools/utils.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>


namespace libBLS {

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

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
