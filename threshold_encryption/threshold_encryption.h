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
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "TEBase.h"
#include "backends/algebra.hpp"
#include <tools/utils.h>

#include "CipheredKey.h"
#include "Ciphertext.h"


namespace libBLS {

constexpr size_t CYPHERTEXT_LENGTH = 64;
using RandSecret = std::array< uint8_t, RANDOM_SECRET_SIZE_BYTES >;

/**
 * @brief The result of the encryption process
 * Only accessible by the party that cyphers the text.
 * `randomSecret` should never be shared.
 */
struct CipherResult {
    std::shared_ptr< Ciphertext > ciphertext;
    RandSecret randomSecret;
};

struct CipheredKeyResult {
    std::vector< CipheredKey > ciphertext;
    RandSecret randomSecret;
};


/**
 * @brief Metadata used during encryption
 */
struct EncryptMetaData {
    // Optional associated data for AES CBC
    // Is used at encryption and at decryption stages only. Does not obey to threshold
    // guarantees since it is associated with symmetric encryption.
    std::optional< std::vector< uint8_t > > associatedDataAesCbc;

    // Optional associated data for TE
    // Is used at encryption and validateEncryption stages only. Obeys to threshold guarantees
    // as long as no party proceeds with the algorithm (partial decryption) in case
    // validateEncryption fails with this associated data.
    std::optional< std::vector< uint8_t > > associatedDataTE;

    // Optional seed used to derive both the random scalar secret and the AES key.
    // Seed must have same size as AES_KEY in order to have the same entropy / security level.
    std::optional< std::array< uint8_t, AES_256_KEY_SIZE_BYTES > > seed;
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
    static CipheredKeyResult getCiphertext( const AES256Key& key,
        const algebra::G2Point& commonPublic,
        const std::optional< std::vector< uint8_t > >& associatedDataTE,
        const std::optional< std::array< uint8_t, AES_256_KEY_SIZE_BYTES > >& seed );

    static CipheredKeyResult getCiphertext( const AES256Key& key,
        const std::vector< algebra::G2Point >& commonPublic,
        const std::optional< std::vector< uint8_t > >& associatedDataTE,
        const std::optional< std::array< uint8_t, AES_256_KEY_SIZE_BYTES > >& seed );

    static CipherResult encryptWithAES( const std::vector< uint8_t >& message,
        const algebra::G2Point& commonPublic,
        const EncryptMetaData& metaData = EncryptMetaData() );

    static CipherResult encryptWithAES( const std::vector< uint8_t >& message,
        const std::vector< algebra::G2Point >& commonPublic,
        const EncryptMetaData& metaData = EncryptMetaData() );

    static std::pair< std::string, RandSecret > encryptMessage(
        const std::vector< uint8_t >& message, const std::string& commonPublic );
    static std::pair< std::string, RandSecret > encryptMessage(
        const std::vector< uint8_t >& message, const std::vector< std::string >& commonPublic );

    static algebra::G2Point getDecryptionShare(
        const CipheredKey& ciphertext, const algebra::FrScalar& secretKey );

    static algebra::G1Point HashToGroup( const algebra::G2Point& U, const AES256Key& V,
        const std::vector< uint8_t >* associatedData = nullptr );

    static std::string Hash( const algebra::G2Point& Y );

    static bool Verify( const CipheredKey& ciphertext, const algebra::G2Point& decryptionShare,
        const algebra::G2Point& publicKey,
        const std::vector< uint8_t >* associatedDataTE = nullptr );

    static std::vector< bool > VerifyBatch( const std::vector< CipheredKey >& ciphertexts,
        const std::vector< algebra::G2Point >& decryptionShares,
        const std::vector< algebra::G2Point >& publicKeys,
        const std::vector< std::vector< uint8_t > >* associatedDataTE = nullptr );

    AES256Key CombineShares( const CipheredKey& ciphertext,
        const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShare );

    AES256Key CombineSharesIntoAESKey(
        const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShare );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
