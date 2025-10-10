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

  @file threshold_encryption.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <string.h>
#include <iostream>
#include <utility>
#include <valarray>

#include <threshold_encryption.h>
#include <tools/utils.h>

#include "TEBase.h"
#include "backends/algebra_types.hpp"
#include <openssl/rand.h>

namespace libBLS {

TE::TE( const TEBase& base ) : t_( base.getRequiredSigners() ), n_( base.getTotalSigners() ) {}

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {}


TE::~TE() {}

std::array< uint8_t, algebra::HASH_SIZE > TE::Hash( const algebra::G2Point& Y ) {
    auto bytes = Y.toByteArray();
    std::string view( reinterpret_cast< const char* >( bytes.data() ), bytes.size() );

    std::array< uint8_t, algebra::HASH_SIZE > hash_result;
    ThresholdUtils::sha256( view, hash_result );

    return hash_result;
}

algebra::G1Point TE::HashToGroup( const algebra::G2Point& U, const AES256Key& V ) {
    // assumed that U lies in G2

    // convert U to bytes
    auto U_bytes = U.toByteArray();

    // concatenate both
    std::array< uint8_t, algebra::G2Point::SIZE_BYTES + AES_256_KEY_SIZE_BYTES > u_v_bytes_arr;
    std::memcpy( u_v_bytes_arr.data(), U_bytes.data(), U_bytes.size() );
    std::memcpy( u_v_bytes_arr.data() + U_bytes.size(), V.data(), V.size() );

    std::string view(
        reinterpret_cast< const char* >( u_v_bytes_arr.data() ), u_v_bytes_arr.size() );

    // hash the concatenated value
    std::array< uint8_t, algebra::HASH_SIZE > hash_result;
    ThresholdUtils::sha256( view, hash_result );

    return algebra::G1Point::fromHash( hash_result );
}


CipheredKeyResult TE::getCiphertext( const AES256Key& key, const algebra::G2Point& commonPublic ) {
    return getCiphertext( key, std::vector< algebra::G2Point >{ commonPublic } );
}


CipheredKeyResult TE::getCiphertext(
    const AES256Key& key, const std::vector< algebra::G2Point >& commonPublicVector ) {
    algebra::FrScalar r = algebra::FrScalar::random();

    while ( r.isZero() ) {
        r = algebra::FrScalar::random();
    }

    std::vector< CipheredKey > cipheredKeys;
    algebra::G2Point U = r * algebra::G2Point::generator();
    // convert to affine coordinate here to avoid doing it twice inside the loop
    U.toAffineCoordinates();
    for ( const auto& commonPublic : commonPublicVector ) {
        algebra::G2Point Y;
        Y = r * commonPublic;

        AES256Key hash = Hash( Y );

        AES256Key V;

        for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
            V[i] = key[i] ^ hash[i];
        }

        algebra::G1Point W, H;

        H = HashToGroup( U, V );
        W = r * H;

        cipheredKeys.emplace_back( U, V, W );
    }

    RandSecret random_secret = r.toByteArray();

    return { cipheredKeys, std::move( random_secret ) };
}

/**
 * @brief Encrypts a message using AES with a randomly generated key and threshold encryption
 *
 * @param message The plaintext message to be encrypted
 * @param commonPublic The common public key used for threshold encryption (G2 group element)
 *
 * @return A pair containing:
 *         - First: CipheredKey struct with (U,V,W) components of the threshold encryption ->
 * Ciphered AES key
 *         - Second: The AES-encrypted message as a byte vector
 *
 * @details The function:
 * 1. Generates a random 32-byte AES key
 * 2. Encrypts the input message with AES using the random key
 * 3. Threshold-encrypts the random AES key using the common public key
 * 4. Returns both the threshold-encrypted key and AES-encrypted message
 *
 * @note Initializes AES before encryption
 */
CipherResult TE::encryptWithAES(
    const std::vector< uint8_t >& message, const algebra::G2Point& commonPublic ) {
    return encryptWithAES( message, std::vector< algebra::G2Point >{ commonPublic } );
}

CipherResult TE::encryptWithAES(
    const std::vector< uint8_t >& message, const std::vector< algebra::G2Point >& commonPublic ) {
    // create random AES key
    AES256Key key;
    if ( RAND_bytes( key.data(), key.size() ) != 1 ) {
        throw ThresholdUtils::IsNotWellFormed( "Failed to generate random key" );
    }
    // cipher aes key
    CipheredKeyResult result = getCiphertext( key, commonPublic );

    // append random secret to end of message
    std::vector< uint8_t > message_to_cipher( message );
    message_to_cipher.insert(
        message_to_cipher.end(), result.random_secret.begin(), result.random_secret.end() );

    // cipher message + random secret using AES key
    AesGcmCipher aesGcmCipher{ key };
    auto encrypted_message = aesGcmCipher.encrypt( message_to_cipher );

    std::shared_ptr< Ciphertext > ciphertext =
        std::make_shared< Ciphertext >( result.ciphertext, encrypted_message );

    return { ciphertext, result.random_secret };
}


/**
 * @brief Encrypts a message using threshold encryption scheme with AES
 * @param message The plaintext message to be encrypted
 * @param commonPublic_str The common public key in string format
 * @return The encrypted ciphertext bytes as a hexadecimal string
 *
 * This function performs threshold encryption by:
 * 1. Creating a random AES key, and encrypting the message with it
 * 2. Ciphering the AES key using threshold encryption
 * 3. Converting the pair { PubCommKey(AES), AES(cipheredMessage) } to a string
 *
 * The encryption is performed using a combination of elliptic curve cryptography
 * and symmetric AES encryption for efficiency.
 */
std::pair< std::string, RandSecret > TE::encryptMessage(
    const std::vector< uint8_t >& message, const std::string& commonPublic ) {
    return encryptMessage( message, std::vector< std::string >{ commonPublic } );
}

// TODO - check if this function and the one above are still used anywhere
std::pair< std::string, RandSecret > TE::encryptMessage(
    const std::vector< uint8_t >& message, const std::vector< std::string >& commonPublicVector ) {
    std::vector< algebra::G2Point > commonPublicRaw;
    for ( const auto& commonPublicStr : commonPublicVector ) {
        algebra::G2Point commonPublic = algebra::G2Point::fromString( commonPublicStr, Base::HEXA );
        commonPublicRaw.push_back( commonPublic );
    }
    libBLS::CipherResult ciphertext = encryptWithAES( message, commonPublicRaw );
    std::vector< uint8_t > ciphertextBytes = ciphertext.ciphertext->toBytes();

    std::string ciphertextHexa = ThresholdUtils::bytesToHexString( ciphertextBytes );
    return std::make_pair( ciphertextHexa, ciphertext.random_secret );
}


/**
 * @brief Generates a decryption share for threshold encryption using a secret key
 *
 * This function assumes both ciphertext has been validated prior to this call
 * via `ThresholdEncryption::validateCiphertext()` call. Also assumes secret_key
 * is non-zero
 *
 * @param ciphertext A tuple containing encryption components (U, V, W) where:
 *        - U is an element of G2
 *        - V is the encrypted message (string)
 *        - W is an element of G1
 * This field usually refers to the threshold-encrypted AES key
 * @param secret_key The secret key share (element of Fr) used for decryption
 */
algebra::G2Point TE::getDecryptionShare(
    const CipheredKey& ciphertext, const algebra::FrScalar& secret_key ) {
    algebra::G2Point ret_val = secret_key * ciphertext.U;
    return ret_val;
}

/**
 * @brief Verifies a ciphertext and decryption share against a public key
 *
 * This function performs verification of a threshold encryption decryption share.
 * It checks two main conditions:
 * 1. Whether the ciphertext is valid by verifying the pairing equality e(W,1) = e(H(U,V),U)
 * 2. Whether the decryption share is valid by verifying e(W,PK) = e(H(U,V),S)
 * where PK is the public key and S is the decryption share
 *
 * @param ciphertext A tuple containing the encryption components (U,V,W). Assumes is already
 * validated
 * @param decryptionShare The decryption share to verify. Assumes is valid & well formed
 * @param public_key The public key used for verification. Assumes is valid & well formed
 *
 * @return true if both the ciphertext and decryption share are valid
 * @return false if either the ciphertext is invalid or the decryption share verification fails
 */
bool TE::Verify( const CipheredKey& ciphertext, const algebra::G2Point& decryptionShare,
    const algebra::G2Point& public_key ) {
    auto [U, V, W] = ciphertext;

    algebra::G1Point H = HashToGroup( U, V );
    // no need to validate ciphertext's pairing - assumed to be validated already via
    // `validateEncryption` call

    bool isSecondPairingValid = algebra::verifyPairingEq( W, public_key, H, decryptionShare );
    return isSecondPairingValid;
}


/**
 * @brief Verifies a ciphertext and decryption share against a public key
 *
 * This function performs verification of a batch of batches of threshold encryption shares.
 * Meaning that conceptually there is a big batch that contains smaller batches.
 * Each small batch contains N shares, and for each small batch the same ciphertext is shared.
 * Thus, the number of small batches in the big batch is equal to the number of ciphertexts.
 *
 * @param ciphertext Vector of tuples containing the encryption components (U,V,W). Assumes is
 * already validated
 * @param decryptionShares The decryption shares to verify. Assumes is valid & well formed. Contains
 * num of small batches * N shares
 * @param public_key The public key used for verification. Assumes is valid & well formed. Contains
 * num of small batches * N shares
 *
 * @return true only for the shares that are valid. If a ciphertext is invalid, it invalidates the
 * whole shares in that batch.
 */
std::vector< bool > TE::VerifyBatch( const std::vector< CipheredKey >& ciphertexts,
    const std::vector< algebra::G2Point >& decryptionShares,
    const std::vector< algebra::G2Point >& publicKeys ) {
    const size_t size = decryptionShares.size();
    const size_t numberOfBatches = ciphertexts.size();

    if ( size % numberOfBatches != 0 ) {
        throw ThresholdUtils::IncorrectInput(
            "decryption shares size must be multiple of ciphertexts size" );
    }

    if ( size != publicKeys.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "decryption shares and public keys must have same size" );
    }

    std::vector< algebra::G1Point > g1P1s;
    std::vector< algebra::G1Point > g1P2s;
    g1P1s.reserve( ciphertexts.size() );
    g1P2s.reserve( ciphertexts.size() );

    for ( const auto& cipher : ciphertexts ) {
        const auto& [U, V, W] = cipher;

        algebra::G1Point H = HashToGroup( U, V );
        // no need to validate H - assumes H has been validated already when performing the
        // ciphertext validation at the start of TE process

        g1P1s.emplace_back( W );
        g1P2s.emplace_back( H );
    }

    algebra::PairingEquality2CommonBasesBatch batch( g1P1s, g1P2s, publicKeys, decryptionShares );
    batch.useOptimisticValidation();
    return algebra::verifyPairingEquality2CommonBasesBatch( batch );
}


/**
 * @brief Combines decryption shares to recover the original message from a ciphertext
 *
 * This function performs the following steps:
 * 1. Verifies the ciphertext validity using bilinear pairing
 * 2. Combines the decryption shares to derive the AES key
 * 3. Uses XOR operation between the derived key and ciphertext component V to recover the message
 *
 * @param ciphertext A tuple containing encryption components (U, V, W) where:
 *        - U is an element of G2 group
 *        - V is the XOR of message with H(e(K,g2))
 *        - W is an element of G1 group
 * @param decryptionShares Vector of pairs containing decryption shares and their indices
 *        where each share is an element of G2 group
 *
 * @return The decrypted original message as a string
 *
 * @throws ThresholdUtils::IncorrectInput if the ciphertext validation fails
 */
AES256Key TE::CombineShares( const CipheredKey& ciphertext,
    const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShares ) {
    auto secret = CombineSharesIntoAESKey( decryptionShares );

    AES256Key aesKey;

    for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
        aesKey[i] = secret[i] ^ ciphertext.V[i];
    }

    return aesKey;
}

/**
 * @brief Combines decryption shares into an AES key using Lagrange interpolation
 *
 * This function performs the following steps:
 * 1. Extracts indices from decryption shares
 * 2. Calculates Lagrange coefficients
 * 3. Computes the sum of products of Lagrange coefficients and decryption shares
 * 4. Hashes the result and converts it to a byte vector
 *
 * @param decryptionShares Vector of pairs containing decryption shares (G2 points) and their
 * indices
 * @return std::vector<uint8_t> The resulting AES key as a byte vector
 *
 * @note The number of decryption shares must be equal to the threshold (t_)
 * @note This is an auxiliar function used by `combineShares` to combine shares & get original
 * message
 */
AES256Key TE::CombineSharesIntoAESKey(
    const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShares ) {
    if ( decryptionShares.size() < t_ )
        throw ThresholdUtils::IncorrectInput( "Expect at least t shares to be provided" );
    std::vector< size_t > idx( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        idx[i] = decryptionShares[i].second;
    }

    std::vector< std::reference_wrapper< const algebra::G2Point > > shares_ref;
    for ( size_t i = 0; i < this->t_; ++i ) {
        shares_ref.emplace_back( std::cref( decryptionShares[i].first ) );
    }
    algebra::G2Point rebuiltG2 = algebra::lagrangeInterpolateAt0( idx, this->t_, shares_ref );

    AES256Key hash = this->Hash( rebuiltG2 );

    return hash;
}

}  // namespace libBLS
