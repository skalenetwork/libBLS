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

namespace {

struct EncryptionProfile {
    TEVersion teVersion;
    AesGcmVersion aesGcmVersion;
};

EncryptionProfile resolveEncryptionProfile( EncryptionVersion version ) {
    switch ( version ) {
    case EncryptionVersion::V0:
        return { TEVersion::V0, AesGcmVersion::V0 };
    case EncryptionVersion::V1:
        return { TEVersion::V1, AesGcmVersion::V1 };
    }
    throw ThresholdUtils::IncorrectInput( "Unsupported encryption version" );
}

/**
 * @brief Encrypts a message using AES and threshold encryption
 *
 * @param message The plaintext message to be encrypted
 * @param commonPublic The common public key(s) used for threshold encryption
 * @param metaData Encryption metadata (encryption profile, optional AES/TE AAD)
 * @param seed Optional 256-bit seed for deterministic encryption; if omitted, generates random key/scalar
 *
 * @return CipherResult containing:
 *         - ciphertext: Shared pointer to Ciphertext (threshold-encrypted AES key(s) and AES-encrypted message)
 *         - randomSecret: The random secret (scalar) used during encryption
 */
CipherResult encryptWithAESInternal( const std::vector< uint8_t >& message,
    const std::vector< algebra::G2Point >& commonPublic, const EncryptMetaData& metaData,
    const std::optional< Seed256 >& seed = std::nullopt ) {
    const EncryptionProfile profile = resolveEncryptionProfile( metaData.encryptionVersion );
    AesGcmCipher aesGcmCipher = seed.has_value() ?
        AesGcmCipher( *seed, profile.aesGcmVersion ) :
        AesGcmCipher( profile.aesGcmVersion );
    const AES256Key& key = aesGcmCipher.getKey();

    CipheredKeyResult cipheredKeyResult =
        TE::cipherAesKey( key, commonPublic, metaData.associatedDataTE, seed, profile.teVersion );

    std::vector< uint8_t > messageToCipher( message );
    messageToCipher.insert(
        messageToCipher.end(), cipheredKeyResult.randomSecret.begin(),
        cipheredKeyResult.randomSecret.end() );

    auto encryptedMessage = aesGcmCipher.encrypt( messageToCipher, metaData.associatedDataAesGcm );
    std::shared_ptr< Ciphertext > ciphertext =
        std::make_shared< Ciphertext >(
            cipheredKeyResult.cipheredKeys, encryptedMessage, true, profile.teVersion );

    return { ciphertext, cipheredKeyResult.randomSecret };
}

}  // namespace

TE::TE( const TEBase& base ) : t_( base.getRequiredSigners() ), n_( base.getTotalSigners() ) {}

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {}


TE::~TE() {}

std::string TE::Hash( const algebra::G2Point& Y ) {
    auto vectorCoordinates = Y.toStringArray( Base::DEC );

    std::string tmp = "";
    for ( const auto& coord : vectorCoordinates ) {
        tmp += coord;
    }

    const std::string sha256hex = ThresholdUtils::sha256( tmp );

    return sha256hex;
}

AES256Key TE::deriveMaskFromHash( const std::string& hashHex, TEVersion version ) {
    AES256Key mask;
    if ( version == TEVersion::V0 ) {
        if ( hashHex.size() < AES_256_KEY_SIZE_BYTES ) {
            throw ThresholdUtils::IsNotWellFormed( "Hash cannot be less than key size" );
        }
        for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
            mask[i] = static_cast< uint8_t >( hashHex[i] );
        }
    } else {
        mask = ThresholdUtils::hexCStringToBytesArray< AES_256_KEY_SIZE_BYTES >( hashHex.c_str() );
    }
    return mask;
}

algebra::G1Point TE::HashToGroup(
    const algebra::G2Point& U, const AES256Key& V, const std::vector< uint8_t >* associatedData ) {
    // assumed that U lies in G2

    auto uStr = U.toStringArray( Base::DEC );
    std::string vStr = ThresholdUtils::bytesToHexString( V );

    // Build hash input: U coordinates + V + optional AAD
    std::string hashInput = uStr[0] + uStr[1] + uStr[2] + uStr[3] + vStr;

    if ( associatedData && !associatedData->empty() ) {
        std::string aadStr = ThresholdUtils::bytesToHexString( *associatedData );
        hashInput += aadStr;
    }

    // hash 2x
    const std::string sha256hex = ThresholdUtils::sha256( hashInput );
    std::string hashStr = ThresholdUtils::sha256( sha256hex );

    std::vector< uint8_t > bytes = ThresholdUtils::hexCStringToBytes( hashStr.c_str() );

    // copy first 32 bytes
    auto hashBytesArr = std::array< uint8_t, algebra::MAX_FIELD_ELEMENT_SIZE_BYTES >();
    std::copy( bytes.begin(), bytes.begin() + algebra::MAX_FIELD_ELEMENT_SIZE_BYTES,
        hashBytesArr.begin() );

    return algebra::G1Point::fromHash( hashBytesArr );
}


CipheredKeyResult TE::cipherAesKey( const AES256Key& key, const algebra::G2Point& commonPublic,
    const std::optional< std::vector< uint8_t > >& associatedDataTE,
    const std::optional< Seed256 >& seed, TEVersion version ) {
    return cipherAesKey(
        key, std::vector< algebra::G2Point >{ commonPublic }, associatedDataTE, seed, version );
}


CipheredKeyResult TE::cipherAesKey( const AES256Key& key,
    const std::vector< algebra::G2Point >& commonPublicVector,
    const std::optional< std::vector< uint8_t > >& associatedDataTE,
    const std::optional< Seed256 >& seed, TEVersion version ) {
    algebra::FrScalar r = algebra::FrScalar::random();

    // set first value for r scalar
    if ( seed.has_value() ) {
        // Derive scalar r using SHA256 with domain separation
        // derivation: SHA256( seed || "Scalar" )
        std::vector< uint8_t > input( seed->data.begin(), seed->data.end() );
        const std::string domain = "Scalar";
        input.insert( input.end(), domain.begin(), domain.end() );

        std::string inputStr( input.begin(), input.end() );
        std::string hashHex = ThresholdUtils::sha256( inputStr );
        std::vector< uint8_t > derivedScalar = ThresholdUtils::hexCStringToBytes( hashHex.c_str() );

        // This maps the 32-byte hash into the scalar field (handling modulo prime order etc)
        r = algebra::FrScalar::fromHashBytes( derivedScalar.data(), derivedScalar.size() );
    } else {
        r = algebra::FrScalar::random();
    }

    // make sure it is different from zero
    while ( r.isZero() ) {
        if ( seed.has_value() ) {
            // Very unlikely case where the derived scalar is zero
            // We can re-hash the derived scalar to get a new one
            std::string hashHex = ThresholdUtils::sha256( r.toString( Base::HEXA ) );
            std::vector< uint8_t > derivedScalar =
                ThresholdUtils::hexCStringToBytes( hashHex.c_str() );
            r = algebra::FrScalar::fromHashBytes( derivedScalar.data(), derivedScalar.size() );
        } else {
            r = algebra::FrScalar::random();
        }
    }

    std::vector< CipheredKey > cipheredKeys;
    algebra::G2Point U = r * algebra::G2Point::generator();
    // convert to affine coordinate here to avoid doing it twice inside the loop
    U.toAffineCoordinates();

    const auto aadPtr = associatedDataTE.has_value() ? &associatedDataTE.value() : nullptr;

    for ( const auto& commonPublic : commonPublicVector ) {
        algebra::G2Point Y;
        Y = r * commonPublic;

        std::string hash = Hash( Y );
        AES256Key mask = deriveMaskFromHash( hash, version );

        AES256Key V;

        for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
            V[i] = key[i] ^ mask[i];
        }

        std::string vStr = ThresholdUtils::bytesToHexString( V );

        algebra::G1Point W, H;

        H = HashToGroup( U, V, aadPtr );
        W = r * H;

        cipheredKeys.emplace_back( U, V, W, true, version );
    }

    RandSecret randomSecret = r.toByteArray();

    return { cipheredKeys, std::move( randomSecret ) };
}

CipherResult TE::encryptWithAES( const std::vector< uint8_t >& message,
    const algebra::G2Point& commonPublic, const EncryptMetaData& metaData ) {
    return encryptWithAES( message, std::vector< algebra::G2Point >{ commonPublic }, metaData );
}

CipherResult TE::encryptWithAES( const std::vector< uint8_t >& message,
    const std::vector< algebra::G2Point >& commonPublic, const EncryptMetaData& metaData ) {
    return encryptWithAESInternal( message, commonPublic, metaData );
}

CipherResult TE::encryptWithAESDeterministic( const std::vector< uint8_t >& message,
    const algebra::G2Point& commonPublic, const Seed256& seed, const EncryptMetaData& metaData ) {
    return encryptWithAESDeterministic(
        message, std::vector< algebra::G2Point >{ commonPublic }, seed, metaData );
}

CipherResult TE::encryptWithAESDeterministic( const std::vector< uint8_t >& message,
    const std::vector< algebra::G2Point >& commonPublic, const Seed256& seed,
    const EncryptMetaData& metaData ) {
    return encryptWithAESInternal( message, commonPublic, metaData, seed );
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
    return std::make_pair( ciphertextHexa, ciphertext.randomSecret );
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
    const CipheredKey& ciphertext, const algebra::FrScalar& secretKey ) {
    algebra::G2Point retVal = secretKey * ciphertext.U;
    return retVal;
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
    const algebra::G2Point& publicKey, const std::vector< uint8_t >* associatedDataTE ) {
    const auto& U = ciphertext.U;
    const auto& V = ciphertext.V;
    const auto& W = ciphertext.W;

    algebra::G1Point H = HashToGroup( U, V, associatedDataTE );
    // no need to validate ciphertext's pairing - assumed to be validated already via
    // `validateEncryption` call

    bool isSecondPairingValid = algebra::verifyPairingEq( W, publicKey, H, decryptionShare );
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
    const std::vector< algebra::G2Point >& publicKeys,
    const std::vector< std::vector< uint8_t > >* associatedDataTE ) {
    const size_t size = decryptionShares.size();
    const size_t numberOfBatches = ciphertexts.size();

    if ( numberOfBatches == 0 ) {
        throw ThresholdUtils::IncorrectInput( "ciphertexts cannot be empty" );
    }

    if ( size % numberOfBatches != 0 ) {
        throw ThresholdUtils::IncorrectInput(
            "decryption shares size must be multiple of ciphertexts size" );
    }

    if ( size != publicKeys.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "decryption shares and public keys must have same size" );
    }

    // Allow partial AAD: first N AADs apply to first N ciphertexts, rest have no AAD
    if ( associatedDataTE && associatedDataTE->size() > numberOfBatches ) {
        throw ThresholdUtils::IncorrectInput(
            "associated data size cannot exceed number of ciphertexts" );
    }

    std::vector< algebra::G1Point > g1P1s;
    std::vector< algebra::G1Point > g1P2s;
    g1P1s.reserve( ciphertexts.size() );
    g1P2s.reserve( ciphertexts.size() );

    for ( size_t i = 0; i < ciphertexts.size(); ++i ) {
        const auto& U = ciphertexts[i].U;
        const auto& V = ciphertexts[i].V;
        const auto& W = ciphertexts[i].W;
        // Apply AAD only if provided and within AAD vector bounds
        const std::vector< uint8_t >* aadPtr =
            ( associatedDataTE && i < associatedDataTE->size() ) ? &associatedDataTE->at( i ) :
                                                                   nullptr;

        algebra::G1Point H = HashToGroup( U, V, aadPtr );
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
    auto secret = CombineSharesIntoAESKey( decryptionShares, ciphertext.getVersion() );

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
 * @note This is an auxiliar function used by `combineValidatedShares` to combine shares & get
 * original
 * message
 */
AES256Key TE::CombineSharesIntoAESKey(
    const std::vector< std::pair< algebra::G2Point, size_t > >& decryptionShares,
    TEVersion version ) {
    if ( decryptionShares.size() < t_ )
        throw ThresholdUtils::IncorrectInput( "Expect at least t shares to be provided" );
    std::vector< size_t > idx( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        idx[i] = decryptionShares[i].second;
    }

    std::vector< std::reference_wrapper< const algebra::G2Point > > sharesRef;
    for ( size_t i = 0; i < this->t_; ++i ) {
        sharesRef.emplace_back( std::cref( decryptionShares[i].first ) );
    }
    algebra::G2Point rebuiltG2 = algebra::lagrangeInterpolateAt0( idx, this->t_, sharesRef );

    std::string hash = this->Hash( rebuiltG2 );

    return deriveMaskFromHash( hash, version );
}

}  // namespace libBLS
