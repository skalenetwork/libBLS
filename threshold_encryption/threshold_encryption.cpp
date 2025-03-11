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
#include <valarray>

#include <threshold_encryption.h>
#include <tools/utils.h>

#include "TEBase.h"
#include <openssl/rand.h>
#include <libff/common/profiling.hpp>

namespace libBLS {

TE::TE( const TEBase& base ) : t_( base.getRequiredSigners() ), n_( base.getTotalSigners() ) {
    libff::init_alt_bn128_params();
    libff::inhibit_profiling_info = true;
}

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    libff::init_alt_bn128_params();
    libff::inhibit_profiling_info = true;
}

TE::~TE() {}

void TE::checkCypher( const CipheredKey& cyphertext ) {
    if ( cyphertext.U.is_zero() || cyphertext.W.is_zero() )
        throw ThresholdUtils::IncorrectInput( "zero element in cyphertext" );

    if ( cyphertext.V.length() != 64 )
        throw ThresholdUtils::IncorrectInput( "wrong string length in cyphertext" );
}

std::string TE::Hash(
    const libff::alt_bn128_G2& Y, std::string ( *hash_func )( const std::string& str ) ) {
    auto vectorCoordinates = ThresholdUtils::G2ToString( Y );

    std::string tmp = "";
    for ( const auto& coord : vectorCoordinates ) {
        tmp += coord;
    }

    const std::string sha256hex = hash_func( tmp );

    return sha256hex;
}

libff::alt_bn128_G1 TE::HashToGroup( const libff::alt_bn128_G2& U, const std::string& V,
    std::string ( *hash_func )( const std::string& str ) ) {
    // assumed that U lies in G2

    auto U_str = ThresholdUtils::G2ToString( U );

    const std::string sha256hex = hash_func( U_str[0] + U_str[1] + U_str[2] + U_str[3] + V );

    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();
    std::string hash_str = cryptlite::sha256::hash_hex( sha256hex );
    for ( size_t i = 0; i < 32; ++i ) {
        hash_bytes_arr->at( i ) = static_cast< uint8_t >( hash_str[i] );
    }

    return ThresholdUtils::HashtoG1( hash_bytes_arr );
}

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
 *
 * @note This is an auxiliar function, used within `encryptWithAES`
 */
CipheredKey TE::getCiphertext(
    const std::string& message, const libff::alt_bn128_G2& common_public ) {
    libff::alt_bn128_Fr r = libff::alt_bn128_Fr::random_element();

    while ( r.is_zero() ) {
        r = libff::alt_bn128_Fr::random_element();
    }

    libff::alt_bn128_G2 U, Y;
    U = r * libff::alt_bn128_G2::one();
    Y = r * common_public;

    std::string hash = Hash( Y );

    size_t size = std::max( message.size(), hash.size() );
    std::valarray< uint8_t > lhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        lhs_to_hash[i] = i < hash.size() ? static_cast< uint8_t >( hash[i] ) : 0;
    }

    std::valarray< uint8_t > rhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        rhs_to_hash[i] = i < message.size() ? static_cast< uint8_t >( message[i] ) : 0;
    }

    std::valarray< uint8_t > res = lhs_to_hash ^ rhs_to_hash;

    std::string V;
    V.resize( size );
    for ( size_t i = 0; i < size; ++i ) {
        V[i] = static_cast< uint8_t >( res[i] );
    }

    libff::alt_bn128_G1 W, H;

    H = HashToGroup( U, V );
    W = r * H;

    return { U, V, W };
}

/**
 * @brief Encrypts a message using AES with a randomly generated key and threshold encryption
 *
 * @param message The plaintext message to be encrypted
 * @param common_public The common public key used for threshold encryption (G2 group element)
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
Ciphertext TE::encryptWithAES(
    const std::string& message, const libff::alt_bn128_G2& common_public ) {
    ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    auto encrypted_message = ThresholdUtils::aesEncrypt( message, random_aes_key );

    auto ciphertext = getCiphertext( random_aes_key, common_public );

    return Ciphertext( ciphertext, encrypted_message );
}


/**
 * @brief Encrypts a message using threshold encryption scheme with AES
 * @param message The plaintext message to be encrypted
 * @param common_public_str The common public key in string format
 * @return The encrypted ciphertext as a string
 *
 * This function performs threshold encryption by:
 * 1. Creating a random AES key, and encrypting the message with it
 * 2. Ciphering the AES key using threshold encryption
 * 3. Converting the pair { PubCommKey(AES), AES(cipheredMessage) } to a string
 *
 * The encryption is performed using a combination of elliptic curve cryptography
 * and symmetric AES encryption for efficiency.
 */
std::string TE::encryptMessage( const std::string& message, const std::string& common_public_str ) {
    libff::alt_bn128_G2 common_public = ThresholdUtils::stringToG2( common_public_str );
    auto ciphertext_with_aes = encryptWithAES( message, common_public );
    return aesCiphertextToString( ciphertext_with_aes );
}


/**
 * @brief Generates a decryption share for threshold encryption using a secret key
 *
 * This function creates a decryption share by validating the ciphertext and performing
 * pairing-based cryptographic operations. It implements part of the threshold encryption scheme
 * using the BLS12-381 elliptic curve.
 *
 * @param ciphertext A tuple containing encryption components (U, V, W) where:
 *        - U is an element of G2
 *        - V is the encrypted message (string)
 *        - W is an element of G1
 * This field usually refers to the threshold-encrypted AES key
 * @param secret_key The secret key share (element of Fr) used for decryption
 *
 * @return libff::alt_bn128_G2 The decryption share (U multiplied by the secret key)
 *
 * @throws ThresholdUtils::ZeroSecretKey if the provided secret key is zero
 * @throws ThresholdUtils::IncorrectInput if the ciphertext fails validation checks
 *
 * @note The function verifies the ciphertext integrity using pairing-based checks before generating
 *       the decryption share
 */
libff::alt_bn128_G2 TE::getDecryptionShare(
    const CipheredKey& ciphertext, const libff::alt_bn128_Fr& secret_key ) {
    checkCypher( ciphertext );
    if ( secret_key.is_zero() )
        throw ThresholdUtils::ZeroSecretKey( "zero secret key" );

    auto [U, V, W] = ciphertext;

    libff::alt_bn128_G1 H = HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    if ( !res ) {
        throw ThresholdUtils::IncorrectInput( "cannot decrypt data" );
    }

    libff::alt_bn128_G2 ret_val = secret_key * U;

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
 * @param ciphertext A tuple containing the encryption components (U,V,W)
 * @param decryptionShare The decryption share to verify
 * @param public_key The public key used for verification
 *
 * @return true if both the ciphertext and decryption share are valid
 * @return false if either the ciphertext is invalid or the decryption share verification fails
 */
bool TE::Verify( const CipheredKey& ciphertext, const libff::alt_bn128_G2& decryptionShare,
    const libff::alt_bn128_G2& public_key ) {
    auto [U, V, W] = ciphertext;

    libff::alt_bn128_G1 H = HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    bool ret_val = true;

    if ( res && !decryptionShare.is_zero() ) {
        libff::alt_bn128_GT pp1, pp2;
        pp1 = libff::alt_bn128_ate_reduced_pairing( W, public_key );
        pp2 = libff::alt_bn128_ate_reduced_pairing( H, decryptionShare );

        return pp1 == pp2;
    }

    return false;
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
std::string TE::CombineShares( const CipheredKey& ciphertext,
    const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShares ) {
    auto [U, V, W] = ciphertext;

    libff::alt_bn128_G1 H = this->HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    if ( !res ) {
        throw ThresholdUtils::IncorrectInput( "error during share combining" );
    }

    auto aesKey = CombineSharesIntoAESKey( decryptionShares );
    std::valarray< uint8_t > lhs_to_hash( aesKey.size() );
    for ( size_t i = 0; i < aesKey.size(); ++i ) {
        lhs_to_hash[i] = aesKey[i];
    }

    std::valarray< uint8_t > rhs_to_hash( V.size() );
    for ( size_t i = 0; i < V.size(); ++i ) {
        rhs_to_hash[i] = static_cast< uint8_t >( V[i] );
    }

    std::valarray< uint8_t > xor_res = lhs_to_hash ^ rhs_to_hash;

    std::string message = "";
    for ( size_t i = 0; i < xor_res.size(); ++i ) {
        message += static_cast< char >( xor_res[i] );
    }

    return message;
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
std::vector< uint8_t > TE::CombineSharesIntoAESKey(
    const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShares ) {
    std::vector< size_t > idx( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        idx[i] = decryptionShares[i].second;
    }

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
        ThresholdUtils::LagrangeCoeffs( idx, this->t_ );

    libff::alt_bn128_G2 sum = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < this->t_; ++i ) {
        libff::alt_bn128_G2 temp = lagrange_coeffs[i] * decryptionShares[i].first;

        sum = sum + temp;
    }

    std::string hash = this->Hash( sum );

    std::vector< uint8_t > ret( hash.size() );
    for ( size_t i = 0; i < hash.size(); ++i ) {
        ret[i] = static_cast< uint8_t >( hash[i] );
    }

    return ret;
}

std::string TE::aesCiphertextToString( const Ciphertext& cipher ) {
    ThresholdUtils::initCurve();
    ThresholdUtils::initAES();

    auto [cipheredKey, data] = cipher;
    auto [U, V, W] = cipheredKey;

    std::string v_str = ThresholdUtils::carray2Hex( ( unsigned char* ) ( V.data() ), V.size() );

    std::string encrypted_data = ThresholdUtils::carray2Hex( data->data(), data->size() );

    auto str = ThresholdUtils::G2ToString( U, 16 );
    std::string u_str = "";
    for ( auto& elem : str ) {
        while ( elem.size() < 64 ) {
            elem = "0" + elem;
        }
        u_str += elem;
    }

    W.to_affine_coordinates();
    std::string x = ThresholdUtils::fieldElementToString( W.X, 16 );
    while ( x.size() < 64 ) {
        x = "0" + x;
    }

    std::string y = ThresholdUtils::fieldElementToString( W.Y, 16 );
    while ( y.size() < 64 ) {
        y = "0" + y;
    }

    std::string w_str = x + y;

    return u_str + v_str + w_str + encrypted_data;
}

Ciphertext TE::aesCiphertextFromString( const std::string& ciphertext ) {
    ThresholdUtils::initCurve();
    ThresholdUtils::initAES();

    if ( !ThresholdUtils::checkHex( ciphertext ) ) {
        throw ThresholdUtils::IncorrectInput( "Provided string contains non-hex symbols" );
    }

    if ( ciphertext.size() < 256 + 128 + 128 + 1 ) {
        throw ThresholdUtils::IncorrectInput(
            "Incoming string is too short to convert to aes ciphertext" );
    }

    std::string u_str = ciphertext.substr( 0, 256 );
    std::string v_str = ciphertext.substr( 256, 128 );
    std::string w_str = ciphertext.substr( 256 + 128, 128 );

    std::string encrypted_data = ciphertext.substr( 256 + 128 + 128, std::string::npos );

    uint64_t bin_len;
    std::vector< uint8_t > aes_cipher( encrypted_data.size() / 2 );
    if ( !ThresholdUtils::hex2carray( encrypted_data.data(), &bin_len, &aes_cipher[0] ) ) {
        throw ThresholdUtils::IncorrectInput( "Bad aes_cipher provided" );
    }

    libff::alt_bn128_G2 U = ThresholdUtils::stringToG2( u_str );

    libff::alt_bn128_G1 W = ThresholdUtils::stringToG1( w_str );

    std::string V;
    V.resize( v_str.size() / 2 );
    if ( !ThresholdUtils::hex2carray( v_str.data(), &bin_len, ( unsigned char* ) &V[0] ) ) {
        throw ThresholdUtils::IncorrectInput( "Bad encrypted aes key provided" );
    }

    return Ciphertext( { U, V, W }, aes_cipher );
}

CipheredKey TE::ciphertextFromString( const std::string& ciphertext ) {
    ThresholdUtils::initCurve();
    ThresholdUtils::initAES();

    if ( !ThresholdUtils::checkHex( ciphertext ) ) {
        throw ThresholdUtils::IncorrectInput( "Provided string contains non-hex symbols" );
    }

    if ( ciphertext.size() < 256 + 128 + 128 + 1 ) {
        throw ThresholdUtils::IncorrectInput(
            "Incoming string is too short to convert to aes ciphertext" );
    }

    std::string u_str = ciphertext.substr( 0, 256 );
    std::string v_str = ciphertext.substr( 256, 128 );
    std::string w_str = ciphertext.substr( 256 + 128, 128 );

    libff::alt_bn128_G2 U = ThresholdUtils::stringToG2( u_str );

    libff::alt_bn128_G1 W = ThresholdUtils::stringToG1( w_str );

    std::string V;
    V.resize( v_str.size() / 2 );
    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( v_str.data(), &bin_len, ( unsigned char* ) &V[0] ) ) {
        throw ThresholdUtils::IncorrectInput( "Bad encrypted aes key provided" );
    }

    return { U, V, W };
}

}  // namespace libBLS
