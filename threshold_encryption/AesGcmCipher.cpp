/*
  Copyright (C) 2021- SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file AesGcmCipher.cpp
  @author Sidnei Teixeira
  @date 2025
*/

#include "threshold_encryption/AesGcmCipher.h"
#include "tools/utils.h"
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <mutex>

namespace libBLS {

AesGcmCipher::AesGcmCipher() : isDeterministic( false ), encryptCounter( 0 ) {
    initAES();
    // Generate random key
    if ( RAND_bytes( key.data(), key.size() ) != 1 ) {
        throw std::runtime_error( "Failed to generate random key" );
    }
    // IV will be generated randomly on each encrypt() call
    iv.fill( 0 );
}

AesGcmCipher::AesGcmCipher( const AES256Key& rawKey )
    : key( rawKey ), isDeterministic( false ), encryptCounter( 0 ) {
    initAES();
    // IV will be generated randomly on each encrypt() call (or extracted from ciphertext for
    // decrypt)
    iv.fill( 0 );
}

AesGcmCipher::AesGcmCipher( const Seed256& seed ) : isDeterministic( true ), encryptCounter( 0 ) {
    initAES();

    // Use HKDF to derive key deterministically from seed
    // IV will be derived per-encryption using Synthetic IV (HMAC of plaintext)
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_HKDF, nullptr );
    if ( !pctx ) {
        throw std::runtime_error( "Failed to create HKDF context" );
    }

    // Using a scope guard pattern for cleanup
    struct CtxGuard {
        EVP_PKEY_CTX* ctx;
        ~CtxGuard() {
            if ( ctx )
                EVP_PKEY_CTX_free( ctx );
        }
    } guard{ pctx };

    if ( EVP_PKEY_derive_init( pctx ) <= 0 ) {
        throw std::runtime_error( "Failed to initialize HKDF" );
    }
    if ( EVP_PKEY_CTX_set_hkdf_md( pctx, EVP_sha256() ) <= 0 ) {
        throw std::runtime_error( "Failed to set HKDF hash" );
    }
    // Salt is optional but recommended - using a fixed salt for determinism
    static const unsigned char salt[] = "AesGcmCipher-v1";
    if ( EVP_PKEY_CTX_set1_hkdf_salt( pctx, salt, sizeof( salt ) - 1 ) <= 0 ) {
        throw std::runtime_error( "Failed to set HKDF salt" );
    }
    if ( EVP_PKEY_CTX_set1_hkdf_key( pctx, seed.data.data(), seed.data.size() ) <= 0 ) {
        throw std::runtime_error( "Failed to set HKDF key" );
    }
    // Info parameter for domain separation - only deriving the encryption key
    static const unsigned char info[] = "encryption-key";
    if ( EVP_PKEY_CTX_add1_hkdf_info( pctx, info, sizeof( info ) - 1 ) <= 0 ) {
        throw std::runtime_error( "Failed to set HKDF info" );
    }

    size_t outlen = AES_256_KEY_SIZE_BYTES;
    if ( EVP_PKEY_derive( pctx, key.data(), &outlen ) <= 0 || outlen != AES_256_KEY_SIZE_BYTES ) {
        throw std::runtime_error( "Failed to derive key material" );
    }

    // IV is not stored - it will be derived per-encryption from plaintext
    iv.fill( 0 );
}

std::vector< uint8_t > AesGcmCipher::encrypt(
    const std::vector< uint8_t >& plaintext, const std::optional< std::vector< uint8_t > >& aad ) {
    initAES();

    // Make sure there is enough space for: IV + plaintext + padding
    size_t enc_length = AES_GCM_IV_SIZE + plaintext.size() + AES_GCM_TAG_SIZE;

    std::vector< unsigned char > output;
    output.resize( enc_length, '\0' );

    // Compute IV: Synthetic IV (HMAC of plaintext + counter) for deterministic mode, random
    // otherwise
    unsigned char localIv[AES_GCM_IV_SIZE];
    if ( isDeterministic ) {
        // Synthetic IV: HMAC-SHA256(key, plaintext || counter) truncated to 12 bytes
        // Counter ensures same plaintext encrypted multiple times gets different IVs
        // As long as encrypt() is called in the same order, they produce identical output
        unsigned char hmacResult[32];
        unsigned int hmacLen = 0;

        // Create input: plaintext || counter (8 bytes, big-endian)
        // Append counter as 8 bytes in big-endian order
        std::vector< uint8_t > hmacInput( plaintext.begin(), plaintext.end() );
        for ( int byteIndex = 7; byteIndex >= 0; --byteIndex ) {
            hmacInput.push_back(
                static_cast< uint8_t >( ( encryptCounter >> ( byteIndex * 8 ) ) & 0xFF ) );
        }

        if ( !HMAC( EVP_sha256(), key.data(), key.size(), hmacInput.data(), hmacInput.size(),
                 hmacResult, &hmacLen ) ) {
            throw std::runtime_error( "Failed to compute synthetic IV" );
        }
        std::copy( hmacResult, hmacResult + AES_GCM_IV_SIZE, localIv );
        ++encryptCounter;
    } else {
        RAND_bytes( localIv, AES_GCM_IV_SIZE );
    }
    // Place IV at start of output
    std::copy( localIv, localIv + AES_GCM_IV_SIZE, output.begin() );

    // Account offset for the IV already stored in output vec
    size_t offset = AES_GCM_IV_SIZE;
    int outlen = 0;

    UniqueCtx e_ctx( EVP_CIPHER_CTX_new() );
    if ( !e_ctx ) {
        throw std::runtime_error( "Failed to create new EVP_CIPHER_CTX" );
    }

    // Initialize context & select AES-256-GCM (no key/IV yet)
    check( EVP_EncryptInit_ex( e_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr ),
        "Failed to initialize encryption context" );
    // now set IV length if non-default:
    check( EVP_CIPHER_CTX_ctrl( e_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr ),
        "Failed to set IV length" );
    // now actually supply key & IV:
    check( EVP_EncryptInit_ex( e_ctx.get(), nullptr, nullptr, key.data(), localIv ),
        "Failed to set key/IV" );

    // Process AAD if provided (authenticated but not encrypted)
    if ( aad.has_value() && !aad->empty() ) {
        int aad_len = 0;
        check( EVP_EncryptUpdate(
                   e_ctx.get(), nullptr, &aad_len, aad->data(), static_cast< int >( aad->size() ) ),
            "Failed to process AAD" );
    }

    // Cypher data and store in output
    check( EVP_EncryptUpdate( e_ctx.get(), &output[offset], &outlen,
               ( const unsigned char* ) plaintext.data(), plaintext.size() ),
        "Failed to set plaintext length" );
    // offset for the data written
    offset += outlen;
    // Finalize encryption - take care of padding
    check( EVP_EncryptFinal_ex( e_ctx.get(), &output[offset], &outlen ),
        "Failed to finalize encryption" );

    offset += outlen;

    // add authentication tag
    unsigned char tag[AES_GCM_TAG_SIZE];
    check( EVP_CIPHER_CTX_ctrl( e_ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag ),
        "Failed to get authentication tag" );

    std::copy( tag, tag + AES_GCM_TAG_SIZE, output.begin() + offset );
    offset += AES_GCM_TAG_SIZE;

    output.resize( offset );
    return std::vector< uint8_t >( output );
}

std::vector< uint8_t > AesGcmCipher::decrypt(
    const std::vector< uint8_t >& ciphertext, const std::optional< std::vector< uint8_t > >& aad ) {
    initAES();

    constexpr size_t meta = AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;

    if ( ciphertext.size() < meta ) {
        throw ThresholdUtils::IncorrectInput( "Ciphertext is too short" );
    }

    // 1) split into IV / body / tag
    unsigned char iv[AES_GCM_IV_SIZE];
    std::copy( ciphertext.begin(), ciphertext.begin() + AES_GCM_IV_SIZE, iv );

    unsigned char tag[AES_GCM_TAG_SIZE];
    std::copy( ciphertext.end() - AES_GCM_TAG_SIZE, ciphertext.end(), tag );

    const size_t body_len = ciphertext.size() - meta;
    const unsigned char* body_ptr = ciphertext.data() + AES_GCM_IV_SIZE;

    std::vector< unsigned char > plaintext( body_len );
    int len = 0;
    int final_len = 0;

    UniqueCtx d_ctx( EVP_CIPHER_CTX_new() );
    if ( !d_ctx )
        throw std::runtime_error( "Failed to create EVP_CIPHER_CTX" );

    // Initialize for GCM
    check( EVP_DecryptInit_ex( d_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr ),
        "Failed to initialize decryption context" );
    check( EVP_CIPHER_CTX_ctrl( d_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr ),
        "Failed to set IV length" );
    check( EVP_DecryptInit_ex( d_ctx.get(), nullptr, nullptr, key.data(), iv ),
        "Failed to set key/IV" );

    // Process AAD if provided (must match what was used during encryption)
    if ( aad.has_value() && !aad->empty() ) {
        int aad_len = 0;
        check( EVP_DecryptUpdate(
                   d_ctx.get(), nullptr, &aad_len, aad->data(), static_cast< int >( aad->size() ) ),
            "Failed to process AAD" );
    }

    // Decrypt body
    check( EVP_DecryptUpdate( d_ctx.get(), plaintext.data(), &len, body_ptr, body_len ),
        "Failed to decrypt data" );
    // tell GCM the expected tag *before* final
    check( EVP_CIPHER_CTX_ctrl( d_ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag ),
        "Failed to set GCM authentication tag" );
    // finalize — this checks the tag
    check( EVP_DecryptFinal_ex( d_ctx.get(), plaintext.data() + len, &final_len ),
        "Failed to finalize decryption" );

    plaintext.resize( len + final_len );
    return plaintext;
}

void AesGcmCipher::initAES() {
    static std::once_flag initFlag;
    std::call_once( initFlag, []() {
        // initialize openssl ciphers
        OpenSSL_add_all_ciphers();
        // initialize random number generator (for IVs)
        ThresholdUtils::initRAND();
    } );
}

}  // namespace libBLS