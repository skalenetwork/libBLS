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
#include <mutex>

namespace libBLS {

std::vector< uint8_t > AesGcmCipher::encrypt(
    const std::vector< uint8_t >& plaintext, const std::optional< std::vector< uint8_t > >& aad ) {
    initAES();

    // Make sure there is enough space for: IV + plaintext + padding
    size_t enc_length = AES_GCM_IV_SIZE + plaintext.size() + AES_GCM_TAG_SIZE;

    std::vector< unsigned char > output;
    output.resize( enc_length, '\0' );

    // Initialize IV vector
    unsigned char iv[AES_GCM_IV_SIZE];
    RAND_bytes( iv, AES_GCM_IV_SIZE );
    // Place IV at start of output
    std::copy( iv, iv + AES_GCM_IV_SIZE, output.begin() );

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
    check( EVP_EncryptInit_ex( e_ctx.get(), nullptr, nullptr, key.data(), iv ),
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