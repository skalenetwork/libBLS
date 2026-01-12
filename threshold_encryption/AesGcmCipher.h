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

  @file AesGcmCipher.h
  @author Sidnei Teixeira
  @date 2025
*/

#ifndef AES_GCM_CIPHER_H
#define AES_GCM_CIPHER_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include "tools/utils.h"

namespace libBLS {

constexpr size_t AES_256_KEY_SIZE_BYTES = 32;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

using AES256Key = std::array< uint8_t, AES_256_KEY_SIZE_BYTES >;


/// -------------------------------
///     EVP_CONTEXT wrapper
/// -------------------------------

struct EvpContextDeleter {
    void operator()( EVP_CIPHER_CTX* ctx ) {
        if ( ctx ) {
            EVP_CIPHER_CTX_free( ctx );
        }
    }
};

using UniqueCtx = std::unique_ptr< EVP_CIPHER_CTX, EvpContextDeleter >;

/// Tag type to distinguish raw key constructor from seed constructor
enum class KeyType { Raw };

class AesGcmCipher {
private:
    AES256Key key;

    // Whether the cipher is deterministic (i.e. uses HKDF to derive key from seed)
    bool isDeterministic;
    // Counter for deterministic IV generation
    uint64_t encryptCounter;
    std::array< uint8_t, AES_GCM_IV_SIZE > iv;

public:
    /// @brief Creates cipher with random key (for encryption)
    AesGcmCipher();

    /// @brief Creates cipher with key derived from seed (for deterministic encryption)
    /// @param seed The seed to derive key from using HKDF
    AesGcmCipher( const std::array< uint8_t, AES_256_KEY_SIZE_BYTES >& seed );

    /// @brief Creates cipher with a known raw key (for decryption)
    /// @param key The raw AES-256 key to use
    /// @param tag KeyType::Raw to indicate this is a raw key, not a seed
    AesGcmCipher( const AES256Key& key, KeyType tag );

    ~AesGcmCipher() = default;

    /// @brief Encrypts the given plaintext using AES-256-GCM
    /// @param plaintext The data to encrypt
    /// @param aad Optional additional authenticated data (not encrypted, but authenticated)
    /// @return Encrypted message
    std::vector< uint8_t > encrypt( const std::vector< uint8_t >& plaintext,
        const std::optional< std::vector< uint8_t > >& aad = std::nullopt );

    /// @brief Decrypts the given ciphertext using AES-256-GCM
    /// @param ciphertext The data to decrypt
    /// @param aad Optional additional authenticated data (must match what was used during
    /// encryption)
    /// @return Decrypted message
    std::vector< uint8_t > decrypt( const std::vector< uint8_t >& ciphertext,
        const std::optional< std::vector< uint8_t > >& aad = std::nullopt );

    /// @brief Returns the AES key (for use as plaintext in threshold encryption)
    /// @return Reference to the 32-byte AES key
    const AES256Key& getKey() const { return key; }

private:
    /// Helper function to check if the operation was successful
    inline void check( int ok, const char* msg ) {
        if ( ok != 1 )
            throw std::runtime_error( msg );
    }

    /// Helper function to initialize AES
    /// @note This function is called once for each `encrypt` / `decrypt`, but internally, only
    ///       the first call will initialize the OpenSSL library.
    /// @note It is thread-safe
    static void initAES();
};

}  // namespace libBLS

#endif  // AES_GCM_CIPHER_H
