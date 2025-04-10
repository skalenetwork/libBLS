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

  @file ThresholdEncryption.h
  @author Sidnei Teixeira
  @date 2025
*/

#ifndef LIBBLS_THRESHOLDENCRYPTION_H
#define LIBBLS_THRESHOLDENCRYPTION_H

#include "TEDecryptSet.h"
#include "TEPrivateKeyShare.h"
#include "TEPublicKeyShare.h"
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>
#include <cstddef>

namespace libBLS {

/**
 * @brief Contains all algorthimtic logic for threshold encryption
 * The order of the below function declarations follow the algorithm's natural order
 *
 * @note TEncryption of the actual message is made using an AES key. This key is encrypted using
 * threshold encryption. When this key is decrypted, the original message can be decrypted using the
 * AES key.
 */
class ThresholdEncryption {
public:
    static std::vector< uint8_t > mockupEncrypt( const std::vector< uint8_t >& _message );
    static std::vector< uint8_t > mockupDecrypt( const std::vector< uint8_t >& _encryptedData );

    /**
     * @brief Encrypts a message using a common public key
     * This function generates a random AES key, and encrypts the message using this key
     * This AES key is then encrypted using the common public key from threshold encryption.
     *
     * @param message The message to be encrypted
     * @param common_public The common public key used for encryption.
     * Public key is validated on constructor. Thus it is assumed to be always valid.
     * @return Ciphertext The encrypted message
     */
    static Ciphertext encrypt(
        const std::vector< uint8_t >& _message, const TEPublicKey& _commonPublic );

    /**
     * @brief Validates the encryption of a message (the ciphered AES key)
     *
     * @param ciphertext The encrypted message
     * @param pkey_share The private key share
     * @throws Exceptions in case validation fails
     */
    static void validateEncryption( const CipheredKey& _ciphertext );

    /**
     * @brief Generates a decryption share for the given cyphertext (ciphered AES key)
     *
     * @param cyphertext The encrypted message
     * @param pkey_share The private key share
     * @return TEDecryptionShare The partial decryption share
     */
    static TEDecryptionShare partialDecrypt(
        const CipheredKey& _cyphertext, const TEPrivateKeyShare& _pkeyShare );

    /**
     * @brief Validates a decryption share
     *
     * @param cipherText The encrypted message
     * @param decryption_share The decryption share
     * @throws Exception if the decryption share is not valid
     */
    static void validateDecryptionShare( const CipheredKey& _cipherText,
        const TEDecryptionShare& _decryptionShare, const TEPublicKeyShare& _publicKey );

    /**
     * @brief Combines decryption shares to reconstruct the original AES key.
     * It combines all shares to derive the AES key.
     *
     * @param cyphertext The encrypted AES key
     * @param decryption_set The decryption set containing the decryption shares
     * @return The deciphered AES key in byte array
     * @throws In case ciphertext is corrupted, or decription set is not ready to be merged
     * @note Does not throw error in case there is a corrupted share. But the output
     * will not be the correct deciphered key, since one of the shares is corrupted.
     */
    static AES256Key combineShares( const CipheredKey& _cypheredKey, TEDecryptSet& _decryptionSet );

    /**
     * @brief Validates if the cyphertext corresponds to the given message
     *
     * @param cyphertext The encrypted message
     * @param message The original message
     * @throws IncorrectInput If the cyphertext is too short
     * @throws IsNotWellFormed If the validation fails
     * @throws runtime_exception If the decryption using the AES fails (should only happen if the
     * key is tampered)
     */
    static void validateCombinedDecryption(
        const Ciphertext& _cyphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey );

    /**
     * @brief Decrypts a message using the AES key
     *
     * @param cyphertext The encrypted message
     * @param aesKey The AES key
     * @return std::vector<uint8_t> The decrypted message apart from the random secret
     */
    static std::vector< uint8_t > decrypt(
        const Ciphertext& _cyphertext, const AES256Key& _aesKey );

    /**
     * @brief Validates the cyphertext and decrypts the message
     * Same as calling `validateCombinedDecryption` and `decrypt` in sequence,
     * but avoids deciphering twice - more performant alternative
     */
    static std::vector< uint8_t > validateAndDecrypt(
        const Ciphertext& _cyphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey );


    static inline std::vector< uint8_t > mergeRandomSecretWithMessage(
        std::vector< uint8_t > _message, RandSecret _randomSecret ) {
        _message.insert( _message.end(), _randomSecret.begin(), _randomSecret.end() );
        return _message;
    }

private:
    static std::string bytesToHexaString( const std::vector< uint8_t >& bytes ) {
        std::stringstream ss;
        for ( auto byte : bytes ) {
            ss << std::setw( 2 ) << std::setfill( '0' ) << std::hex << ( int ) byte;
        }
        return ss.str();
    }

    static inline RandSecret extractRandomSecretFromMessage(
        const std::vector< uint8_t >& _message ) {
        size_t msg_length = _message.size();

        if ( msg_length < RANDOM_SECRET_SIZE_BYTES ) {
            throw ThresholdUtils::IncorrectInput( "Message is too short" );
        }

        RandSecret randSecret;
        std::copy_n( _message.end() - RANDOM_SECRET_SIZE_BYTES, RANDOM_SECRET_SIZE_BYTES,
            randSecret.begin() );

        return randSecret;
    }

    /**
     * @brief Deciphers the AES key and validates the message
     * Checks for deciphered message length
     *
     * Helper function
     */
    static std::vector< uint8_t > decipherAESAndValidate(
        const Ciphertext& _ciphertext, const AES256Key& key );
};

}  // namespace libBLS

#endif  // LIBBLS_THRESHOLDENCRYPTION_H
