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

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_THRESHOLDENCRYPTION_H
#define LIBBLS_THRESHOLDENCRYPTION_H

#include "TEDecryptSet.h"
#include "TEPrivateKeyShare.h"
#include "TEPublicKeyShare.h"
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>
#include <cstddef>


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
    /**
     * @brief Encrypts a message using a common public key
     * This function generates a random AES key, and encrypts the message using this key
     * This AES key is then encrypted using the common public key from threshold encryption.
     *
     * @param message The message to be encrypted
     * @param common_public The common public key used for encryption
     * @return libBLS::Ciphertext The encrypted message
     */
    static libBLS::Ciphertext encrypt(
        const std::string& message, const TEPublicKey& commonPublic );

    /**
     * @brief Validates the encryption of a message (the ciphered AES key)
     *
     * @param ciphertext The encrypted message
     * @param pkey_share The private key share
     * @return bool True if the encryption is valid, false otherwise
     */
    static bool validateEncryption( const libBLS::CipheredKey& ciphertext );

    /**
     * @brief Generates a decryption share for the given cyphertext (ciphered AES key)
     *
     * @param cyphertext The encrypted message
     * @param pkey_share The private key share
     * @return TEDecryptionShare The partial decryption share
     */
    static TEDecryptionShare partialDecrypt(
        const libBLS::CipheredKey& cyphertext, const TEPrivateKeyShare& pkeyShare );

    /**
     * @brief Validates a decryption share
     *
     * @param cipherText The encrypted message
     * @param decryption_share The decryption share
     * @return bool True if the decryption share is valid, false otherwise
     */
    static bool validateDecryptionShare( const libBLS::CipheredKey& cipherText,
        const TEDecryptionShare& decryptionShare, const TEPublicKeyShare& publicKey );

    /**
     * @brief Combines decryption shares to reconstruct the original message.
     * It first combines all shares to derive the AES key, and then uses the AES key to decrypt the
     * message.
     *
     * @param cyphertext The encrypted AES key + encrypted message
     * @param decryption_set The decryption set containing the decryption shares
     * @return std::string The original message
     */
    static std::string combineShares(
        const libBLS::Ciphertext& cyphertext, TEDecryptSet& decryptionSet );

    /**
     * @brief Validates if the cyphertext corresponds to the given message
     *
     * @param cyphertext The encrypted message
     * @param message The original message
     * @return bool True if the message corresponds to the cyphertext. False otherwise.
     */
    static bool validateCombinedDecryption(
        const libBLS::Ciphertext& cyphertext, const std::string& message );
};


#endif  // LIBBLS_THRESHOLDENCRYPTION_H
