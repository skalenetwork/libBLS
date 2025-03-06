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

#ifndef LIBBLS_TEDECRYPTSET_H
#define LIBBLS_TEDECRYPTSET_H

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEDecryptionShare.h>
#include <threshold_encryption/threshold_encryption.h>
#include <unordered_set>

/**
 * @brief A class to manage threshold encryption decryption sets
 * 
 * TEDecryptSet handles partial decryption shares from multiple signers in a threshold encryption scheme.
 * It collects and combines these shares to reconstruct the original encrypted message.
 * 
 * 
 * @details The class maintains a collection of partial decrypts from different participants and provides
 * functionality to merge them once sufficient shares are collected.
 * 
 * @param requiredSigners The minimum number of participants needed for successful decryption
 * @param totalSigners The total number of participants in the system
 */
class TEDecryptSet : public TEBase {
private:
    bool was_merged;

    std::unordered_set< TEDecryptionShare, TEDecryptionShareHash > decrypts;

public:
    TEDecryptSet( size_t _requiredSigners, size_t _totalSigners );


    /**
     * @brief Adds a decryption share to the set
     * @param _signerIndex Index of the signer contributing the decryption share
     * @param _el Decryption share element in G2 group
     */
    void addDecrypt( TEDecryptionShare _share );


    /**
     * @brief Merges the decrypted shares from this DecryptSet with the given ciphertext
     * @param ciphertext The encrypted text to be merged with decryption shares
     * @return The final decrypted message as a string
     * @throw ThresholdEcryptionError if merge operation fails or insufficient valid shares
     */
    std::string merge( const libBLS::Ciphertext& ciphertext );

    std::vector< uint8_t > mergeIntoAESKey();
};


#endif  // LIBBLS_TEDECRYPTSET_H
