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

#include <cstddef>
#include <threshold_encryption/threshold_encryption.h>
#include "TEPublicKey.h"
#include "TEPrivateKeyShare.h"


/**
 * @brief Contains all algorthimtic logic for threshold encryption
 */
class ThresholdEncryption {

public:
    static libBLS::Ciphertext encrypt(const std::string& message, const TEPublicKey& common_public);

    static bool validateEncryption(const libBLS::Ciphertext& ciphertext, const TEPrivateKeyShare& pkey_share);
    
    static TEDecryptionShare partialDecrypt(const libBLS::Ciphertext& cyphertext, const TEPrivateKeyShare& pkey_share);
    
    static bool validateDecryptionShare(const libBLS::Ciphertext& cipherText, const TEDecryptionShare& decryption_share);
    
    static std::string combineShares(const libBLS::Ciphertext& cyphertext, const std::vector<TEDecryptionShare>& decryption_shares);
};


#endif  // LIBBLS_THRESHOLDENCRYPTION_H
