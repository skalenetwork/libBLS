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

#ifndef LIBBLS_TEDECRYPTIONSHARE_H
#define LIBBLS_TEDECRYPTIONSHARE_H

#include <cstddef>
#include <threshold_encryption/threshold_encryption.h>

/**
 * @brief Represents a single decryption share
 */
class TEDecryptionShare {
private:
    size_t signerIndex;
    libff::alt_bn128_G2 share;

public:

    /**
     * @brief Validates that the share is well formed and non-zero. 
     * @param _signerIndex Index of the signer
     * @param _share Decryption share
     * 
     * @note This creates a contract of correctness for each TEDecryptionShare 
     * object in-memory. It can thereafter be assumed for each TEDecryptionShare 
     * object to be correct syntatically.
     */
    TEDecryptionShare( size_t _signerIndex, libff::alt_bn128_G2 _share );

    size_t getSignerIndex() const;

    libff::alt_bn128_G2 getShareRaw() const;

    bool validate() const;

    /**
     * @brief Converts the decryption share to a pair
     */
    operator std::pair<libff::alt_bn128_G2, size_t>() const;

    bool operator==(const TEDecryptionShare& other) const;

    std::string toString() const;
};

struct TEDecryptionShareHash {
    std::size_t operator()(const TEDecryptionShare& obj) const {
        return std::hash<int>()(obj.getSignerIndex());
    }
};


#endif  // LIBBLS_TEDECRYPTIONSHARE_H
