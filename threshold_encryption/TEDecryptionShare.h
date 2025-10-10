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

  @file TEDecryptionShare.h
  @author Sidnei Teixeira
  @date 2025
*/

#ifndef LIBBLS_TEDECRYPTIONSHARE_H
#define LIBBLS_TEDECRYPTIONSHARE_H

#include <threshold_encryption/threshold_encryption.h>
#include <cstddef>

namespace libBLS {

/**
 * @brief Represents a single decryption share. That is, the result of some party
 * decrypting a ciphertext using their private key share.
 */
class TEDecryptionShare {
private:
    size_t signerIndex;
    algebra::G2Point share;

public:
    
    /**
     * @param _signerIndex Index of the signer
     * @param _share Decryption share
     * @note Validates that the share is well formed and non-zero.
     */
    TEDecryptionShare( const algebra::G2Point& _share, size_t _signerIndex );

    /**
     * @param _signerIndex Index of the signer
     * @param _hexaEncoded Hexa encoded string of the share
     * @note Used when building from serialized decription share
     */
    TEDecryptionShare( const std::string& _hexaEncoded, size_t _signerIndex );


    size_t getSignerIndex() const;

    const algebra::G2Point& getShareRaw() const;

    /**
     * Basic validation on the share (G2 point)
     */
    void validate() const;

    /**
     * @brief Converts the decryption share to a pair
     */
    operator std::pair< algebra::G2Point, size_t >() const;

    bool operator==( const TEDecryptionShare& _other ) const;

    std::string toString() const;
};

struct TEDecryptionShareHash {
    std::size_t operator()( const TEDecryptionShare& _obj ) const {
        return std::hash< int >()( _obj.getSignerIndex() );
    }
};

}  // namespace libBLS

#endif  // LIBBLS_TEDECRYPTIONSHARE_H