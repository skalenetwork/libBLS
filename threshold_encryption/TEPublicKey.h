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

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_TEPUBLICKEY_H
#define LIBBLS_TEPUBLICKEY_H

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/threshold_encryption.h>

namespace libBLS {

class TEPublicKey {
private:
    libff::alt_bn128_G2 publicKey;

public:
    TEPublicKey( const libff::alt_bn128_G2& _pkey );

    /**
     * @brief Construct a public key from a vector of strings,
     * each representing a coordinate of the public key in
     * hexadecimal format.
     */
    TEPublicKey( const std::vector< std::string >& _keyStrPtr );

    /**
     * @brief Construct a public key from a string containing
     * the 4 components concatenated, and encoded in hexadecimal
     * format.
     */
    TEPublicKey( const std::string& _keyStr );

    TEPublicKey( const TEPrivateKey& _comonPrivate );

    TEPublicKey( const std::array< uint8_t, G2_SIZE_BYTES >& _keyBytes );

    TEPublicKey( const std::vector< uint8_t >& _keyBytes );

    /**
     * @brief Returns the public key as a single string, with
     * with all 4 components concatenated and encoded in hexadecimal.AES256Key
     * String size is always 256 characters long.
     */
    std::string toString();

    std::array< uint8_t, G2_SIZE_BYTES > toBytesArray() const;

    std::vector< uint8_t > toBytesVec() const;

    libff::alt_bn128_G2 getPublicKeyRaw() const;
};

}  // namespace libBLS

#endif  // LIBBLS_TEPUBLICKEY_H
