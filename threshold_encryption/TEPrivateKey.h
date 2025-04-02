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
  @date 2025
*/

#ifndef LIBBLS_TEPRIVATEKEY_H
#define LIBBLS_TEPRIVATEKEY_H

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/threshold_encryption.h>

namespace libBLS {

class TEPrivateKey {
private:
    libff::alt_bn128_Fr privateKey;

public:
    TEPrivateKey( const std::string& _keyStr );

    TEPrivateKey( libff::alt_bn128_Fr _skey );

    TEPrivateKey( const std::vector< uint8_t > _keyBytes );

    TEPrivateKey( const std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > _keyBytes );

    std::string toString() const;

    libff::alt_bn128_Fr getPrivateKeyRaw() const;

    std::vector< uint8_t > toBytesVec() const;

    std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > toBytesArray() const;
};

}  // namespace libBLS

#endif  // LIBBLS_TEPRIVATEKEY_H
