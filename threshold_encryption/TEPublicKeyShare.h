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

#ifndef LIBBLS_TEPUBLICKEYSHARE_H
#define LIBBLS_TEPUBLICKEYSHARE_H

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/threshold_encryption.h>

namespace libBLS {

class TEPublicKeyShare : TEBase {
private:
    algebra::G2Point publicKey;

    size_t signerIndex;

public:
    TEPublicKeyShare( TEPrivateKeyShare _pKey );

    TEPublicKeyShare( algebra::G2Point _point, size_t signerIndex, size_t _requiredSigners,
        size_t _totalSigners );

    TEPublicKeyShare( const std::vector< uint8_t >& _bytes, size_t signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    TEPublicKeyShare( const std::array< uint8_t, algebra::G2Point::SIZE_BYTES >& bytes, size_t signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    inline void validate() const { ThresholdUtils::validateG2( publicKey ); }

    // std::string toString() const;

    std::vector< uint8_t > toBytesVec() const;

    std::array< uint8_t, algebra::G2Point::SIZE_BYTES > toBytesArray() const;

    const algebra::G2Point& getPublicKeyRaw() const;
};

}  // namespace libBLS

#endif  // LIBBLS_TEPUBLICKEYSHARE_H
