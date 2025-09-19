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

  @file BLSPublicKeyShare.h
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSPUBLICKEYSHARE_H
#define LIBBLS_BLSPUBLICKEYSHARE_H

#include <bls/bls.h>

namespace libBLS {

class BLSSigShare;

class BLSPublicKeyShare {
private:
    algebra::G2Point publicKey;
    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSPublicKeyShare( const std::vector< std::string >& vec, size_t _requiredSigners,
        size_t _totalSigners );

    BLSPublicKeyShare(
        const algebra::FrScalar& skey, size_t _requiredSigners, size_t _totalSigners );

    const algebra::G2Point& getPublicKey() const;

    bool VerifySig( const std::array< uint8_t, 32 >& hash_ptr,
        const BLSSigShare& sign_ptr, size_t _requiredSigners, size_t _totalSigners );

    bool VerifySigWithHelper( const std::array< uint8_t, 32 >& hash_ptr,
        const BLSSigShare& sign_ptr, size_t _requiredSigners, size_t _totalSigners );

    std::vector< std::string > toString();
};

}  // namespace libBLS

#endif  // LIBBLS_BLSPUBLICKEYSHARE_H
