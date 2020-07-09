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

class BLSSigShare;

class BLSPublicKeyShare {
private:
    std::shared_ptr< libff::alt_bn128_G2 > publicKey;
    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSPublicKeyShare( const std::shared_ptr< std::vector< std::string > >, size_t _requiredSigners,
        size_t _totalSigners );

    BLSPublicKeyShare(
        const libff::alt_bn128_Fr& skey, size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< libff::alt_bn128_G2 > getPublicKey() const;

    bool VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
        std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners );

    bool VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
        std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< std::vector< std::string > > toString();
};

#endif  // LIBBLS_BLSPUBLICKEYSHARE_H
