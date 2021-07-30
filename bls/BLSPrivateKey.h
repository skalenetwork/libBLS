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

  @file BLSPrivateKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSPRIVATEKEY_H
#define LIBBLS_BLSPRIVATEKEY_H


#include <bls/BLSPrivateKeyShare.h>
#include <bls/bls.h>


class BLSPrivateKey {
private:
    size_t requiredSigners;
    size_t totalSigners;

    std::shared_ptr< libff::alt_bn128_Fr > privateKey;

public:
    BLSPrivateKey(
        const std::shared_ptr< std::string >& _key, size_t _requiredSigners, size_t _totalSigners );

    BLSPrivateKey( std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >,
        std::shared_ptr< std::vector< size_t > > koefs, size_t _requiredSigners,
        size_t _totalSigners );

    std::shared_ptr< libff::alt_bn128_Fr > getPrivateKey() const;

    std::shared_ptr< std::string > toString();
};


#endif  // LIBBLS_BLSPRIVATEKEY_H
