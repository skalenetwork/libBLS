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

  @file BLSPrivateKeyShare.h
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSPRIVATEKEYSHARE_H
#define LIBBLS_BLSPRIVATEKEYSHARE_H


#include <bls/BLSPublicKey.h>


class BLSSigShare;


class BLSPrivateKeyShare {
protected:
    std::shared_ptr< libff::alt_bn128_Fr > privateKey;

    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSPrivateKeyShare( const std::string& _key, size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< BLSSigShare > sign(
        std::shared_ptr< std::array< uint8_t, 32 > >, size_t _signerIndex );

    std::shared_ptr< BLSSigShare > signWithHelper(
        std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr, size_t _signerIndex );

    BLSPrivateKeyShare( const libff::alt_bn128_Fr&, size_t _requiredSigners, size_t _totalSigners );

    // generate a vector of correct _totalSigners private keys that work together and common public
    // key

    static std::shared_ptr<
        std::pair< std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >,
            std::shared_ptr< BLSPublicKey > > >
    generateSampleKeys( size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< libff::alt_bn128_Fr > getPrivateKey() const;

    std::shared_ptr< std::string > toString();
};


#endif  // LIBBLS_BLSPRIVATEKEYSHARE_H
