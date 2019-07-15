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

    @file BLSSigShare.h
    @author Stan Kladko
    @date 2019
*/

#ifndef LIBBLS_BLSPUBLICKEYSHARE_H
#define LIBBLS_BLSPUBLICKEYSHARE_H

#include <stdlib.h>
#include <string>
#include <memory>

#include "bls.h"
#include "BLSSigShare.h"
#include "BLSPrivateKeyShare.h"

class BLSPublicKeyShare {

    std::shared_ptr< libff::alt_bn128_G2 > publicKey;
    size_t totalSigners;
    size_t requiredSigners;

public:
    BLSPublicKeyShare( const std::string& k1, const std::string& k2, const std::string& k3, const std::string& k4,
                        size_t _totalSigners, size_t _requiredSigners );

    BLSPublicKeyShare(  const libff::alt_bn128_Fr skey,
                       size_t _totalSigners, size_t _requiredSigners );

    BLSPublicKeyShare(  const libff::alt_bn128_G2 pkey,
                        size_t _totalSigners, size_t _requiredSigners );


    std::shared_ptr< libff::alt_bn128_G2 > getPublicKey() const;

    bool VerifySig ( std::shared_ptr< std::string > _msg, std::shared_ptr< BLSSigShare > sign_ptr,
                     size_t _requiredSigners, size_t _totalSigners);

};

#endif // LIBBLS_BLSPUBLICKEYSHARE_H