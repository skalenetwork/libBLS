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
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSSIGSHARE_H
#define LIBBLS_BLSSIGSHARE_H

#include <bls/bls.h>

class BLSSigShare {
private:
    std::shared_ptr< libff::alt_bn128_G1 > sigShare;

    std::string hint;

    size_t signerIndex;

    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSSigShare( const std::shared_ptr< libff::alt_bn128_G1 >& sigShare, std::string& hint,
        size_t signerIndex, size_t _requiredSigners, size_t _totalSigners );


    BLSSigShare( std::shared_ptr< std::string > _sigShare, size_t signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< libff::alt_bn128_G1 > getSigShare() const;

    size_t getSignerIndex() const;

    std::string getHint() const;

    std::shared_ptr< std::string > toString();
    size_t getTotalSigners() const;
    size_t getRequiredSigners() const;
};


#endif  // LIBBLS_BLSSIGSHARE_H
