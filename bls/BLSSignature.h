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

  @file BLSSignature.h
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSSIGNATURE_H
#define LIBBLS_BLSSIGNATURE_H

#include <bls/bls.h>

class BLSSignature {
private:
    std::shared_ptr< libff::alt_bn128_G1 > sig;
    std::string hint;

    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSSignature( std::shared_ptr< std::string > s, size_t _requiredSigners, size_t _totalSigners );
    BLSSignature( const std::shared_ptr< libff::alt_bn128_G1 > sig, std::string& _hint,
        size_t _requiredSigners, size_t _totalSigners );
    std::shared_ptr< libff::alt_bn128_G1 > getSig() const;
    std::shared_ptr< std::string > toString();

    static void checkSigners( size_t _requiredSigners, size_t _totalSigners );
    std::string getHint() const;
    size_t getTotalSigners() const;
    size_t getRequiredSigners() const;
};


#endif  // LIBBLS_BLSSIGNATURE_H
