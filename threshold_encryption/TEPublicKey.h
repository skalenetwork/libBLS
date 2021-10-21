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

#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/threshold_encryption.h>

class TEPublicKey {
private:
    libff::alt_bn128_G2 PublicKey;

    size_t requiredSigners;
    size_t totalSigners;


public:
    TEPublicKey( std::shared_ptr< std::vector< std::string > > _key_str_ptr,
        size_t _requiredSigners, size_t _totalSigners );

    TEPublicKey( libff::alt_bn128_G2 _pkey, size_t _requiredSigners, size_t _totalSigners );

    TEPublicKey( TEPrivateKey _comon_private, size_t _requiredSigners, size_t _totalSigners );

    std::shared_ptr< std::vector< std::string > > toString();

    libBLS::Ciphertext encrypt( std::shared_ptr< std::string > message );

    libff::alt_bn128_G2 getPublicKey() const;
};


#endif  // LIBBLS_TEPUBLICKEY_H
