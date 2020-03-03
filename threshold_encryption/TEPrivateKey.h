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

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_TEPRIVATEKEY_H
#define LIBBLS_TEPRIVATEKEY_H

#include <threshold_encryption/TEDataSingleton.h>
#include <threshold_encryption/threshold_encryption.h>

class TEPrivateKey {
private:
    encryption::element_wrapper privateKey;

    size_t requiredSigners;
    size_t totalSigners;

public:
    TEPrivateKey( std::shared_ptr< std::string > _key_str_ptr, size_t _requiredSigners,
        size_t _totalSigners );

    TEPrivateKey(
        encryption::element_wrapper _skey, size_t _requiredSigners, size_t _totalSigners );

    std::string toString();

    encryption::element_wrapper getPrivateKey() const;
};


#endif  // LIBBLS_TEPRIVATEKEY_H
