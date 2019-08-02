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

#ifndef LIBBLS_TEPUBLICKEY_H
#define LIBBLS_TEPUBLICKEY_H

#include "threshold_encryption.h"

class TEPublicKey {
  element_t PublicKey;

  size_t totalSigners;
  size_t requiredSigners;
public:
    TEPublicKey ( std::shared_ptr<std::string> _key_str, size_t  _requiredSigners, size_t _totalSigners );

    encryption::Ciphertext encrypt(const std::shared_ptr<std::string> message);

    ~TEPublicKey();
};


#endif //LIBBLS_TEPUBLICKEY_H
