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

#include "TEPublicKey.h"

#include <iostream>

TEPublicKey::TEPublicKey(std::shared_ptr<std::string> _key_str, size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    if (!_key_str)
        throw std::runtime_error("public key is null");

    encryption::TE te(_requiredSigners, _totalSigners);
    element_t pkey;
    element_init_G1(pkey, te.pairing_);
    element_set_str(pkey, _key_str->c_str(), 10);
    PublicKey = pkey;
    element_clear(pkey);
}

TEPublicKey:: TEPublicKey ( encryption::element_wrapper _pkey, size_t  _requiredSigners, size_t _totalSigners )
    : requiredSigners(_requiredSigners), totalSigners(_totalSigners), PublicKey(_pkey) {

}

encryption::Ciphertext TEPublicKey::encrypt(const std::shared_ptr<std::string> message){
    encryption::TE te(requiredSigners, totalSigners);
    if (element_is0(PublicKey.el_))
        std::runtime_error("Public key is zero");
    return te.Encrypt( *message, PublicKey.el_);
}

encryption::element_wrapper TEPublicKey::getPublicKey() const{
    return PublicKey;
}
