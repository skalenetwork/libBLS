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

  @file TEPrivateKeyShare.h
  @author Sveta Rogova
  @date 2019
*/

#include "TEPrivateKeyShare.h"

TEPrivateKeyShare::TEPrivateKeyShare( std::shared_ptr<std::string> _key_str, size_t _signerIndex,  size_t  _requiredSigners, size_t _totalSigners )
        : signerIndex(_signerIndex), requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    if (!_key_str)
        throw std::runtime_error("private key share is null");

    encryption::TE te(_requiredSigners, _totalSigners);
    element_t pkey;
    element_init_Zr(pkey, te.pairing_);
    element_set_str(pkey, _key_str->c_str(), 10);
    privateKey = pkey;
    element_clear(pkey);
}

TEPrivateKeyShare::TEPrivateKeyShare( encryption::element_wrapper _skey_share, size_t _signerIndex, size_t  _requiredSigners, size_t _totalSigners )
    : signerIndex(_signerIndex), requiredSigners(_requiredSigners), totalSigners(_totalSigners), privateKey(_skey_share) {

}

encryption::element_wrapper TEPrivateKeyShare::decrypt(encryption::Ciphertext& cipher){
    encryption::TE te(requiredSigners, totalSigners);
    element_t  decrypt;
    element_init_G1(decrypt, te.pairing_);
    te.Decrypt(decrypt, cipher, privateKey.el_);
    encryption::element_wrapper decrypted (decrypt);
    element_clear(decrypt);
    return decrypted;
}

size_t TEPrivateKeyShare::getSignerIndex() const {
    return signerIndex;
}

encryption::element_wrapper  TEPrivateKeyShare::getPrivateKey() const{
    return privateKey;
}
