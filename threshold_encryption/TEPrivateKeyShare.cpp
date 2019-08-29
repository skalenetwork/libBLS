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

#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/utils.h>

TEPrivateKeyShare::TEPrivateKeyShare(std::shared_ptr<std::string> _key_str, size_t _signerIndex,  size_t  _requiredSigners, size_t _totalSigners)
: signerIndex(_signerIndex), requiredSigners(_requiredSigners), totalSigners(_totalSigners) {

  TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);

  if (!_key_str) {
    throw std::runtime_error("private key share is null");
  }

  element_t pkey;
  element_init_Zr(pkey, TEDataSingleton::getData().pairing_);
  element_set_str(pkey, _key_str->c_str(), 10);
  privateKey = encryption::element_wrapper(pkey);
  element_clear(pkey);

  if (element_is0(privateKey.el_)) {
    throw std::runtime_error ("Zero private key share");
  }
}

TEPrivateKeyShare::TEPrivateKeyShare(encryption::element_wrapper _skey_share, size_t _signerIndex, size_t  _requiredSigners, size_t _totalSigners)
: signerIndex(_signerIndex), requiredSigners(_requiredSigners), totalSigners(_totalSigners), privateKey(_skey_share) {

  TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);

 /* if (_signerIndex > _totalSigners) {
    throw std::runtime_error ("Wrong _signerIndex");
  }*/
  if (element_is0(_skey_share.el_)) {
    throw std::runtime_error ("Zero private key share");
  }
}

encryption::element_wrapper TEPrivateKeyShare::decrypt(encryption::Ciphertext& cypher){
  checkCypher(cypher);

  encryption::TE te(requiredSigners, totalSigners);

  element_t  decrypt;
  element_init_G1(decrypt, TEDataSingleton::getData().pairing_);

  te.Decrypt(decrypt, cypher, privateKey.el_);
  encryption::element_wrapper decrypted (decrypt);

  if (isG1Element0(decrypt)) {
    std::runtime_error ("zero decrypt");
  }
  element_clear(decrypt);
  return decrypted;
}

std::string TEPrivateKeyShare::toString() {
  return ElementZrToString(privateKey.el_);
}

size_t TEPrivateKeyShare::getSignerIndex() const {
  return signerIndex;
}

encryption::element_wrapper TEPrivateKeyShare::getPrivateKey() const {
  return privateKey;
}

TEPrivateKeyShare::~TEPrivateKeyShare() {}
