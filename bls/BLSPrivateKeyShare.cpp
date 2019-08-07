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

  @file BLSPrivateKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSSigShare.h>
#include <bls/BLSSignature.h>

#include  <bls/BLSutils.h>
#include  <dkg/dkg.h>


BLSPrivateKeyShare::BLSPrivateKeyShare(const std::string &_key, size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    BLSutils::initBLS();
    if (_key.empty()) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share string is empty"));
    }
    privateKey = std::make_shared<libff::alt_bn128_Fr>(_key.c_str());

    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share is equal to zero or corrupt"));
    }
}

BLSPrivateKeyShare::BLSPrivateKeyShare(const libff::alt_bn128_Fr& libff_skey,
                             size_t _requiredSigners, size_t _totalSigners) :
        requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    privateKey = std::make_shared<libff::alt_bn128_Fr>(libff_skey);

    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share is equal to zero or corrupt"));
    }
}

std::shared_ptr<BLSSigShare> BLSPrivateKeyShare::sign(std::shared_ptr<std::array< uint8_t, 32>> hash_byte_arr, size_t _signerIndex){
    std::shared_ptr <signatures::Bls> obj;

    if (_signerIndex == 0) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Zero signer index"));
    }

    obj = std::make_shared<signatures::Bls>(signatures::Bls(requiredSigners, totalSigners));

    libff::alt_bn128_G1 hash = obj->HashtoG1(hash_byte_arr);

    auto ss = std::make_shared<libff::alt_bn128_G1>(obj->Signing(hash, *privateKey));

    ss->to_affine_coordinates();

    std::pair<libff::alt_bn128_G1, std::string> hash_with_hint = obj-> HashtoG1withHint(hash_byte_arr);
    std::string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" + hash_with_hint.second;

    auto s = std::make_shared<BLSSigShare>(ss, hint, _signerIndex, requiredSigners, totalSigners);

    return s;
}

std::shared_ptr<BLSSigShare>  BLSPrivateKeyShare::signWithHint(std::shared_ptr<std::array< uint8_t, 32>> hash_byte_arr, size_t _signerIndex){
    std::shared_ptr <signatures::Bls> obj;

    if (_signerIndex == 0) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Zero signer index"));
    }

    obj = std::make_shared<signatures::Bls>(signatures::Bls(requiredSigners, totalSigners));

    std::pair<libff::alt_bn128_G1, std::string> hash_with_hint = obj-> HashtoG1withHint(hash_byte_arr);

    auto ss = std::make_shared<libff::alt_bn128_G1>(obj->Signing(hash_with_hint.first, *privateKey));

    ss->to_affine_coordinates();

    std::string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" + hash_with_hint.second;

    auto s = std::make_shared<BLSSigShare>(ss, hint, _signerIndex, requiredSigners, totalSigners);

    return s;
}

std::shared_ptr<std::pair<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>, std::shared_ptr<BLSPublicKey>>>
BLSPrivateKeyShare::generateSampleKeys(
        size_t _requiredSigners, size_t _totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    std::vector<std::shared_ptr<BLSPrivateKeyShare>> skeys_shares;

    signatures::Dkg dkg_obj = signatures::Dkg(_requiredSigners, _totalSigners);
    const std::vector<libff::alt_bn128_Fr> pol = dkg_obj.GeneratePolynomial();
    std::vector<libff::alt_bn128_Fr> skeys = dkg_obj.SecretKeyContribution(pol);

    libff::alt_bn128_Fr common_skey = pol.at(0);
    std::shared_ptr<BLSPublicKey>pkey_ptr = std::make_shared<BLSPublicKey>(common_skey, _requiredSigners,
                                                                   _totalSigners);

    for (size_t i = 0; i < _totalSigners; ++i) {
        std::string key_str = BLSutils::ConvertToString(skeys.at(i));

        std::shared_ptr <BLSPrivateKeyShare> key_ptr = std::make_shared<BLSPrivateKeyShare>(key_str, _requiredSigners,
                                                                                  _totalSigners);
        skeys_shares.push_back(key_ptr);
    }
    // return ptr to pair  : first is ptr to vector of ptrs to BLSPrivateKeyShare (secret key shares), second is ptr to BLSPublicKey (common public key)
    std::pair<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>, std::shared_ptr<BLSPublicKey>>keys(std::make_shared<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>(skeys_shares), pkey_ptr);

    return std::make_shared<std::pair<std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>>, std::shared_ptr<BLSPublicKey> > >(keys);
}

std::shared_ptr<libff::alt_bn128_Fr> BLSPrivateKeyShare::getPrivateKey() const {
    return privateKey;
}

std::shared_ptr<std::string> BLSPrivateKeyShare::toString() {
    if (!privateKey)
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share is null"));
    if (*privateKey == libff::alt_bn128_Fr::zero()) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share is equal to zero or corrupt"));
    }
    std::shared_ptr<std::string> key_str = std::make_shared<std::string>(BLSutils::ConvertToString(*privateKey));

    if (key_str->empty())
        BOOST_THROW_EXCEPTION(std::runtime_error("Secret key share string is empty"));
    return key_str;
}