/*
    Copyright (C) 2019 SKALE Labs

    This file is part of skale-consensus.

    skale-consensus is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    skale-consensus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with skale-consensus.  If not, see <https://www.gnu.org/licenses/>.

    @file BLSPublicKey.cpp
    @author Stan Kladko
    @date 2019
*/


#include <stdint.h>
#include <string>

using namespace std;



#include "BLSPublicKey.h"
#include "BLSPublicKeyShare.h"
#include "BLSutils.cpp"


BLSPublicKey::BLSPublicKey(const std::shared_ptr<std::vector<std::string> > pkey_str_vect, size_t _requiredSigners,
                           size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {

    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    libffPublicKey = make_shared<libff::alt_bn128_G2>();

    libffPublicKey->X.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(0).c_str());
    libffPublicKey->X.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(1).c_str());
    libffPublicKey->Y.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(2).c_str());
    libffPublicKey->Y.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(3).c_str());
    libffPublicKey->Z.c0 = libff::alt_bn128_Fq::one();
    libffPublicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if (libffPublicKey->X.c0 == libff::alt_bn128_Fq::zero() ||
        libffPublicKey->X.c1 == libff::alt_bn128_Fq::zero() ||
        libffPublicKey->Y.c0 == libff::alt_bn128_Fq::zero() ||
        libffPublicKey->Y.c1 == libff::alt_bn128_Fq::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }
}

BLSPublicKey::BLSPublicKey(const libff::alt_bn128_Fr &skey, size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    libffPublicKey = make_shared<libff::alt_bn128_G2>(skey * libff::alt_bn128_G2::one());
    if (libffPublicKey->is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }
}

size_t BLSPublicKey::getTotalSigners() const {
    return totalSigners;
}

size_t BLSPublicKey::getRequiredSigners() const {
    return requiredSigners;
}

bool BLSPublicKey::VerifySig(std::shared_ptr<std::string> _msg, std::shared_ptr<BLSSignature> sign_ptr,
                             size_t _requiredSigners, size_t _totalSigners) {

    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    if (_msg->empty() || !_msg) {
        BOOST_THROW_EXCEPTION(runtime_error("Message is empty or null"));
    }
    if (!sign_ptr) {
        BOOST_THROW_EXCEPTION(runtime_error("Sognature is null"));
    }

    std::shared_ptr<signatures::Bls> obj;

    obj = std::make_shared<signatures::Bls>(signatures::Bls(_requiredSigners, _totalSigners));

    bool res = obj->Verification(*_msg, *(sign_ptr->getSig()), *libffPublicKey);
    return res;
}

BLSPublicKey::BLSPublicKey(std::shared_ptr<std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > > koefs_pkeys_map,
                           size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);

    signatures::Bls obj = signatures::Bls(requiredSigners, totalSigners);
    if (!koefs_pkeys_map) {
        BOOST_THROW_EXCEPTION(runtime_error("map is null"));
    }

    vector<size_t> participatingNodes;
    vector<libff::alt_bn128_G1> shares;

    for (auto &&item : *koefs_pkeys_map) {
        participatingNodes.push_back(static_cast< uint64_t >( item.first ));
    }

    vector<libff::alt_bn128_Fr> lagrangeCoeffs = obj.LagrangeCoeffs(participatingNodes);

    libff::alt_bn128_G2 key = libff::alt_bn128_G2::zero();
    size_t i = 0;
    for (auto &&item: *koefs_pkeys_map) {
        key = key + lagrangeCoeffs.at(i) * (*item.second->getPublicKey());
        i++;
    }

    libffPublicKey = make_shared<libff::alt_bn128_G2>(key);
    if (libffPublicKey->is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }

}

std::shared_ptr<std::vector<std::string> > BLSPublicKey::toString() {
    std::vector<std::string> pkey_str_vect;

    libffPublicKey->to_affine_coordinates();

    pkey_str_vect.push_back(ConvertToString(libffPublicKey->X.c0));
    pkey_str_vect.push_back(ConvertToString(libffPublicKey->X.c1));
    pkey_str_vect.push_back(ConvertToString(libffPublicKey->Y.c0));
    pkey_str_vect.push_back(ConvertToString(libffPublicKey->Y.c1));

    return make_shared<vector<string>>(pkey_str_vect);
}

std::shared_ptr<libff::alt_bn128_G2> BLSPublicKey::getPublicKey() const {
    return libffPublicKey;
}