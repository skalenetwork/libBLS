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

  @file BLSPublicKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSignature.h"
#include "BLSutils.h"
#include "bls.h"

using namespace std;

BLSPublicKeyShare::BLSPublicKeyShare(const std::shared_ptr<std::vector<std::string> > pkey_str_vect,
                                     size_t _requiredSigners,
                                     size_t _totalSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {

    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    BLSutils::initBLS();
    publicKey = make_shared<libff::alt_bn128_G2>();

    publicKey->X.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(0).c_str());
    publicKey->X.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(1).c_str());
    publicKey->Y.c0 = libff::alt_bn128_Fq(pkey_str_vect->at(2).c_str());
    publicKey->Y.c1 = libff::alt_bn128_Fq(pkey_str_vect->at(3).c_str());
    publicKey->Z.c0 = libff::alt_bn128_Fq::one();
    publicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if (publicKey->X.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->X.c1 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c0 == libff::alt_bn128_Fq::zero() ||
        publicKey->Y.c1 == libff::alt_bn128_Fq::zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Public Key is equal to zero or corrupt"));
    }
}

BLSPublicKeyShare::BLSPublicKeyShare(const libff::alt_bn128_Fr &_skey,
                                     size_t _totalSigners, size_t _requiredSigners)
        : requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
    BLSutils::initBLS();
    if (_skey.is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Secret Key is equal to zero or corrupt"));
    }
    publicKey = make_shared<libff::alt_bn128_G2>(_skey * libff::alt_bn128_G2::one());
}

std::shared_ptr<libff::alt_bn128_G2> BLSPublicKeyShare::getPublicKey() const {
    return publicKey;
}

std::shared_ptr<std::vector<std::string> > BLSPublicKeyShare::toString() {
    std::vector<std::string> pkey_str_vect;

    publicKey->to_affine_coordinates();

    pkey_str_vect.push_back(BLSutils::ConvertToString(publicKey->X.c0));
    pkey_str_vect.push_back(BLSutils::ConvertToString(publicKey->X.c1));
    pkey_str_vect.push_back(BLSutils::ConvertToString(publicKey->Y.c0));
    pkey_str_vect.push_back(BLSutils::ConvertToString(publicKey->Y.c1));

    return make_shared<vector<string>>(pkey_str_vect);
}

bool
BLSPublicKeyShare::VerifySig(std::shared_ptr<std::array<uint8_t, 32> > hash_ptr, std::shared_ptr<BLSSigShare> sign_ptr,
                             size_t _requiredSigners, size_t _totalSigners) {
    std::shared_ptr<signatures::Bls> obj;
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    if (!hash_ptr) {
        BOOST_THROW_EXCEPTION(runtime_error("hash is null"));
    }
    if (!sign_ptr || sign_ptr->getSigShare()->is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Sig share is equal to zero or corrupt"));
    }

    obj = std::make_shared<signatures::Bls>(signatures::Bls(_requiredSigners, _totalSigners));

    bool res = obj->Verification(hash_ptr, *(sign_ptr->getSigShare()), *publicKey);
    return res;
}

bool BLSPublicKeyShare::VerifySigWithHint(std::shared_ptr<std::array<uint8_t, 32> > hash_ptr, std::shared_ptr<BLSSigShare> sign_ptr,
                                          size_t _requiredSigners, size_t _totalSigners) {
    std::shared_ptr<signatures::Bls> obj;
    BLSSignature::checkSigners(_requiredSigners, _totalSigners);
    if (!hash_ptr) {
        BOOST_THROW_EXCEPTION(runtime_error("hash is null"));
    }
    if (!sign_ptr || sign_ptr->getSigShare()->is_zero()) {
        BOOST_THROW_EXCEPTION(runtime_error("Sig share is equal to zero or corrupt"));
    }

    std::string hint = sign_ptr -> getHint();

    std::pair <libff::alt_bn128_Fq , libff::alt_bn128_Fq > y_shift_x = BLSutils::ParseHint(hint);

    libff::alt_bn128_Fq x = BLSutils::HashToFq(hash_ptr);
    x = x + y_shift_x.second;

    libff::alt_bn128_Fq y_sqr = y_shift_x.first ^ 2;
    libff::alt_bn128_Fq x3B = x ^ 3;
    x3B = x3B + libff::alt_bn128_coeff_b;

    if ( y_sqr != x3B) {
        std::cerr<< "NOT G1" << std::endl;
        std::cerr << " X: ";
        x.print();
        std::cerr << " Y: ";
        y_shift_x.first.print();
        std::cerr << "counter:";
        y_shift_x.second.print();

                return false;
    }

    libff::alt_bn128_G1 hash(x, y_shift_x.first, libff::alt_bn128_Fq::one());

    return (libff::alt_bn128_ate_reduced_pairing(*sign_ptr->getSigShare(), libff::alt_bn128_G2::one()) ==
            libff::alt_bn128_ate_reduced_pairing(hash, *publicKey));
}
