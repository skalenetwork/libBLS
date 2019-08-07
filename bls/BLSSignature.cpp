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

  @file BLSSignature.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSSignature.h>
#include <bls/BLSutils.h>

std::shared_ptr<libff::alt_bn128_G1> BLSSignature::getSig() const {
    return sig;
}
BLSSignature::BLSSignature(
    const std::shared_ptr<libff::alt_bn128_G1> sig, std::string& _hint, size_t _requiredSigners, size_t _totalSigners)
    : sig(sig), hint(_hint), requiredSigners(_requiredSigners), totalSigners(_totalSigners) {
  checkSigners(_requiredSigners, _totalSigners);
  BLSSignature::checkSigners(requiredSigners, totalSigners);
  if (sig->is_zero()) {
    BOOST_THROW_EXCEPTION(std::runtime_error( "Zero signature"));
  }
}

BLSSignature::BLSSignature(std::shared_ptr<std::string> _sig, size_t _requiredSigners, size_t _totalSigners)
        : totalSigners(_totalSigners),
          requiredSigners(_requiredSigners) {
  BLSSignature::checkSigners(requiredSigners, totalSigners);
  BLSutils::initBLS();

  if (!_sig) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Null _sigShare"));
  }

  if (_sig->size() < 10) {
    BOOST_THROW_EXCEPTION(
            std::runtime_error("Signature too short:" + std::to_string(_sig->size())));
  }

  if (_sig->size() > BLS_MAX_SIG_LEN) {
    BOOST_THROW_EXCEPTION(
            std::runtime_error("Signature too long:" + std::to_string(_sig->size())));
  }

  auto position = _sig->find(":");

  if (position == std::string::npos) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Misformatted sig:" + *_sig));
  }

  std::shared_ptr<std::vector<std::string>> result = BLSutils::SplitString(_sig, ":");
  if (result->size() != 4) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Misformatted signature"));
  }
  for (auto && str : *result){
    for (char& c : str) {
      if (!( c >= '0' && c <= '9')) {
        BOOST_THROW_EXCEPTION(std::runtime_error(
                                      "Misformatted char:" + std::to_string((int)c) + " in component " + str));
      }
    }
  }
  libff::alt_bn128_Fq X(result->at(0).c_str());
  libff::alt_bn128_Fq Y(result->at(1).c_str());
  sig = std::make_shared<libff::alt_bn128_G1>( X, Y,libff::alt_bn128_Fq::one());
  hint = result->at(2) + ":" + result->at(3);
}

std::shared_ptr<std::string> BLSSignature::toString() {
  char str[512];

  sig->to_affine_coordinates();

  gmp_sprintf(str, "%Nd:%Nd:%s", sig->X.as_bigint().data, libff::alt_bn128_Fq::num_limbs,
      sig->Y.as_bigint().data, libff::alt_bn128_Fq::num_limbs, hint.c_str());

  return std::make_shared<std::string>(str);
}
void BLSSignature::checkSigners(size_t _requiredSigners, size_t _totalSigners) {
  if (_requiredSigners > _totalSigners) {
    BOOST_THROW_EXCEPTION(std::runtime_error("_requiredSigners > _totalSigners"));
  }

  if (_totalSigners == 0) {
    BOOST_THROW_EXCEPTION(std::runtime_error("_totalSigners == 0"));
  }
}

std::string BLSSignature::getHint() const{
  return hint;
}

size_t BLSSignature::getTotalSigners() const {
  return totalSigners;
}
size_t BLSSignature::getRequiredSigners() const {
  return requiredSigners;
}
