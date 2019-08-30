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

#include "DKGBLSSecret.h"

#include <dkg/dkg.h>
#include <bls/BLSSignature.h>

DKGBLSSecret::DKGBLSSecret(size_t _requiredSigners, size_t _totalSigners) : requiredSigners(_requiredSigners),
                                                                          totalSigners(_totalSigners) {

  BLSSignature::checkSigners(_requiredSigners, _totalSigners);

  signatures::Dkg dkg(requiredSigners, totalSigners);
  poly = dkg.GeneratePolynomial();
}

void DKGBLSSecret::setPoly(std::vector <libff::alt_bn128_Fr> _poly){
  if (_poly.size() != requiredSigners){
    throw std::runtime_error("Wrong size of vector");
  }
  poly = _poly;
}

std::vector <libff::alt_bn128_Fr> DKGBLSSecret::getDKGBLSSecretShares(){
  signatures::Dkg dkg(requiredSigners, totalSigners);
  return dkg.SecretKeyContribution(poly);
}

std::vector < libff::alt_bn128_G2> DKGBLSSecret::getDKGBLSPublicShares(){
  signatures::Dkg dkg(requiredSigners, totalSigners);
  return dkg.VerificationVector(poly);
}

libff::alt_bn128_Fr DKGBLSSecret::getValueAt0(){
  return poly.at(0);
}
