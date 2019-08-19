//
// Created by stan on 19.08.19.
//

#include "DKGBLSSecret.h"

#include <dkg/dkg.h>

DKGTESecret::DKGTESecret(size_t _requiredSigners, size_t _totalSigners) : requiredSigners(_requiredSigners),
                                                                          totalSigners(_totalSigners) {

  TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);

  encryption::Dkg dkg(requiredSigners, totalSigners);
  poly = dkg.GeneratePolynomial();
}

std::vector <libff::alt_bn128_Fr> DKGTESecret::setPoly(std::vector <libff::alt_bn128_Fr> _poly){
  if (_poly.size() != totalSigners){
    std::runtime_error("Wrong size of vector");
  }
  poly = _poly;
}

std::vector <libff::alt_bn128_Fr> DKGBLSSecret::getDKGBLSSecretShares(){
  encryption::DkgTe dkg(requiredSigners, totalSigners);
  return dkg.SecretKeyContribution(poly);
}

std::vector < libff::alt_bn128_G2> DKGBLSSecret::getDKGBLSPublicShares(){
  encryption::Dkg dkg(requiredSigners, totalSigners);
  return dkg.VerificationVector(poly);
}

libff::alt_bn128_Fr DKGTESecret::getValueAt0(){
  return poly.at(0);
}