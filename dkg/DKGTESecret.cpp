//
// Created by stan on 16.08.19.
//

#include "DKGTESecret.h"

#include <dkg/dkg_te.h>
#include <threshold_encryption/TEDataSingleton.h>


DKGTESecret::DKGTESecret(size_t _requiredSigners, size_t _totalSigners) : requiredSigners(_requiredSigners),
                                                                          totalSigners(_totalSigners) {

  TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);

  encryption::DkgTe dkg_te(requiredSigners, totalSigners);
  poly = dkg_te.GeneratePolynomial();
}

std::vector <encryption::element_wrapper> DKGTESecret::setPoly(std::vector <encryption::element_wrapper> _poly){
  if (_poly.size() != totalSigners){
    std::runtime_error("Wrong size of vector");
  }
  poly = _poly;
}

std::vector <encryption::element_wrapper> DKGTESecret::getDKGTESecretShares(){
  encryption::DkgTe dkg_te(requiredSigners, totalSigners);
  return dkg_te.CreateSecretKeyContribution(poly);
}

std::vector <encryption::element_wrapper> DKGTESecret::getDKGTEPublicShares(){
  encryption::DkgTe dkg_te(requiredSigners, totalSigners);
  return dkg_te.CreateVerificationVector(poly);
}

encryption::element_wrapper DKGTESecret::getValueAt0(){
  return poly.at(0);
}
