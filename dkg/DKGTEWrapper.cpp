//
// Created by stan on 15.08.19.
//

#include "DKGTEWrapper.h"

#include <threshold_encryption/TEDataSingleton.h>

DKGTEWrapper::DKGTEWrapper(size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ){

  TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);

   DKGTESecret temp (_requiredSigners, _totalSigners);
   dkg_secret_ptr = std::make_shared<DKGTESecret>(temp);
}

bool DKGTEWrapper::VerifyDKGShare( size_t _signerIndex, const encryption::element_wrapper& _share,
             const std::vector<encryption::element_wrapper>& _verification_vector){
  if ( element_is0(_share.el_))
    throw std::runtime_error(" Zero secret share");
  encryption::DkgTe dkg_te(requiredSigners, totalSigners);
  return dkg_te.Verify(_signerIndex, _share, _verification_vector);
}

void  DKGTEWrapper::setDKGSecret(std::shared_ptr < std::vector< encryption::element_wrapper>> _poly_ptr){
  if (_poly_ptr == nullptr)
    throw std::runtime_error("Null polynomial ptr");
  dkg_secret_ptr->setPoly(*_poly_ptr);
}

std::shared_ptr < std::vector < encryption::element_wrapper>> DKGTEWrapper::createDKGSecretShares(){
  if (dkg_secret_ptr == nullptr)
    throw std::runtime_error("Null DKG secret");
  return std::make_shared<std::vector< encryption::element_wrapper>>(dkg_secret_ptr->getDKGTESecretShares());
}

std::shared_ptr < std::vector <encryption::element_wrapper>> DKGTEWrapper::createDKGPublicShares(){
  if (dkg_secret_ptr == nullptr)
    throw std::runtime_error("Null DKG secret");
  return std::make_shared<std::vector< encryption::element_wrapper>>(dkg_secret_ptr->getDKGTEPublicShares());
}

TEPrivateKeyShare DKGTEWrapper::CreateTEPrivateKeyShare( size_t signerIndex_, std::shared_ptr<std::vector<encryption::element_wrapper>> secret_shares_ptr){

  if ((*secret_shares_ptr).size() != totalSigners)
    throw std::runtime_error("Wrong number of secret key parts ");

  encryption::DkgTe dkg_te(requiredSigners, totalSigners);

  encryption::element_wrapper skey_share = dkg_te.CreateSecretKeyShare(*secret_shares_ptr);

  return TEPrivateKeyShare(skey_share, signerIndex_, requiredSigners, totalSigners);
}

encryption::element_wrapper DKGTEWrapper::getValueAt0(){
  return dkg_secret_ptr->getValueAt0();
}

