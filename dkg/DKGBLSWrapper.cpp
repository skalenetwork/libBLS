//
// Created by stan on 16.08.19.
//

#include "DKGBLSWrapper.h"

#include <bls/BLSSignature.h>
#include <dkg/dkg.h>

DKGBLSWrapper::DKGBLSWrapper(size_t _requiredSigners, size_t _totalSigners)
        : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ){

  BLSSignature::checkSigners(_requiredSigners, _totalSigners);

  DKGBLSSecret temp (_requiredSigners, _totalSigners);
  dkg_secret_ptr = std::make_shared<DKGBLSSecret>(temp);
}

bool DKGBLSWrapper::VerifyDKGShare( size_t _signerIndex, const libff::alt_bn128_Fr& _share,
                                   const std::vector<libff::alt_bn128_G2>& _verification_vector){
  if ( _share.is_zero())
    throw std::runtime_error(" Zero secret share");
  signatures::Dkg dkg(requiredSigners, totalSigners);
  return dkg.Verification(_signerIndex, _share, _verification_vector);
}

void  DKGBLSWrapper::setDKGSecret(std::shared_ptr < std::vector< libff::alt_bn128_Fr >> _poly_ptr){
  if (_poly_ptr == nullptr)
    throw std::runtime_error("Null polynomial ptr");
  dkg_secret_ptr->setPoly(*_poly_ptr);
}

std::shared_ptr < std::vector < libff::alt_bn128_Fr>> DKGBLSWrapper::createDKGSecretShares(){
  if (dkg_secret_ptr == nullptr)
    throw std::runtime_error("Null DKG secret");
  return std::make_shared<std::vector< libff::alt_bn128_Fr>>(dkg_secret_ptr->getDKGBLSSecretShares());
}

std::shared_ptr < std::vector <libff::alt_bn128_G2>> DKGBLSWrapper::createDKGPublicShares(){
  if (dkg_secret_ptr == nullptr)
    throw std::runtime_error("Null DKG secret");
  return std::make_shared<std::vector< libff::alt_bn128_G2>>(dkg_secret_ptr->getDKGBLSPublicShares());
}

BLSPrivateKeyShare DKGBLSWrapper::CreateBLSPrivateKeyShare(std::shared_ptr<std::vector<libff::alt_bn128_Fr>> secret_shares_ptr){

  if ((*secret_shares_ptr).size() != totalSigners)
    throw std::runtime_error("Wrong number of secret key parts ");

  signatures::Dkg dkg(requiredSigners, totalSigners);

  libff::alt_bn128_Fr skey_share = dkg.SecretKeyShareCreate(*secret_shares_ptr);

  return BLSPrivateKeyShare(skey_share, requiredSigners, totalSigners);
}

libff::alt_bn128_Fr DKGBLSWrapper::getValueAt0(){
  return dkg_secret_ptr->getValueAt0();
}
