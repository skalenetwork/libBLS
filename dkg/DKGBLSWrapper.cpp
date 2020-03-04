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

#include "DKGBLSWrapper.h"

#include <bls/BLSSignature.h>
#include <dkg/dkg.h>

DKGBLSWrapper::DKGBLSWrapper( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    DKGBLSSecret temp( _requiredSigners, _totalSigners );
    dkg_secret_ptr = std::make_shared< DKGBLSSecret >( temp );
}

bool DKGBLSWrapper::VerifyDKGShare( size_t _signerIndex, const libff::alt_bn128_Fr& _share,
    const std::shared_ptr< std::vector< libff::alt_bn128_G2 > >& _verification_vector ) {
    if ( _share.is_zero() )
        throw std::runtime_error( " Zero secret share" );
    if ( _verification_vector == nullptr ) {
        throw std::runtime_error( " Null verification vector" );
    }
    if ( _verification_vector->size() != requiredSigners )
        throw std::runtime_error( "Wrong vector size" );
    signatures::Dkg dkg( requiredSigners, totalSigners );
    return dkg.Verification( _signerIndex, _share, *_verification_vector );
}

void DKGBLSWrapper::setDKGSecret(
    std::shared_ptr< std::vector< libff::alt_bn128_Fr > > _poly_ptr ) {
    if ( _poly_ptr == nullptr )
        throw std::runtime_error( "Null polynomial ptr" );
    dkg_secret_ptr->setPoly( *_poly_ptr );
}

std::shared_ptr< std::vector< libff::alt_bn128_Fr > > DKGBLSWrapper::createDKGSecretShares() {
    return std::make_shared< std::vector< libff::alt_bn128_Fr > >(
        dkg_secret_ptr->getDKGBLSSecretShares() );
}

std::shared_ptr< std::vector< libff::alt_bn128_G2 > > DKGBLSWrapper::createDKGPublicShares() {
    return std::make_shared< std::vector< libff::alt_bn128_G2 > >(
        dkg_secret_ptr->getDKGBLSPublicShares() );
}

BLSPrivateKeyShare DKGBLSWrapper::CreateBLSPrivateKeyShare(
    std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr ) {
    if ( secret_shares_ptr == nullptr )
        throw std::runtime_error( "Null secret_shares_ptr " );

    if ( secret_shares_ptr->size() != totalSigners )
        throw std::runtime_error( "Wrong number of secret key parts " );

    signatures::Dkg dkg( requiredSigners, totalSigners );

    libff::alt_bn128_Fr skey_share = dkg.SecretKeyShareCreate( *secret_shares_ptr );

    return BLSPrivateKeyShare( skey_share, requiredSigners, totalSigners );
}

libff::alt_bn128_Fr DKGBLSWrapper::getValueAt0() {
    return dkg_secret_ptr->getValueAt0();
}
