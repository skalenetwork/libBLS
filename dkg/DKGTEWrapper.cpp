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
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file TEPrivateKeyShare.h
  @author Sveta Rogova
  @date 2019
*/


#include <dkg/DKGTEWrapper.h>
#include <tools/utils.h>

DKGTEWrapper::DKGTEWrapper( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    DKGTESecret temp( _requiredSigners, _totalSigners );
    dkg_secret_ptr = std::make_shared< DKGTESecret >( temp );
}

bool DKGTEWrapper::VerifyDKGShare( size_t _signerIndex, const libff::alt_bn128_Fr& _share,
    std::shared_ptr< std::vector< libff::alt_bn128_G2 > > _verification_vector ) {
    if ( _share.is_zero() )
        throw crypto::ThresholdUtils::ZeroSecretKey( "Zero secret share" );
    if ( _verification_vector == nullptr )
        throw crypto::ThresholdUtils::IncorrectInput( "Null verification vector" );
    if ( _verification_vector->size() != requiredSigners )
        throw crypto::ThresholdUtils::IncorrectInput( "Wrong size of verification vector" );
    crypto::Dkg dkg_te( requiredSigners, totalSigners );
    return dkg_te.Verification( _signerIndex, _share, *_verification_vector );
}

void DKGTEWrapper::setDKGSecret( std::shared_ptr< std::vector< libff::alt_bn128_Fr > > _poly_ptr ) {
    if ( _poly_ptr == nullptr )
        throw crypto::ThresholdUtils::IncorrectInput( "Null polynomial ptr" );
    if ( _poly_ptr->size() != requiredSigners )
        throw crypto::ThresholdUtils::IncorrectInput( "Wrong size of polynomial vector" );
    dkg_secret_ptr->setPoly( *_poly_ptr );
}

std::shared_ptr< std::vector< libff::alt_bn128_Fr > > DKGTEWrapper::createDKGSecretShares() {
    return std::make_shared< std::vector< libff::alt_bn128_Fr > >(
        dkg_secret_ptr->getDKGTESecretShares() );
}

std::shared_ptr< std::vector< libff::alt_bn128_G2 > > DKGTEWrapper::createDKGPublicShares() {
    return std::make_shared< std::vector< libff::alt_bn128_G2 > >(
        dkg_secret_ptr->getDKGTEPublicShares() );
}

TEPrivateKeyShare DKGTEWrapper::CreateTEPrivateKeyShare(
    size_t signerIndex_, std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr ) {
    if ( secret_shares_ptr == nullptr )
        throw crypto::ThresholdUtils::IncorrectInput( "Null secret_shares_ptr " );
    if ( secret_shares_ptr->size() != totalSigners )
        throw crypto::ThresholdUtils::IncorrectInput( "Wrong number of secret key parts " );

    crypto::Dkg dkg_te( requiredSigners, totalSigners );

    libff::alt_bn128_Fr skey_share = dkg_te.SecretKeyShareCreate( *secret_shares_ptr );

    return TEPrivateKeyShare( skey_share, signerIndex_, requiredSigners, totalSigners );
}

TEPublicKey DKGTEWrapper::CreateTEPublicKey(
    std::shared_ptr< std::vector< std::vector< libff::alt_bn128_G2 > > > public_shares_all,
    size_t _requiredSigners, size_t _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( public_shares_all == nullptr )
        throw crypto::ThresholdUtils::IncorrectInput( "Null public shares all" );

    libff::alt_bn128_G2 public_key = libff::alt_bn128_G2::zero();

    for ( size_t i = 0; i < _totalSigners; i++ ) {
        public_key = public_key + public_shares_all->at( i ).at( 0 );
    }

    TEPublicKey common_public( public_key, _requiredSigners, _totalSigners );

    return common_public;
}
