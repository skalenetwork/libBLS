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

namespace libBLS {

DKGTEWrapper::DKGTEWrapper( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    DKGTESecret temp( _requiredSigners, _totalSigners );
    dkg_secret_ptr = std::make_shared< DKGTESecret >( temp );
}

bool DKGTEWrapper::VerifyDKGShare( size_t _signerIndex, const algebra::FrScalar& _share,
    std::shared_ptr< std::vector< algebra::G2Point > > _verification_vector ) {
    if ( _share.isZero() )
        throw libBLS::ThresholdUtils::ZeroSecretKey( "Zero secret share" );
    if ( _verification_vector == nullptr )
        throw libBLS::ThresholdUtils::IncorrectInput( "Null verification vector" );
    if ( _verification_vector->size() != requiredSigners )
        throw libBLS::ThresholdUtils::IncorrectInput( "Wrong size of verification vector" );
    libBLS::Dkg dkg_te( requiredSigners, totalSigners );
    return dkg_te.Verification( _signerIndex, _share, *_verification_vector );
}

void DKGTEWrapper::setDKGSecret( std::shared_ptr< std::vector< algebra::FrScalar > > _poly_ptr ) {
    if ( _poly_ptr == nullptr )
        throw libBLS::ThresholdUtils::IncorrectInput( "Null polynomial ptr" );

    dkg_secret_ptr->setPoly( *_poly_ptr );
}

std::shared_ptr< std::vector< algebra::FrScalar > > DKGTEWrapper::createDKGSecretShares() {
    return std::make_shared< std::vector< algebra::FrScalar > >(
        dkg_secret_ptr->getDKGTESecretShares() );
}

std::shared_ptr< std::vector< algebra::G2Point > > DKGTEWrapper::createDKGPublicShares() {
    return std::make_shared< std::vector< algebra::G2Point > >(
        dkg_secret_ptr->getDKGTEPublicShares() );
}

libBLS::TEPrivateKeyShare DKGTEWrapper::CreateTEPrivateKeyShare(
    size_t signerIndex_, std::shared_ptr< std::vector< algebra::FrScalar > > secret_shares_ptr ) {
    if ( secret_shares_ptr == nullptr )
        throw libBLS::ThresholdUtils::IncorrectInput( "Null secret_shares_ptr " );
    if ( secret_shares_ptr->size() != totalSigners )
        throw libBLS::ThresholdUtils::IncorrectInput( "Wrong number of secret key parts " );

    libBLS::Dkg dkg_te( requiredSigners, totalSigners );

    algebra::FrScalar skey_share = dkg_te.SecretKeyShareCreate( *secret_shares_ptr );

    return libBLS::TEPrivateKeyShare( skey_share, signerIndex_, requiredSigners, totalSigners );
}

libBLS::TEPublicKey DKGTEWrapper::CreateTEPublicKey(
    std::shared_ptr< std::vector< std::vector< algebra::G2Point > > > public_shares_all,
    size_t _requiredSigners, size_t _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( public_shares_all == nullptr )
        throw libBLS::ThresholdUtils::IncorrectInput( "Null public shares all" );

    algebra::G2Point public_key = algebra::G2Point::zero();

    for ( size_t i = 0; i < _totalSigners; i++ ) {
        public_key = public_key + public_shares_all->at( i ).at( 0 );
    }

    libBLS::TEPublicKey common_public( public_key );

    return common_public;
}

}  // namespace libBLS
