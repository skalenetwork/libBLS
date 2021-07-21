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

  @file BLSPrivateKey.cpp
  @author Sveta Rogova
  @date 2019
*/

#include "bls.h"
#include <bls/BLSPrivateKey.h>
#include <bls/BLSutils.h>


BLSPrivateKey::BLSPrivateKey(
    const std::shared_ptr< std::string >& _key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSutils::initBLS();

    BLSSignature::checkSigners( _requiredSigners, _totalSigners );
    if ( _key == nullptr ) {
        throw signatures::Bls::IncorrectInput( "Secret key share is null" );
    }
    if ( _key->empty() ) {
        throw signatures::Bls::IncorrectInput( "Secret key share is empty" );
    }

    privateKey = std::make_shared< libff::alt_bn128_Fr >( _key->c_str() );
    if ( *privateKey == libff::alt_bn128_Fr::zero() ) {
        throw signatures::Bls::ZeroSecretKey( "Secret key share is equal to zero or corrupt" );
    }
}

BLSPrivateKey::BLSPrivateKey(
    const std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > > skeys,
    std::shared_ptr< std::vector< size_t > > koefs, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    if ( skeys == nullptr ) {
        throw signatures::Bls::IncorrectInput( "Secret keys ptr is null" );
    }
    if ( koefs == nullptr ) {
        throw signatures::Bls::IncorrectInput( "Signers indices ptr is null" );
    }
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );
    signatures::Bls obj = signatures::Bls( _requiredSigners, _totalSigners );
    std::vector lagrange_koefs = obj.LagrangeCoeffs( *koefs );
    libff::alt_bn128_Fr privateKeyObj( libff::alt_bn128_Fr::zero() );
    for ( size_t i = 0; i < requiredSigners; i++ ) {
        libff::alt_bn128_Fr skey = *skeys->at( koefs->at( i ) - 1 )->getPrivateKey();
        privateKeyObj = privateKeyObj + lagrange_koefs.at( i ) * skey;
    }

    if ( privateKeyObj == libff::alt_bn128_Fr::zero() ) {
        throw signatures::Bls::ZeroSecretKey( "Secret key share is equal to zero or corrupt" );
    }

    privateKey = std::make_shared< libff::alt_bn128_Fr >( privateKeyObj );
}

std::shared_ptr< libff::alt_bn128_Fr > BLSPrivateKey::getPrivateKey() const {
    return privateKey;
}

std::shared_ptr< std::string > BLSPrivateKey::toString() {
    std::shared_ptr< std::string > key_str =
        std::make_shared< std::string >( BLSutils::ConvertToString( *privateKey ) );

    if ( key_str->empty() )
        throw signatures::Bls::ZeroSecretKey( "Secret key share string is empty" );

    return key_str;
}
