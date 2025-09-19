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

  @file BLSPrivateKey.cpp
  @author Sveta Rogova
  @date 2019
*/

#include <bls/BLSPrivateKey.h>
#include <bls/bls.h>
#include <tools/utils.h>

namespace libBLS {

// TODO - should define clearly base of the string
BLSPrivateKey::BLSPrivateKey(
    const std::string& _key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    if ( _key.empty() ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Secret key share is empty" );
    }

    privateKey = algebra::FrScalar::fromString( _key, Base::DEC );
    if ( privateKey.isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey(
            "Secret key share is equal to zero or corrupt" );
    }
}

BLSPrivateKey::BLSPrivateKey(
    const std::vector< BLSPrivateKeyShare >& skeys,
    const std::vector< size_t >& koefs, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {

    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    auto lagrange_koefs = algebra::lagrangeCoeffs( koefs, this->requiredSigners );
    algebra::FrScalar privateKeyObj = algebra::FrScalar::zero();
    for ( size_t i = 0; i < requiredSigners; ++i ) {
        algebra::FrScalar skey = skeys.at( koefs.at( i ) - 1 ).getPrivateKey();
        privateKeyObj = privateKeyObj + lagrange_koefs.at( i ) * skey;
    }

    if ( privateKeyObj.isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey(
            "Secret key share is equal to zero or corrupt" );
    }

    privateKey = privateKeyObj;
}

const algebra::FrScalar& BLSPrivateKey::getPrivateKey() const {
    return privateKey;
}

std::string BLSPrivateKey::toString() {
    return privateKey.toString( Base::DEC );
}

}  // namespace libBLS
