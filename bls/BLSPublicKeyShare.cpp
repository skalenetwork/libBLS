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

  @file BLSPublicKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSSigShare.h>
#include <bls/bls.h>
#include <tools/utils.h>

namespace libBLS {

BLSPublicKeyShare::BLSPublicKeyShare(
    const std::shared_ptr< std::vector< std::string > > pkey_str_vect, size_t _requiredSigners,
    size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    CHECK( pkey_str_vect );

    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libBLS::ThresholdUtils::initCurve(); // TODO - maybe we can get rid of this

    publicKey = std::make_shared< algebra::G2Point >( pkey_str_vect );

    if ( publicKey->is_zero() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS public Key share" );
    }

    if ( !( publicKey->is_well_formed() ) ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Corrupt BLS public key share" );
    }
}

BLSPublicKeyShare::BLSPublicKeyShare(
    const algebra::FrScalar& _skey, size_t _totalSigners, size_t _requiredSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::initCurve();
    if ( _skey.is_zero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "Zero BLS Secret Key" );
    }
    publicKey = std::make_shared< algebra::G2Point >( _skey * algebra::G2Point::one() );
}

std::shared_ptr< algebra::G2Point > BLSPublicKeyShare::getPublicKey() const {
    CHECK( publicKey );
    return publicKey;
}

std::shared_ptr< std::vector< std::string > > BLSPublicKeyShare::toString() {
    return std::make_shared< std::vector< std::string > >( publicKey->toStringVector( libBLS::Base::DEC ) );
}

bool BLSPublicKeyShare::VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    CHECK( hash_ptr );
    CHECK( sign_ptr );

    std::shared_ptr< libBLS::Bls > obj;
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( sign_ptr->getSigShare()->is_zero() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS Sig share" );
    }

    obj = std::make_shared< libBLS::Bls >( libBLS::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification( hash_ptr, *( sign_ptr->getSigShare() ), *publicKey );
    return res;
}

bool BLSPublicKeyShare::VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    CHECK( sign_ptr )

    std::shared_ptr< libBLS::Bls > obj;
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    if ( !hash_ptr ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "hash is null" );
    }
    if ( sign_ptr->getSigShare()->is_zero() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Sig share is equal to zero" );
    }

    std::string hint = sign_ptr->getHint();

    std::pair< algebra::FqElement, algebra::FqElement > y_shift_x =
        libBLS::ThresholdUtils::ParseHint( hint );

    algebra::FqElement x = libBLS::ThresholdUtils::HashToFq( hash_ptr );

    x = x + y_shift_x.second;

    algebra::FqElement y_sqr = y_shift_x.first ^ 2;
    algebra::FqElement x3B = x ^ 3;
    x3B = x3B + libff::alt_bn128_coeff_b;

    if ( y_sqr != x3B ) {
        return false;
    }

    libff::alt_bn128_G1 hash( x.value, y_shift_x.first.value, algebra::FqElement::one().value );

    return algebra::pairing(*sign_ptr->getSigShare(), algebra::G2Point::one() ) ==
             algebra::pairing( hash, *publicKey );
}

}
