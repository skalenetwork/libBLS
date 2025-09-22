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
    const std::vector< std::string >& pkey_str_vect, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    publicKey = algebra::G2Point::fromString( pkey_str_vect, Base::DEC );

    if ( publicKey.isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS public Key share" );
    }

    if ( !( publicKey.isWellFormed() ) ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Corrupt BLS public key share" );
    }
}

BLSPublicKeyShare::BLSPublicKeyShare(
    const algebra::FrScalar& _skey, size_t _totalSigners, size_t _requiredSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    if ( _skey.isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "Zero BLS Secret Key" );
    }
    publicKey = _skey * algebra::G2Point::generator();
}

const algebra::G2Point& BLSPublicKeyShare::getPublicKey() const {
    return publicKey;
}

std::vector< std::string > BLSPublicKeyShare::toString() {
    return publicKey.toStringVector( libBLS::Base::DEC );
}

bool BLSPublicKeyShare::VerifySig( const std::array< uint8_t, 32 >& hash_ptr,
    const BLSSigShare& sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( sign_ptr.getSigShare().isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS Sig share" );
    }

    libBLS::Bls obj = libBLS::Bls( _requiredSigners, _totalSigners );

    bool res = obj.Verify( hash_ptr, sign_ptr.getSigShare(), publicKey );
    return res;
}

// TODO - this function is replicated in BLSPublicKey - refactor it
bool BLSPublicKeyShare::VerifySigWithHelper( const std::array< uint8_t, 32 >& hash_ptr,
    const BLSSigShare& sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    std::shared_ptr< libBLS::Bls > obj;
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( sign_ptr.getSigShare().isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Sig share is equal to zero" );
    }

    std::string hint = sign_ptr.getHint();

    std::pair< algebra::FqElement, algebra::FqElement > y_shift_x = algebra::parseHint( hint );

    algebra::FqElement x = algebra::hashToFq( hash_ptr );

    x = x + y_shift_x.second;

    algebra::FqElement y_sqr = y_shift_x.first ^ 2;
    algebra::FqElement x3B = x ^ 3;
    x3B = x3B + algebra::AltBn128Contract::coeffB();

    if ( y_sqr != x3B ) {
        return false;
    }

    algebra::G1Point hash( x, y_shift_x.first, algebra::FqElement::one() );

    return algebra::verifyPairingEq(
        sign_ptr.getSigShare(), algebra::G2Point::generator(), hash, publicKey );
}

}  // namespace libBLS
