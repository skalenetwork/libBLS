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

  @file BLSPrivateKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSSigShare.h>
#include <tools/utils.h>

#include <dkg/dkg.h>

namespace libBLS {

BLSPrivateKeyShare::BLSPrivateKeyShare(
    const std::string& _key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    if ( _key.empty() ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Secret key share string is empty" );
    }
    privateKey = algebra::FrScalar::fromString( _key, Base::DEC );

    if ( privateKey.isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey(
            "Secret key share is equal to zero or corrupt" );
    }
}

BLSPrivateKeyShare::BLSPrivateKeyShare(
    const algebra::FrScalar& libff_skey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    privateKey = libff_skey;

    if ( privateKey.isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "BLS Secret key share is equal to zero" );
    }
}

BLSSigShare BLSPrivateKeyShare::sign(
    const std::array< uint8_t, 32 >& hash_byte_arr, size_t _signerIndex ) {
    if ( _signerIndex == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Zero signer index during BLS sign" );
    }

    libBLS::Bls obj( requiredSigners, totalSigners );

    algebra::G1Point hash = algebra::G1Point::fromHash( hash_byte_arr );

    auto ss = obj.Signing( hash, privateKey );
    ss.toAffineCoordinates();

    std::pair< algebra::G1Point, std::string > hash_with_hint =
        libBLS::algebra::hashToG1withHint( hash_byte_arr );
    std::string hint =
        hash_with_hint.first.getY().toString( Base::DEC ) + ":" + hash_with_hint.second;

    return BLSSigShare( ss, hint, _signerIndex, requiredSigners, totalSigners );
}

BLSSigShare BLSPrivateKeyShare::signWithHelper(
    const std::array< uint8_t, 32 >& hash_byte_arr, size_t _signerIndex ) {
    if ( _signerIndex == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Zero signer index" );
    }

    libBLS::Bls obj( requiredSigners, totalSigners );

    std::pair< algebra::G1Point, std::string > hash_with_hint =
        libBLS::algebra::hashToG1withHint( hash_byte_arr );

    auto ss = obj.Signing( hash_with_hint.first, privateKey );
    ss.toAffineCoordinates();

    std::string hint =
        hash_with_hint.first.getY().toString( Base::DEC ) + ":" + hash_with_hint.second;

    return BLSSigShare( ss, hint, _signerIndex, requiredSigners, totalSigners );
}

std::pair< std::vector< BLSPrivateKeyShare >, BLSPublicKey > BLSPrivateKeyShare::generateSampleKeys(
    size_t _requiredSigners, size_t _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    std::vector< BLSPrivateKeyShare > skeys_shares;

    libBLS::Dkg dkg_obj = libBLS::Dkg( _requiredSigners, _totalSigners );
    const std::vector< algebra::FrScalar > pol = dkg_obj.GeneratePolynomial();
    std::vector< algebra::FrScalar > skeys = dkg_obj.SecretKeyContribution( pol );

    algebra::FrScalar common_skey = pol.at( 0 );
    BLSPublicKey pkey_ptr = BLSPublicKey( common_skey, _requiredSigners, _totalSigners );

    for ( size_t i = 0; i < _totalSigners; ++i ) {
        std::string key_str = skeys.at( i ).toString( Base::DEC );
        skeys_shares.push_back( BLSPrivateKeyShare( key_str, _requiredSigners, _totalSigners ) );
    }
    std::pair< std::vector< BLSPrivateKeyShare >, BLSPublicKey > keys( skeys_shares, pkey_ptr );

    return keys;
}

const algebra::FrScalar& BLSPrivateKeyShare::getPrivateKey() const {
    return privateKey;
}

std::string BLSPrivateKeyShare::toString() {
    return privateKey.toString( Base::DEC );
}

}  // namespace libBLS
