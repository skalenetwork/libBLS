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


BLSPrivateKeyShare::BLSPrivateKeyShare(
    const std::string& _key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    crypto::ThresholdUtils::initCurve();
    if ( _key.empty() ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Secret key share string is empty" );
    }
    privateKey = std::make_shared< libff::alt_bn128_Fr >( _key.c_str() );

    if ( *privateKey == libff::alt_bn128_Fr::zero() ) {
        throw crypto::ThresholdUtils::ZeroSecretKey(
            "Secret key share is equal to zero or corrupt" );
    }
}

BLSPrivateKeyShare::BLSPrivateKeyShare(
    const libff::alt_bn128_Fr& libff_skey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    privateKey = std::make_shared< libff::alt_bn128_Fr >( libff_skey );

    if ( *privateKey == libff::alt_bn128_Fr::zero() ) {
        throw crypto::ThresholdUtils::ZeroSecretKey( "BLS Secret key share is equal to zero" );
    }
}

std::shared_ptr< BLSSigShare > BLSPrivateKeyShare::sign(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr, size_t _signerIndex ) {
    std::shared_ptr< crypto::Bls > obj;

    if ( _signerIndex == 0 ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Zero signer index during BLS sign" );
    }
    if ( hash_byte_arr == nullptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Hash is null during BLS sign" );
    }

    obj = std::make_shared< crypto::Bls >( crypto::Bls( requiredSigners, totalSigners ) );

    libff::alt_bn128_G1 hash = crypto::ThresholdUtils::HashtoG1( hash_byte_arr );

    auto ss = std::make_shared< libff::alt_bn128_G1 >( obj->Signing( hash, *privateKey ) );

    ss->to_affine_coordinates();

    std::pair< libff::alt_bn128_G1, std::string > hash_with_hint =
        obj->HashtoG1withHint( hash_byte_arr );
    std::string hint = crypto::ThresholdUtils::fieldElementToString( hash_with_hint.first.Y ) +
                       ":" + hash_with_hint.second;

    auto s =
        std::make_shared< BLSSigShare >( ss, hint, _signerIndex, requiredSigners, totalSigners );

    return s;
}

std::shared_ptr< BLSSigShare > BLSPrivateKeyShare::signWithHelper(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr, size_t _signerIndex ) {
    std::shared_ptr< crypto::Bls > obj;

    if ( _signerIndex == 0 ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Zero signer index" );
    }
    if ( hash_byte_arr == nullptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Null hash is bls signWithHelper" );
    }

    obj = std::make_shared< crypto::Bls >( crypto::Bls( requiredSigners, totalSigners ) );

    std::pair< libff::alt_bn128_G1, std::string > hash_with_hint =
        obj->HashtoG1withHint( hash_byte_arr );

    auto ss = std::make_shared< libff::alt_bn128_G1 >(
        obj->Signing( hash_with_hint.first, *privateKey ) );

    ss->to_affine_coordinates();

    std::string hint = crypto::ThresholdUtils::fieldElementToString( hash_with_hint.first.Y ) +
                       ":" + hash_with_hint.second;

    auto s =
        std::make_shared< BLSSigShare >( ss, hint, _signerIndex, requiredSigners, totalSigners );

    return s;
}

std::shared_ptr< std::pair< std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >,
    std::shared_ptr< BLSPublicKey > > >
BLSPrivateKeyShare::generateSampleKeys( size_t _requiredSigners, size_t _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    std::vector< std::shared_ptr< BLSPrivateKeyShare > > skeys_shares;

    crypto::Dkg dkg_obj = crypto::Dkg( _requiredSigners, _totalSigners );
    const std::vector< libff::alt_bn128_Fr > pol = dkg_obj.GeneratePolynomial();
    std::vector< libff::alt_bn128_Fr > skeys = dkg_obj.SecretKeyContribution( pol );

    libff::alt_bn128_Fr common_skey = pol.at( 0 );
    std::shared_ptr< BLSPublicKey > pkey_ptr =
        std::make_shared< BLSPublicKey >( common_skey, _requiredSigners, _totalSigners );

    for ( size_t i = 0; i < _totalSigners; ++i ) {
        std::string key_str = crypto::ThresholdUtils::fieldElementToString( skeys.at( i ) );

        std::shared_ptr< BLSPrivateKeyShare > key_ptr =
            std::make_shared< BLSPrivateKeyShare >( key_str, _requiredSigners, _totalSigners );
        skeys_shares.push_back( key_ptr );
    }
    std::pair< std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >,
        std::shared_ptr< BLSPublicKey > >
        keys( std::make_shared< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >(
                  skeys_shares ),
            pkey_ptr );

    return std::make_shared<
        std::pair< std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >,
            std::shared_ptr< BLSPublicKey > > >( keys );
}

std::shared_ptr< libff::alt_bn128_Fr > BLSPrivateKeyShare::getPrivateKey() const {
    CHECK( privateKey );
    return privateKey;
}

std::shared_ptr< std::string > BLSPrivateKeyShare::toString() {
    if ( !privateKey )
        throw crypto::ThresholdUtils::IncorrectInput( "Secret key share is null" );
    if ( *privateKey == libff::alt_bn128_Fr::zero() ) {
        throw crypto::ThresholdUtils::ZeroSecretKey(
            "Secret key share is equal to zero or corrupt" );
    }
    std::shared_ptr< std::string > key_str = std::make_shared< std::string >(
        crypto::ThresholdUtils::fieldElementToString( *privateKey ) );

    if ( key_str->empty() )
        throw crypto::ThresholdUtils::IncorrectInput( "Secret key share string is empty" );
    return key_str;
}
