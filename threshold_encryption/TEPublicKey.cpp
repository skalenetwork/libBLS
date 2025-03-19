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

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/

#include <threshold_encryption/TEPublicKey.h>
#include <tools/utils.h>

#include <iostream>
#include <utility>


TEPublicKey::TEPublicKey( std::shared_ptr< std::vector< std::string > > _keyStrPtr,
    size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ) {
    if ( !_keyStrPtr ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "public key is null" );
    }

    if ( _keyStrPtr->size() != 4 ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "wrong number of components in public key share" );
    }

    if ( !libBLS::ThresholdUtils::isStringNumber( _keyStrPtr->at( 0 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _keyStrPtr->at( 1 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _keyStrPtr->at( 2 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _keyStrPtr->at( 3 ) ) ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "non-digit symbol or first zero in non-zero public key share" );
    }

    publicKey.Z = libff::alt_bn128_Fq2::one();
    publicKey.X.c0 = libff::alt_bn128_Fq( _keyStrPtr->at( 0 ).c_str() );
    publicKey.X.c1 = libff::alt_bn128_Fq( _keyStrPtr->at( 1 ).c_str() );
    publicKey.Y.c0 = libff::alt_bn128_Fq( _keyStrPtr->at( 2 ).c_str() );
    publicKey.Y.c1 = libff::alt_bn128_Fq( _keyStrPtr->at( 3 ).c_str() );

    if ( publicKey.is_zero() || !publicKey.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "corrupted string or zero public key" );
    }
}

TEPublicKey::TEPublicKey( TEPrivateKey _commonPrivate )
    : TEBase( _commonPrivate.getRequiredSigners(), _commonPrivate.getTotalSigners() ) {
    if ( _commonPrivate.getPrivateKeyRaw().is_zero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "zero key" );
    }

    publicKey = _commonPrivate.getPrivateKeyRaw() * libff::alt_bn128_G2::one();
}

TEPublicKey::TEPublicKey( libff::alt_bn128_G2 _pkey, size_t _requiredSigners, size_t _totalSigners )
    : publicKey( _pkey ), TEBase( _requiredSigners, _totalSigners ) {
    if ( _pkey.is_zero() || !_pkey.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "zero or corrupted public key" );
    }
}

std::shared_ptr< std::vector< std::string > > TEPublicKey::toString() {
    return std::make_shared< std::vector< std::string > >(
        libBLS::ThresholdUtils::G2ToString( publicKey ) );
}

libff::alt_bn128_G2 TEPublicKey::getPublicKeyRaw() const {
    return publicKey;
}
