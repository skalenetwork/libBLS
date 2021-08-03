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


TEPublicKey::TEPublicKey( std::shared_ptr< std::vector< std::string > > _key_str_ptr,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str_ptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "public key is null" );
    }

    if ( _key_str_ptr->size() != 4 ) {
        throw crypto::ThresholdUtils::IncorrectInput(
            "wrong number of components in public key share" );
    }

    if ( !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 0 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 1 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 2 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 3 ) ) ) {
        throw crypto::ThresholdUtils::IncorrectInput(
            "non-digit symbol or first zero in non-zero public key share" );
    }

    libff::init_alt_bn128_params();

    PublicKey.Z = libff::alt_bn128_Fq2::one();
    PublicKey.X.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 0 ).c_str() );
    PublicKey.X.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 1 ).c_str() );
    PublicKey.Y.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 2 ).c_str() );
    PublicKey.Y.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 3 ).c_str() );

    if ( PublicKey.is_zero() || !PublicKey.is_well_formed() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "corrupted string or zero public key" );
    }
}

TEPublicKey::TEPublicKey(
    TEPrivateKey _common_private, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    if ( _common_private.getPrivateKey().is_zero() ) {
        throw crypto::ThresholdUtils::ZeroSecretKey( "zero key" );
    }

    PublicKey = _common_private.getPrivateKey() * libff::alt_bn128_G2::one();
}

TEPublicKey::TEPublicKey( libff::alt_bn128_G2 _pkey, size_t _requiredSigners, size_t _totalSigners )
    : PublicKey( _pkey ), requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( _pkey.is_zero() || !_pkey.is_well_formed() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "zero or corrupted public key" );
    }
}

crypto::Ciphertext TEPublicKey::encrypt( std::shared_ptr< std::string > mes_ptr ) {
    crypto::TE te( requiredSigners, totalSigners );

    if ( mes_ptr == nullptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Message is null" );
    }

    crypto::Ciphertext cypher = te.Encrypt( *mes_ptr, PublicKey );
    crypto::ThresholdUtils::checkCypher( cypher );

    return std::make_tuple(
        std::get< 0 >( cypher ), std::get< 1 >( cypher ), std::get< 2 >( cypher ) );
}

std::shared_ptr< std::vector< std::string > > TEPublicKey::toString() {
    return std::make_shared< std::vector< std::string > >(
        crypto::ThresholdUtils::G2ToString( PublicKey ) );
}

libff::alt_bn128_G2 TEPublicKey::getPublicKey() const {
    return PublicKey;
}
