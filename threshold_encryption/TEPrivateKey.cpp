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

#include <threshold_encryption/TEPrivateKey.h>
#include <tools/utils.h>

TEPrivateKey::TEPrivateKey(
    std::shared_ptr< std::string > _key_str, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str ) {
        throw std::runtime_error( "private key is null" );
    }

    libff::init_alt_bn128_params();

    privateKey = libff::alt_bn128_Fr( _key_str->c_str() );

    if ( privateKey.is_zero() ) {
        throw std::runtime_error( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey(
    libff::alt_bn128_Fr _skey, size_t _requiredSigners, size_t _totalSigners )
    : privateKey( _skey ), requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    if ( _skey.is_zero() )
        throw std::runtime_error( "private key is zero" );
}

std::string TEPrivateKey::toString() const {
    return ThresholdUtils::fieldElementToString( privateKey );
}

libff::alt_bn128_Fr TEPrivateKey::getPrivateKey() const {
    return privateKey;
}
