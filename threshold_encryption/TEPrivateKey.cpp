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
@date 2025
*/

#include <threshold_encryption/TEPrivateKey.h>
#include <tools/utils.h>

namespace libBLS {

TEPrivateKey::TEPrivateKey( const std::string& _keyStr ) {
    
    // already validates the string
    std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes =
        ThresholdUtils::hexCStringToBytesArray<libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES>( _keyStr.c_str() );

    privateKey = ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fr >( privBytes );

    if ( privateKey.is_zero() ) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey( libff::alt_bn128_Fr _skey ) : privateKey( _skey ) {
    if ( _skey.is_zero() )
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
}

TEPrivateKey::TEPrivateKey( const std::vector< uint8_t > _keyBytes ) {
    privateKey = ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fr >( _keyBytes );
    if (privateKey.is_zero()) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey( const std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > _keyBytes ) {
    privateKey = ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fr >( _keyBytes );
    if (privateKey.is_zero()) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

std::vector< uint8_t > TEPrivateKey::toBytesVec() const {
    return ThresholdUtils::fieldElementToBytes( privateKey );
}

std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > TEPrivateKey::toBytesArray() const {
    return ThresholdUtils::fieldElementToBytesArray( privateKey );
}

std::string TEPrivateKey::toString() const {
    return ThresholdUtils::fieldElementToString( privateKey, BASE_HEXA );
}

libff::alt_bn128_Fr TEPrivateKey::getPrivateKeyRaw() const {
    return privateKey;
}

}  // namespace libBLS