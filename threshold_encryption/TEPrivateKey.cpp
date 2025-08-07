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
    std::array< uint8_t, algebra::FrScalar::SIZE_BYTES > privBytes =
        ThresholdUtils::hexCStringToBytesArray< algebra::FrScalar::SIZE_BYTES >(
            _keyStr.c_str() );

    privateKey = algebra::FrScalar::fromBytes( privBytes );

    if ( privateKey.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey( algebra::FrScalar _skey ) : privateKey( _skey ) {
    if ( _skey.isZero() )
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
}

TEPrivateKey::TEPrivateKey( const std::vector< uint8_t > _keyBytes ) {
    privateKey = algebra::FrScalar::fromBytes( _keyBytes );
    if ( privateKey.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey(
    const std::array< uint8_t, algebra::FrScalar::SIZE_BYTES > _keyBytes ) {
    privateKey = algebra::FrScalar::fromBytes( _keyBytes );
    if ( privateKey.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "private key is zero" );
    }
}

std::vector< uint8_t > TEPrivateKey::toBytesVec() const {
    return privateKey.toByteVector();
}

std::array< uint8_t, algebra::FrScalar::SIZE_BYTES > TEPrivateKey::toBytesArray() const {
    return privateKey.toByteArray();
}

std::string TEPrivateKey::toString() const {
    return privateKey.toString( Base::HEXA );
}

const algebra::FrScalar& TEPrivateKey::getPrivateKeyRaw() const {
    return privateKey;
}

}  // namespace libBLS