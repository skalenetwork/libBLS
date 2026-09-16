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

namespace libBLS {


TEPublicKey::TEPublicKey( const std::vector< std::string >& _keyStrPtr, Base base ) {
    publicKey = algebra::G2Point::fromString( _keyStrPtr, base );
    publicKey.validate();
}

TEPublicKey::TEPublicKey( const std::string& _keyStr, Base base )
    : TEPublicKey( algebra::G2Point::fromString( _keyStr, base ) ) {}

TEPublicKey::TEPublicKey( const TEPrivateKey& _commonPrivate ) {
    if ( _commonPrivate.getPrivateKeyRaw().isZero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "zero key" );
    }

    publicKey = _commonPrivate.getPrivateKeyRaw() * algebra::G2Point::generator();
    publicKey.validate();
}

TEPublicKey::TEPublicKey( const algebra::G2Point& _pkey ) : publicKey( _pkey ) {
    publicKey.validate();
}

TEPublicKey::TEPublicKey( const std::array< uint8_t, algebra::G2Point::SIZE_BYTES >& _keyBytes )
    : TEPublicKey( algebra::G2Point::fromBytes( _keyBytes ) ) {}

TEPublicKey::TEPublicKey( const std::vector< uint8_t >& _keyBytes )
    : TEPublicKey( algebra::G2Point::fromBytes( _keyBytes ) ) {}

std::string TEPublicKey::toString( Base base ) const {
    return publicKey.toString( base );
}

const algebra::G2Point& TEPublicKey::getPublicKeyRaw() const {
    return publicKey;
}

std::array< uint8_t, algebra::G2Point::SIZE_BYTES > TEPublicKey::toBytesArray() const {
    return publicKey.toByteArray();
}

std::vector< uint8_t > TEPublicKey::toBytesVec() const {
    return publicKey.toByteVector();
}

TEPublicKey TEPublicKey::random() {
    return TEPublicKey( algebra::G2Point::random() );
}

}  // namespace libBLS