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


TEPublicKey::TEPublicKey( const std::vector< std::string >& _keyStrPtr ) {
    if ( _keyStrPtr.size() != 4 ) {
        throw ThresholdUtils::IncorrectInput( "wrong number of components in public key share" );
    }

    std::array< std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >, 4 > components;

    // check each component
    for ( size_t i = 0; i < _keyStrPtr.size(); ++i ) {
        if ( _keyStrPtr[i].length() != MAX_FIELD_ELEMENT_SIZE_BYTES * 2 ) {
            throw ThresholdUtils::IncorrectInput( "wrong string length in public key share" );
        }
        // throws if cannot hexa is not valid
        components[i] = ThresholdUtils::hexCStringToBytesArray<MAX_FIELD_ELEMENT_SIZE_BYTES>( _keyStrPtr[i].c_str() );
    }

    publicKey.Z = libff::alt_bn128_Fq2::one();
    publicKey.X.c0 =
        libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( components[0] );
    publicKey.X.c1 =
        libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( components[1] );
    publicKey.Y.c0 =
        libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( components[2] );
    publicKey.Y.c1 =
        libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( components[3] );

    ThresholdUtils::validateG2( publicKey );
}

TEPublicKey::TEPublicKey( const std::string& _keyStr )
    : TEPublicKey( ThresholdUtils::stringToG2( _keyStr ) ) {}

TEPublicKey::TEPublicKey( const TEPrivateKey& _commonPrivate ) {
    if ( _commonPrivate.getPrivateKeyRaw().is_zero() ) {
        throw libBLS::ThresholdUtils::ZeroSecretKey( "zero key" );
    }

    publicKey = _commonPrivate.getPrivateKeyRaw() * libff::alt_bn128_G2::one();
}

TEPublicKey::TEPublicKey( const libff::alt_bn128_G2& _pkey ) : publicKey( _pkey ) {
    ThresholdUtils::validateG2( publicKey );
}

TEPublicKey::TEPublicKey( const std::array< uint8_t, G2_SIZE_BYTES >& _keyBytes )
    : TEPublicKey( ThresholdUtils::bytesToG2( _keyBytes ) ) {}

TEPublicKey::TEPublicKey( const std::vector< uint8_t >& _keyBytes )
    : TEPublicKey( ThresholdUtils::bytesToG2( _keyBytes ) ) {}

std::string TEPublicKey::toString() const {
    std::vector< std::string > res = ThresholdUtils::G2ToString( publicKey, libBLS::BASE_HEXA );
    std::string concatenated;
    // Nbr of hexa digits = 2 x byte size
    concatenated.reserve( 2 * G2_SIZE_BYTES );
    for ( const auto& str : res ) {
        concatenated += str;
    }

    return concatenated;
}

libff::alt_bn128_G2 TEPublicKey::getPublicKeyRaw() const {
    return publicKey;
}

std::array< uint8_t, G2_SIZE_BYTES > TEPublicKey::toBytesArray() const {
    return libBLS::ThresholdUtils::G2ToBytesArray( publicKey );
}

std::vector< uint8_t > TEPublicKey::toBytesVec() const {
    return libBLS::ThresholdUtils::G2ToBytes( publicKey );
}

}  // namespace libBLS