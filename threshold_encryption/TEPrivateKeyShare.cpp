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

@file TEPrivateKeyShare.h
@author Sveta Rogova
@date 2019
*/

#include <dkg/dkg.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <tools/utils.h>

namespace libBLS {

TEPrivateKeyShare::TEPrivateKeyShare( const std::string& _fieldStr, Base _base, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    if ( _signerIndex > _totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Wrong _signerIndex" );
    }

    privateKey = algebra::FrScalar::fromString( _fieldStr, _base );

    if ( privateKey.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "Zero private key share" );
    }
}

TEPrivateKeyShare::TEPrivateKeyShare( const algebra::FrScalar& _skeyShare, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ),
      privateKey( _skeyShare ),
      signerIndex( _signerIndex ) {
    if ( _signerIndex > _totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Wrong _signerIndex" );
    }

    if ( _skeyShare.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "Zero private key share" );
    }
}

TEPrivateKeyShare::TEPrivateKeyShare( const std::vector< uint8_t >& _bytes, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEPrivateKeyShare(
          algebra::FrScalar::fromBytes( _bytes ), _signerIndex, _requiredSigners, _totalSigners ) {}

TEPrivateKeyShare::TEPrivateKeyShare(
    const std::array< uint8_t, algebra::FrScalar::SIZE_BYTES >& _bytes, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEPrivateKeyShare(
          algebra::FrScalar::fromBytes( _bytes ), _signerIndex, _requiredSigners, _totalSigners ) {}


std::string TEPrivateKeyShare::toString() const {
    return privateKey.toString( Base::DEC );
}

// TODO - should refactor to a single toString method that accepts a Base parameter
std::string TEPrivateKeyShare::toStringHex() const {
    return privateKey.toString( Base::HEXA );
}

size_t TEPrivateKeyShare::getSignerIndex() const {
    return signerIndex;
}

const algebra::FrScalar& TEPrivateKeyShare::getPrivateKeyRaw() const {
    return privateKey;
}

std::vector< uint8_t > TEPrivateKeyShare::toBytesVec() const {
    return privateKey.toByteVector();
}

std::array< uint8_t, algebra::FrScalar::SIZE_BYTES > TEPrivateKeyShare::toBytesArray() const {
    return privateKey.toByteArray();
}

}  // namespace libBLS
