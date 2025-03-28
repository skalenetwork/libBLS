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

#include <threshold_encryption/TEPublicKeyShare.h>
#include <tools/utils.h>

namespace libBLS {

TEPublicKeyShare::TEPublicKeyShare( std::shared_ptr< std::vector< std::string > > _keyStrPtr,
    size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    if ( !_keyStrPtr ) {
        throw ThresholdUtils::IncorrectInput( "public key share is null" );
    }

    // assume only using affine coordinates
    if ( _keyStrPtr->size() != 4 ) {
        throw ThresholdUtils::IncorrectInput( "wrong number of components in public key share" );
    }

    if ( _signerIndex > _totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Signer index must be <= total signers" );
    }

    if ( !ThresholdUtils::isStringNumber( _keyStrPtr->at( 0 ) ) ||
         !ThresholdUtils::isStringNumber( _keyStrPtr->at( 1 ) ) ||
         !ThresholdUtils::isStringNumber( _keyStrPtr->at( 2 ) ) ||
         !ThresholdUtils::isStringNumber( _keyStrPtr->at( 3 ) ) ) {
        throw ThresholdUtils::IncorrectInput(
            "non-digit symbol or first zero in non-zero public key share" );
    }

    publicKey.Z = libff::alt_bn128_Fq2::one();
    publicKey.X.c0 = libff::alt_bn128_Fq( _keyStrPtr->at( 0 ).c_str() );
    publicKey.X.c1 = libff::alt_bn128_Fq( _keyStrPtr->at( 1 ).c_str() );
    publicKey.Y.c0 = libff::alt_bn128_Fq( _keyStrPtr->at( 2 ).c_str() );
    publicKey.Y.c1 = libff::alt_bn128_Fq( _keyStrPtr->at( 3 ).c_str() );

    ThresholdUtils::validateG2( publicKey );
}

TEPublicKeyShare::TEPublicKeyShare( TEPrivateKeyShare _pKey )
    : TEBase( _pKey.getRequiredSigners(), _pKey.getTotalSigners() ) {
    _pKey.validate();
    publicKey = _pKey.getPrivateKeyRaw() * libff::alt_bn128_G2::one();
    signerIndex = _pKey.getSignerIndex();
}

TEPublicKeyShare::TEPublicKeyShare(
    libff::alt_bn128_G2 _point, size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), publicKey( _point ), signerIndex( _signerIndex ) {
    ThresholdUtils::validateG2( publicKey );
}

std::shared_ptr< std::vector< std::string > > TEPublicKeyShare::toString() const {
    return std::make_shared< std::vector< std::string > >(
        ThresholdUtils::G2ToString( publicKey ) );
}

libff::alt_bn128_G2 TEPublicKeyShare::getPublicKeyRaw() const {
    return publicKey;
}

}  // namespace libBLS