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

TEPublicKeyShare::TEPublicKeyShare( const std::vector< uint8_t >& _bytes, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    publicKey = ThresholdUtils::bytesToG2( _bytes );
    ThresholdUtils::validateG2( publicKey );
}

TEPublicKeyShare::TEPublicKeyShare( const std::array< uint8_t, libBLS::G2_SIZE_BYTES >& bytes,
    size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    publicKey = ThresholdUtils::bytesToG2( bytes );
    ThresholdUtils::validateG2( publicKey );
}

std::vector< uint8_t > TEPublicKeyShare::toBytesVec() const {
    return ThresholdUtils::G2ToBytes( publicKey );
}

std::array< uint8_t, libBLS::G2_SIZE_BYTES > TEPublicKeyShare::toBytesArray() const {
    return ThresholdUtils::G2ToBytesArray( publicKey );
}

libff::alt_bn128_G2 TEPublicKeyShare::getPublicKeyRaw() const {
    return publicKey;
}

}  // namespace libBLS