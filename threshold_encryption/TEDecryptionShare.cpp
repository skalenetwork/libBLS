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

#include <threshold_encryption/TEDecryptionShare.h>
#include <tools/utils.h>

namespace libBLS {

TEDecryptionShare::TEDecryptionShare( size_t _signerIndex, libff::alt_bn128_G2 _share )
    : signerIndex( _signerIndex ), share( _share ) {
    if ( _share.is_zero() ) {
        throw ThresholdUtils::IsNotWellFormed( "decryption share is zero" );
    }
    if ( !_share.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed( "decryption share is not well formed" );
    }
}

TEDecryptionShare::TEDecryptionShare( size_t _signerIndex, const std::string& _hexaEncoded )
    : signerIndex( _signerIndex ) {
    share = ThresholdUtils::stringToG2( _hexaEncoded );
}

size_t TEDecryptionShare::getSignerIndex() const {
    return signerIndex;
}

libff::alt_bn128_G2 TEDecryptionShare::getShareRaw() const {
    return share;
}

bool TEDecryptionShare::validate() const {
    return !share.is_zero() && share.is_well_formed();
}

bool TEDecryptionShare::operator==( const TEDecryptionShare& _other ) const {
    return signerIndex == _other.signerIndex;
}

TEDecryptionShare::operator std::pair< libff::alt_bn128_G2, size_t >() const {
    return std::make_pair( share, signerIndex );
}

std::string TEDecryptionShare::toString() const {
    std::vector< std::string > str = ThresholdUtils::G2ToString( share );
    std::ostringstream oss;
    oss << signerIndex;
    for ( size_t i = 0; i < str.size(); ++i ) {
        if ( i > 0 )
            oss << " ";
        oss << str[i];
    }
    return oss.str();
}

}  // namespace libBLS