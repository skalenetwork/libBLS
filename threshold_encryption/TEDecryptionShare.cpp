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

@file TEDecryptionShare.h
@author Sidnei Teixeira
@date 2025
*/

#include <threshold_encryption/TEDecryptionShare.h>
#include <tools/utils.h>

namespace libBLS {

TEDecryptionShare::TEDecryptionShare( algebra::G2Point _share, size_t _signerIndex )
    : signerIndex( _signerIndex ), share( _share ) {
    ThresholdUtils::validateG2( share );
}

TEDecryptionShare::TEDecryptionShare( const std::string& _hexaEncoded, size_t _signerIndex )
    : signerIndex( _signerIndex ) {
    share = ThresholdUtils::stringToG2( _hexaEncoded );
    ThresholdUtils::validateG2( share );
}

size_t TEDecryptionShare::getSignerIndex() const {
    return signerIndex;
}

algebra::G2Point TEDecryptionShare::getShareRaw() const {
    return share;
}

void TEDecryptionShare::validate() const {
    ThresholdUtils::validateG2( share );
}

bool TEDecryptionShare::operator==( const TEDecryptionShare& _other ) const {
    return signerIndex == _other.signerIndex;
}

TEDecryptionShare::operator std::pair< algebra::G2Point, size_t >() const {
    return std::make_pair( share, signerIndex );
}

std::string TEDecryptionShare::toString() const {
    std::vector< std::string > str = share.toStringVector( Base::HEXA );
    std::ostringstream oss;
    for ( size_t i = 0; i < str.size(); ++i ) {
        oss << str[i];
    }

    std::string s = oss.str();

    return s;
}

}  // namespace libBLS