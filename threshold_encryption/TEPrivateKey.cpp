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

namespace libBLS {

TEPrivateKey::TEPrivateKey( std::shared_ptr< std::string > _keyStrPtr ) {
    if ( !_keyStrPtr ) {
        throw ThresholdUtils::IncorrectInput( "private key is null" );
    }

    privateKey = libff::alt_bn128_Fr( _keyStrPtr->c_str() );

    if ( privateKey.is_zero() ) {
        throw ThresholdUtils::IsNotWellFormed( "private key is zero" );
    }
}

TEPrivateKey::TEPrivateKey( libff::alt_bn128_Fr _skey ) : privateKey( _skey ) {
    if ( _skey.is_zero() )
        throw ThresholdUtils::IsNotWellFormed( "private key is zero" );
}

std::string TEPrivateKey::toString() const {
    return ThresholdUtils::fieldElementToString( privateKey );
}

libff::alt_bn128_Fr TEPrivateKey::getPrivateKeyRaw() const {
    return privateKey;
}

}  // namespace libBLS