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

@file utils.cpp
@author Oleh Nikolaiev
@date 2019
*/

#include <threshold_encryption/utils.h>

bool isStringNumber( std::string& str ) {
    if ( str.at( 0 ) == '0' && str.length() > 1 )
        return false;
    for ( char& c : str ) {
        if ( !( c >= '0' && c <= '9' ) ) {
            return false;
        }
    }
    return true;
}

void checkCypher( const encryption::Ciphertext& cyphertext ) {
    if ( std::get< 0 >( cyphertext ).is_zero() || std::get< 2 >( cyphertext ).is_zero() )
        throw std::runtime_error( "zero element in cyphertext" );

    if ( std::get< 1 >( cyphertext ).length() != 64 )
        throw std::runtime_error( "wrong string length in cyphertext" );
}
