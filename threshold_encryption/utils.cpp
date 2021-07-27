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
along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

@file utils.cpp
@author Oleh Nikolaiev
@date 2019
*/

#include <threshold_encryption/utils.h>

libff::bigint< num_limbs > modulus = libff::bigint< num_limbs >(
    "8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422"
    "662221423155858769582317459277713367317481324925129998224791" );

void MpzSquareRoot( mpz_t ret_val, mpz_t x ) {
    libff::bigint< num_limbs > to_find_square_root = libff::bigint< num_limbs >(
        "219517769991582813060944549618851245395172079985355205275716334981661890772005"
        "573926965629485566555535578896469239557936481942834182937033123128249955619"
        "8" );  // type_a_Fq(libff::bigint<num_limbs>(x));

    mpz_t deg;
    mpz_init( deg );
    to_find_square_root.to_mpz( deg );

    mpz_t mode;
    mpz_init( mode );
    modulus.to_mpz( mode );

    mpz_powm( ret_val, x, deg, mode );

    mpz_clears( deg, mode, 0 );
}

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
