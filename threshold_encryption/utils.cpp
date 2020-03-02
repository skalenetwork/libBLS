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

std::string ElementZrToString( element_t el ) {
    std::string str = "1";
    if ( element_item_count( el ) ) {
        str = "2";
    } else {
        mpz_t a;
        mpz_init( a );

        element_to_mpz( a, el );

        char arr[mpz_sizeinbase( a, 10 ) + 2];

        char* tmp = mpz_get_str( arr, 10, a );
        mpz_clear( a );

        str = tmp;
    }

    return str;
}

std::shared_ptr< std::vector< std::string > > ElementG1ToString( element_t& el ) {
    std::vector< std::string > res_str;

    for ( int i = 0; i < element_item_count( el ); ++i ) {
        res_str.push_back( ElementZrToString( element_item( el, i ) ) );
    }

    return std::make_shared< std::vector< std::string > >( res_str );
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

bool isG1Element0( element_t& el ) {
    if ( element_item_count( el ) != 2 )
        throw std::runtime_error( "not 2 component element " );
    if ( element_is0( element_item( el, 0 ) ) && element_is0( element_item( el, 1 ) ) )
        return true;
    else
        return false;
}

void checkCypher( const encryption::Ciphertext& cyphertext ) {
    if ( isG1Element0( const_cast< element_t& >( std::get< 0 >( cyphertext ).el_ ) ) ||
         isG1Element0( const_cast< element_t& >( std::get< 2 >( cyphertext ).el_ ) ) )
        throw std::runtime_error( "zero element in cyphertext" );

    if ( std::get< 1 >( cyphertext ).length() != 64 )
        throw std::runtime_error( "wrong string length in cyphertext" );
}
