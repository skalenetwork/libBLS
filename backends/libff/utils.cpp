#pragma once

#include "utils.hpp"

namespace libff_bakcend {

template < size_t N >
std::array< uint8_t, N > hexCStringToBytesArray( const char* hexStr ) {
    size_t characterCountNeeded = N * 2;
    if ( validateHexCString( hexStr ) < characterCountNeeded ) {
        throw IncorrectInput( "Hex string length must be at least 64 characters." );
    }

    std::array< uint8_t, N > bytes;

    // Convert hex string to byte array
    for ( size_t i = 0; i < characterCountNeeded; i += 2 ) {
        bytes[i / 2] = ( std::stoi( std::string( hexStr + i, 2 ), nullptr, 16 ) );
    }

    return bytes;
}


template < class T >
std::string fieldElementToString( const T& field_elem, int base ) {
    mpz_class t;

    field_elem.as_bigint().to_mpz( t.get_mpz_t() );

    std::string output = t.get_str( base );

    if ( base == BASE_HEXA ) {
        const std::size_t width = 64;
        if ( output.length() < width ) {
            output.insert( 0, width - output.length(), '0' );
        }
    }

    return output;
}

}