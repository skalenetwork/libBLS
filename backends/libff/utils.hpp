#ifdef LIBFF

#pragma once
#include <gmpxx.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <libff/common/utils.hpp>
#include <string>
#include <vector>

#include "backends/algebra_types.hpp"
#include "tools/utils.h"


namespace libBLS {
namespace algebra {

inline std::string convertHexToDec( const std::string& hex_str ) {
    try {
        // construct from base 16
        mpz_class dec( hex_str, libBLS::BASE_HEXA );

        // convert to base 10
        return dec.get_str( libBLS::BASE_DEC );

    } catch ( std::exception& e ) {
        throw ThresholdUtils::IncorrectInput( e.what() );
    } catch ( ... ) {
        throw ThresholdUtils::IncorrectInput( "Exception in convert hex to dec" );
    }
}

// ----------------- Template Declarations ----------------- //

template < class T >
std::string fieldElementToString( const T& field_elem, size_t base );

template < class T >
std::array< uint8_t, T::SIZE_BYTES > fieldElementToBytesArray( const T& field_elem );

template < class T >
std::vector< uint8_t > fieldElementToBytes( const T& field_elem );

template < class T >
static T bytesToFieldElement( const std::array< uint8_t, T::SIZE_BYTES >& byte_array );


// ------------------- Template Implementations ------------------- //

template < class T >
std::string fieldElementToString( const T& field_elem, size_t base ) {
    mpz_class t;

    field_elem.as_bigint().to_mpz( t.get_mpz_t() );

    std::string output = t.get_str( base );

    constexpr size_t hexa = 16;
    if ( base == hexa ) {
        const std::size_t width = 64;
        if ( output.length() < width ) {
            output.insert( 0, width - output.length(), '0' );
        }
    }

    return output;
}

template < class T >
std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > fieldElementToBytesArray(
    const T& field_elem ) {
    mpz_class t;
    field_elem.as_bigint().to_mpz( t.get_mpz_t() );

    // Compute byte count (at least 1 byte)
    size_t bit_len = mpz_sizeinbase( t.get_mpz_t(), 2 );
    size_t byte_count = std::max< size_t >( 1, ( bit_len + 7 ) / 8 );

    // Prepare output array (zero-initialized)
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > byte_array = {};

    // Export into the least-significant end of the buffer
    mpz_export( byte_array.data() + ( MAX_FIELD_ELEMENT_SIZE_BYTES - byte_count ), nullptr, 1, 1, 0,
        0, t.get_mpz_t() );

    return byte_array;
}

template < class T >
std::vector< uint8_t > fieldElementToBytes( const T& field_elem ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes =
        fieldElementToBytesArray( field_elem );
    std::vector< uint8_t > bytesVec( bytes.begin(), bytes.end() );
    return bytesVec;
}

// Convert a 32-byte array back to a algebra::FqElement or FrScalar element
template < class T >
T bytesToFieldElement( const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
    mpz_class t;

    // Import the byte array into the mpz_t (in little-endian order)
    mpz_import( t.get_mpz_t(), byte_array.size(), 1, 1, 0, 0, byte_array.data() );

    // Convert the mpz_t back to a algebra::FqElement field element
    T field_elem( t.get_mpz_t() );

    return field_elem;
}

// Converts the first 32 bytes from the vector into a field element
template < class T >
T bytesToFieldElement( const std::vector< uint8_t >& byte_array ) {
    if ( byte_array.size() < MAX_FIELD_ELEMENT_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes in vector" );
    }

    std::array< uint8_t, T::SIZE_BYTES > bytes;
    std::copy( byte_array.begin(), byte_array.end(), bytes.begin() );
    return bytesToFieldElement< T >( bytes );
}

}  // namespace algebra
}  // namespace libBLS

#endif // LIBFF