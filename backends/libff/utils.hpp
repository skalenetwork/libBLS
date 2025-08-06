#pragma once
#include <cstddef>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace libBLS {
namespace algebra {

// same size as libff::alt_bn128_Fq and libff::alt_bn128_Fr
// This is the maximum size of a field element in bytes
constexpr size_t MAX_FIELD_ELEMENT_SIZE_BYTES = 32;

// ----------------- Template Declarations ----------------- //

template < class T >
std::string fieldElementToString( const T& field_elem, size_t base );

template < class T >
std::array< uint8_t, T::SIZE_BYTES > fieldElementToBytesArray( const T& field_elem );

template < class T >
std::vector< uint8_t > fieldElementToBytes( const T& field_elem );

template < class T >
static T bytesToFieldElement(const std::array< uint8_t, T::SIZE_BYTES >& byte_array );


// ------------------- Template Implementations ------------------- //

template < class T >
std::string fieldElementToString( const T& field_elem, size_t base ) {
    mpz_class t;

    field_elem.as_bigint().to_mpz( t.get_mpz_t() );

    std::string output = t.get_str( base );

    if ( base == HEXA ) {
        const std::size_t width = 64;
        if ( output.length() < width ) {
            output.insert( 0, width - output.length(), '0' );
        }
    }

    return output;
}

template < class T >
std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > fieldElementToBytesArray(const T& field_elem ) {
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
T bytesToFieldElement(const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
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

} // namespace algebra
} // namespace libBLS