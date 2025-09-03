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


namespace libBLS::algebra {

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

/// @brief Converts a decimal string to a hex string
/// @param field field represented as a mpz_class
/// @param base base to convert to (10 or 16)
/// @return The converted hex string
inline std::string mpzClassToString( mpz_class& field, size_t base ) {
    std::string output = field.get_str( base );

    constexpr size_t hexa = 16;
    if ( base == hexa ) {
        const std::size_t width = 64;
        if ( output.length() < width ) {
            output.insert( 0, width - output.length(), '0' );
        }
    }

    return output;
}

inline mpz_class stringToMpzClass( const std::string& str, size_t base ) {
    mpz_class t;
    try {
        t = mpz_class( str, base );
    } catch ( std::exception& e ) {
        THROW( e.what() );
    } catch ( ... ) {
        THROW( "Exception in string to mpz class" );
    }
    return t;
}

inline std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > mpzClassToByteArray( mpz_class& field ) {
    // Compute byte count (at least 1 byte)
    size_t bit_len = mpz_sizeinbase( field.get_mpz_t(), 2 );
    size_t byte_count = std::max< size_t >( 1, ( bit_len + 7 ) / 8 );

    // Prepare output array (zero-initialized)
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > byte_array = {};

    // Export into the least-significant end of the buffer
    mpz_export( byte_array.data() + ( MAX_FIELD_ELEMENT_SIZE_BYTES - byte_count ), nullptr, 1, 1, 0,
        0, field.get_mpz_t() );

    return byte_array;
}

inline std::vector< uint8_t > mpzClassToByteVector( mpz_class& field_elem ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes = mpzClassToByteArray( field_elem );
    std::vector< uint8_t > bytesVec( bytes.begin(), bytes.end() );
    return bytesVec;
}


inline mpz_class bytesToMpzClass(
    const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
    mpz_class t;
    // Import the byte array into the mpz_t (in little-endian order)
    mpz_import( t.get_mpz_t(), byte_array.size(), 1, 1, 0, 0, byte_array.data() );
    return t;
}

inline mpz_class bytesToMpzClass( const std::vector< uint8_t >& byte_array ) {
    if ( byte_array.size() < MAX_FIELD_ELEMENT_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes in vector" );
    }

    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes;
    std::copy( byte_array.begin(), byte_array.end(), bytes.begin() );
    return bytesToMpzClass( bytes );
}

}  // namespace libBLS::algebra

#endif  // LIBFF