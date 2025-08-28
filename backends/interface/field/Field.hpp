#pragma once
#include "backends/algebra_types.hpp"
#include "tools/utils.h"
#include <gmpxx.h>

namespace libBLS::algebra {

/// @brief Base parent class for field types.
/// Declares both zero() and one() static methods.
/// Includes all common serialization / deserialization methods from/to mpz_class.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper >
class Field : public WrapperCore< BackendType, Wrapper > {
protected:
    /// @brief Converts a decimal string to a hex string
    /// @param field field represented as a mpz_class
    /// @param base base to convert to (10 or 16)
    /// @return The converted hex string
    static std::string mpzClassToString( mpz_class& field, size_t base ) {
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

    static mpz_class stringToMpzClass( const std::string& str, size_t base ) {
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

    static std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > mpzClassToByteArray(
        mpz_class& field ) {
        // Compute byte count (at least 1 byte)
        size_t bit_len = mpz_sizeinbase( field.get_mpz_t(), 2 );
        size_t byte_count = std::max< size_t >( 1, ( bit_len + 7 ) / 8 );

        // Prepare output array (zero-initialized)
        std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > byte_array = {};

        // Export into the least-significant end of the buffer
        mpz_export( byte_array.data() + ( MAX_FIELD_ELEMENT_SIZE_BYTES - byte_count ), nullptr, 1,
            1, 0, 0, field.get_mpz_t() );

        return byte_array;
    }

    static std::vector< uint8_t > mpzClassToByteVector( mpz_class& field_elem ) {
        std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes =
            mpzClassToByteArray( field_elem );
        std::vector< uint8_t > bytesVec( bytes.begin(), bytes.end() );
        return bytesVec;
    }


    static mpz_class bytesToMpzClass(
        const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
        mpz_class t;
        // Import the byte array into the mpz_t (in little-endian order)
        mpz_import( t.get_mpz_t(), byte_array.size(), 1, 1, 0, 0, byte_array.data() );
        return t;
    }

    static mpz_class bytesToMpzClass( const std::vector< uint8_t >& byte_array ) {
        if ( byte_array.size() < MAX_FIELD_ELEMENT_SIZE_BYTES ) {
            throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes in vector" );
        }

        std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes;
        std::copy( byte_array.begin(), byte_array.end(), bytes.begin() );
        return bytesToMpzClass( bytes );
    }


public:
    Field() : WrapperCore< BackendType, Wrapper >() {}
    Field( const BackendType& v ) : WrapperCore< BackendType, Wrapper >( v ) {}

    // Must be declared as static functions, not fields.
    // We need to have initialized the curve before calling them.
    // If they were static fields, they would be both initialized as 0,
    // since the curve was not initialized yet.
    static Wrapper one();
    static Wrapper zero();

    bool isOne() const;
    bool isZero() const;
};

}  // namespace libBLS::algebra