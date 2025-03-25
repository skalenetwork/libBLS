/*
  Copyright (C) 2021- SKALE Labs

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

  @file utils.h
  @author Oleh Nikolaiev
  @date 2021
*/

#ifndef LIBBLS_UTILS_H
#define LIBBLS_UTILS_H

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

static constexpr size_t BLS_MAX_COMPONENT_LEN = 77;

namespace libBLS {

constexpr size_t AES_256_KEY_SIZE_BYTES = 32;
using AES256Key = std::array< uint8_t, AES_256_KEY_SIZE_BYTES >;

constexpr size_t MAX_FIELD_ELEMENT_SIZE_BYTES = 32;
// 4 x 32 bytes
constexpr size_t G2_SIZE_BYTES = 128;
// 2 x 32 bytes
constexpr size_t G1_SIZE_BYTES = 64;

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

class ThresholdUtils {
private:
    class Exception : public std::exception {
    protected:
        std::string what_str;

    public:
        Exception( const std::string& err_str ) { what_str = err_str; }

        virtual const char* what() const noexcept override { return what_str.c_str(); }
    };

public:
    class IsNotWellFormed : public Exception {
    public:
        IsNotWellFormed( const std::string& err_str ) : Exception( err_str ) {
            what_str = "IsNotWellFormedData : " + err_str;
        }
    };

    class ZeroSecretKey : public Exception {
    public:
        ZeroSecretKey( const std::string& err_str ) : Exception( err_str ) {
            what_str = "Secret key is equal to zero : " + err_str;
        }
    };

    class IncorrectInput : public Exception {
    public:
        IncorrectInput( const std::string& err_str ) : Exception( err_str ) {
            what_str = "Failed to proceed data : " + err_str;
        }
    };

    static std::atomic< bool > is_initialized;

    static void initCurve();

    static void initAES();

    static void checkSigners( size_t _requiredSigners, size_t _totalSigners );

    static std::vector< libff::alt_bn128_Fr > LagrangeCoeffs(
        const std::vector< size_t >& idx, size_t t );

    static libff::alt_bn128_Fq HashToFq(
        std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr );

    static libff::alt_bn128_G1 HashtoG1(
        std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr );

    static libff::alt_bn128_G1 HashtoG1( const std::string& message );

    static std::vector< uint8_t > aesEncrypt(
        const std::vector< uint8_t >& message, const AES256Key& key );

    static std::vector< uint8_t > aesDecrypt(
        const std::vector< uint8_t >& ciphertext, const AES256Key& key );

    static bool isStringNumber( const std::string& str );

    static int char2int( char _input );

    static std::string carray2Hex( const unsigned char* d, uint64_t len );

    static bool hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin );

    static std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > ParseHint(
        const std::string& hint );

    static std::shared_ptr< std::vector< std::string > > SplitString(
        const std::shared_ptr< std::string >, const std::string& delim );

    template < class T >
    static std::string fieldElementToString( const T& field_elem, int base = BASE_DEC );

    template < class T >
    static std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > fieldElementToBytes(
        const T& field_elem );

    template < class T >
    static T bytesToFieldElement(
        const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array );

    static std::vector< std::string > G2ToString( libff::alt_bn128_G2 elem, int base = BASE_DEC );

    static std::array< uint8_t, G2_SIZE_BYTES > G2ToBytes( libff::alt_bn128_G2 elem );

    static std::array< uint8_t, G1_SIZE_BYTES > G1ToBytes( libff::alt_bn128_G1 elem );

    static libff::alt_bn128_G2 bytesToG2( std::array< uint8_t, G2_SIZE_BYTES > elem );

    static libff::alt_bn128_G1 bytesToG1( std::array< uint8_t, G1_SIZE_BYTES > elem );

    static libff::alt_bn128_G2 stringToG2( const std::string& str );

    static libff::alt_bn128_G1 stringToG1( const std::string& str );

    static std::string convertHexToDec( const std::string& hex_str );

    static std::string convertDecToHex( std::string dec, int numBytes );

    static bool checkHex( const std::string& hex );

    static char* bytesToHexCString( const std::vector< uint8_t >& bytes );
    static char* bytesToHexCString( const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES>& bytes );

    static std::vector< uint8_t > hexCStringToBytes( const char* hexStr );

    template < class T >
    static bool ValidateKey( const T& point );
};

template < class T >
std::string ThresholdUtils::fieldElementToString( const T& field_elem, int base ) {
    mpz_t t;
    mpz_init( t );

    field_elem.as_bigint().to_mpz( t );

    char arr[mpz_sizeinbase( t, base ) + 2];

    char* tmp = mpz_get_str( arr, base, t );

    std::string output = tmp;
    if ( base == libBLS::BASE_HEXA ) {
        // 64-characters long - fill 0's if needed
        int n_zeroes = 64 - output.length();
        output.insert( 0, n_zeroes, '0' );
    }

    mpz_clear( t );
    return output;
}

template < class T >
std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > ThresholdUtils::fieldElementToBytes(
    const T& field_elem ) {
    mpz_t t;
    mpz_init( t );

    field_elem.as_bigint().to_mpz( t );

    // Determine the number of bytes required to store the number
    size_t byte_count = std::max< size_t >( 1, ( mpz_sizeinbase( t, 2 ) + 7 ) / 8 );
    // Start with 32 bytes, initialized to 0
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > byte_array = {};
    // Export the number into the byte array, starting from the least significant byte
    mpz_export(
        byte_array.data() + ( MAX_FIELD_ELEMENT_SIZE_BYTES - byte_count ), nullptr, 1, 1, 0, 0, t );

    mpz_clear( t );
    return byte_array;
}

// Convert a 32-byte array back to a libff::alt_bn128_Fq field element
template < class T >
T ThresholdUtils::bytesToFieldElement(
    const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
    mpz_t t;
    mpz_init( t );

    // Import the byte array into the mpz_t (in little-endian order)
    mpz_import( t, byte_array.size(), 1, 1, 0, 0, byte_array.data() );

    // Convert the mpz_t back to a libff::alt_bn128_Fq field element
    T field_elem( t );

    // Clear mpz_t
    mpz_clear( t );

    return field_elem;
}


template < class T >
bool ThresholdUtils::ValidateKey( const T& point ) {
    return point.is_well_formed() && T::order() * point == T::zero();
}

}  // namespace libBLS

#endif  // LIBBLS_UTILS_H
