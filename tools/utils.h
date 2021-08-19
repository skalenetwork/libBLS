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

namespace crypto {

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

    static std::vector< uint8_t > aesEncrypt( const std::string& message, const std::string& key );

    static std::string aesDecrypt(
        const std::vector< uint8_t >& ciphertext, const std::string& key );

    static bool isStringNumber( const std::string& str );

    static int char2int( char _input );

    static std::string carray2Hex( const unsigned char* d, uint64_t len );

    static bool hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin );

    static std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > ParseHint(
        const std::string& hint );

    static std::shared_ptr< std::vector< std::string > > SplitString(
        const std::shared_ptr< std::string >, const std::string& delim );

    template < class T >
    static std::string fieldElementToString( const T& field_elem, int base = 10 );

    static std::vector< std::string > G2ToString( libff::alt_bn128_G2 elem, int base = 10 );

    static libff::alt_bn128_G2 stringToG2( const std::string& str );

    static libff::alt_bn128_G1 stringToG1( const std::string& str );

    static std::string convertHexToDec( const std::string& hex_str );

    static bool checkHex( const std::string& hex );

    static bool isG2( const libff::alt_bn128_G2& point );
};

template < class T >
std::string ThresholdUtils::fieldElementToString( const T& field_elem, int base ) {
    mpz_t t;
    mpz_init( t );

    field_elem.as_bigint().to_mpz( t );

    char arr[mpz_sizeinbase( t, base ) + 2];

    char* tmp = mpz_get_str( arr, base, t );
    mpz_clear( t );

    std::string output = tmp;

    return output;
}

}  // namespace crypto

#endif  // LIBBLS_UTILS_H
