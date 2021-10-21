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

  @file unit_tests_utils.cpp
  @author Oleh Nikolaiev
  @date 2021
*/

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>

#include <bls/bls.h>

#include <tools/utils.h>

#include <openssl/rand.h>


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( TestLagrange )

// a goal is to get correct polynomial's value at zero point

BOOST_AUTO_TEST_CASE( RandomPolynomial ) {
    std::cout << "Testing Random Polynomial case\n";

    std::srand( unsigned( std::time( 0 ) ) );

    size_t deg = std::rand() % 30 + 1;  // a degree of polynomial should never be 0

    std::vector< libff::alt_bn128_Fr > pol( deg + 1 );

    libBLS::ThresholdUtils::initCurve();

    // random polynomial generation
    for ( size_t i = 0; i < deg + 1; ++i ) {
        pol[i] = libff::alt_bn128_Fr::random_element();

        while ( i == deg && pol[i] == libff::alt_bn128_Fr::zero() ) {
            pol[i] = libff::alt_bn128_Fr::random_element();
        }
    }

    auto polynomial_value = [&pol, deg]( libff::alt_bn128_Fr point ) {
        libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

        libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();

        for ( size_t i = 0; i < deg + 1; ++i ) {
            if ( i == deg && pol[i] == libff::alt_bn128_Fr::zero() ) {
                throw std::runtime_error( "Error, incorrect degree of a polynomial" );
            }
            value += pol[i] * pow;
            pow *= point;
        }

        return value;
    };

    // generating random points to interpolate their values and to get a value at point zero
    std::vector< size_t > indexes( deg + 1, 0 );
    std::set< size_t > nodes;
    for ( size_t i = 0; i < deg + 1; ++i ) {
        std::srand( unsigned( std::time( 0 ) ) );
        while ( indexes[i] == 0 || nodes.find( indexes[i] ) != nodes.end() ) {
            indexes[i] = std::rand() % ( 5 * deg );
        }
        nodes.insert( indexes[i] );
    }

    libBLS::Bls obj = libBLS::Bls( deg + 1, deg + 1 );
    auto coeffs = libBLS::ThresholdUtils::LagrangeCoeffs( indexes, deg + 1 );

    std::vector< libff::alt_bn128_Fr > values( deg + 1 );
    for ( size_t i = 0; i < deg + 1; ++i ) {
        values[i] = polynomial_value( libff::alt_bn128_Fr( std::to_string( indexes[i] ).c_str() ) );
    }

    libff::alt_bn128_Fr value_at_zero_point = pol[0];

    BOOST_REQUIRE( value_at_zero_point == obj.KeysRecover( coeffs, values ).first );
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( TestAES )

BOOST_AUTO_TEST_CASE( SimpleAES ) {
    libBLS::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    auto ciphertext = libBLS::ThresholdUtils::aesEncrypt( message, random_aes_key );
    auto decrypted_text = libBLS::ThresholdUtils::aesDecrypt( ciphertext, random_aes_key );

    BOOST_REQUIRE( decrypted_text == message );
}

BOOST_AUTO_TEST_CASE( wrongCiphertext ) {
    libBLS::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    auto ciphertext = libBLS::ThresholdUtils::aesEncrypt( message, random_aes_key );

    const std::string bad_message =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    auto bad_ciphertext = libBLS::ThresholdUtils::aesEncrypt( bad_message, random_aes_key );

    auto decrypted_text = libBLS::ThresholdUtils::aesDecrypt( bad_ciphertext, random_aes_key );

    BOOST_REQUIRE( decrypted_text != message );
}

BOOST_AUTO_TEST_CASE( wrongKey ) {
    libBLS::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    auto ciphertext = libBLS::ThresholdUtils::aesEncrypt( message, random_aes_key );

    unsigned char bad_key_bytes[32];
    RAND_bytes( bad_key_bytes, sizeof( bad_key_bytes ) );
    std::string bad_key = std::string( ( char* ) bad_key_bytes, sizeof( bad_key_bytes ) );

    auto decrypted_text = libBLS::ThresholdUtils::aesDecrypt( ciphertext, bad_key );

    BOOST_REQUIRE( decrypted_text != message );
}

BOOST_AUTO_TEST_SUITE_END()
