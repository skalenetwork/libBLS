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


BOOST_AUTO_TEST_SUITE( TestFieldConversions )

BOOST_AUTO_TEST_CASE( G1ToAndFromBytes ) {
    libBLS::ThresholdUtils::initCurve();

    for ( size_t i = 0; i < 10000; i++ ) {
        libff::alt_bn128_G1 point = libff::alt_bn128_G1::random_element();
        std::array< uint8_t, libBLS::G1_SIZE_BYTES > point_bytes =
            libBLS::ThresholdUtils::G1ToBytes( point );
        libff::alt_bn128_G1 restored_point = libBLS::ThresholdUtils::bytesToG1( point_bytes );
        BOOST_REQUIRE( point == restored_point );
    }
}

BOOST_AUTO_TEST_CASE( G2ToAndFromBytes ) {
    libBLS::ThresholdUtils::initCurve();

    for ( size_t i = 0; i < 10000; i++ ) {
        libff::alt_bn128_G2 point = libff::alt_bn128_G2::random_element();
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > point_bytes =
            libBLS::ThresholdUtils::G2ToBytes( point );
        libff::alt_bn128_G2 restored_point = libBLS::ThresholdUtils::bytesToG2( point_bytes );
        BOOST_REQUIRE( point == restored_point );
    }
}

BOOST_AUTO_TEST_CASE( FieldElementToAndFromBytes ) {
    libBLS::ThresholdUtils::initCurve();

    for ( size_t i = 0; i < 10000; i++ ) {
        // Fr element
        libff::alt_bn128_Fr element = libff::alt_bn128_Fr::random_element();
        auto bytes = libBLS::ThresholdUtils::fieldElementToBytes( element );
        libff::alt_bn128_Fr restored_element =
            libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fr >( bytes );
        BOOST_REQUIRE( element == restored_element );
        // Fq element
        libff::alt_bn128_Fq element2 = libff::alt_bn128_Fq::random_element();
        auto bytes2 = libBLS::ThresholdUtils::fieldElementToBytes( element2 );
        libff::alt_bn128_Fq restored_element2 =
            libBLS::ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( bytes2 );
        BOOST_REQUIRE( element2 == restored_element2 );
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( TestBytesToHexCString )

BOOST_AUTO_TEST_CASE( BytesToAndFromHexCString ) {
    libBLS::ThresholdUtils::initCurve();

    for ( size_t i = 0; i < 10000; i++ ) {
        size_t len = rand() % 1000 + libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES;
        std::vector< uint8_t > bytes( len );
        RAND_bytes( bytes.data(), bytes.size() );

        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes2;
        std::copy_n( bytes.begin(), libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES, bytes2.begin() );

        // using vector
        std::string hex = libBLS::ThresholdUtils::bytesToHexCString( bytes );
        BOOST_REQUIRE( hex.size() == 2 * len );
        std::vector< uint8_t > restored_bytes =
            libBLS::ThresholdUtils::hexCStringToBytes( hex.c_str() );
        BOOST_REQUIRE( bytes == restored_bytes );

        // using fixed-size array
        std::string hex2 = libBLS::ThresholdUtils::bytesToHexCString( bytes2 );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > restored_bytes2 =
            libBLS::ThresholdUtils::hexCStringToBytesArray( hex2.c_str() );
        BOOST_REQUIRE( bytes2 == restored_bytes2 );
    }
}

BOOST_AUTO_TEST_CASE( HexCStringToBytesException ) {
    std::string hexa = "0123456789abcdefABCDEF";

    for ( size_t i = 0; i < 100; ++i ) {
        // Odd length
        size_t len = rand() % 1000 + 1;
        if ( len % 2 == 0 ) {
            len++;
        }

        std::string oddHex;
        for ( size_t j = 0; j < len; ++j ) {
            oddHex += hexa[rand() % hexa.length()];
        }

        BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytes( oddHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );
        BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytesArray( oddHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );

        // String with invalid hexa characters
        size_t len2 = rand() % 1000 + 1;
        std::string invalidHex;
        for ( size_t j = 0; j < len2; ++j ) {
            invalidHex += rand() % 256;
        }

        BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytes( invalidHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );
        BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytesArray( invalidHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // Empty string
    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::hexCStringToBytes( "" ), libBLS::ThresholdUtils::IncorrectInput );
    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytesArray( "" ),
        libBLS::ThresholdUtils::IncorrectInput );

    // Empty byte vector
    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::bytesToHexCString( std::vector< uint8_t >() ),
        libBLS::ThresholdUtils::IncorrectInput );
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( TestAES )

BOOST_AUTO_TEST_CASE( SimpleAES ) {
    libBLS::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    libBLS::AES256Key random_aes_key;
    std::copy( key_bytes, key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_aes_key.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    auto ciphertext = libBLS::ThresholdUtils::aesEncrypt( message_bytes, random_aes_key );
    auto decrypted_text = libBLS::ThresholdUtils::aesDecrypt( ciphertext, random_aes_key );

    BOOST_REQUIRE( decrypted_text == message_bytes );
}

BOOST_AUTO_TEST_CASE( wrongCiphertext ) {
    libBLS::ThresholdUtils::initAES();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    const std::string bad_message =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::vector< uint8_t > bad_message_bytes( bad_message.begin(), bad_message.end() );

    auto bad_ciphertext = libBLS::ThresholdUtils::aesEncrypt( bad_message_bytes, random_aes_key );

    auto decrypted_text = libBLS::ThresholdUtils::aesDecrypt( bad_ciphertext, random_aes_key );

    BOOST_REQUIRE( decrypted_text != message_bytes );
    BOOST_REQUIRE( decrypted_text == bad_message_bytes );
}

BOOST_AUTO_TEST_CASE( wrongKey ) {
    libBLS::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    libBLS::AES256Key random_aes_key;
    std::copy( key_bytes, key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_aes_key.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    auto ciphertext = libBLS::ThresholdUtils::aesEncrypt( message_bytes, random_aes_key );

    unsigned char bad_key_bytes[32];
    RAND_bytes( bad_key_bytes, sizeof( bad_key_bytes ) );
    libBLS::AES256Key random_bad_aes_key;
    std::copy(
        bad_key_bytes, bad_key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_bad_aes_key.begin() );

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::aesDecrypt( ciphertext, random_bad_aes_key ), std::runtime_error );
}

BOOST_AUTO_TEST_SUITE_END()
