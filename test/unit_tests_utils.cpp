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

#include "test/utils.h"
#include <bls/bls.h>
#include <openssl/rand.h>
#include <tools/utils.h>
#include <cstdlib>
#include <ctime>
#include <map>
#include <set>


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_GLOBAL_FIXTURE( GlobalConfig );

BOOST_AUTO_TEST_SUITE( TestLagrange )

// a goal is to get correct polynomial's value at zero point

BOOST_AUTO_TEST_CASE( RandomPolynomial ) {
    std::cout << "Testing Random Polynomial case\n";

    std::srand( unsigned( std::time( 0 ) ) );

    size_t deg = std::rand() % 30 + 1;  // a degree of polynomial should never be 0

    std::vector< libBLS::algebra::FrScalar > pol( deg + 1 );

    // random polynomial generation
    for ( size_t i = 0; i < deg + 1; ++i ) {
        pol[i] = libBLS::algebra::FrScalar::random();

        while ( i == deg && pol[i] == libBLS::algebra::FrScalar::zero() ) {
            pol[i] = libBLS::algebra::FrScalar::random();
        }
    }

    auto polynomial_value = [&pol, deg]( libBLS::algebra::FrScalar point ) {
        libBLS::algebra::FrScalar value = libBLS::algebra::FrScalar::zero();

        libBLS::algebra::FrScalar pow = libBLS::algebra::FrScalar::one();

        for ( size_t i = 0; i < deg + 1; ++i ) {
            if ( i == deg && pol[i] == libBLS::algebra::FrScalar::zero() ) {
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
    auto coeffs = libBLS::algebra::lagrangeCoeffs( indexes, deg + 1 );

    std::vector< libBLS::algebra::FrScalar > values( deg + 1 );
    for ( size_t i = 0; i < deg + 1; ++i ) {
        values[i] = polynomial_value( libBLS::algebra::FrScalar::fromString(
            std::to_string( indexes[i] ), libBLS::Base::DEC ) );
    }

    libBLS::algebra::FrScalar value_at_zero_point = pol[0];

    BOOST_REQUIRE( value_at_zero_point == obj.KeysRecover( coeffs, values ).first );
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( TestFieldConversions )

BOOST_AUTO_TEST_CASE( G1ToAndFromBytes ) {
    for ( size_t i = 0; i < 10000; i++ ) {
        libBLS::algebra::G1Point point = libBLS::algebra::G1Point::random();
        std::array< uint8_t, libBLS::G1_SIZE_BYTES > point_bytes = point.toByteArray();
        libBLS::algebra::G1Point restored_point =
            libBLS::algebra::G1Point::fromBytes( point_bytes );
        BOOST_REQUIRE( point == restored_point );
    }
}

BOOST_AUTO_TEST_CASE( G2ToAndFromBytes ) {
    for ( size_t i = 0; i < 10000; i++ ) {
        libBLS::algebra::G2Point point = libBLS::algebra::G2Point::random();
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > point_bytes = point.toByteArray();
        libBLS::algebra::G2Point restored_point =
            libBLS::algebra::G2Point::fromBytes( point_bytes );
        BOOST_REQUIRE( point == restored_point );
    }
}

BOOST_AUTO_TEST_CASE( FieldElementToAndFromBytes ) {
    for ( size_t i = 0; i < 10000; i++ ) {
        // Fr element
        libBLS::algebra::FrScalar element = libBLS::algebra::FrScalar::random();
        auto bytes = element.toByteArray();
        libBLS::algebra::FrScalar restored_element = libBLS::algebra::FrScalar::fromBytes( bytes );
        BOOST_REQUIRE( element == restored_element );
        // Fq element
        libBLS::algebra::FqElement element2 = libBLS::algebra::FqElement::random();
        auto bytes2 = element2.toByteArray();
        libBLS::algebra::FqElement restored_element2 =
            libBLS::algebra::FqElement::fromBytes( bytes2 );
        BOOST_REQUIRE( element2 == restored_element2 );
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( TestBytesToHexString )

BOOST_AUTO_TEST_CASE( BytesToAndFromHexCString ) {
    for ( size_t i = 0; i < 10000; i++ ) {
        size_t len = rand() % 1000 + libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES;
        std::vector< uint8_t > bytes( len );
        RAND_bytes( bytes.data(), bytes.size() );

        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes2;
        std::copy_n( bytes.begin(), libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES, bytes2.begin() );

        // using vector
        std::string hex = libBLS::ThresholdUtils::bytesToHexString( bytes );
        BOOST_REQUIRE( hex.size() == 2 * len );
        std::vector< uint8_t > restored_bytes =
            libBLS::ThresholdUtils::hexCStringToBytes( hex.c_str() );
        BOOST_REQUIRE( bytes == restored_bytes );

        // using fixed-size array
        std::string hex2 = libBLS::ThresholdUtils::bytesToHexString( bytes2 );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > restored_bytes2 =
            libBLS::ThresholdUtils::hexCStringToBytesArray< libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES >(
                hex2.c_str() );
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
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdUtils::hexCStringToBytesArray< libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES >(
                oddHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );

        // String with invalid hexa characters
        size_t len2 = rand() % 1000 + 1;
        std::string invalidHex;
        invalidHex.reserve( len2 );

        while ( invalidHex.size() < len2 ) {
            char c = static_cast< char >( rand() % 256 );

            if ( c == '\0' ) {
                continue;  // Skip null character
            }

            // only add if not hexadecimal
            if ( hexa.find( c ) == std::string::npos ) {
                invalidHex += c;
            }
        }

        BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::hexCStringToBytes( invalidHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdUtils::hexCStringToBytesArray< libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES >(
                invalidHex.c_str() ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_SUITE_END()
