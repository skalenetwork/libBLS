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
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file unit_tests_dkg_te.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <dkg/dkg_te.h>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( DkgTeAlgorithm )

BOOST_AUTO_TEST_CASE( PolynomialValue ) {
    encryption::DkgTe obj = encryption::DkgTe( 3, 4 );
    std::vector< encryption::element_wrapper > polynomial;

    for ( size_t i = 0; i < 3; ++i ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );
        element_set_si( tmp, ( i % 2 == 0 ? 1 : 0 ) );

        polynomial.push_back( encryption::element_wrapper( tmp ) );

        element_clear( tmp );
    }

    element_t five;
    element_init_Zr( five, TEDataSingleton::getData().pairing_ );
    element_set_si( five, 5 );

    encryption::element_wrapper value =
        obj.ComputePolynomialValue( polynomial, encryption::element_wrapper( five ) );

    element_t twenty_six;
    element_init_Zr( twenty_six, TEDataSingleton::getData().pairing_ );
    element_set_si( twenty_six, 26 );

    BOOST_REQUIRE( !element_cmp( twenty_six, value.el_ ) );  // element_cmp(a, b) returns false iff
                                                             // a == b

    element_clear( twenty_six );

    polynomial.clear();

    for ( size_t i = 0; i < 3; ++i ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );
        element_set_si( tmp, ( i % 2 == 0 ? 0 : 1 ) );

        polynomial.push_back( encryption::element_wrapper( tmp ) );

        element_clear( tmp );
    }

    bool is_exception_caught = false;

    try {
        value = obj.ComputePolynomialValue( polynomial, encryption::element_wrapper( five ) );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }

    element_clear( five );

    BOOST_REQUIRE( is_exception_caught );
}

BOOST_AUTO_TEST_CASE( Verification ) {
    encryption::DkgTe obj = encryption::DkgTe( 2, 2 );

    auto polynomial_fst = obj.GeneratePolynomial();
    auto polynomial_snd = obj.GeneratePolynomial();

    auto verification_vector_fst = obj.CreateVerificationVector( polynomial_fst );
    auto verification_vector_snd = obj.CreateVerificationVector( polynomial_snd );

    encryption::element_wrapper shared_by_fst_to_snd =
        obj.CreateSecretKeyContribution( polynomial_snd )[1];
    encryption::element_wrapper shared_by_snd_to_fst =
        obj.CreateSecretKeyContribution( polynomial_fst )[0];

    BOOST_REQUIRE( obj.Verify( 0, shared_by_snd_to_fst, verification_vector_fst ) );
    BOOST_REQUIRE( obj.Verify( 1, shared_by_fst_to_snd, verification_vector_snd ) );

    element_t rand;
    element_init_Zr( rand, TEDataSingleton::getData().pairing_ );
    element_random( rand );

    element_t sum;
    element_init_Zr( sum, TEDataSingleton::getData().pairing_ );
    element_add( sum, rand, shared_by_snd_to_fst.el_ );

    BOOST_REQUIRE( obj.Verify( 0, sum, verification_vector_fst ) == false );

    element_clear( sum );
    element_clear( rand );

    element_init_Zr( rand, TEDataSingleton::getData().pairing_ );
    element_random( rand );

    element_init_Zr( sum, TEDataSingleton::getData().pairing_ );
    element_add( sum, rand, shared_by_fst_to_snd.el_ );
    BOOST_REQUIRE( obj.Verify( 1, sum, verification_vector_snd ) == false );

    element_clear( sum );
    element_clear( rand );
}

BOOST_AUTO_TEST_SUITE_END()
