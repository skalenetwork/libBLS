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

  @file unit_tests_te.cpp
  @author Oleh Nikolaiev
  @date 2019
 */

#include <threshold_encryption.h>
#include <random>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

static char aparam[] =
    "type a\n"
    "q "
    "8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422"
    "662221423155858769582317459277713367317481324925129998224791\n"
    "h "
    "1201601226489114607938882136674053420480295440125131182291961513104720728935970453110284480218"
    "3906537786776\n"
    "r 730750818665451621361119245571504901405976559617\n"
    "exp2 159\n"
    "exp1 107\n"
    "sign1 1\n"
    "sign0 1\n";

BOOST_AUTO_TEST_SUITE( ThresholdEncryption )

BOOST_AUTO_TEST_CASE( PairingBillinearity ) {
    pairing_t pairing;

    pairing_init_set_str( pairing, aparam );

    element_t g, h;
    element_t public_key, secret_key;
    element_t sig;
    element_t temp1, temp2;

    element_init_Zr( secret_key, pairing );
    element_init_G1( h, pairing );
    element_init_G1( sig, pairing );
    element_init_G1( g, pairing );
    element_init_G1( public_key, pairing );
    element_init_GT( temp1, pairing );
    element_init_GT( temp2, pairing );

    element_random( g );
    element_random( secret_key );
    element_pow_zn( public_key, g, secret_key );

    const char message[] = "abcdef";
    element_from_hash( h, ( char* ) message, 6 );

    element_pow_zn( sig, h, secret_key );

    pairing_apply( temp1, sig, g, pairing );
    pairing_apply( temp2, h, public_key, pairing );

    BOOST_REQUIRE( !element_cmp( temp1, temp2 ) );

    element_clear( g );
    element_clear( h );
    element_clear( public_key );
    element_clear( secret_key );
    element_clear( sig );
    element_clear( temp1 );
    element_clear( temp2 );

    pairing_clear( pairing );
}

BOOST_AUTO_TEST_CASE( SimpleEncryption ) {
    encryption::TE te_instance = encryption::TE( 1, 1 );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    element_t secret_key;
    element_init_Zr( secret_key, TEDataSingleton::getData().pairing_ );
    element_random( secret_key );

    element_t public_key;
    element_init_G1( public_key, TEDataSingleton::getData().pairing_ );
    element_pow_zn( public_key, TEDataSingleton::getData().generator_, secret_key );

    auto ciphertext = te_instance.Encrypt( message, public_key );

    element_t decrypted;
    element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

    te_instance.Decrypt( decrypted, ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decrypted, public_key ) );

    std::vector< std::pair< encryption::element_wrapper, size_t > > shares;
    encryption::element_wrapper ev( decrypted );
    shares.push_back( std::make_pair( ev, size_t( 1 ) ) );

    std::string res = te_instance.CombineShares( ciphertext, shares );

    element_clear( secret_key );
    element_clear( public_key );
    element_clear( decrypted );

    BOOST_REQUIRE( res == message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionReal ) {
    encryption::TE obj = encryption::TE( 11, 16 );

    std::vector< encryption::element_wrapper > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );

        element_random( tmp );

        while ( element_is0( tmp ) ) {
            element_random( tmp );
        }

        elem = encryption::element_wrapper( tmp );

        element_clear( tmp );
    }

    std::vector< encryption::element_wrapper > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        element_t sk;
        element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
        element_set0( sk );

        for ( size_t j = 0; j < 11; ++j ) {
            element_t tmp1;
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp1, i + 1 );

            element_t tmp2;
            element_init_Zr( tmp2, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp2, j );

            element_t tmp3;
            element_init_Zr( tmp3, TEDataSingleton::getData().pairing_ );
            element_pow_zn( tmp3, tmp1, tmp2 );

            element_t tmp4;
            element_init_Zr( tmp4, TEDataSingleton::getData().pairing_ );
            element_mul_zn( tmp4, coeffs[j].el_, tmp3 );

            element_clear( tmp1 );
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_add( tmp1, sk, tmp4 );

            element_clear( sk );
            element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
            element_set( sk, tmp1 );

            element_clear( tmp1 );
            element_clear( tmp2 );
            element_clear( tmp3 );
            element_clear( tmp4 );
        }

        secret_keys[i] = encryption::element_wrapper( sk );

        element_clear( sk );
    }

    element_t common_secret;
    element_init_Zr( common_secret, TEDataSingleton::getData().pairing_ );
    element_set( common_secret, coeffs[0].el_ );

    element_t common_public;
    element_init_G1( common_public, TEDataSingleton::getData().pairing_ );
    element_pow_zn( common_public, TEDataSingleton::getData().generator_, common_secret );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< encryption::element_wrapper, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        element_t decrypted;
        element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

        obj.Decrypt( decrypted, ciphertext, secret_keys[i].el_ );

        element_t public_key;
        element_init_G1( public_key, TEDataSingleton::getData().pairing_ );
        element_pow_zn( public_key, TEDataSingleton::getData().generator_, secret_keys[i].el_ );

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = encryption::element_wrapper( decrypted );

        element_clear( decrypted );
        element_clear( public_key );

        shares[i].second = i + 1;
    }

    std::string res = obj.CombineShares( ciphertext, shares );

    element_clear( common_secret );
    element_clear( common_public );

    BOOST_REQUIRE( res == message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomPK ) {
    encryption::TE obj = encryption::TE( 11, 16 );

    std::vector< encryption::element_wrapper > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );

        element_random( tmp );

        while ( element_is0( tmp ) ) {
            element_random( tmp );
        }

        elem = encryption::element_wrapper( tmp );

        element_clear( tmp );
    }

    std::vector< encryption::element_wrapper > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        element_t sk;
        element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
        element_set0( sk );

        for ( size_t j = 0; j < 11; ++j ) {
            element_t tmp1;
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp1, i + 1 );

            element_t tmp2;
            element_init_Zr( tmp2, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp2, j );

            element_t tmp3;
            element_init_Zr( tmp3, TEDataSingleton::getData().pairing_ );
            element_pow_zn( tmp3, tmp1, tmp2 );

            element_t tmp4;
            element_init_Zr( tmp4, TEDataSingleton::getData().pairing_ );
            element_mul_zn( tmp4, coeffs[j].el_, tmp3 );

            element_clear( tmp1 );
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_add( tmp1, sk, tmp4 );

            element_clear( sk );
            element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
            element_set( sk, tmp1 );

            element_clear( tmp1 );
            element_clear( tmp2 );
            element_clear( tmp3 );
            element_clear( tmp4 );
        }

        secret_keys[i] = encryption::element_wrapper( sk );

        element_clear( sk );
    }

    element_t common_secret;
    element_init_Zr( common_secret, TEDataSingleton::getData().pairing_ );
    element_set( common_secret, coeffs[0].el_ );

    element_t common_public;
    element_init_G1( common_public, TEDataSingleton::getData().pairing_ );

    // element_pow_zn(common_public, obj.generator_, common_secret);
    // let common_public be a random element of G1 instead of correct one in the previous line

    element_random( common_public );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< encryption::element_wrapper, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        element_t decrypted;
        element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

        obj.Decrypt( decrypted, ciphertext, secret_keys[i].el_ );

        element_t public_key;
        element_init_G1( public_key, TEDataSingleton::getData().pairing_ );
        element_pow_zn( public_key, TEDataSingleton::getData().generator_, secret_keys[i].el_ );

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = encryption::element_wrapper( decrypted );

        element_clear( decrypted );
        element_clear( public_key );

        shares[i].second = i + 1;
    }

    element_clear( common_secret );
    element_clear( common_public );

    std::string res = obj.CombineShares( ciphertext, shares );

    BOOST_REQUIRE( res != message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomSK ) {
    encryption::TE obj = encryption::TE( 11, 16 );

    std::vector< encryption::element_wrapper > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );

        element_random( tmp );

        while ( element_is0( tmp ) ) {
            element_random( tmp );
        }

        elem = encryption::element_wrapper( tmp );

        element_clear( tmp );
    }

    std::vector< encryption::element_wrapper > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        element_t sk;
        element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
        element_set0( sk );

        for ( size_t j = 0; j < 11; ++j ) {
            element_t tmp1;
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp1, i + 1 );

            element_t tmp2;
            element_init_Zr( tmp2, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp2, j );

            element_t tmp3;
            element_init_Zr( tmp3, TEDataSingleton::getData().pairing_ );
            element_pow_zn( tmp3, tmp1, tmp2 );

            element_t tmp4;
            element_init_Zr( tmp4, TEDataSingleton::getData().pairing_ );
            element_mul_zn( tmp4, coeffs[j].el_, tmp3 );

            element_clear( tmp1 );
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_add( tmp1, sk, tmp4 );

            element_clear( sk );
            element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
            element_set( sk, tmp1 );

            element_clear( tmp1 );
            element_clear( tmp2 );
            element_clear( tmp3 );
            element_clear( tmp4 );
        }

        // let secret_key[7] be a random generated value instead of correctly generated
        if ( i == 7 ) {
            element_clear( sk );
            element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
            element_random( sk );
        }

        secret_keys[i] = encryption::element_wrapper( sk );

        element_clear( sk );
    }

    element_t common_secret;
    element_init_Zr( common_secret, TEDataSingleton::getData().pairing_ );
    element_set( common_secret, coeffs[0].el_ );

    element_t common_public;
    element_init_G1( common_public, TEDataSingleton::getData().pairing_ );
    element_pow_zn( common_public, TEDataSingleton::getData().generator_, common_secret );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< encryption::element_wrapper, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        element_t decrypted;
        element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

        obj.Decrypt( decrypted, ciphertext, secret_keys[i].el_ );

        element_t public_key;
        element_init_G1( public_key, TEDataSingleton::getData().pairing_ );
        element_pow_zn( public_key, TEDataSingleton::getData().generator_, secret_keys[i].el_ );

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = encryption::element_wrapper( decrypted );

        element_clear( decrypted );
        element_clear( public_key );

        shares[i].second = i + 1;
    }

    std::string res = obj.CombineShares( ciphertext, shares );

    element_clear( common_secret );
    element_clear( common_public );

    BOOST_REQUIRE( res != message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionCorruptedCiphertext ) {
    encryption::TE obj = encryption::TE( 11, 16 );

    std::vector< encryption::element_wrapper > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        element_t tmp;
        element_init_Zr( tmp, TEDataSingleton::getData().pairing_ );

        element_random( tmp );

        while ( element_is0( tmp ) ) {
            element_random( tmp );
        }

        elem = encryption::element_wrapper( tmp );

        element_clear( tmp );
    }

    std::vector< encryption::element_wrapper > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        element_t sk;
        element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
        element_set0( sk );

        for ( size_t j = 0; j < 11; ++j ) {
            element_t tmp1;
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp1, i + 1 );

            element_t tmp2;
            element_init_Zr( tmp2, TEDataSingleton::getData().pairing_ );
            element_set_si( tmp2, j );

            element_t tmp3;
            element_init_Zr( tmp3, TEDataSingleton::getData().pairing_ );
            element_pow_zn( tmp3, tmp1, tmp2 );

            element_t tmp4;
            element_init_Zr( tmp4, TEDataSingleton::getData().pairing_ );
            element_mul_zn( tmp4, coeffs[j].el_, tmp3 );

            element_clear( tmp1 );
            element_init_Zr( tmp1, TEDataSingleton::getData().pairing_ );
            element_add( tmp1, sk, tmp4 );

            element_clear( sk );
            element_init_Zr( sk, TEDataSingleton::getData().pairing_ );
            element_set( sk, tmp1 );

            element_clear( tmp1 );
            element_clear( tmp2 );
            element_clear( tmp3 );
            element_clear( tmp4 );
        }

        secret_keys[i] = encryption::element_wrapper( sk );

        element_clear( sk );
    }

    element_t common_secret;
    element_init_Zr( common_secret, TEDataSingleton::getData().pairing_ );
    element_set( common_secret, coeffs[0].el_ );

    element_t common_public;
    element_init_G1( common_public, TEDataSingleton::getData().pairing_ );
    element_pow_zn( common_public, TEDataSingleton::getData().generator_, common_secret );

    element_clear( common_secret );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    element_clear( common_public );

    element_t rand;
    element_init_G1( rand, TEDataSingleton::getData().pairing_ );
    element_random( rand );

    std::tuple< encryption::element_wrapper, std::string, encryption::element_wrapper >
        corrupted_ciphertext;
    std::get< 0 >( corrupted_ciphertext ) = std::get< 0 >( ciphertext );
    std::get< 1 >( corrupted_ciphertext ) = std::get< 1 >( ciphertext );
    std::get< 2 >( corrupted_ciphertext ) = encryption::element_wrapper( rand );

    element_clear( rand );

    for ( size_t i = 0; i < 11; ++i ) {
        element_t decrypted;
        element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

        bool is_exception_caught = false;
        try {
            obj.Decrypt( decrypted, corrupted_ciphertext, secret_keys[i].el_ );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }

        element_clear( decrypted );
        BOOST_REQUIRE( is_exception_caught );

        element_init_G1( decrypted, TEDataSingleton::getData().pairing_ );

        obj.Decrypt( decrypted, ciphertext, secret_keys[i].el_ );

        element_t public_key;
        element_init_G1( public_key, TEDataSingleton::getData().pairing_ );
        element_pow_zn( public_key, TEDataSingleton::getData().generator_, secret_keys[i].el_ );

        BOOST_REQUIRE( !obj.Verify( corrupted_ciphertext, decrypted, public_key ) );

        element_clear( decrypted );
        element_clear( public_key );
    }
}

BOOST_AUTO_TEST_CASE( LagrangeInterpolationExceptions ) {
    for ( size_t i = 0; i < 100; i++ ) {
        std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 2;

        bool is_exception_caught = false;
        try {
            encryption::TE obj( num_signed, num_all );
            std::vector< int > vect;
            for ( size_t i = 0; i < num_signed - 1; i++ )
                vect.push_back( i + 1 );
            obj.LagrangeCoeffs( vect );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            encryption::TE obj( num_signed, num_all );
            std::vector< int > vect;
            for ( size_t i = 0; i < num_signed; i++ ) {
                vect.push_back( i + 1 );
            }
            vect.at( 1 ) = vect.at( 0 );
            obj.LagrangeCoeffs( vect );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );
    }
}

BOOST_AUTO_TEST_SUITE_END()
