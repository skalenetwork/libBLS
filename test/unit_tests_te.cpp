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

  @file unit_tests_te.cpp
  @author Oleh Nikolaiev
  @date 2019
 */

#include <random>

#include <threshold_encryption.h>
#include <tools/utils.h>

#include <openssl/rand.h>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( ThresholdEncryption )

BOOST_AUTO_TEST_CASE( SimpleEncryption ) {
    crypto::TE te_instance = crypto::TE( 1, 1 );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto ciphertext = te_instance.Encrypt( message, public_key );

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    std::string res = te_instance.CombineShares( ciphertext, shares );

    BOOST_REQUIRE( res == message );
}

BOOST_AUTO_TEST_CASE( SimpleEncryptionWithAES ) {
    crypto::TE te_instance = crypto::TE( 1, 1 );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto ciphertext_with_aes = te_instance.encryptWithAES( message, public_key );

    auto ciphertext = ciphertext_with_aes.first;
    auto encrypted_message = ciphertext_with_aes.second;

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string plaintext =
        crypto::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    BOOST_REQUIRE( plaintext == message );
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongKey ) {
    crypto::TE te_instance = crypto::TE( 1, 1 );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto ciphertext_with_aes = te_instance.encryptWithAES( message, public_key );

    auto ciphertext = ciphertext_with_aes.first;
    auto encrypted_message = ciphertext_with_aes.second;

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    // std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );
    crypto::ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    std::string plaintext = crypto::ThresholdUtils::aesDecrypt( encrypted_message, random_aes_key );

    BOOST_REQUIRE( plaintext != message );
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongCiphertext ) {
    crypto::TE te_instance = crypto::TE( 1, 1 );

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto ciphertext_with_aes = te_instance.encryptWithAES( message, public_key );

    auto ciphertext = ciphertext_with_aes.first;
    // auto encrypted_message = ciphertext_with_aes.second;

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string bad_message = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    auto bad_encrypted_message = te_instance.encryptWithAES( bad_message, public_key ).second;

    std::string plaintext =
        crypto::ThresholdUtils::aesDecrypt( bad_encrypted_message, decrypted_aes_key );

    BOOST_REQUIRE( plaintext != message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionReal ) {
    crypto::TE obj = crypto::TE( 11, 16 );

    std::vector< libff::alt_bn128_Fr > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();
        while ( elem.is_zero() ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libff::alt_bn128_Fr sk = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libff::alt_bn128_Fr tmp1( i + 1 );

            libff::alt_bn128_Fr tmp3 = libff::power( tmp1, j );

            libff::alt_bn128_Fr tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    libff::alt_bn128_Fr common_secret = coeffs[0];

    libff::alt_bn128_G2 common_public = common_secret * libff::alt_bn128_G2::one();

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted = obj.getDecryptionShare( ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    std::string res = obj.CombineShares( ciphertext, shares );

    BOOST_REQUIRE( res == message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomPK ) {
    crypto::TE obj = crypto::TE( 11, 16 );

    std::vector< libff::alt_bn128_Fr > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();
        while ( elem.is_zero() ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libff::alt_bn128_Fr sk = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libff::alt_bn128_Fr tmp1( i + 1 );

            libff::alt_bn128_Fr tmp3 = libff::power( tmp1, j );

            libff::alt_bn128_Fr tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    // libff::alt_bn128_Fr common_secret = coeffs[0];

    // element_pow_zn(common_public, obj.generator_, common_secret);
    // let common_public be a random element of G1 instead of correct one in the previous line

    libff::alt_bn128_G2 common_public = libff::alt_bn128_G2::random_element();

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted = obj.getDecryptionShare( ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    std::string res = obj.CombineShares( ciphertext, shares );

    BOOST_REQUIRE( res != message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomSK ) {
    crypto::TE obj = crypto::TE( 11, 16 );

    std::vector< libff::alt_bn128_Fr > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();
        while ( elem.is_zero() ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libff::alt_bn128_Fr sk = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libff::alt_bn128_Fr tmp1( i + 1 );

            libff::alt_bn128_Fr tmp3 = libff::power( tmp1, j );

            libff::alt_bn128_Fr tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        // let secret_key[7] be a random generated value instead of correctly generated
        if ( i == 7 ) {
            sk = libff::alt_bn128_Fr::random_element();
        }

        secret_keys[i] = sk;
    }

    libff::alt_bn128_Fr common_secret = coeffs[0];

    libff::alt_bn128_G2 common_public = common_secret * libff::alt_bn128_G2::one();

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted = obj.getDecryptionShare( ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    std::string res = obj.CombineShares( ciphertext, shares );

    BOOST_REQUIRE( res != message );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionCorruptedCiphertext ) {
    crypto::TE obj = crypto::TE( 11, 16 );

    std::vector< libff::alt_bn128_Fr > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();
        while ( elem.is_zero() ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libff::alt_bn128_Fr sk = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libff::alt_bn128_Fr tmp1( i + 1 );

            libff::alt_bn128_Fr tmp3 = libff::power( tmp1, j );

            libff::alt_bn128_Fr tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    libff::alt_bn128_Fr common_secret = coeffs[0];

    libff::alt_bn128_G2 common_public = common_secret * libff::alt_bn128_G2::one();

    std::string message =
        "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";  // message should be 64
                                                                             // length

    auto ciphertext = obj.Encrypt( message, common_public );

    libff::alt_bn128_G1 rand = libff::alt_bn128_G1::random_element();

    std::tuple< libff::alt_bn128_G2, std::string, libff::alt_bn128_G1 > corrupted_ciphertext;
    std::get< 0 >( corrupted_ciphertext ) = std::get< 0 >( ciphertext );
    std::get< 1 >( corrupted_ciphertext ) = std::get< 1 >( ciphertext );
    std::get< 2 >( corrupted_ciphertext ) = rand;

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted;

        BOOST_REQUIRE_THROW(
            decrypted = obj.getDecryptionShare( corrupted_ciphertext, secret_keys[i] ),
            crypto::ThresholdUtils::IncorrectInput );

        decrypted = obj.getDecryptionShare( ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( !obj.Verify( corrupted_ciphertext, decrypted, public_key ) );
    }
}

BOOST_AUTO_TEST_CASE( LagrangeInterpolationExceptions ) {
    for ( size_t i = 0; i < 100; i++ ) {
        std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 2;

        {
            crypto::TE obj( num_signed, num_all );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < num_signed - 1; i++ )
                vect.push_back( i + 1 );
            BOOST_REQUIRE_THROW( crypto::ThresholdUtils::LagrangeCoeffs( vect, num_signed ),
                crypto::ThresholdUtils::IncorrectInput );
        }

        {
            crypto::TE obj( num_signed, num_all );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < num_signed; i++ ) {
                vect.push_back( i + 1 );
            }
            vect.at( 1 ) = vect.at( 0 );
            BOOST_REQUIRE_THROW( crypto::ThresholdUtils::LagrangeCoeffs( vect, num_signed ),
                crypto::ThresholdUtils::IncorrectInput );
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
