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
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( ThresholdEncryption )

BOOST_AUTO_TEST_CASE( CipheredKeyToAndFromBytes ) {
    libBLS::TEBase::initializeIfNecessary();

    for ( size_t i = 0; i < 1000; i++ ) {
        // random key data
        libff::alt_bn128_G2 u = libff::alt_bn128_G2::random_element();
        libBLS::AES256Key ciphered_key;
        RAND_bytes( ciphered_key.data(), ciphered_key.size() );
        libff::alt_bn128_G1 w = libff::alt_bn128_G1::random_element();
        // convert to bytes & back
        libBLS::CipheredKey key = libBLS::CipheredKey( u, ciphered_key, w );
        std::array< uint8_t, libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES > bytes = key.toBytes();
        libBLS::CipheredKey restored_key = libBLS::CipheredKey::fromBytes( bytes );

        BOOST_REQUIRE( key == restored_key );
    }
}

BOOST_AUTO_TEST_CASE( CiphertextToAndFromBytes ) {
    libBLS::TEBase::initializeIfNecessary();

    for ( size_t i = 0; i < 1000; i++ ) {
        // random key data
        libff::alt_bn128_G2 u = libff::alt_bn128_G2::random_element();
        libBLS::AES256Key ciphered_key;
        RAND_bytes( ciphered_key.data(), ciphered_key.size() );
        libff::alt_bn128_G1 w = libff::alt_bn128_G1::random_element();
        // convert to bytes & back
        libBLS::CipheredKey key = libBLS::CipheredKey( u, ciphered_key, w );

        // random 1000 bytes
        std::vector< uint8_t > data;
        data.resize( rand() % 1000 + 1 );  // must be at least 1 byte
        RAND_bytes( data.data(), data.size() );

        libBLS::Ciphertext ciphertext = libBLS::Ciphertext( key, data );
        std::vector< uint8_t > bytes = ciphertext.toBytes();
        libBLS::Ciphertext restoredCiphertext = libBLS::Ciphertext::fromBytes( bytes );

        BOOST_REQUIRE( ciphertext == restoredCiphertext );
    }
}

BOOST_AUTO_TEST_CASE( CiphertextFromBytesException ) {
    // bytes only allow for key bytes. No data
    std::vector< uint8_t > bytes( libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES );
    RAND_bytes( bytes.data(), bytes.size() );
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( bytes ), libBLS::ThresholdUtils::IncorrectInput );

    // bytes are too short, even for key bytes
    std::vector< uint8_t > bytes2( libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES - 1 );
    RAND_bytes( bytes2.data(), bytes2.size() );
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( bytes2 ), libBLS::ThresholdUtils::IncorrectInput );

    // bytes allow at least 1 byte of data
    std::vector< uint8_t > bytes3( libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES + 1 );
    RAND_bytes( bytes3.data(), bytes3.size() );
    libBLS::Ciphertext cipher;
    BOOST_REQUIRE_NO_THROW( cipher = libBLS::Ciphertext::fromBytes( bytes3 ) );
    BOOST_REQUIRE( cipher.getData().size() == 1 );
}

BOOST_AUTO_TEST_CASE( SimpleEncryption ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto result = te_instance.getCiphertext( random_aes_key, public_key );

    libff::alt_bn128_G2 decryption_share =
        te_instance.getDecryptionShare( *result.ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( *result.ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    libBLS::AES256Key res = te_instance.CombineShares( *result.ciphertext, shares );

    BOOST_REQUIRE( res == random_aes_key );
}

BOOST_AUTO_TEST_CASE( SimpleEncryptionWithAES ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key );

    auto ciphertext = ciphertext_with_aes.ciphertext->key;
    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::vector< uint8_t > plaintext =
        libBLS::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    // append random secret to end of original message
    libBLS::RandSecret rand_secret = ciphertext_with_aes.random_secret;
    message_bytes.insert( message_bytes.end(), rand_secret.begin(), rand_secret.end() );

    BOOST_REQUIRE( plaintext == message_bytes );
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongKey ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto ciphertext_with_aes = te_instance.encryptWithAES( message_bytes, public_key );

    auto ciphertext = ciphertext_with_aes.ciphertext->key;
    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    libBLS::ThresholdUtils::initAES();

    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::aesDecrypt( encrypted_message, random_aes_key ),
        std::runtime_error );
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongCiphertext ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key );

    libBLS::CipheredKey ciphertext = ciphertext_with_aes.ciphertext->key;

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string bad_message = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::vector< uint8_t > bad_message_bytes( message.begin(), message.end() );

    auto bad_encrypted_message =
        te_instance.encryptWithAES( bad_message_bytes, public_key ).ciphertext->getData();

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::aesDecrypt( bad_encrypted_message, decrypted_aes_key ),
        std::runtime_error );
}

BOOST_AUTO_TEST_CASE( EncryptionCipherToBytes ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();

    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    auto str = libBLS::ThresholdUtils::G2ToString( public_key, 16 );
    std::string common_public_str = "";
    for ( auto& elem : str ) {
        while ( elem.size() < 64 ) {
            elem = "0" + elem;
        }
        common_public_str += elem;
    }

    auto result = te_instance.encryptMessage( message_bytes, common_public_str );
    libBLS::RandSecret rand_secret = result.second;

    std::vector< uint8_t > encrypted_msg_bytes =
        libBLS::ThresholdUtils::hexCStringToBytes( result.first.c_str() );

    libBLS::Ciphertext ciphertext = libBLS::Ciphertext::fromBytes( encrypted_msg_bytes );

    libBLS::CipheredKey ciphered_key = ciphertext.key;
    auto encrypted_message = ciphertext.getData();

    libff::alt_bn128_G2 decryption_share =
        te_instance.getDecryptionShare( ciphered_key, secret_key );

    BOOST_REQUIRE( te_instance.Verify( ciphered_key, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( ciphered_key, shares );

    std::vector< uint8_t > plaintext =
        libBLS::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    // append random secret to the message
    message_bytes.insert( message_bytes.end(), rand_secret.begin(), rand_secret.end() );

    BOOST_REQUIRE( plaintext == message_bytes );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionReal ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

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

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted =
            obj.getDecryptionShare( *result.ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( *result.ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    libBLS::AES256Key res = obj.CombineShares( *result.ciphertext, shares );

    BOOST_REQUIRE( res == key );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomPK ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

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

    libff::alt_bn128_G2 common_public = libff::alt_bn128_G2::random_element();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted =
            obj.getDecryptionShare( *result.ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( *result.ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    libBLS::AES256Key res = obj.CombineShares( *result.ciphertext, shares );

    BOOST_REQUIRE( res != key );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomSK ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

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

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares( 11 );

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted =
            obj.getDecryptionShare( *result.ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( obj.Verify( *result.ciphertext, decrypted, public_key ) );

        shares[i].first = decrypted;

        shares[i].second = i + 1;
    }

    libBLS::AES256Key res = obj.CombineShares( *result.ciphertext, shares );

    BOOST_REQUIRE( res != key );
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionCorruptedCiphertext ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

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

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    libff::alt_bn128_G1 rand = libff::alt_bn128_G1::random_element();

    libBLS::CipheredKey corrupted_ciphered_key = { result.ciphertext->U, result.ciphertext->V,
        rand };

    for ( size_t i = 0; i < 11; ++i ) {
        libff::alt_bn128_G2 decrypted;

        BOOST_REQUIRE_THROW(
            decrypted = obj.getDecryptionShare( corrupted_ciphered_key, secret_keys[i] ),
            libBLS::ThresholdUtils::IncorrectInput );

        decrypted = obj.getDecryptionShare( *result.ciphertext, secret_keys[i] );

        libff::alt_bn128_G2 public_key = secret_keys[i] * libff::alt_bn128_G2::one();

        BOOST_REQUIRE( !obj.Verify( corrupted_ciphered_key, decrypted, public_key ) );
    }
}

BOOST_AUTO_TEST_CASE( LagrangeInterpolationExceptions ) {
    for ( size_t i = 0; i < 100; i++ ) {
        std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 2;

        {
            libBLS::TE obj( num_signed, num_all );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < num_signed - 1; i++ )
                vect.push_back( i + 1 );
            BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::LagrangeCoeffs( vect, num_signed ),
                libBLS::ThresholdUtils::IncorrectInput );
        }

        {
            libBLS::TE obj( num_signed, num_all );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < num_signed; i++ ) {
                vect.push_back( i + 1 );
            }
            vect.at( 1 ) = vect.at( 0 );
            BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::LagrangeCoeffs( vect, num_signed ),
                libBLS::ThresholdUtils::IncorrectInput );
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()