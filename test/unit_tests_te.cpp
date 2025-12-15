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

#include "test/utils.h"
#include <threshold_encryption.h>
#include <tools/utils.h>
#include <memory>

#include <openssl/rand.h>

#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_TEST_GLOBAL_CONFIGURATION( GlobalConfig );

BOOST_AUTO_TEST_SUITE( TestAES )

BOOST_AUTO_TEST_CASE( SimpleAES ) {
    libBLS::ThresholdUtils::initRAND();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    libBLS::AES256Key random_aes_key;
    std::copy( key_bytes, key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_aes_key.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ random_aes_key };
    auto ciphertext = cipher.encrypt( message_bytes );
    auto decrypted_text = cipher.decrypt( ciphertext );

    BOOST_REQUIRE( decrypted_text == message_bytes );
}

BOOST_AUTO_TEST_CASE( wrongCiphertext ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    const std::string bad_message =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::vector< uint8_t > bad_message_bytes( bad_message.begin(), bad_message.end() );

    libBLS::AesGcmCipher cipher{ random_aes_key };
    auto bad_ciphertext = cipher.encrypt( bad_message_bytes );

    auto decrypted_text = cipher.decrypt( bad_ciphertext );

    BOOST_REQUIRE( decrypted_text != message_bytes );
    BOOST_REQUIRE( decrypted_text == bad_message_bytes );
}

BOOST_AUTO_TEST_CASE( wrongKey ) {
    libBLS::ThresholdUtils::initRAND();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    libBLS::AES256Key random_aes_key;
    std::copy( key_bytes, key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_aes_key.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ random_aes_key };
    auto ciphertext = cipher.encrypt( message_bytes );

    unsigned char bad_key_bytes[32];
    RAND_bytes( bad_key_bytes, sizeof( bad_key_bytes ) );
    libBLS::AES256Key random_bad_aes_key;
    std::copy(
        bad_key_bytes, bad_key_bytes + libBLS::AES_256_KEY_SIZE_BYTES, random_bad_aes_key.begin() );

    libBLS::AesGcmCipher bad_cipher{ random_bad_aes_key };
    BOOST_REQUIRE_THROW( bad_cipher.decrypt( ciphertext ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // Create AAD (additional authenticated data)
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    libBLS::AesGcmCipher cipher{ random_aes_key };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( message_bytes, aad );

    // Decrypt with same AAD - should succeed
    auto decrypted_text = cipher.decrypt( ciphertext, aad );
    BOOST_REQUIRE( decrypted_text == message_bytes );
}

BOOST_AUTO_TEST_CASE( AESWithWrongAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // Create AAD
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    // Different AAD
    std::vector< uint8_t > wrong_aad = { 0xFF, 0xFE, 0xFD, 0xFC };

    libBLS::AesGcmCipher cipher{ random_aes_key };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( message_bytes, aad );

    // Decrypt with different AAD - should fail (authentication error)
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, wrong_aad ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithMissingAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // Create AAD
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    libBLS::AesGcmCipher cipher{ random_aes_key };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( message_bytes, aad );

    // Decrypt without AAD (nullopt) - should fail (authentication error)
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, std::nullopt ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithoutAAD_BackwardCompatibility ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "Hello, this is a test message without AAD!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ random_aes_key };

    // Encrypt without AAD (backward compatible)
    auto ciphertext = cipher.encrypt( message_bytes );

    // Decrypt without AAD - should succeed
    auto decrypted_text = cipher.decrypt( ciphertext );
    BOOST_REQUIRE( decrypted_text == message_bytes );

    // Encrypt without AAD, try to decrypt with AAD - should fail
    auto ciphertext2 = cipher.encrypt( message_bytes, std::nullopt );
    std::vector< uint8_t > fake_aad = { 0x01, 0x02, 0x03 };
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext2, fake_aad ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithEmptyAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    const std::string message = "Hello, this is a test message with empty AAD!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // Empty AAD (different from nullopt)
    std::vector< uint8_t > empty_aad = {};

    libBLS::AesGcmCipher cipher{ random_aes_key };

    // Encrypt with empty AAD
    auto ciphertext = cipher.encrypt( message_bytes, empty_aad );

    // Decrypt with empty AAD - should succeed
    auto decrypted_text = cipher.decrypt( ciphertext, empty_aad );
    BOOST_REQUIRE( decrypted_text == message_bytes );

    // Empty AAD should behave the same as nullopt
    auto decrypted_text2 = cipher.decrypt( ciphertext, std::nullopt );
    BOOST_REQUIRE( decrypted_text2 == message_bytes );
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( ThresholdEncryption )

BOOST_AUTO_TEST_CASE( CipheredKey ) {
    for ( size_t i = 0; i < 20; i++ ) {
        // random key data
        libBLS::algebra::G2Point u = libBLS::algebra::G2Point::random();
        libBLS::AES256Key ciphered_key;
        RAND_bytes( ciphered_key.data(), ciphered_key.size() );
        libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();

        // check constructor
        libBLS::CipheredKey key = libBLS::CipheredKey( u, ciphered_key, w );

        BOOST_REQUIRE( key.U == u );
        BOOST_REQUIRE( key.V == ciphered_key );
        BOOST_REQUIRE( key.W == w );

        // convert to bytes & back
        std::array< uint8_t, libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES > bytes = key.toBytes();
        libBLS::CipheredKey restored_key = libBLS::CipheredKey::fromBytes( bytes );

        BOOST_REQUIRE( key == restored_key );
    }
}

BOOST_AUTO_TEST_CASE( CipheredKeyException ) {
    // zero u element
    libBLS::algebra::G2Point u = libBLS::algebra::G2Point::identity();
    libBLS::AES256Key ciphered_key;
    RAND_bytes( ciphered_key.data(), ciphered_key.size() );
    libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();
    BOOST_REQUIRE_THROW(
        libBLS::CipheredKey( u, ciphered_key, w ), libBLS::ThresholdUtils::IsNotWellFormed );

    // zero w element
    u = libBLS::algebra::G2Point::random();
    w = libBLS::algebra::G1Point::identity();
    BOOST_REQUIRE_THROW(
        libBLS::CipheredKey( u, ciphered_key, w ), libBLS::ThresholdUtils::IsNotWellFormed );

    // correct ciphered key, but changed U mid-execution
    w = libBLS::algebra::G1Point::random();
    libBLS::CipheredKey key = libBLS::CipheredKey( u, ciphered_key, w );
    key.U = libBLS::algebra::G2Point::identity();
    BOOST_REQUIRE_THROW( key.validate(), libBLS::ThresholdUtils::IsNotWellFormed );

    // correct ciphered key, but changed W mid-execution
    key.U = libBLS::algebra::G2Point::random();
    key.W = libBLS::algebra::G1Point::identity();
    BOOST_REQUIRE_THROW( key.validate(), libBLS::ThresholdUtils::IsNotWellFormed );
}

BOOST_AUTO_TEST_CASE( Ciphertext ) {
    for ( size_t i = 0; i < 20; i++ ) {
        // random key data
        libBLS::algebra::G2Point u = libBLS::algebra::G2Point::random();
        libBLS::AES256Key ciphered_key;
        RAND_bytes( ciphered_key.data(), ciphered_key.size() );
        libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();
        // convert to bytes & back
        libBLS::CipheredKey key = libBLS::CipheredKey( u, ciphered_key, w );

        // random 1000 bytes
        std::vector< uint8_t > data;
        data.resize( rand() % 1000 + libBLS::RANDOM_SECRET_SIZE_BYTES );  // must be at least rand
                                                                          // secret bytes
        RAND_bytes( data.data(), data.size() );

        libBLS::Ciphertext ciphertext = libBLS::Ciphertext( key, data );
        std::vector< uint8_t > bytes = ciphertext.toBytes();
        libBLS::Ciphertext restoredCiphertext = libBLS::Ciphertext::fromBytes( bytes );

        BOOST_REQUIRE( ciphertext == restoredCiphertext );

        // getDecryptionShareInput
        auto uCopy = u;
        uCopy.toAffineCoordinates();
        auto U = uCopy.toString( libBLS::Base::HEXA );
        std::string concatenated;
        for ( size_t j = 0; j < U.size(); ++j ) {
            concatenated += U[j];
        }
        for ( auto cipheredkey : ciphertext.keys ) {
            BOOST_REQUIRE( cipheredkey.getDecryptionShareInput() == concatenated );
        }
    }
}

BOOST_AUTO_TEST_CASE( CiphertextException ) {
    // constructor
    // data is too short
    auto key = libBLS::CipheredKey::random();
    std::vector< uint8_t > data;
    BOOST_REQUIRE_THROW( libBLS::Ciphertext( key, data ), libBLS::ThresholdUtils::IsNotWellFormed );

    // still too short - should have at least +1 byte of actual data
    data.resize( libBLS::RANDOM_SECRET_SIZE_BYTES );
    BOOST_REQUIRE_THROW( libBLS::Ciphertext( key, data ), libBLS::ThresholdUtils::IsNotWellFormed );

    // requires exactly 1 or 2 keys
    BOOST_REQUIRE_THROW( libBLS::Ciphertext( std::vector< libBLS::CipheredKey >(), data ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    // requires exactly 1 or 2 keys
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext( { key, key, key }, data ), libBLS::ThresholdUtils::IsNotWellFormed );

    // getDecryptionShareInput - U element from key is not well formed
    libBLS::Ciphertext ciphertext;

    for ( auto cipheredKey : ciphertext.keys ) {
        cipheredKey.U = libBLS::algebra::G2Point::identity();
        BOOST_REQUIRE_THROW(
            cipheredKey.getDecryptionShareInput(), libBLS::ThresholdUtils::IncorrectInput );
    }

    // from bytes
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

    // bytes allow for ciphered key + random secret, but no data
    std::vector< uint8_t > bytes3( libBLS::RANDOM_SECRET_SIZE_BYTES );
    RAND_bytes( bytes3.data(), bytes3.size() );
    libBLS::Ciphertext cipher;
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( bytes2 ), libBLS::ThresholdUtils::IncorrectInput );
}

BOOST_AUTO_TEST_CASE( SimpleEncryption ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    libBLS::AES256Key random_aes_key;
    RAND_bytes( random_aes_key.data(), random_aes_key.size() );

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    auto result = te_instance.getCiphertext( random_aes_key, public_key );

    // one decrypt share at a time
    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< libBLS::algebra::G2Point > shares1;

        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );
        shares1.push_back( decryption_share );

        // standalone validation
        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryption_share, public_key ) );

        // batched decryption - optimistic
        std::vector< libBLS::CipheredKey > cipheredKeys = { cipheredKey };
        std::vector< bool > verifications_key1 =
            te_instance.VerifyBatch( cipheredKeys, shares1, { public_key } );
        BOOST_REQUIRE( std::all_of(
            verifications_key1.begin(), verifications_key1.end(), []( bool v ) { return v; } ) );


        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key res = te_instance.CombineShares( cipheredKey, shares );

        BOOST_REQUIRE( res == random_aes_key );
    }
}

BOOST_AUTO_TEST_CASE( SimpleEncryptionWithAES ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key );

    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();
    for ( const auto& cipheredKey : ciphertext_with_aes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryption_share, public_key ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( cipheredKey, shares );

        libBLS::AesGcmCipher aesGcmCipher{ decrypted_aes_key };
        std::vector< uint8_t > plaintext = aesGcmCipher.decrypt( encrypted_message );

        // append random secret to end of original message
        libBLS::RandSecret rand_secret = ciphertext_with_aes.random_secret;
        message_bytes.insert( message_bytes.end(), rand_secret.begin(), rand_secret.end() );

        BOOST_REQUIRE( plaintext == message_bytes );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionWithAES_AAD ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users! This is a test with AAD!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // AAD that binds the ciphertext to a specific context (e.g., contract address)
    std::vector< uint8_t > aad = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    // Encrypt with AAD
    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key, aad );

    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertext_with_aes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryption_share, public_key ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with the same AAD - should succeed
        libBLS::AesGcmCipher aesGcmCipher{ decrypted_aes_key };
        std::vector< uint8_t > plaintext = aesGcmCipher.decrypt( encrypted_message, aad );

        // Append random secret to end of original message for comparison
        libBLS::RandSecret rand_secret = ciphertext_with_aes.random_secret;
        std::vector< uint8_t > expected_message = message_bytes;
        expected_message.insert( expected_message.end(), rand_secret.begin(), rand_secret.end() );

        BOOST_REQUIRE( plaintext == expected_message );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionWithAES_WrongAAD ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users! This is a test with AAD!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    // AAD used for encryption
    std::vector< uint8_t > aad = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    // Wrong AAD for decryption
    std::vector< uint8_t > wrong_aad = { 0x01, 0x02, 0x03, 0x04 };

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    // Encrypt with AAD
    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key, aad );

    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertext_with_aes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with wrong AAD - should fail
        libBLS::AesGcmCipher aesGcmCipher{ decrypted_aes_key };
        BOOST_REQUIRE_THROW( aesGcmCipher.decrypt( encrypted_message, wrong_aad ), std::runtime_error );

        // Decrypt without AAD - should also fail
        BOOST_REQUIRE_THROW( aesGcmCipher.decrypt( encrypted_message, std::nullopt ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongKey ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    auto ciphertext_with_aes = te_instance.encryptWithAES( message_bytes, public_key );

    auto encrypted_message = ciphertext_with_aes.ciphertext->getData();
    for ( const auto& cipheredKey : ciphertext_with_aes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryption_share, public_key ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key random_aes_key;
        RAND_bytes( random_aes_key.data(), random_aes_key.size() );


        libBLS::AesGcmCipher cipher{ random_aes_key };
        BOOST_REQUIRE_THROW( cipher.decrypt( encrypted_message ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongCiphertext ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    libBLS::CipherResult ciphertext_with_aes =
        te_instance.encryptWithAES( message_bytes, public_key );

    for ( const auto& cipheredKey : ciphertext_with_aes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredKey, secret_key );
        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryption_share, public_key ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );
        libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( cipheredKey, shares );

        std::string bad_message =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        std::vector< uint8_t > bad_message_bytes( message.begin(), message.end() );

        auto bad_encrypted_message =
            te_instance.encryptWithAES( bad_message_bytes, public_key ).ciphertext->getData();

        libBLS::AesGcmCipher cipher{ decrypted_aes_key };
        BOOST_REQUIRE_THROW( cipher.decrypt( bad_encrypted_message ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionCipherToBytes ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > message_bytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point public_key = secret_key * libBLS::algebra::G2Point::generator();

    std::string common_public_str = public_key.toString( libBLS::Base::HEXA );
    auto result = te_instance.encryptMessage( message_bytes, common_public_str );
    libBLS::RandSecret rand_secret = result.second;

    std::vector< uint8_t > encrypted_msg_bytes =
        libBLS::ThresholdUtils::hexCStringToBytes( result.first.c_str() );

    libBLS::Ciphertext ciphertext = libBLS::Ciphertext::fromBytes( encrypted_msg_bytes );
    auto encrypted_message = ciphertext.getData();

    for ( const auto& cipheredkey : ciphertext.getKeys() ) {
        libBLS::algebra::G2Point decryption_share =
            te_instance.getDecryptionShare( cipheredkey, secret_key );

        BOOST_REQUIRE( te_instance.Verify( cipheredkey, decryption_share, public_key ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

        libBLS::AES256Key decrypted_aes_key = te_instance.CombineShares( cipheredkey, shares );

        libBLS::AesGcmCipher cipher{ decrypted_aes_key };
        std::vector< uint8_t > plaintext = cipher.decrypt( encrypted_message );

        // append random secret to the message
        message_bytes.insert( message_bytes.end(), rand_secret.begin(), rand_secret.end() );

        BOOST_REQUIRE( plaintext == message_bytes );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionReal ) {
    size_t t = 11;
    size_t n = 16;
    libBLS::TE obj = libBLS::TE( t, n );

    std::vector< libBLS::algebra::FrScalar > coeffs( t );
    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();
        while ( elem.isZero() ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( n );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    libBLS::algebra::FrScalar common_secret = coeffs[0];

    libBLS::algebra::G2Point common_public = common_secret * libBLS::algebra::G2Point::generator();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( t );
        std::vector< libBLS::algebra::G2Point > decrypted_shares( t );
        std::vector< libBLS::algebra::G2Point > pubKeys( t );

        for ( size_t i = 0; i < t; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secret_keys[i] );

            decrypted_shares[i] = decrypted;

            libBLS::algebra::G2Point public_key =
                secret_keys[i] * libBLS::algebra::G2Point::generator();

            pubKeys[i] = public_key;

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, public_key ) );

            shares[i].first = decrypted;

            shares[i].second = i + 1;
        }

        // batched decryption - optimistic
        std::vector< libBLS::CipheredKey > keysBatch;
        keysBatch.push_back( cipheredKey );

        auto verifications = obj.VerifyBatch( keysBatch, decrypted_shares, pubKeys );
        BOOST_REQUIRE(
            std::all_of( verifications.begin(), verifications.end(), []( bool v ) { return v; } ) );


        libBLS::AES256Key res = obj.CombineShares( cipheredKey, shares );

        BOOST_REQUIRE( res == key );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > tooFewShares(
            shares.begin(), shares.begin() + shares.size() - 2 );  // t - 1 elements

        BOOST_REQUIRE_THROW( obj.CombineShares( cipheredKey, tooFewShares ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomPK ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

    std::vector< libBLS::algebra::FrScalar > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();
        while ( elem.isZero() ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    libBLS::algebra::G2Point common_public = libBLS::algebra::G2Point::random();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( 11 );


    for ( const auto& cipheredKey : result.ciphertext ) {
        for ( size_t i = 0; i < 11; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secret_keys[i] );
            libBLS::algebra::G2Point public_key =
                secret_keys[i] * libBLS::algebra::G2Point::generator();

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, public_key ) );

            shares[i].first = decrypted;

            shares[i].second = i + 1;
        }

        libBLS::AES256Key res = obj.CombineShares( cipheredKey, shares );

        BOOST_REQUIRE( res != key );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionRandomSK ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

    std::vector< libBLS::algebra::FrScalar > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();
        while ( elem.isZero() ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        // let secret_key[7] be a random generated value instead of correctly generated
        if ( i == 7 ) {
            sk = libBLS::algebra::FrScalar::random();
        }

        secret_keys[i] = sk;
    }

    libBLS::algebra::FrScalar common_secret = coeffs[0];

    libBLS::algebra::G2Point common_public = common_secret * libBLS::algebra::G2Point::generator();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( 11 );

        for ( size_t i = 0; i < 11; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secret_keys[i] );
            libBLS::algebra::G2Point public_key =
                secret_keys[i] * libBLS::algebra::G2Point::generator();

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, public_key ) );

            shares[i].first = decrypted;

            shares[i].second = i + 1;
        }

        libBLS::AES256Key res = obj.CombineShares( cipheredKey, shares );

        BOOST_REQUIRE( res != key );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionCorruptedCiphertext ) {
    libBLS::TE obj = libBLS::TE( 11, 16 );

    std::vector< libBLS::algebra::FrScalar > coeffs( 11 );
    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();
        while ( elem.isZero() ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secret_keys[i] = sk;
    }

    libBLS::algebra::FrScalar common_secret = coeffs[0];

    libBLS::algebra::G2Point common_public = common_secret * libBLS::algebra::G2Point::identity();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, common_public );

    libBLS::algebra::G1Point rand = libBLS::algebra::G1Point::random();

    libBLS::CipheredKey cipheredKeyToCorrupt = result.ciphertext[0];
    libBLS::CipheredKey corrupted_ciphered_key = { cipheredKeyToCorrupt.U, cipheredKeyToCorrupt.V,
        rand };

    for ( size_t i = 0; i < 11; ++i ) {
        libBLS::algebra::G2Point decryptedWrong =
            obj.getDecryptionShare( corrupted_ciphered_key, secret_keys[i] );
        libBLS::algebra::G2Point decryptedCorrect =
            obj.getDecryptionShare( cipheredKeyToCorrupt, secret_keys[i] );

        libBLS::algebra::G2Point public_key = secret_keys[i] * libBLS::algebra::G2Point::identity();

        // wrong cipher key, correct decrypted key - should return false
        BOOST_REQUIRE( !obj.Verify( corrupted_ciphered_key, decryptedCorrect, public_key ) );

        // wrong decrypted key, correct cipher key - should return false
        BOOST_REQUIRE( !obj.Verify( cipheredKeyToCorrupt, decryptedWrong, public_key ) );
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
            BOOST_REQUIRE_THROW( libBLS::algebra::lagrangeCoeffs( vect, num_signed ),
                libBLS::ThresholdUtils::IncorrectInput );
        }

        {
            libBLS::TE obj( num_signed, num_all );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < num_signed; i++ ) {
                vect.push_back( i + 1 );
            }
            vect.at( 1 ) = vect.at( 0 );
            BOOST_REQUIRE_THROW( libBLS::algebra::lagrangeCoeffs( vect, num_signed ),
                libBLS::ThresholdUtils::IncorrectInput );
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
