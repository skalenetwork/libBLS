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
    unsigned char keyBytes[32];
    RAND_bytes( keyBytes, sizeof( keyBytes ) );
    libBLS::AES256Key randomAesKey;
    std::copy( keyBytes, keyBytes + libBLS::AES_256_KEY_SIZE_BYTES, randomAesKey.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ randomAesKey };
    auto ciphertext = cipher.encrypt( messageBytes );
    auto decryptedText = cipher.decrypt( ciphertext );

    BOOST_REQUIRE( decryptedText == messageBytes );
}

BOOST_AUTO_TEST_CASE( wrongCiphertext ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    const std::string badMessage =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    std::vector< uint8_t > badMessageBytes( badMessage.begin(), badMessage.end() );

    libBLS::AesGcmCipher cipher{ randomAesKey };
    auto bad_ciphertext = cipher.encrypt( badMessageBytes );

    auto decryptedText = cipher.decrypt( bad_ciphertext );

    BOOST_REQUIRE( decryptedText != messageBytes );
    BOOST_REQUIRE( decryptedText == badMessageBytes );
}

BOOST_AUTO_TEST_CASE( wrongKey ) {
    libBLS::ThresholdUtils::initRAND();
    unsigned char keyBytes[32];
    RAND_bytes( keyBytes, sizeof( keyBytes ) );
    libBLS::AES256Key randomAesKey;
    std::copy( keyBytes, keyBytes + libBLS::AES_256_KEY_SIZE_BYTES, randomAesKey.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ randomAesKey };
    auto ciphertext = cipher.encrypt( messageBytes );

    unsigned char bad_keyBytes[32];
    RAND_bytes( bad_keyBytes, sizeof( bad_keyBytes ) );
    libBLS::AES256Key randomBadAesKey;
    std::copy(
        bad_keyBytes, bad_keyBytes + libBLS::AES_256_KEY_SIZE_BYTES, randomBadAesKey.begin() );

    libBLS::AesGcmCipher bad_cipher{ randomBadAesKey };
    BOOST_REQUIRE_THROW( bad_cipher.decrypt( ciphertext ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Create AAD (additional authenticated data)
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    libBLS::AesGcmCipher cipher{ randomAesKey };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Decrypt with same AAD - should succeed
    auto decryptedText = cipher.decrypt( ciphertext, aad );
    BOOST_REQUIRE( decryptedText == messageBytes );
}

BOOST_AUTO_TEST_CASE( AESWithWrongAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Create AAD
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    // Different AAD
    std::vector< uint8_t > wrong_aad = { 0xFF, 0xFE, 0xFD, 0xFC };

    libBLS::AesGcmCipher cipher{ randomAesKey };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Decrypt with different AAD - should fail (authentication error)
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, wrong_aad ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithMissingAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Hello, this is a test message for AAD encryption!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Create AAD
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    libBLS::AesGcmCipher cipher{ randomAesKey };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Decrypt without AAD (nullopt) - should fail (authentication error)
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, std::nullopt ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithoutAAD_BackwardCompatibility ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Hello, this is a test message without AAD!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ randomAesKey };

    // Encrypt without AAD (backward compatible)
    auto ciphertext = cipher.encrypt( messageBytes );

    // Decrypt without AAD - should succeed
    auto decryptedText = cipher.decrypt( ciphertext );
    BOOST_REQUIRE( decryptedText == messageBytes );

    // Encrypt without AAD, try to decrypt with AAD - should fail
    auto ciphertext2 = cipher.encrypt( messageBytes, std::nullopt );
    std::vector< uint8_t > fakeAad = { 0x01, 0x02, 0x03 };
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext2, fakeAad ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESWithEmptyAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Hello, this is a test message with empty AAD!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Empty AAD (different from nullopt)
    std::vector< uint8_t > empty_aad = {};

    libBLS::AesGcmCipher cipher{ randomAesKey };

    // Encrypt with empty AAD
    auto ciphertext = cipher.encrypt( messageBytes, empty_aad );

    // Decrypt with empty AAD - should succeed
    auto decryptedText = cipher.decrypt( ciphertext, empty_aad );
    BOOST_REQUIRE( decryptedText == messageBytes );

    // Empty AAD should behave the same as nullopt
    auto decryptedText2 = cipher.decrypt( ciphertext, std::nullopt );
    BOOST_REQUIRE( decryptedText2 == messageBytes );
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( ThresholdEncryption )

BOOST_AUTO_TEST_CASE( CipheredKey ) {
    for ( size_t i = 0; i < 20; i++ ) {
        // random key data
        libBLS::algebra::G2Point u = libBLS::algebra::G2Point::random();
        libBLS::AES256Key cipheredKey;
        RAND_bytes( cipheredKey.data(), cipheredKey.size() );
        libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();

        // check constructor
        libBLS::CipheredKey key = libBLS::CipheredKey( u, cipheredKey, w );

        BOOST_REQUIRE( key.U == u );
        BOOST_REQUIRE( key.V == cipheredKey );
        BOOST_REQUIRE( key.W == w );

        // convert to bytes & back
        std::array< uint8_t, libBLS::CipheredKey::CIPHERED_KEY_SIZE_BYTES > bytes = key.toBytes();
        libBLS::CipheredKey restoredKey = libBLS::CipheredKey::fromBytes( bytes );

        BOOST_REQUIRE( key == restoredKey );
    }
}

BOOST_AUTO_TEST_CASE( CipheredKeyException ) {
    // zero u element
    libBLS::algebra::G2Point u = libBLS::algebra::G2Point::identity();
    libBLS::AES256Key cipheredKey;
    RAND_bytes( cipheredKey.data(), cipheredKey.size() );
    libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();
    BOOST_REQUIRE_THROW(
        libBLS::CipheredKey( u, cipheredKey, w ), libBLS::ThresholdUtils::IsNotWellFormed );

    // zero w element
    u = libBLS::algebra::G2Point::random();
    w = libBLS::algebra::G1Point::identity();
    BOOST_REQUIRE_THROW(
        libBLS::CipheredKey( u, cipheredKey, w ), libBLS::ThresholdUtils::IsNotWellFormed );

    // correct ciphered key, but changed U mid-execution
    w = libBLS::algebra::G1Point::random();
    libBLS::CipheredKey key = libBLS::CipheredKey( u, cipheredKey, w );
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
        libBLS::AES256Key cipheredKey;
        RAND_bytes( cipheredKey.data(), cipheredKey.size() );
        libBLS::algebra::G1Point w = libBLS::algebra::G1Point::random();
        // convert to bytes & back
        libBLS::CipheredKey key = libBLS::CipheredKey( u, cipheredKey, w );

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

    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    auto result = te_instance.getCiphertext( randomAesKey, publicKey );

    // one decrypt share at a time
    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< libBLS::algebra::G2Point > shares1;

        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );
        shares1.push_back( decryptionShare );

        // standalone validation
        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        // batched decryption - optimistic
        std::vector< libBLS::CipheredKey > cipheredKeys = { cipheredKey };
        std::vector< bool > verificationsKey1 =
            te_instance.VerifyBatch( cipheredKeys, shares1, { publicKey } );
        BOOST_REQUIRE( std::all_of(
            verificationsKey1.begin(), verificationsKey1.end(), []( bool v ) { return v; } ) );


        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key res = te_instance.CombineShares( cipheredKey, shares );

        BOOST_REQUIRE( res == randomAesKey );
    }
}

BOOST_AUTO_TEST_CASE( SimpleEncryptionWithAES ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    libBLS::CipherResult ciphertextWithAes = te_instance.encryptWithAES( messageBytes, publicKey );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();
    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey };
        std::vector< uint8_t > plaintext = aesGcmCipher.decrypt( encryptedMessage );

        // append random secret to end of original message
        libBLS::RandSecret randSecret = ciphertextWithAes.randomSecret;
        messageBytes.insert( messageBytes.end(), randSecret.begin(), randSecret.end() );

        BOOST_REQUIRE( plaintext == messageBytes );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionWithAES_AAD ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users! This is a test with AAD!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // AAD that binds the ciphertext to a specific context (e.g., contract address)
    std::vector< uint8_t > aad = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    // Encrypt with AAD
    libBLS::CipherResult ciphertextWithAes =
        te_instance.encryptWithAES( messageBytes, publicKey, aad );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with the same AAD - should succeed
        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey };
        std::vector< uint8_t > plaintext = aesGcmCipher.decrypt( encryptedMessage, aad );

        // Append random secret to end of original message for comparison
        libBLS::RandSecret randSecret = ciphertextWithAes.randomSecret;
        std::vector< uint8_t > expectedMessage = messageBytes;
        expectedMessage.insert( expectedMessage.end(), randSecret.begin(), randSecret.end() );

        BOOST_REQUIRE( plaintext == expectedMessage );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionWithAES_WrongAAD ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users! This is a test with AAD!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // AAD used for encryption
    std::vector< uint8_t > aad = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    // Wrong AAD for decryption
    std::vector< uint8_t > wrong_aad = { 0x01, 0x02, 0x03, 0x04 };

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    // Encrypt with AAD
    libBLS::CipherResult ciphertextWithAes =
        te_instance.encryptWithAES( messageBytes, publicKey, aad );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with wrong AAD - should fail
        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey };
        BOOST_REQUIRE_THROW(
            aesGcmCipher.decrypt( encryptedMessage, wrong_aad ), std::runtime_error );

        // Decrypt without AAD - should also fail
        BOOST_REQUIRE_THROW(
            aesGcmCipher.decrypt( encryptedMessage, std::nullopt ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongKey ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    auto ciphertextWithAes = te_instance.encryptWithAES( messageBytes, publicKey );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();
    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key randomAesKey;
        RAND_bytes( randomAesKey.data(), randomAesKey.size() );


        libBLS::AesGcmCipher cipher{ randomAesKey };
        BOOST_REQUIRE_THROW( cipher.decrypt( encryptedMessage ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( encryptionWithAESWrongCiphertext ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    libBLS::CipherResult ciphertextWithAes = te_instance.encryptWithAES( messageBytes, publicKey );

    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );
        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );
        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        std::string badMessage = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        std::vector< uint8_t > badMessageBytes( message.begin(), message.end() );

        auto bad_encryptedMessage =
            te_instance.encryptWithAES( badMessageBytes, publicKey ).ciphertext->getData();

        libBLS::AesGcmCipher cipher{ decryptedAesKey };
        BOOST_REQUIRE_THROW( cipher.decrypt( bad_encryptedMessage ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( EncryptionCipherToBytes ) {
    libBLS::TE te_instance = libBLS::TE( 1, 1 );

    std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();

    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    std::string commonPublicStr = publicKey.toString( libBLS::Base::HEXA );
    auto result = te_instance.encryptMessage( messageBytes, commonPublicStr );
    libBLS::RandSecret randSecret = result.second;

    std::vector< uint8_t > encryptedMsgBytes =
        libBLS::ThresholdUtils::hexCStringToBytes( result.first.c_str() );

    libBLS::Ciphertext ciphertext = libBLS::Ciphertext::fromBytes( encryptedMsgBytes );
    auto encryptedMessage = ciphertext.getData();

    for ( const auto& cipheredkey : ciphertext.getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredkey, secretKey );

        BOOST_REQUIRE( te_instance.Verify( cipheredkey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredkey, shares );

        libBLS::AesGcmCipher cipher{ decryptedAesKey };
        std::vector< uint8_t > plaintext = cipher.decrypt( encryptedMessage );

        // append random secret to the message
        messageBytes.insert( messageBytes.end(), randSecret.begin(), randSecret.end() );

        BOOST_REQUIRE( plaintext == messageBytes );
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

    std::vector< libBLS::algebra::FrScalar > secretKeys( n );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secretKeys[i] = sk;
    }

    libBLS::algebra::FrScalar commonSecret = coeffs[0];

    libBLS::algebra::G2Point commonPublic = commonSecret * libBLS::algebra::G2Point::generator();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, commonPublic );

    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( t );
        std::vector< libBLS::algebra::G2Point > decryptedShares( t );
        std::vector< libBLS::algebra::G2Point > pubKeys( t );

        for ( size_t i = 0; i < t; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secretKeys[i] );

            decryptedShares[i] = decrypted;

            libBLS::algebra::G2Point publicKey =
                secretKeys[i] * libBLS::algebra::G2Point::generator();

            pubKeys[i] = publicKey;

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, publicKey ) );

            shares[i].first = decrypted;

            shares[i].second = i + 1;
        }

        // batched decryption - optimistic
        std::vector< libBLS::CipheredKey > keysBatch;
        keysBatch.push_back( cipheredKey );

        auto verifications = obj.VerifyBatch( keysBatch, decryptedShares, pubKeys );
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

    std::vector< libBLS::algebra::FrScalar > secretKeys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secretKeys[i] = sk;
    }

    libBLS::algebra::G2Point commonPublic = libBLS::algebra::G2Point::random();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, commonPublic );

    std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( 11 );


    for ( const auto& cipheredKey : result.ciphertext ) {
        for ( size_t i = 0; i < 11; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secretKeys[i] );
            libBLS::algebra::G2Point publicKey =
                secretKeys[i] * libBLS::algebra::G2Point::generator();

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, publicKey ) );

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

    std::vector< libBLS::algebra::FrScalar > secretKeys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        // let secretKey[7] be a random generated value instead of correctly generated
        if ( i == 7 ) {
            sk = libBLS::algebra::FrScalar::random();
        }

        secretKeys[i] = sk;
    }

    libBLS::algebra::FrScalar commonSecret = coeffs[0];

    libBLS::algebra::G2Point commonPublic = commonSecret * libBLS::algebra::G2Point::generator();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, commonPublic );

    for ( const auto& cipheredKey : result.ciphertext ) {
        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( 11 );

        for ( size_t i = 0; i < 11; ++i ) {
            libBLS::algebra::G2Point decrypted =
                obj.getDecryptionShare( cipheredKey, secretKeys[i] );
            libBLS::algebra::G2Point publicKey =
                secretKeys[i] * libBLS::algebra::G2Point::generator();

            BOOST_REQUIRE( obj.Verify( cipheredKey, decrypted, publicKey ) );

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

    std::vector< libBLS::algebra::FrScalar > secretKeys( 16 );

    for ( size_t i = 0; i < 16; ++i ) {
        libBLS::algebra::FrScalar sk = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            libBLS::algebra::FrScalar tmp1( i + 1 );

            libBLS::algebra::FrScalar tmp3 = libBLS::algebra::power( tmp1, j );

            libBLS::algebra::FrScalar tmp4 = coeffs[j] * tmp3;

            sk += tmp4;
        }

        secretKeys[i] = sk;
    }

    libBLS::algebra::FrScalar commonSecret = coeffs[0];

    libBLS::algebra::G2Point commonPublic = commonSecret * libBLS::algebra::G2Point::identity();

    libBLS::AES256Key key;
    RAND_bytes( key.data(), key.size() );

    auto result = obj.getCiphertext( key, commonPublic );

    libBLS::algebra::G1Point rand = libBLS::algebra::G1Point::random();

    libBLS::CipheredKey cipheredKeyToCorrupt = result.ciphertext[0];
    libBLS::CipheredKey corruptedCipheredKey = { cipheredKeyToCorrupt.U, cipheredKeyToCorrupt.V,
        rand };

    for ( size_t i = 0; i < 11; ++i ) {
        libBLS::algebra::G2Point decryptedWrong =
            obj.getDecryptionShare( corruptedCipheredKey, secretKeys[i] );
        libBLS::algebra::G2Point decryptedCorrect =
            obj.getDecryptionShare( cipheredKeyToCorrupt, secretKeys[i] );

        libBLS::algebra::G2Point publicKey = secretKeys[i] * libBLS::algebra::G2Point::identity();

        // wrong cipher key, correct decrypted key - should return false
        BOOST_REQUIRE( !obj.Verify( corruptedCipheredKey, decryptedCorrect, publicKey ) );

        // wrong decrypted key, correct cipher key - should return false
        BOOST_REQUIRE( !obj.Verify( cipheredKeyToCorrupt, decryptedWrong, publicKey ) );
    }
}

BOOST_AUTO_TEST_CASE( LagrangeInterpolationExceptions ) {
    for ( size_t i = 0; i < 100; i++ ) {
        std::default_random_engine randGen( ( unsigned int ) time( 0 ) );
        size_t numAll = randGen() % 15 + 2;
        size_t numSigned = randGen() % ( numAll - 1 ) + 2;

        {
            libBLS::TE obj( numSigned, numAll );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < numSigned - 1; i++ )
                vect.push_back( i + 1 );
            BOOST_REQUIRE_THROW( libBLS::algebra::lagrangeCoeffs( vect, numSigned ),
                libBLS::ThresholdUtils::IncorrectInput );
        }

        {
            libBLS::TE obj( numSigned, numAll );
            std::vector< size_t > vect;
            for ( size_t i = 0; i < numSigned; i++ ) {
                vect.push_back( i + 1 );
            }
            vect.at( 1 ) = vect.at( 0 );
            BOOST_REQUIRE_THROW( libBLS::algebra::lagrangeCoeffs( vect, numSigned ),
                libBLS::ThresholdUtils::IncorrectInput );
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
