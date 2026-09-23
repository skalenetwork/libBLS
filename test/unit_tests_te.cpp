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

#include <algorithm>
#include <optional>
#include <random>

#include "test/utils.h"
#include "threshold_encryption/AesGcmCipher.h"
#include <threshold_encryption.h>
#include <tools/utils.h>

#include <openssl/rand.h>

#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_TEST_GLOBAL_CONFIGURATION( GlobalConfig );

BOOST_AUTO_TEST_SUITE( TestAES )

// Test the default constructor generates a random key
BOOST_AUTO_TEST_CASE( RandomKeyConstructor ) {
    libBLS::ThresholdUtils::initRAND();

    const std::string message = "Test message for random key constructor";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Create cipher with random key
    libBLS::AesGcmCipher cipher{ libBLS::AesGcmVersion::V1 };

    // Encrypt and decrypt
    auto ciphertext = cipher.encrypt( messageBytes );
    auto decrypted = cipher.decrypt( ciphertext );

    BOOST_REQUIRE( decrypted == messageBytes );

    // Verify getKey() returns a non-zero key
    const auto& key = cipher.getKey();
    bool allZeros = std::all_of( key.begin(), key.end(), []( uint8_t b ) { return b == 0; } );
    BOOST_REQUIRE( !allZeros );
}

// Test that two random ciphers produce different keys
BOOST_AUTO_TEST_CASE( RandomKeyUniqueness ) {
    libBLS::ThresholdUtils::initRAND();

    libBLS::AesGcmCipher cipher1{ libBLS::AesGcmVersion::V1 };
    libBLS::AesGcmCipher cipher2{ libBLS::AesGcmVersion::V1 };

    // Two separate random ciphers should have different keys
    BOOST_REQUIRE( cipher1.getKey() != cipher2.getKey() );
}

// Test seeded constructor produces deterministic key
BOOST_AUTO_TEST_CASE( SeededKeyDeterminism ) {
    libBLS::ThresholdUtils::initRAND();

    // Create a fixed seed
    libBLS::Seed256 seed;
    RAND_bytes( seed.data.data(), seed.data.size() );

    // Create two ciphers with the same seed
    libBLS::AesGcmCipher cipher1{ seed, libBLS::AesGcmVersion::V1 };
    libBLS::AesGcmCipher cipher2{ seed, libBLS::AesGcmVersion::V1 };

    // Both should produce the same key
    BOOST_REQUIRE( cipher1.getKey() == cipher2.getKey() );
}

// Test seeded constructor - same seed produces same ciphertext for same plaintext sequence
BOOST_AUTO_TEST_CASE( SeededEncryptionDeterminism ) {
    libBLS::ThresholdUtils::initRAND();

    // Create a fixed seed
    libBLS::Seed256 seed;
    RAND_bytes( seed.data.data(), seed.data.size() );

    const std::string message1 = "First message";
    const std::string message2 = "Second message";
    std::vector< uint8_t > msg1Bytes( message1.begin(), message1.end() );
    std::vector< uint8_t > msg2Bytes( message2.begin(), message2.end() );

    // Simulate two nodes with same seed
    libBLS::AesGcmCipher node1Cipher{ seed, libBLS::AesGcmVersion::V1 };
    libBLS::AesGcmCipher node2Cipher{ seed, libBLS::AesGcmVersion::V1 };

    // Encrypt same messages in same order
    auto ct1_node1 = node1Cipher.encrypt( msg1Bytes );
    auto ct2_node1 = node1Cipher.encrypt( msg2Bytes );

    auto ct1_node2 = node2Cipher.encrypt( msg1Bytes );
    auto ct2_node2 = node2Cipher.encrypt( msg2Bytes );

    // Both nodes should produce identical ciphertexts
    BOOST_REQUIRE( ct1_node1 == ct1_node2 );
    BOOST_REQUIRE( ct2_node1 == ct2_node2 );

    // Verify same message encrypted again produces DIFFERENT ciphertext (counter incremented)
    auto ct3_node1 = node1Cipher.encrypt( msg1Bytes );
    BOOST_REQUIRE( ct1_node1 != ct3_node1 );
}

// Test that different seeds produce different keys
BOOST_AUTO_TEST_CASE( DifferentSeedsDifferentKeys ) {
    libBLS::ThresholdUtils::initRAND();

    libBLS::Seed256 seed1;
    libBLS::Seed256 seed2;
    RAND_bytes( seed1.data.data(), seed1.data.size() );
    RAND_bytes( seed2.data.data(), seed2.data.size() );

    libBLS::AesGcmCipher cipher1{ seed1, libBLS::AesGcmVersion::V1 };
    libBLS::AesGcmCipher cipher2{ seed2, libBLS::AesGcmVersion::V1 };

    BOOST_REQUIRE( cipher1.getKey() != cipher2.getKey() );
}

// Test raw key constructor
BOOST_AUTO_TEST_CASE( RawKeyConstructor ) {
    libBLS::ThresholdUtils::initRAND();

    // Generate a key manually
    libBLS::AES256Key rawKey;
    RAND_bytes( rawKey.data(), rawKey.size() );

    // Create cipher with raw key
    libBLS::AesGcmCipher cipher{ rawKey, libBLS::AesGcmVersion::V1 };

    // Verify getKey() returns the same key
    BOOST_REQUIRE( cipher.getKey() == rawKey );
}

// Test raw key constructor - encrypt/decrypt round trip
BOOST_AUTO_TEST_CASE( RawKeyRoundTrip ) {
    libBLS::ThresholdUtils::initRAND();

    libBLS::AES256Key rawKey;
    RAND_bytes( rawKey.data(), rawKey.size() );

    const std::string message = "Test message for raw key round trip";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    // Encrypt with one instance
    libBLS::AesGcmCipher encryptor{ rawKey, libBLS::AesGcmVersion::V1 };
    auto ciphertext = encryptor.encrypt( messageBytes );

    // Decrypt with a new instance using same key
    libBLS::AesGcmCipher decryptor{ rawKey, libBLS::AesGcmVersion::V1 };
    auto decrypted = decryptor.decrypt( ciphertext );

    BOOST_REQUIRE( decrypted == messageBytes );
}

BOOST_AUTO_TEST_CASE( SimpleAES ) {
    libBLS::ThresholdUtils::initRAND();
    unsigned char keyBytes[32];
    RAND_bytes( keyBytes, sizeof( keyBytes ) );
    libBLS::AES256Key randomAesKey;
    std::copy( keyBytes, keyBytes + libBLS::AES_256_KEY_SIZE_BYTES, randomAesKey.begin() );

    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };
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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };
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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };
    auto ciphertext = cipher.encrypt( messageBytes );

    unsigned char bad_keyBytes[32];
    RAND_bytes( bad_keyBytes, sizeof( bad_keyBytes ) );
    libBLS::AES256Key randomBadAesKey;
    std::copy(
        bad_keyBytes, bad_keyBytes + libBLS::AES_256_KEY_SIZE_BYTES, randomBadAesKey.begin() );

    libBLS::AesGcmCipher bad_cipher{ randomBadAesKey, libBLS::AesGcmVersion::V1 };
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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

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

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    // Encrypt with empty AAD
    auto ciphertext = cipher.encrypt( messageBytes, empty_aad );

    // Decrypt with empty AAD - should succeed
    auto decryptedText = cipher.decrypt( ciphertext, empty_aad );
    BOOST_REQUIRE( decryptedText == messageBytes );

    // Empty AAD should behave the same as nullopt
    auto decryptedText2 = cipher.decrypt( ciphertext, std::nullopt );
    BOOST_REQUIRE( decryptedText2 == messageBytes );
}

BOOST_AUTO_TEST_CASE( AESWithTamperedCiphertext ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Test message for tampered ciphertext!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );
    std::vector< uint8_t > aad = { 0x01, 0x02, 0x03, 0x04 };

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Tamper with the ciphertext data (not the IV or tag)
    if ( ciphertext.size() > libBLS::AES_GCM_IV_SIZE + libBLS::AES_GCM_TAG_SIZE + 1 ) {
        // ciphertext is between IV (start) and tag (end)
        ciphertext[libBLS::AES_GCM_IV_SIZE + 5] ^= 0xFF;

        // Decryption should fail due to authentication tag mismatch
        BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, aad ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( AESWithTamperedTag ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Test message for tampered tag!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );
    std::vector< uint8_t > aad = { 0xAA, 0xBB, 0xCC };

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Tamper with the authentication tag (last 16 bytes)
    if ( ciphertext.size() >= libBLS::AES_GCM_TAG_SIZE ) {
        // tag is at the end of the ciphertext
        size_t tagStart = ciphertext.size() - libBLS::AES_GCM_TAG_SIZE;
        ciphertext[tagStart] ^= 0x01;

        // Decryption should fail due to tag mismatch
        BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, aad ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( AESWithTamperedIV ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    const std::string message = "Test message for tampered IV!";
    std::vector< uint8_t > messageBytes( message.begin(), message.end() );
    std::vector< uint8_t > aad = { 0x11, 0x22, 0x33, 0x44 };

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    // Encrypt with AAD
    auto ciphertext = cipher.encrypt( messageBytes, aad );

    // Tamper with the IV (first 12 bytes)
    if ( ciphertext.size() >= libBLS::AES_GCM_IV_SIZE ) {
        // IV is at the start
        ciphertext[5] ^= 0xAA;

        // Decryption should fail - either due to wrong decryption or tag mismatch
        BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, aad ), std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( AESAADLargePayload ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    // Large message (1 MB)
    std::vector< uint8_t > largeMessage( 1024 * 1024 );
    RAND_bytes( largeMessage.data(), largeMessage.size() );

    // Large AAD (64 KB)
    std::vector< uint8_t > largeAad( 64 * 1024 );
    RAND_bytes( largeAad.data(), largeAad.size() );

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    // Encrypt with large AAD
    auto ciphertext = cipher.encrypt( largeMessage, largeAad );

    // Decrypt with same large AAD - should succeed
    auto decrypted = cipher.decrypt( ciphertext, largeAad );
    BOOST_REQUIRE( decrypted == largeMessage );

    // Modify one byte in the large AAD - should fail
    largeAad[1234] ^= 0x01;
    BOOST_REQUIRE_THROW( cipher.decrypt( ciphertext, largeAad ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AESMultipleEncryptionsWithDifferentAAD ) {
    libBLS::ThresholdUtils::initRAND();
    libBLS::AES256Key randomAesKey;
    RAND_bytes( randomAesKey.data(), randomAesKey.size() );

    libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };

    const std::string msg1 = "First message";
    const std::string msg2 = "Second message";
    const std::string msg3 = "Third message";

    std::vector< uint8_t > msg1Bytes( msg1.begin(), msg1.end() );
    std::vector< uint8_t > msg2Bytes( msg2.begin(), msg2.end() );
    std::vector< uint8_t > msg3Bytes( msg3.begin(), msg3.end() );

    std::vector< uint8_t > aad1 = { 0x01 };
    std::vector< uint8_t > aad2 = { 0x02 };
    std::vector< uint8_t > aad3 = { 0x03 };

    // Encrypt three messages with different AADs
    auto ct1 = cipher.encrypt( msg1Bytes, aad1 );
    auto ct2 = cipher.encrypt( msg2Bytes, aad2 );
    auto ct3 = cipher.encrypt( msg3Bytes, aad3 );

    // Decrypt each with correct AAD
    BOOST_REQUIRE( cipher.decrypt( ct1, aad1 ) == msg1Bytes );
    BOOST_REQUIRE( cipher.decrypt( ct2, aad2 ) == msg2Bytes );
    BOOST_REQUIRE( cipher.decrypt( ct3, aad3 ) == msg3Bytes );

    // Cross-decryption with wrong AAD should fail
    BOOST_REQUIRE_THROW( cipher.decrypt( ct1, aad2 ), std::runtime_error );
    BOOST_REQUIRE_THROW( cipher.decrypt( ct2, aad3 ), std::runtime_error );
    BOOST_REQUIRE_THROW( cipher.decrypt( ct3, aad1 ), std::runtime_error );
}

BOOST_AUTO_TEST_CASE( AesGcmVersionDeterministicIvAadBinding ) {
    libBLS::ThresholdUtils::initRAND();

    libBLS::Seed256 seed;
    RAND_bytes( seed.data.data(), seed.data.size() );

    const std::string msg = "Identical message across different AAD contexts";
    std::vector< uint8_t > msgBytes( msg.begin(), msg.end() );

    std::vector< uint8_t > aad1 = { 0xAA, 0xBB, 0xCC };
    std::vector< uint8_t > aad2 = { 0xDD, 0xEE, 0xFF };

    // Under V0: same seed, same counter (0), same plaintext -> IV is identical despite different AAD
    libBLS::AesGcmCipher cipherV0_1{ seed, libBLS::AesGcmVersion::V0 };
    libBLS::AesGcmCipher cipherV0_2{ seed, libBLS::AesGcmVersion::V0 };

    auto ctV0_1 = cipherV0_1.encrypt( msgBytes, aad1 );
    auto ctV0_2 = cipherV0_2.encrypt( msgBytes, aad2 );

    // Extract IVs (first 12 bytes), ciphertext bodies, and authentication tags (last 16 bytes)
    std::vector< uint8_t > ivV0_1( ctV0_1.begin(), ctV0_1.begin() + libBLS::AES_GCM_IV_SIZE );
    std::vector< uint8_t > ivV0_2( ctV0_2.begin(), ctV0_2.begin() + libBLS::AES_GCM_IV_SIZE );

    std::vector< uint8_t > bodyV0_1( ctV0_1.begin() + libBLS::AES_GCM_IV_SIZE,
        ctV0_1.end() - libBLS::AES_GCM_TAG_SIZE );
    std::vector< uint8_t > bodyV0_2( ctV0_2.begin() + libBLS::AES_GCM_IV_SIZE,
        ctV0_2.end() - libBLS::AES_GCM_TAG_SIZE );

    std::vector< uint8_t > tagV0_1( ctV0_1.end() - libBLS::AES_GCM_TAG_SIZE, ctV0_1.end() );
    std::vector< uint8_t > tagV0_2( ctV0_2.end() - libBLS::AES_GCM_TAG_SIZE, ctV0_2.end() );

    // Demonstrates legacy V0 vulnerability:
    // 1) Same IV is reused across different AAD contexts
    // 2) Ciphertext body is identical (same CTR keystream used on same plaintext)
    // 3) Authentication tags differ (tag includes AAD in GHASH)
    BOOST_REQUIRE( ivV0_1 == ivV0_2 );
    BOOST_REQUIRE( bodyV0_1 == bodyV0_2 );
    BOOST_REQUIRE( tagV0_1 != tagV0_2 );

    // Under V1: AAD is bound into IV derivation -> different AAD produces different IVs
    libBLS::AesGcmCipher cipherV1_1{ seed, libBLS::AesGcmVersion::V1 };
    libBLS::AesGcmCipher cipherV1_2{ seed, libBLS::AesGcmVersion::V1 };

    auto ctV1_1 = cipherV1_1.encrypt( msgBytes, aad1 );
    auto ctV1_2 = cipherV1_2.encrypt( msgBytes, aad2 );

    std::vector< uint8_t > ivV1_1( ctV1_1.begin(), ctV1_1.begin() + libBLS::AES_GCM_IV_SIZE );
    std::vector< uint8_t > ivV1_2( ctV1_2.begin(), ctV1_2.begin() + libBLS::AES_GCM_IV_SIZE );

    std::vector< uint8_t > bodyV1_1( ctV1_1.begin() + libBLS::AES_GCM_IV_SIZE,
        ctV1_1.end() - libBLS::AES_GCM_TAG_SIZE );
    std::vector< uint8_t > bodyV1_2( ctV1_2.begin() + libBLS::AES_GCM_IV_SIZE,
        ctV1_2.end() - libBLS::AES_GCM_TAG_SIZE );

    // In V1, both IVs and ciphertext bodies must be distinct (fresh keystream per AAD)
    BOOST_REQUIRE( ivV1_1 != ivV1_2 );
    BOOST_REQUIRE( bodyV1_1 != bodyV1_2 );

    // Verify round-trip decryption for both V0 and V1
    BOOST_REQUIRE( cipherV0_1.decrypt( ctV0_1, aad1 ) == msgBytes );
    BOOST_REQUIRE( cipherV0_2.decrypt( ctV0_2, aad2 ) == msgBytes );
    BOOST_REQUIRE( cipherV1_1.decrypt( ctV1_1, aad1 ) == msgBytes );
    BOOST_REQUIRE( cipherV1_2.decrypt( ctV1_2, aad2 ) == msgBytes );
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

    auto result = te_instance.cipherAesKey( randomAesKey, publicKey, std::nullopt, std::nullopt );

    // one decrypt share at a time
    for ( const auto& cipheredKey : result.cipheredKeys ) {
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

        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey, libBLS::AesGcmVersion::V1 };
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

    libBLS::EncryptMetaData encryptMeta;
    encryptMeta.associatedDataAesGcm = aad;

    // Encrypt with AAD
    libBLS::CipherResult ciphertextWithAes =
        te_instance.encryptWithAES( messageBytes, publicKey, encryptMeta );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        BOOST_REQUIRE( te_instance.Verify( cipheredKey, decryptionShare, publicKey ) );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with the same AAD - should succeed
        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey, libBLS::AesGcmVersion::V1 };
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

    libBLS::EncryptMetaData encryptMeta;
    encryptMeta.associatedDataAesGcm = aad;

    // Encrypt with AAD
    libBLS::CipherResult ciphertextWithAes =
        te_instance.encryptWithAES( messageBytes, publicKey, encryptMeta );

    auto encryptedMessage = ciphertextWithAes.ciphertext->getData();

    for ( const auto& cipheredKey : ciphertextWithAes.ciphertext->getKeys() ) {
        libBLS::algebra::G2Point decryptionShare =
            te_instance.getDecryptionShare( cipheredKey, secretKey );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        shares.push_back( std::make_pair( decryptionShare, size_t( 1 ) ) );

        libBLS::AES256Key decryptedAesKey = te_instance.CombineShares( cipheredKey, shares );

        // Decrypt with wrong AAD - should fail
        libBLS::AesGcmCipher aesGcmCipher{ decryptedAesKey, libBLS::AesGcmVersion::V1 };
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


        libBLS::AesGcmCipher cipher{ randomAesKey, libBLS::AesGcmVersion::V1 };
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

        libBLS::AesGcmCipher cipher{ decryptedAesKey, libBLS::AesGcmVersion::V1 };
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

        libBLS::AesGcmCipher cipher{ decryptedAesKey, libBLS::AesGcmVersion::V1 };
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

    auto result = obj.cipherAesKey( key, commonPublic, std::nullopt, std::nullopt );

    for ( const auto& cipheredKey : result.cipheredKeys ) {
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

    auto result = obj.cipherAesKey( key, commonPublic, std::nullopt, std::nullopt );

    std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares( 11 );


    for ( const auto& cipheredKey : result.cipheredKeys ) {
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

    auto result = obj.cipherAesKey( key, commonPublic, std::nullopt, std::nullopt );

    for ( const auto& cipheredKey : result.cipheredKeys ) {
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

    auto result = obj.cipherAesKey( key, commonPublic, std::nullopt, std::nullopt );

    libBLS::algebra::G1Point rand = libBLS::algebra::G1Point::random();

    libBLS::CipheredKey cipheredKeyToCorrupt = result.cipheredKeys[0];
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

BOOST_AUTO_TEST_CASE( CiphertextHeaderAndVersioning ) {
    // 1. Verify V0 (legacy) header parsing
    // Legacy header 0x01: version 0 (V0), 1 key
    uint8_t legacyHeader1Key = 0x01;
    // Legacy header 0x02: version 0 (V0), 2 keys
    uint8_t legacyHeader2Keys = 0x02;

    auto key1 = libBLS::CipheredKey::random( libBLS::TEVersion::V0 );
    auto key2 = libBLS::CipheredKey::random( libBLS::TEVersion::V0 );

    std::vector< uint8_t > dummyPayload( libBLS::RANDOM_SECRET_SIZE_BYTES + 10, 0xAA );

    // Build raw wire bytes with legacy V0 1-key header
    std::vector< uint8_t > v0Wire1Key;
    v0Wire1Key.push_back( legacyHeader1Key );
    auto key1Bytes = key1.toBytes();
    v0Wire1Key.insert( v0Wire1Key.end(), key1Bytes.begin(), key1Bytes.end() );
    v0Wire1Key.insert( v0Wire1Key.end(), dummyPayload.begin(), dummyPayload.end() );

    libBLS::Ciphertext ctV0_1 = libBLS::Ciphertext::fromBytes( v0Wire1Key );
    BOOST_REQUIRE( ctV0_1.getVersion() == libBLS::TEVersion::V0 );
    BOOST_REQUIRE_EQUAL( ctV0_1.getKeys().size(), size_t{ 1 } );
    BOOST_REQUIRE( ctV0_1.getKeys()[0].getVersion() == libBLS::TEVersion::V0 );

    // Build raw wire bytes with legacy V0 2-keys header
    std::vector< uint8_t > v0Wire2Keys;
    v0Wire2Keys.push_back( legacyHeader2Keys );
    v0Wire2Keys.insert( v0Wire2Keys.end(), key1Bytes.begin(), key1Bytes.end() );
    auto key2Bytes = key2.toBytes();
    v0Wire2Keys.insert( v0Wire2Keys.end(), key2Bytes.begin(), key2Bytes.end() );
    v0Wire2Keys.insert( v0Wire2Keys.end(), dummyPayload.begin(), dummyPayload.end() );

    libBLS::Ciphertext ctV0_2 = libBLS::Ciphertext::fromBytes( v0Wire2Keys );
    BOOST_REQUIRE( ctV0_2.getVersion() == libBLS::TEVersion::V0 );
    BOOST_REQUIRE_EQUAL( ctV0_2.getKeys().size(), size_t{ 2 } );
    BOOST_REQUIRE( ctV0_2.getKeys()[0].getVersion() == libBLS::TEVersion::V0 );
    BOOST_REQUIRE( ctV0_2.getKeys()[1].getVersion() == libBLS::TEVersion::V0 );

    // 2. Verify V1 (latest) header serialization & parsing
    auto v1Key = libBLS::CipheredKey::random();
    BOOST_REQUIRE( v1Key.getVersion() == libBLS::TEVersion::V1 );
    libBLS::Ciphertext ctV1( v1Key, dummyPayload, true, libBLS::TEVersion::V1 );
    std::vector< uint8_t > v1Bytes = ctV1.toBytes();
    // V1 with 1 key header byte: (1 << 2) | 1 = 0x05
    BOOST_REQUIRE_EQUAL( v1Bytes[0], 0x05 );

    libBLS::Ciphertext restoredV1 = libBLS::Ciphertext::fromBytes( v1Bytes );
    BOOST_REQUIRE( restoredV1.getVersion() == libBLS::TEVersion::V1 );
    BOOST_REQUIRE( restoredV1 == ctV1 );
    BOOST_REQUIRE( restoredV1.getKeys()[0].getVersion() == libBLS::TEVersion::V1 );

    // V1 with 2 keys header byte: (1 << 2) | 2 = 0x06
    auto v1Key2 = libBLS::CipheredKey::random();
    libBLS::Ciphertext ctV1_2( v1Key, v1Key2, dummyPayload, true, libBLS::TEVersion::V1 );
    std::vector< uint8_t > v1_2Bytes = ctV1_2.toBytes();
    BOOST_REQUIRE_EQUAL( v1_2Bytes[0], 0x06 );
    libBLS::Ciphertext restoredV1_2 = libBLS::Ciphertext::fromBytes( v1_2Bytes );
    BOOST_REQUIRE( restoredV1_2.getVersion() == libBLS::TEVersion::V1 );
    BOOST_REQUIRE( restoredV1_2 == ctV1_2 );

    // 3. Verify invalid header rejections
    // Invalid key count 0: (0 << 2) | 0 = 0x00
    v1Bytes[0] = 0x00;
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( v1Bytes ), libBLS::ThresholdUtils::IncorrectInput );

    // Invalid key count 3: (0 << 2) | 3 = 0x03
    v1Bytes[0] = 0x03;
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( v1Bytes ), libBLS::ThresholdUtils::IncorrectInput );

    // Unsupported future version > V1 (e.g. version 2 with 1 key: (2 << 2) | 1 = 0x09)
    v1Bytes[0] = 0x09;
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( v1Bytes ), libBLS::ThresholdUtils::IncorrectInput );

    // Maximum version in 6 bits: (63 << 2) | 1 = 0xFD
    v1Bytes[0] = 0xFD;
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext::fromBytes( v1Bytes ), libBLS::ThresholdUtils::IncorrectInput );
}

BOOST_AUTO_TEST_CASE( CiphertextRejectsMismatchedKeyVersions ) {
    std::vector< uint8_t > payload( libBLS::RANDOM_SECRET_SIZE_BYTES + 10, 0xAA );
    auto v0Key = libBLS::CipheredKey::random( libBLS::TEVersion::V0 );
    auto v1Key = libBLS::CipheredKey::random( libBLS::TEVersion::V1 );

    // A V0 key must not be serialized under a V1 ciphertext header.
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext( v0Key, payload, true, libBLS::TEVersion::V1 ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    // The inverse mismatch must also be rejected.
    BOOST_REQUIRE_THROW(
        libBLS::Ciphertext( v1Key, payload, true, libBLS::TEVersion::V0 ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    // Validation can be disabled for construction, but serialization must still
    // refuse to emit a wire header that disagrees with the embedded key.
    libBLS::Ciphertext unchecked( v0Key, payload, false, libBLS::TEVersion::V1 );
    BOOST_REQUIRE_THROW( unchecked.toBytes(), libBLS::ThresholdUtils::IsNotWellFormed );
}

BOOST_AUTO_TEST_CASE( LegacyV0MaskingDecapsulationCompatibility ) {
    // End-to-end verification that V0 (ASCII hex masking) and V1 (raw SHA256 byte masking)
    // both decapsulate and decrypt correctly with their respective rules.
    libBLS::TE te_instance( 1, 1 );

    libBLS::algebra::FrScalar secretKey = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point publicKey = secretKey * libBLS::algebra::G2Point::generator();

    libBLS::AES256Key originalKey;
    RAND_bytes( originalKey.data(), originalKey.size() );

    // Manually construct a V0 CipheredKey using legacy ASCII masking
    libBLS::algebra::FrScalar r = libBLS::algebra::FrScalar::random();
    libBLS::algebra::G2Point U = r * libBLS::algebra::G2Point::generator();
    U.toAffineCoordinates();
    libBLS::algebra::G2Point Y = r * publicKey;
    std::string hashHex = libBLS::TE::Hash( Y );

    // V0 Mask: raw ASCII characters
    libBLS::AES256Key v0Mask =
        libBLS::TE::deriveMaskFromHash( hashHex, libBLS::TEVersion::V0 );
    for ( size_t i = 0; i < libBLS::AES_256_KEY_SIZE_BYTES; ++i ) {
        BOOST_REQUIRE_EQUAL( v0Mask[i], static_cast< uint8_t >( hashHex[i] ) );
    }

    libBLS::AES256Key V_v0;
    for ( size_t i = 0; i < libBLS::AES_256_KEY_SIZE_BYTES; ++i ) {
        V_v0[i] = originalKey[i] ^ v0Mask[i];
    }
    libBLS::algebra::G1Point H = libBLS::TE::HashToGroup( U, V_v0, nullptr );
    libBLS::algebra::G1Point W = r * H;

    libBLS::CipheredKey cipheredKeyV0( U, V_v0, W, true, libBLS::TEVersion::V0 );

    // Verify decryption share creation and verification
    libBLS::algebra::G2Point decShare = te_instance.getDecryptionShare( cipheredKeyV0, secretKey );
    BOOST_REQUIRE( te_instance.Verify( cipheredKeyV0, decShare, publicKey ) );

    // Combine shares using V0 CipheredKey -> must recover original AES key
    std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
    shares.push_back( { decShare, 1 } );

    libBLS::AES256Key recoveredKeyV0 = te_instance.CombineShares( cipheredKeyV0, shares );
    BOOST_REQUIRE( recoveredKeyV0 == originalKey );

    // Compare with V1 masking for the same ephemeral r and key -> masks must differ
    libBLS::AES256Key v1Mask =
        libBLS::TE::deriveMaskFromHash( hashHex, libBLS::TEVersion::V1 );
    BOOST_REQUIRE( v0Mask != v1Mask );

    libBLS::AES256Key V_v1;
    for ( size_t i = 0; i < libBLS::AES_256_KEY_SIZE_BYTES; ++i ) {
        V_v1[i] = originalKey[i] ^ v1Mask[i];
    }
    libBLS::algebra::G1Point H_v1 = libBLS::TE::HashToGroup( U, V_v1, nullptr );
    libBLS::algebra::G1Point W_v1 = r * H_v1;
    libBLS::CipheredKey cipheredKeyV1( U, V_v1, W_v1, true, libBLS::TEVersion::V1 );

    libBLS::algebra::G2Point decShareV1 =
        te_instance.getDecryptionShare( cipheredKeyV1, secretKey );
    BOOST_REQUIRE( te_instance.Verify( cipheredKeyV1, decShareV1, publicKey ) );

    std::vector< std::pair< libBLS::algebra::G2Point, size_t > > sharesV1;
    sharesV1.push_back( { decShareV1, 1 } );
    libBLS::AES256Key recoveredKeyV1 = te_instance.CombineShares( cipheredKeyV1, sharesV1 );
    BOOST_REQUIRE( recoveredKeyV1 == originalKey );

    // Cross-decapsulation attempt: attempting to decapsulate V0 ciphered key with V1 mask must fail
    libBLS::CipheredKey mismatchedKey = cipheredKeyV0;
    mismatchedKey.setVersion( libBLS::TEVersion::V1 );
    libBLS::AES256Key wrongRecoveredKey = te_instance.CombineShares( mismatchedKey, shares );
    BOOST_REQUIRE( wrongRecoveredKey != originalKey );

    // Full roundtrip: V0 serialized wire bytes -> Ciphertext::fromBytes -> CombineShares -> AES decrypt
    std::string testMsg = "Legacy V0 payload compatibility test message!";
    std::vector< uint8_t > plaintext( testMsg.begin(), testMsg.end() );
    libBLS::AesGcmCipher aesGcm( originalKey, libBLS::AesGcmVersion::V1 );
    std::vector< uint8_t > encryptedData = aesGcm.encrypt( plaintext );

    // Construct legacy V0 wire format: [header = 0x01][CipheredKey (U, V, W)][encryptedData]
    std::vector< uint8_t > v0WireBytes;
    v0WireBytes.push_back( 0x01 );  // V0 1-key header
    auto ckV0Bytes = cipheredKeyV0.toBytes();
    v0WireBytes.insert( v0WireBytes.end(), ckV0Bytes.begin(), ckV0Bytes.end() );
    v0WireBytes.insert( v0WireBytes.end(), encryptedData.begin(), encryptedData.end() );

    // Import legacy wire bytes via Ciphertext::fromBytes
    libBLS::Ciphertext importedV0Ciphertext = libBLS::Ciphertext::fromBytes( v0WireBytes );
    BOOST_REQUIRE( importedV0Ciphertext.getVersion() == libBLS::TEVersion::V0 );
    BOOST_REQUIRE_EQUAL( importedV0Ciphertext.getKeys().size(), size_t{ 1 } );
    BOOST_REQUIRE( importedV0Ciphertext.getKeys()[0].getVersion() == libBLS::TEVersion::V0 );

    // Decapsulate using TE::CombineShares and imported key
    libBLS::AES256Key recoveredKeyFromImported =
        te_instance.CombineShares( importedV0Ciphertext.getKeys()[0], shares );
    BOOST_REQUIRE( recoveredKeyFromImported == originalKey );

    // Decrypt the payload
    libBLS::AesGcmCipher aesGcmDecrypt( recoveredKeyFromImported, libBLS::AesGcmVersion::V1 );
    std::vector< uint8_t > decryptedPlaintext =
        aesGcmDecrypt.decrypt( importedV0Ciphertext.getData() );
    BOOST_REQUIRE( decryptedPlaintext == plaintext );
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
