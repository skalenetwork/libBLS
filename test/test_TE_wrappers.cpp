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

@file libBLS::TEPublicKey.h
@author Sveta Rogova
@date 2019
*/


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

#include <dkg/dkg.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/ThresholdEncryption.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>

#include <dkg/DKGTEWrapper.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <test/utils.h>
#include <random>

namespace utf = boost::unit_test;

std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );

std::string spoilMessage( std::string& message ) {
    std::string mes = message;
    size_t ind = rand_gen() % message.length();
    char ch = rand_gen() % 128;
    while ( mes[ind] == ch )
        ch = rand_gen() % 128;
    mes[ind] = ch;
    return mes;
}

BOOST_TEST_GLOBAL_CONFIGURATION( GlobalConfig );

BOOST_AUTO_TEST_SUITE( ThresholdEncryptionWrappers )

BOOST_AUTO_TEST_CASE( TEMockupEncryption ) {
    std::vector< uint8_t > message;
    size_t msg_length = 64;
    for ( size_t length = 0; length < msg_length; ++length ) {
        message.push_back( rand_gen() % 256 );
    }

    auto encryptedMsg = libBLS::ThresholdEncryption::mockupEncrypt( message );
    auto decryptedMsg = libBLS::ThresholdEncryption::mockupDecrypt( encryptedMsg );

    BOOST_REQUIRE( message == decryptedMsg );
}

BOOST_AUTO_TEST_CASE( TEEncryptDecryptWithAAD ) {
    // Test the full ThresholdEncryption::encrypt/decrypt flow with AAD
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );

    std::vector< uint8_t > message = randomByteVec( 100 );

    // Separate AADs for AES and TE with different values
    std::vector< uint8_t > aadAES = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    // Encrypt with both AADs
    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataAesCbc = aadAES;
    metaData.associatedDataTE = aadTE;
    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate with TE AAD
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &aadTE );

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipheredKey, decr_share, public_key_shares[i], &aadTE );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

        // Decrypt WITH the same AES AAD - should succeed
        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, aadAES );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( TEEncryptDecryptWithWrongAAD ) {
    // Test that decryption fails when AAD doesn't match
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );

    std::vector< uint8_t > message = randomByteVec( 100 );

    // AADs used for encryption
    std::vector< uint8_t > aadAES = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    // Wrong AADs for decryption/validation
    std::vector< uint8_t > wrong_aadAES = { 0x11, 0x22, 0x33, 0x44 };
    std::vector< uint8_t > wrong_aadTE = { 0xAA, 0xBB, 0xCC, 0xDD };

    // Encrypt with both AADs
    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataAesCbc = aadAES;
    metaData.associatedDataTE = aadTE;
    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate with wrong TE AAD - should fail
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &wrong_aadTE ),
            libBLS::ThresholdUtils::IsNotWellFormed );

        // Validate with correct TE AAD - should succeed
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &aadTE );

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

        // Decrypt with wrong AES AAD - should fail
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, wrong_aadAES ),
            std::runtime_error );

        // Decrypt without AES AAD - should also fail
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, std::nullopt ),
            std::runtime_error );
    }
}

BOOST_AUTO_TEST_CASE( TEValidateDecryptionShareWithWrongAAD ) {
    // Test that validateDecryptionShare fails with wrong TE AAD
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, 0x04 };
    std::vector< uint8_t > wrong_aadTE = { 0xAA, 0xBB, 0xCC, 0xDD };

    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataTE = aadTE;
    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        libBLS::TEDecryptionShare decr_share =
            libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[0] );

        // Validate with correct TE AAD - should succeed
        libBLS::ThresholdEncryption::validateDecryptionShare(
            cipheredKey, decr_share, public_key_shares[0], &aadTE );

        // Validate with wrong TE AAD - should fail
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                 cipheredKey, decr_share, public_key_shares[0], &wrong_aadTE ),
            libBLS::ThresholdUtils::IsNotWellFormed );

        // Validate with nullptr AAD on AAD-encrypted ciphertext - should fail
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                 cipheredKey, decr_share, public_key_shares[0], nullptr ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
}

BOOST_AUTO_TEST_CASE( TEEncryptWithTEAADOnly ) {
    // Test encryption with only TE AAD (no AES AAD)
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, 0x04 };

    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataTE = aadTE;  // Only TE AAD, no AES AAD

    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate encryption with TE AAD
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &aadTE );

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipheredKey, decr_share, public_key_shares[i], &aadTE );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

        // Decrypt without AES AAD - should succeed since no AES AAD was used
        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, std::nullopt );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( TEEncryptWithAESAADOnly ) {
    // Test encryption with only AES AAD (no TE AAD)
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    std::vector< uint8_t > aadAES = { 0xDE, 0xAD, 0xBE, 0xEF };

    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataAesCbc = aadAES;  // Only AES AAD, no TE AAD

    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate encryption without TE AAD - should succeed
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, nullptr );

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipheredKey, decr_share, public_key_shares[i], nullptr );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

        // Decrypt with AES AAD - should succeed
        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, aadAES );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( TEEncryptWithEmptyAAD ) {
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    // Empty AAD vectors
    std::vector< uint8_t > emptyAadAES = {};
    std::vector< uint8_t > emptyAadTE = {};

    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataAesCbc = emptyAadAES;
    metaData.associatedDataTE = emptyAadTE;

    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    std::vector< libBLS::TEPublicKeyShare > public_key_shares;
    for ( size_t i = 0; i < numAll; i++ ) {
        public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
    }

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate with empty TE AAD
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &emptyAadTE );

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

        // Decrypt with empty AES AAD
        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted, emptyAadAES );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( TEValidateWithoutAADOnAADEncrypted ) {
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, 0x04 };

    libBLS::ThresholdEncryption::EncryptMetaData metaData;
    metaData.associatedDataTE = aadTE;

    libBLS::Ciphertext cypher =
        libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );

    for ( const auto& cipheredKey : cypher.getKeys() ) {
        // Validate without TE AAD (nullptr) - should fail
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey, nullptr ),
            libBLS::ThresholdUtils::IsNotWellFormed );

        // Validate with correct TE AAD - should succeed
        libBLS::ThresholdEncryption::validateEncryption( cipheredKey, &aadTE );
    }
}

BOOST_AUTO_TEST_CASE( TEBatchValidationWithAAD ) {
    // Test batch validation with AAD
    size_t numAll = 4;
    size_t numSigned = 3;

    keys keys = generateKeys( numSigned, numAll );
    std::vector< uint8_t > message = randomByteVec( 100 );

    // Create multiple ciphertexts with AAD
    size_t batchSize = 5;
    std::vector< libBLS::CipheredKey > cipheredKeys;
    std::vector< std::vector< uint8_t > > aadVec;

    for ( size_t i = 0; i < batchSize; ++i ) {
        std::vector< uint8_t > aadTE = { 0x01, 0x02, 0x03, static_cast< uint8_t >( i ) };
        aadVec.push_back( aadTE );

        libBLS::ThresholdEncryption::EncryptMetaData metaData;
        metaData.associatedDataTE = aadTE;

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic, metaData );
        cipheredKeys.push_back( cypher.getKeys()[0] );
    }

    // Batch validate with correct AADs - all should pass
    auto results = libBLS::ThresholdEncryption::validateEncryptionBatch( cipheredKeys, &aadVec );
    BOOST_REQUIRE( results.size() == batchSize );
    for ( size_t i = 0; i < batchSize; ++i ) {
        BOOST_REQUIRE( results[i] == true );
    }

    // Create wrong AADs
    std::vector< std::vector< uint8_t > > wrongAadVec;
    for ( size_t i = 0; i < batchSize; ++i ) {
        wrongAadVec.push_back( { 0xFF, 0xFE, 0xFD, static_cast< uint8_t >( i ) } );
    }

    // Batch validate with wrong AADs - all should fail
    auto wrongResults =
        libBLS::ThresholdEncryption::validateEncryptionBatch( cipheredKeys, &wrongAadVec );
    BOOST_REQUIRE( wrongResults.size() == batchSize );
    for ( size_t i = 0; i < batchSize; ++i ) {
        BOOST_REQUIRE( wrongResults[i] == false );
    }
}


BOOST_AUTO_TEST_CASE( TEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

        std::vector< libBLS::algebra::FrScalar > poly = dkg_te.GeneratePolynomial();

        libBLS::algebra::FrScalar zero_el = libBLS::algebra::FrScalar::zero();

        libBLS::algebra::FrScalar common_skey = dkg_te.PolynomialValue( poly, zero_el );
        BOOST_REQUIRE( common_skey == poly.at( 0 ) );

        libBLS::TEPrivateKey common_private( common_skey );

        std::vector< uint8_t > message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message.push_back( rand_gen() % 256 );
        }

        libBLS::TEPublicKey common_public( common_private );
        libBLS::Ciphertext cypher = libBLS::ThresholdEncryption::encrypt( message, common_public );

        std::vector< libBLS::algebra::FrScalar > skeys = dkg_te.SecretKeyContribution( poly );
        std::vector< libBLS::TEPrivateKeyShare > skey_shares;
        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < numAll; i++ ) {
            skey_shares.emplace_back(
                libBLS::TEPrivateKeyShare( skeys[i], i + 1, numSigned, numAll ) );
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( skey_shares[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % skey_shares.size();
            auto pos4del = skey_shares.begin();
            advance( pos4del, ind4del );
            skey_shares.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        for ( const auto& cipheredKey : cypher.getKeys() ) {
            libBLS::TEDecryptSet decrSet( numSigned, numAll );
            for ( size_t i = 0; i < numSigned; i++ ) {
                libBLS::TEDecryptionShare share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, skey_shares[i] );
                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, share, public_key_shares[i] );
                decrSet.addDecryptShare( share );
            }
            // each can only combine the shares once - thus several copies
            libBLS::TEDecryptSet decr_set2 = decrSet;
            libBLS::TEDecryptSet decr_set3 = decrSet;
            libBLS::TEDecryptSet decr_set4 = decrSet;


            // 1) Merge the set normally
            libBLS::AES256Key key =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

            libBLS::ThresholdEncryption::validateCombinedDecryption( cypher, key, common_public );

            std::vector< uint8_t > decipheredMsg =
                libBLS::ThresholdEncryption::decrypt( cypher, key );
            BOOST_REQUIRE( decipheredMsg == message );

            // 2) cannot add after merge
            BOOST_REQUIRE_THROW( decrSet.addDecryptShare( libBLS::TEDecryptionShare(
                                     libBLS::algebra::G2Point::random(), 1 ) ),
                libBLS::ThresholdUtils::IncorrectInput );

            // 3) Merge set with corrupted data - will fail at decryption step.
            // Ciphertext should always be validated before any other TE call. This
            // test is to check last-resort safety check.
            libBLS::CipheredKey bad_cyphered_key = cipheredKey;  // corrupt V in cypher

            size_t ind4del = rand_gen() % libBLS::AES_256_KEY_SIZE_BYTES;
            bad_cyphered_key.V[ind4del] = rand_gen() % 256;
            bad_cyphered_key.V[( ind4del + 1 ) % libBLS::AES_256_KEY_SIZE_BYTES] = rand_gen() % 256;

            // corrupting V field changes the key - and decryption throws
            libBLS::AES256Key corruptedKey =
                libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set2 );
            BOOST_REQUIRE( key != corruptedKey );
            BOOST_REQUIRE_THROW(
                libBLS::ThresholdEncryption::decrypt( cypher, corruptedKey ), std::runtime_error );

            bad_cyphered_key = cipheredKey;  // corrupt U in cypher
            libBLS::algebra::G2Point rand_el = libBLS::algebra::G2Point::random();
            bad_cyphered_key.U = rand_el;

            // changing U only results in failure at decryption validation step
            libBLS::Ciphertext cipherWithBadKey = cypher;
            cipherWithBadKey.keys[0] = bad_cyphered_key;
            // the deciphered key will still be correct, but the final decryption will not
            corruptedKey =
                libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set3 );
            decipheredMsg = libBLS::ThresholdEncryption::decrypt( cypher, corruptedKey );

            try {
                libBLS::ThresholdEncryption::validateDecipheredMessage(
                    decipheredMsg, cipherWithBadKey, corruptedKey, common_public );
                BOOST_FAIL( "Expected exception, but none thrown" );
            } catch ( const libBLS::ThresholdUtils::IsNotWellFormed& ) {
                // In case final reconstructed key does not match the one in ciphertext
            } catch ( const libBLS::ThresholdUtils::IncorrectInput& ) {
                // In case deciphered text has tampered invalid rand secret that does not build into
                // FrScalar
            } catch ( ... ) {
                BOOST_FAIL( "Unexpected exception type thrown" );
            }

            // changing U only results in failure at decryption validation step.
            bad_cyphered_key = cipheredKey;  // corrupt W in cypher
            libBLS::algebra::G1Point rand_el2 = libBLS::algebra::G1Point::random();
            bad_cyphered_key.W = rand_el2;
            // the deciphered key will still be correct, but the final decryption will not
            corruptedKey =
                libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set4 );
            decipheredMsg = libBLS::ThresholdEncryption::decrypt( cypher, corruptedKey );

            try {
                libBLS::ThresholdEncryption::validateDecipheredMessage(
                    decipheredMsg, cipherWithBadKey, corruptedKey, common_public );
                BOOST_FAIL( "Expected exception, but none thrown" );
            } catch ( const libBLS::ThresholdUtils::IsNotWellFormed& ) {
                // In case final reconstructed key does not match the one in ciphertext
            } catch ( const libBLS::ThresholdUtils::IncorrectInput& ) {
                // In case deciphered text has tampered invalid rand secret that does not build into
                // FrScalar
            } catch ( ... ) {
                BOOST_FAIL( "Unexpected exception type thrown" );
            }


            size_t ind = rand_gen() % numSigned;  // corrupt random private key share

            libBLS::algebra::FrScalar bad_pkey = libBLS::algebra::FrScalar::random();
            libBLS::TEPrivateKeyShare bad_key(
                bad_pkey, skey_shares[ind].getSignerIndex(), numSigned, numAll );
            skey_shares[ind] = bad_key;


            libBLS::TEDecryptSet bad_decr_set( numSigned, numAll );
            for ( size_t i = 0; i < numSigned; i++ ) {
                libBLS::TEDecryptionShare decr_share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, skey_shares[i] );
                if ( i == ind )
                    BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                             cipheredKey, decr_share, public_key_shares[i] ),
                        libBLS::ThresholdUtils::IsNotWellFormed );
                bad_decr_set.addDecryptShare( decr_share );
            }

            libBLS::AES256Key bad_key_decrypted =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, bad_decr_set );
            BOOST_REQUIRE( key != bad_key_decrypted );
        }
    }
}

BOOST_AUTO_TEST_CASE( ShortTEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

        std::vector< uint8_t > message = randomByteVec( 64 );

        keys keys = generateKeys( numSigned, numAll );

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < numAll; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        for ( const auto& cipheredKey : cypher.getKeys() ) {
            libBLS::TEDecryptSet decrSet( numSigned, numAll );
            for ( size_t i = 0; i < numSigned; i++ ) {
                libBLS::TEDecryptionShare decr_share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, decr_share, public_key_shares.at( i ) );
                decrSet.addDecryptShare( decr_share );
            }

            libBLS::AES256Key key_decrypted =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

            libBLS::ThresholdEncryption::validateCombinedDecryption(
                cypher, key_decrypted, keys.commonPublic );

            std::vector< uint8_t > decipheredMsg =
                libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted );
            BOOST_REQUIRE( decipheredMsg == message );
        }
    }
}


BOOST_AUTO_TEST_CASE( TEFailingValidation ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

        std::vector< uint8_t > message = randomByteVec( 100 );

        keys keys = generateKeys( numSigned, numAll );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < numAll; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        libBLS::CipheredKey bad_key = cypher.keys[0];
        bad_key.V[0] = ( bad_key.V[0] + 1 ) % 256;  // spoil the ciphered key
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateEncryption( bad_key ),
            libBLS::ThresholdUtils::IsNotWellFormed );
        for ( const auto& cipheredKey : cypher.getKeys() ) {
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey );

            libBLS::TEDecryptSet decrSet( numSigned, numAll );
            for ( size_t i = 0; i < numSigned; i++ ) {
                libBLS::TEDecryptionShare decr_share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[i] );
                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, decr_share, public_key_shares.at( i ) );

                decrSet.addDecryptShare( decr_share );
            }
            libBLS::AES256Key key_decrypted =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

            // change some bytes from key_decrypted
            libBLS::AES256Key copy = key_decrypted;
            copy[0] = ( key_decrypted[0] + 1 ) % 256;
            // this can throw either runtime_exception OR IsNotWellFormed. depends on AES content
            BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateCombinedDecryption(
                                     cypher, copy, keys.commonPublic ),
                std::exception );

            BOOST_REQUIRE_THROW(
                libBLS::ThresholdEncryption::decrypt( cypher, copy ), std::runtime_error );
        }
    }
}


BOOST_AUTO_TEST_CASE( WrappersFromString ) {
    for ( size_t i = 0; i < 100; i++ ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::algebra::G2Point test0 = libBLS::algebra::G2Point::random();
        libBLS::TEPublicKey common_pkey( test0 );

        libBLS::TEPublicKey common_pkey_from_str(
            common_pkey.toString( libBLS::Base::HEXA ), libBLS::Base::HEXA );
        BOOST_REQUIRE( common_pkey.getPublicKeyRaw() == common_pkey_from_str.getPublicKeyRaw() );

        libBLS::algebra::FrScalar test = libBLS::algebra::FrScalar::random();
        libBLS::TEPrivateKey private_key( test );

        libBLS::algebra::FrScalar test2 = libBLS::algebra::FrScalar::random();
        size_t signer = rand_gen() % numAll;
        libBLS::TEPrivateKeyShare pr_key_share( test2, signer, numSigned, numAll );

        std::string a( pr_key_share.toString( libBLS::Base::HEXA ) );
        libBLS::TEPrivateKeyShare pr_key_share_from_str(
            a, libBLS::Base::HEXA, signer, numSigned, numAll );
        BOOST_REQUIRE(
            pr_key_share.getPrivateKeyRaw() == pr_key_share_from_str.getPrivateKeyRaw() );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWithDKG ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t numAll = rand_gen() % 15 + 2;
        size_t numSigned = rand_gen() % numAll + 1;
        std::vector< std::vector< libBLS::algebra::FrScalar > > secret_shares_all;
        std::vector< std::vector< libBLS::algebra::G2Point > > public_shares_all;
        std::vector< libBLS::DKGTEWrapper > dkgs;
        std::vector< libBLS::TEPrivateKeyShare > skeys;
        std::vector< libBLS::TEPublicKeyShare > pkeys;

        for ( size_t i = 0; i < numAll; i++ ) {
            libBLS::DKGTEWrapper dkg_wrap( numSigned, numAll );

            libBLS::Dkg dkg_te( numSigned, numAll );
            std::vector< libBLS::algebra::FrScalar > poly = dkg_te.GeneratePolynomial();
            auto shared_poly = std::make_shared< std::vector< libBLS::algebra::FrScalar > >( poly );
            dkg_wrap.setDKGSecret( shared_poly );

            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< libBLS::algebra::FrScalar > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< libBLS::algebra::G2Point > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }

        for ( size_t i = 0; i < numAll; i++ )
            for ( size_t j = 0; j < numAll; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< libBLS::algebra::G2Point > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< libBLS::algebra::FrScalar > > secret_key_shares;

        for ( size_t i = 0; i < numAll; i++ ) {
            std::vector< libBLS::algebra::FrScalar > secret_key_contribution;
            for ( size_t j = 0; j < numAll; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < numAll; i++ ) {
            libBLS::TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
                i + 1, std::make_shared< std::vector< libBLS::algebra::FrScalar > >(
                           secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
            pkeys.push_back( libBLS::TEPublicKeyShare( pkey_share ) );
        }

        libBLS::TEPublicKey common_public = libBLS::DKGTEWrapper::CreateTEPublicKey(
            std::make_shared< std::vector< std::vector< libBLS::algebra::G2Point > > >(
                public_shares_all ),
            numSigned, numAll );

        std::vector< uint8_t > message;
        size_t msg_length = rand_gen() % 800;

        for ( size_t length = 0; length < msg_length; ++length ) {
            message.push_back( rand_gen() % 256 );
        }

        libBLS::Ciphertext cypher = libBLS::ThresholdEncryption::encrypt( message, common_public );

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % secret_shares_all.size();
            auto pos4del = secret_shares_all.begin();
            advance( pos4del, ind4del );
            secret_shares_all.erase( pos4del );
            auto pos2 = public_shares_all.begin();
            advance( pos2, ind4del );
            public_shares_all.erase( pos2 );
        }

        for ( const auto& cipheredKey : cypher.getKeys() ) {
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey );

            libBLS::TEDecryptSet decrSet( numSigned, numAll );
            for ( size_t i = 0; i < numSigned; i++ ) {
                libBLS::TEDecryptionShare decr_share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, skeys[i] );

                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, decr_share, pkeys[i] );

                decrSet.addDecryptShare( decr_share );
            }

            libBLS::AES256Key key_deciphered =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, decrSet );

            libBLS::ThresholdEncryption::validateCombinedDecryption(
                cypher, key_deciphered, common_public );

            std::vector< uint8_t > decipheredMsg =
                libBLS::ThresholdEncryption::decrypt( cypher, key_deciphered );
            BOOST_REQUIRE( decipheredMsg == message );
        }
    }
}

BOOST_AUTO_TEST_CASE( CheckSigners ) {
    size_t numAll = rand_gen() % 15 + 2;

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, numAll ), libBLS::ThresholdUtils::IncorrectInput );

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, 0 ), libBLS::ThresholdUtils::IncorrectInput );
}

BOOST_AUTO_TEST_CASE( ExceptionsDKGWrappersTest ) {
    size_t numAll = rand_gen() % 15 + 2;
    size_t numSigned = rand_gen() % numAll + 1;

    {
        // zero share
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );

        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::zero();

        BOOST_REQUIRE_THROW( dkg_te.VerifyDKGShare( 1, el, dkg_te.createDKGPublicShares() ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        // null verification vector
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );

        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::random();
        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare( 1, el, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );

        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::random();

        std::vector< libBLS::algebra::G2Point > pub_shares = *dkg_te.createDKGPublicShares();
        pub_shares.erase( pub_shares.begin() );

        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare(
                1, el, std::make_shared< std::vector< libBLS::algebra::G2Point > >( pub_shares ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        std::shared_ptr< std::vector< libBLS::algebra::FrScalar > > shares =
            dkg_te.createDKGSecretShares();
        shares = nullptr;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        dkg_te.createDKGSecretShares();

        std::shared_ptr< std::vector< libBLS::algebra::FrScalar > > v;

        BOOST_REQUIRE_THROW( dkg_te.setDKGSecret( v ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        BOOST_REQUIRE_THROW(
            dkg_te.CreateTEPrivateKeyShare( 1, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        auto wrong_size_vector = std::make_shared< std::vector< libBLS::algebra::FrScalar > >();
        wrong_size_vector->resize( numSigned - 1 );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPrivateKeyShare( 1, wrong_size_vector ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        std::shared_ptr< std::vector< libBLS::algebra::FrScalar > > shares;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libBLS::DKGTEWrapper dkg_te( numSigned, numAll );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPublicKey( nullptr, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_CASE( TEPublicKey ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 30; ++i ) {
        libBLS::algebra::FrScalar priv = libBLS::algebra::FrScalar::random();
        libBLS::algebra::G2Point pub = priv * libBLS::algebra::G2Point::generator();

        // consruct from field element
        libBLS::TEPublicKey pkey( pub );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pub );

        // construct from vec of hexadecimal strings
        std::vector< std::string > vecOfStrings = pub.toStringVector( libBLS::Base::HEXA );
        libBLS::TEPublicKey pkey2( vecOfStrings, libBLS::Base::HEXA );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey2.getPublicKeyRaw() );

        // Convert To and From concatenated string
        std::string concatenatedPubKey;
        for ( const auto& str : vecOfStrings ) {
            concatenatedPubKey += str;
        }
        libBLS::TEPublicKey pkey3( concatenatedPubKey, libBLS::Base::HEXA );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey3.getPublicKeyRaw() );
        std::string concatenatedPubKey2 = pkey3.toString( libBLS::Base::HEXA );
        libBLS::TEPublicKey pkey4( concatenatedPubKey2, libBLS::Base::HEXA );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey4.getPublicKeyRaw() );

        // construct from private key
        libBLS::TEPrivateKey privKey( priv );
        libBLS::TEPublicKey pkey5( privKey );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey5.getPublicKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::algebra::G2Point::SIZE_BYTES > pubKeyBytes = pub.toByteArray();
        libBLS::TEPublicKey pkey6( pubKeyBytes );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey6.getPublicKeyRaw() );
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > bytes6 = pkey6.toBytesArray();
        BOOST_REQUIRE( pubKeyBytes == bytes6 );

        // convert To and From vec of bytes
        std::vector< uint8_t > pubKeyBytesVec( pubKeyBytes.begin(), pubKeyBytes.end() );
        libBLS::TEPublicKey pkey7( pubKeyBytesVec );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey7.getPublicKeyRaw() );
        std::vector< uint8_t > bytes7 = pkey7.toBytesVec();
        BOOST_REQUIRE( pubKeyBytesVec == bytes7 );
    }

    // Exceptions

    // From G2
    {
        // zero public key
        libBLS::algebra::G2Point el = libBLS::algebra::G2Point::identity();
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey pkey( el ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    // From vec of strings
    {
        // Vec has incorrect length
        std::vector< std::string > pkeyStr( { "0", "0", "0" } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ), libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not 64-char length
        std::vector< std::string > pkeyStr( { "0", "0", "0", "0" } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ), libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not hexadecimal
        std::vector< std::string > pkeyStr(
            { "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP",
                randomHexaString( 64 ), randomHexaString( 64 ), randomHexaString( 64 ) } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ), libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From string
    {
        // string has wrong length
        std::string pkey = "a";
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey p( pkey, libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 256 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey p( hexa, libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length + 1
        std::vector< uint8_t > randBytes = randomByteVec( libBLS::G2_SIZE_BYTES + 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes ), libBLS::ThresholdUtils::IncorrectInput );
        // necessary length - 1
        std::vector< uint8_t > randBytes2 = randomByteVec( libBLS::G2_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes2 ), libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes3 ), libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_CASE( TEPublicKeyShare ) {
    size_t signer = 1;
    size_t numSigned = 10;
    size_t numAll = 15;

    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libBLS::algebra::FrScalar priv = libBLS::algebra::FrScalar::random();
        libBLS::algebra::G2Point pub = priv * libBLS::algebra::G2Point::generator();

        // construct from field element
        libBLS::TEPublicKeyShare pkey( pub, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pub );

        // construct from private key
        libBLS::TEPrivateKeyShare privKey( priv, signer, numSigned, numAll );
        libBLS::TEPublicKeyShare pkey2( privKey );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey2.getPublicKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > pubKeyBytes = pub.toByteArray();
        libBLS::TEPublicKeyShare pkey6( pubKeyBytes, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey6.getPublicKeyRaw() );
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > bytes6 = pkey6.toBytesArray();
        BOOST_REQUIRE( pubKeyBytes == bytes6 );

        // convert To and From vec of bytes
        std::vector< uint8_t > pubKeyBytesVec( pubKeyBytes.begin(), pubKeyBytes.end() );
        libBLS::TEPublicKeyShare pkey7( pubKeyBytesVec, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey7.getPublicKeyRaw() );
        std::vector< uint8_t > bytes7 = pkey7.toBytesVec();
        BOOST_REQUIRE( pubKeyBytesVec == bytes7 );
    }

    // Exceptions

    // From G2
    {
        // zero public key
        libBLS::algebra::G2Point el = libBLS::algebra::G2Point::identity();
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare pkey( el, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    // From byte vector
    {
        // wrong size
        // necessary length + 1
        std::vector< uint8_t > randBytes = randomByteVec( libBLS::G2_SIZE_BYTES + 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
        // necessary length - 1
        std::vector< uint8_t > randBytes2 = randomByteVec( libBLS::G2_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes2, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes3, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKey ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libBLS::algebra::FrScalar priv = libBLS::algebra::FrScalar::random();

        // consruct from field element
        libBLS::TEPrivateKey pkey( priv );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == priv );

        // construct from hexadecimal string
        std::string stringField = priv.toString( libBLS::Base::HEXA );
        libBLS::TEPrivateKey pkey2( stringField, libBLS::Base::HEXA );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey2.getPrivateKeyRaw() );

        // to and from string
        std::string stringField2 = pkey.toString( libBLS::Base::HEXA );
        libBLS::TEPrivateKey pkey3( stringField2, libBLS::Base::HEXA );
        BOOST_REQUIRE( pkey3.getPrivateKeyRaw() == pkey2.getPrivateKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes = priv.toByteArray();
        libBLS::TEPrivateKey pkey4( privBytes );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey4.getPrivateKeyRaw() );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes4 = pkey4.toBytesArray();
        BOOST_REQUIRE( privBytes == bytes4 );

        // convert To and From vec of bytes
        std::vector< uint8_t > privKeyBytesVec( privBytes.begin(), privBytes.end() );
        libBLS::TEPrivateKey pkey5( privKeyBytesVec );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey5.getPrivateKeyRaw() );
        std::vector< uint8_t > bytes5 = pkey5.toBytesVec();
        BOOST_REQUIRE( privKeyBytesVec == bytes5 );
    }


    // Exceptions
    // From field element
    {
        // zero private key
        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( el ), libBLS::ThresholdUtils::ZeroSecretKey );
    }

    // From string
    {
        // string has wrong length
        std::string priv = "aadwad";
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKey pkey( priv, libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 64 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKey pkey( hexa, libBLS::Base::HEXA ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length - 1
        std::vector< uint8_t > randBytes2 =
            randomByteVec( libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( randBytes2 ), libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( randBytes3 ), libBLS::ThresholdUtils::IncorrectInput );
        // no problem if length is higher
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKeyShare ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 30; ++i ) {
        libBLS::algebra::FrScalar priv = libBLS::algebra::FrScalar::random();
        size_t signer = 1;
        size_t numSigned = 10;
        size_t numAll = 15;

        // consruct from field element
        libBLS::TEPrivateKeyShare share( priv, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == priv );

        // construct from hexadecimal string
        std::string stringField = priv.toString( libBLS::Base::HEXA );
        libBLS::TEPrivateKeyShare share2(
            stringField, libBLS::Base::HEXA, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share2.getPrivateKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes = priv.toByteArray();
        libBLS::TEPrivateKeyShare share3( privBytes, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share3.getPrivateKeyRaw() );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes3 = share3.toBytesArray();
        BOOST_REQUIRE( privBytes == bytes3 );

        // convert To and From vec of bytes
        std::vector< uint8_t > privKeyBytesVec( privBytes.begin(), privBytes.end() );
        libBLS::TEPrivateKeyShare share4( privKeyBytesVec, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share4.getPrivateKeyRaw() );
        std::vector< uint8_t > bytes4 = share4.toBytesVec();
        BOOST_REQUIRE( privKeyBytesVec == bytes4 );
    }


    // Exceptions

    // From field element
    {
        // zero private key
        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::zero();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 10, 15 ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }
    {
        // signer index > total signers
        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::random();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 11, 10, 10 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required signers > total signers
        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::random();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 12, 11 ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // zero required signer & total signers
        libBLS::algebra::FrScalar el = libBLS::algebra::FrScalar::random();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 0, 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From string
    {
        // string has wrong length
        std::string priv = "a";
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( priv, libBLS::Base::HEXA, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 64 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( hexa, libBLS::Base::HEXA, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // signer index > total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKeyShare share( hexa, libBLS::Base::HEXA, 11, 10, 10 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required signers > total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( hexa, libBLS::Base::HEXA, 1, 12, 11 ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // zero required signer & total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( hexa, libBLS::Base::HEXA, 1, 0, 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length - 1
        std::vector< uint8_t > randBytes2 =
            randomByteVec( libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( randBytes2, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( randBytes3, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_CASE( TEDecryptionShare ) {
    size_t signer = 1;

    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libBLS::algebra::G2Point priv = libBLS::algebra::G2Point::random();

        // consruct from field element
        libBLS::TEDecryptionShare share( priv, signer );
        BOOST_REQUIRE( share.getShareRaw() == priv );

        // construct from hexadecimal string
        std::string str = priv.toString( libBLS::Base::HEXA );
        libBLS::TEDecryptionShare share2( str, signer );
        BOOST_REQUIRE( share.getShareRaw() == share2.getShareRaw() );

        std::string str2 = share2.toString();
        libBLS::TEDecryptionShare share3( str2, signer );
        BOOST_REQUIRE( share.getShareRaw() == share3.getShareRaw() );
    }

    // Exceptions
    // From G2
    {
        // zero key
        libBLS::algebra::G2Point el = libBLS::algebra::G2Point::identity();
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( el, signer ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    // From string
    {
        // tampered string - not hexadecimal
        libBLS::algebra::G2Point el = libBLS::algebra::G2Point::random();

        std::string str = el.toString( libBLS::Base::HEXA );
        str[0] = 'U';  // make it not hexa
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str, signer ),
            libBLS::ThresholdUtils::IncorrectInput );

        // string has wrong length
        str[0] = 'A';  // make it hexa again
        str.resize( str.size() - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str, signer ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // zero element
        libBLS::algebra::G2Point el2 = libBLS::algebra::G2Point::identity();
        std::string str2 = el2.toString( libBLS::Base::HEXA );
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str2, signer ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
}

BOOST_AUTO_TEST_CASE( TEDecryptSet ) {
    libBLS::TEDecryptSet decrSet( 1, 1 );
    // well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        size_t numAll = rand_gen() % 15 + 2;
        size_t numSigned = rand_gen() % numAll + 1;

        keys keys = generateKeys( numSigned, numAll );

        decrSet = libBLS::TEDecryptSet( numSigned, numAll );
        BOOST_REQUIRE( decrSet.getRequiredSigners() == numSigned );
        BOOST_REQUIRE( decrSet.getTotalSigners() == numAll );


        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares;
        for ( size_t i = 0; i < numSigned; ++i ) {
            libBLS::algebra::G2Point group = libBLS::algebra::G2Point::random();
            libBLS::TEDecryptionShare share( group, i );
            BOOST_REQUIRE( decrSet.addDecryptShare( share ) );
            shares.push_back( std::make_pair( group, i ) );
        }

        BOOST_REQUIRE( decrSet.size() == numSigned );
        BOOST_REQUIRE( decrSet.canMerge() );

        decrSet.markAsMerged();
        BOOST_REQUIRE( decrSet.canMerge() == false );

        std::vector< std::pair< libBLS::algebra::G2Point, size_t > > shares2 =
            decrSet.getSharesRaw();
        for ( size_t i = 0; i < shares2.size(); ++i ) {
            BOOST_REQUIRE( std::find( shares.begin(), shares.end(), shares2[i] ) != shares.end() );
        }
    }

    // removing
    {
        libBLS::TEDecryptSet decrSet( 1, 1 );
        libBLS::TEDecryptionShare decr_share( libBLS::algebra::G2Point::random(), 0 );
        decrSet.addDecryptShare( decr_share );
        BOOST_REQUIRE( decrSet.size() == 1 );
        decrSet.removeDecryptShare( decr_share );
        BOOST_REQUIRE( decrSet.size() == 0 );
    }


    // Exceptions
    {
        // already merged
        BOOST_REQUIRE_THROW( decrSet.addDecryptShare( libBLS::TEDecryptionShare(
                                 libBLS::algebra::G2Point::random(), 1 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required > all
        BOOST_REQUIRE_THROW(
            libBLS::TEDecryptSet decrSet( 2, 1 ), libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // share signer index > total signers
        libBLS::TEDecryptSet decrSet( 1, 1 );
        libBLS::TEDecryptionShare decr_share( libBLS::algebra::G2Point::random(), 2 );
        BOOST_REQUIRE_THROW(
            decrSet.addDecryptShare( decr_share ), libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // set is full
        libBLS::TEDecryptSet decrSet( 1, 1 );
        libBLS::TEDecryptionShare decr_share( libBLS::algebra::G2Point::random(), 0 );
        decrSet.addDecryptShare( decr_share );
        libBLS::TEDecryptionShare decr_share2( libBLS::algebra::G2Point::random(), 1 );
        BOOST_REQUIRE_THROW(
            decrSet.addDecryptShare( decr_share2 ), libBLS::ThresholdUtils::IncorrectInput );
    }
}


// Helper function to test a function call against the exception, when ciphertext data is tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextData(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
    for ( auto& cipheredKey : cipher.keys )
        tamperCipheredKeyV( cipheredKey );

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}

// Helper function to test a function call against the exception, when ciphertext U field is
// tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextU(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );

    for ( auto& cipheredKey : cipher.keys )
        cipheredKey.U = libBLS::algebra::G2Point::random();

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}

// Helper function to test a function call against the exception, when ciphertext W field is
// tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextW(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );

    for ( auto& cipheredKey : cipher.keys )
        cipheredKey.W = libBLS::algebra::G1Point::random();

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}


BOOST_AUTO_TEST_CASE( Encryption ) {
    keys keys = generateKeys( 16, 22 );
    size_t dataSize = 100;

    for ( size_t i = 0; i < 100; ++i ) {
        std::vector< uint8_t > data = randomByteVec( dataSize );
        libBLS::Ciphertext cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );

        // should be big enough to contain message and random secret
        BOOST_REQUIRE( cipher.getData().size() >= data.size() + libBLS::RANDOM_SECRET_SIZE_BYTES );

        for ( const auto& cipheredKey : cipher.getKeys() )
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey );
    }

    // Exceptions
    for ( size_t i = 0; i < 40; ++i ) {
        {
            // should not pass pairing validation
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateEncryption( cipheredKey );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered U field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateEncryption( cipheredKey );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered W field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateEncryption( cipheredKey );
                },
                dataSize, keys );
        }
    }
}

BOOST_AUTO_TEST_CASE( BatchedEncryptionValidation ) {
    std::vector< size_t > batchSizes = { 1, 5, 10, 100 };
    keys keys = generateKeys( 16, 22 );
    size_t dataSize = 100;
    for ( const auto& batchSize : batchSizes ) {
        std::vector< libBLS::CipheredKey > ciphers1;
        for ( size_t i = 0; i < batchSize; ++i ) {
            std::vector< uint8_t > data = randomByteVec( dataSize );
            libBLS::Ciphertext cipher =
                libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );

            // should be big enough to contain message and random secret
            BOOST_REQUIRE(
                cipher.getData().size() >= data.size() + libBLS::RANDOM_SECRET_SIZE_BYTES );
            ciphers1.push_back( cipher.keys[0] );  // we only ciphered using 1 public key, thus we
                                                   // have only 1 ciphered key
        }

        // should validate correctly
        auto validation = libBLS::ThresholdEncryption::validateEncryptionBatch( ciphers1 );
        auto validationParallel =
            libBLS::ThresholdEncryption::validateEncryptionBatchParallel( ciphers1 );
        BOOST_REQUIRE( validation == validationParallel );
        BOOST_REQUIRE(
            std::find( validation.begin(), validation.end(), false ) == validation.end() );

        // Faulty key
        auto rnd = rand_gen() % ciphers1.size();
        auto originalCipher = ciphers1[rnd];
        tamperCipheredKeyV( ciphers1[rnd] );
        auto validation2 = libBLS::ThresholdEncryption::validateEncryptionBatch( ciphers1 );
        auto validationParallel2 =
            libBLS::ThresholdEncryption::validateEncryptionBatchParallel( ciphers1 );
        BOOST_REQUIRE( validation2 == validationParallel2 );
        BOOST_REQUIRE( validation2[rnd] == false );

        ciphers1[rnd] = originalCipher;  // restore original

        // Faulty U
        rnd = rand_gen() % ciphers1.size();
        originalCipher = ciphers1[rnd];
        ciphers1[rnd].U = libBLS::algebra::G2Point::random();
        auto validation3 = libBLS::ThresholdEncryption::validateEncryptionBatch( ciphers1 );
        auto validationParallel3 =
            libBLS::ThresholdEncryption::validateEncryptionBatchParallel( ciphers1 );
        BOOST_REQUIRE( validation3 == validationParallel3 );
        BOOST_REQUIRE( validation3[rnd] == false );
        ciphers1[rnd] = originalCipher;  // restore original

        // Faulty W
        rnd = rand_gen() % ciphers1.size();
        originalCipher = ciphers1[rnd];
        ciphers1[rnd].W = libBLS::algebra::G1Point::random();
        auto validation4 = libBLS::ThresholdEncryption::validateEncryptionBatch( ciphers1 );
        auto validationParallel4 =
            libBLS::ThresholdEncryption::validateEncryptionBatchParallel( ciphers1 );
        BOOST_REQUIRE( validation4 == validationParallel4 );
        BOOST_REQUIRE( validation4[rnd] == false );
    }

    // Exceptions - empty input
    auto res = libBLS::ThresholdEncryption::validateEncryptionBatch(
        std::vector< libBLS::CipheredKey >() );
    BOOST_REQUIRE( res.size() == 0 );
    auto res2 = libBLS::ThresholdEncryption::validateEncryptionBatchParallel(
        std::vector< libBLS::CipheredKey >() );
    BOOST_REQUIRE( res2.size() == 0 );
}

BOOST_AUTO_TEST_CASE( PartialDecrypt ) {
    keys keys = generateKeys( 1, 1 );
    size_t dataSize = 100;
    for ( size_t i = 0; i < 20; ++i ) {
        libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
        // should not throw any exception
        for ( const auto& cipheredKey : cipher.getKeys() )
            libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[0] );
    }
}

BOOST_AUTO_TEST_CASE( ValidateDecryptionShare ) {
    size_t requiredSigners = 2;
    size_t totalSigners = 4;
    keys keys = generateKeys( requiredSigners, totalSigners );
    size_t dataSize = 100;
    libBLS::TEDecryptionShare decrShare( libBLS::algebra::G2Point::random(), 1 );
    libBLS::Ciphertext cipher;

    for ( size_t i = 0; i < 40; ++i ) {
        cipher = generateRandomCiphertext( dataSize, keys );
        for ( const auto& cipheredKey : cipher.getKeys() ) {
            decrShare =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[0] );

            libBLS::TEDecryptionShare decrShare2 =
                libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[1] );

            // should not throw
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipheredKey, decrShare, keys.publicKeys[0] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipheredKey, decrShare2, keys.publicKeys[1] );
        }
    }

    libBLS::TEDecryptionShare original = decrShare;

    // Exceptions
    for ( size_t i = 0; i < 40; ++i ) {
        {
            // passed ciphered key has tampered data field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &original]( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateDecryptionShare(
                            cipheredKey, original, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered U field
            exceptionOnTamperedCiphertextU< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &decrShare]( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateDecryptionShare(
                            cipheredKey, decrShare, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered W field
            exceptionOnTamperedCiphertextW< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &decrShare]( libBLS::Ciphertext& cipher ) {
                    for ( const auto& cipheredKey : cipher.getKeys() )
                        libBLS::ThresholdEncryption::validateDecryptionShare(
                            cipheredKey, decrShare, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        // tampered TEDecryptionShare
        {
            // wrong decription share
            libBLS::TEDecryptionShare decrShare2( libBLS::algebra::G2Point::random(), 1 );
            for ( const auto& cipheredKey : cipher.getKeys() )
                BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                         cipheredKey, decrShare2, keys.publicKeys[0] ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
        }
        {
            // wrong te public key share should not pass pairing validation
            libBLS::TEPublicKeyShare pKeyShare(
                libBLS::algebra::G2Point::random(), 1, requiredSigners, totalSigners );
            for ( const auto& cipheredKey : cipher.getKeys() )
                BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                         cipheredKey, original, pKeyShare ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
        }
    }
}


std::pair< std::vector< bool >, std::vector< libBLS::TEDecryptionShare > >
randomTamperDecryptionShares( size_t totalSigners, libBLS::CipheredKey cipheredKey,
    std::vector< libBLS::TEPrivateKeyShare >& privKeys, bool skipTampering ) {
    std::vector< bool > tampered( totalSigners, false );
    std::vector< libBLS::TEDecryptionShare > shares;
    libBLS::TEDecryptionShare decrShare(
        libBLS::algebra::G2Point::random(), 1 );  // random init value - wil be replaced below

    // collect decryption shares
    for ( size_t j = 0; j < totalSigners; ++j ) {
        decrShare = libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, privKeys[j] );

        // allow tampering for all but the first 10 iterations
        if ( !skipTampering ) {
            // randomly decide which indices to tamper
            const auto rnd = rand_gen() % 10;
            if ( rnd < 3 ) {
                // tamper decryption share
                decrShare = libBLS::TEDecryptionShare( libBLS::algebra::G2Point::random(), j );
                tampered[j] = true;
            }
        }
        shares.push_back( decrShare );
    }

    return std::make_pair( tampered, shares );
}


/**
 * Validate a batch of decryption shares for a given ciphered key and public keys.
 * First 10 iterations are not tampered, the rest have random shares tampered.
 * Randomly select which indices / decryptShares to tamper. Run N times.
 *
 * This tests the simple case where all shares from the (inner) batch
 * have the same cipheredKey.
 */
BOOST_AUTO_TEST_CASE( ValidateDecryptionSharesBatch ) {
    size_t requiredSigners = 15;
    size_t totalSigners = 22;
    keys keys = generateKeys( requiredSigners, totalSigners );
    size_t dataSize = 100;
    libBLS::TEDecryptionShare decrShare( libBLS::algebra::G2Point::random(), 1 );
    libBLS::Ciphertext cipher;

    for ( size_t i = 0; i < 40; ++i ) {
        cipher = generateRandomCiphertext( dataSize, keys );
        for ( const auto& cipheredKey : cipher.getKeys() ) {
            std::vector< libBLS::TEPublicKeyShare > pubKeys;
            std::vector< libBLS::TEPrivateKeyShare > privKeys;

            for ( size_t j = 0; j < totalSigners; ++j ) {
                privKeys.push_back( keys.secretKeys[j] );
                pubKeys.push_back( keys.publicKeys[j] );
            }

            auto [tampered, shares] =
                randomTamperDecryptionShares( totalSigners, cipheredKey, privKeys, i <= 10 );

            // batch validate
            std::vector< libBLS::CipheredKey > cipheredKeys = { cipheredKey };
            std::vector< bool > results =
                libBLS::ThresholdEncryption::validateDecryptionSharesBatch(
                    cipheredKeys, shares, pubKeys );

            for ( size_t j = 0; j < totalSigners; ++j ) {
                // only the ones not tampered should pass
                if ( tampered[j] ) {
                    BOOST_REQUIRE( !results[j] );
                } else {
                    BOOST_REQUIRE( results[j] );
                }
            }
        }
    }
}


/**
 * Validate a batch of batches of decryption shares.
 * 'Randomly' select which shares from which batches to tamper &
 * check that only those fail validation.
 */
BOOST_AUTO_TEST_CASE( ValidateDecryptionSharesMegaBatch ) {
    std::vector< size_t > numOfBatchesPerRunVec = { 0, 1, 10 };
    size_t requiredSigners = 15;
    size_t totalSigners = 22;
    keys keys = generateKeys( requiredSigners, totalSigners );
    size_t dataSize = 100;
    libBLS::TEDecryptionShare decrShare( libBLS::algebra::G2Point::random(), 1 );
    libBLS::Ciphertext cipher;

    // test different batch sizes - catch edge cases like 0, 1, and larger sizes
    for ( auto numOfBatchesPerRun : numOfBatchesPerRunVec ) {
        size_t totalNumShares = numOfBatchesPerRun * totalSigners;

        for ( size_t i = 0; i < 20; ++i ) {
            std::vector< bool > tampered( totalNumShares, false );
            std::vector< libBLS::CipheredKey > cipheredKeys;
            std::vector< libBLS::TEDecryptionShare > shares;
            std::vector< libBLS::TEPublicKeyShare > pubKeys;
            cipheredKeys.reserve( numOfBatchesPerRun );
            shares.reserve( totalNumShares );
            pubKeys.reserve( totalNumShares );

            for ( size_t j = 0; j < numOfBatchesPerRun; ++j ) {
                cipher = generateRandomCiphertext( dataSize, keys );
                cipheredKeys.emplace_back( cipher.getKeys()[0] );
                auto [tamperedCurrent, batchShares] = randomTamperDecryptionShares(
                    totalSigners, cipheredKeys[j], keys.secretKeys, ( i + j ) % 2 == 0 );

                for ( size_t k = 0; k < totalSigners; ++k ) {
                    shares.emplace_back( batchShares[k] );
                    pubKeys.emplace_back( keys.publicKeys[k] );
                    if ( tamperedCurrent[k] ) {
                        tampered[j * totalSigners + k] = true;
                    }
                }
            }

            if ( numOfBatchesPerRun == 0 ) {
                auto res = libBLS::ThresholdEncryption::validateDecryptionSharesBatch(
                    cipheredKeys, shares, pubKeys );
                auto res2 = libBLS::ThresholdEncryption::validateDecryptionSharesBatchParallel(
                    cipheredKeys, shares, pubKeys );
                BOOST_REQUIRE( res.size() == 0 );
                BOOST_REQUIRE( res == res2 );
            } else {
                std::vector< bool > results =
                    libBLS::ThresholdEncryption::validateDecryptionSharesBatch(
                        cipheredKeys, shares, pubKeys );

                std::vector< bool > resultsParallel =
                    libBLS::ThresholdEncryption::validateDecryptionSharesBatchParallel(
                        cipheredKeys, shares, pubKeys );

                for ( size_t j = 0; j < totalNumShares; ++j ) {
                    // only the ones not tampered should pass
                    if ( tampered[j] ) {
                        BOOST_REQUIRE( !results[j] );
                        BOOST_REQUIRE( !resultsParallel[j] );
                    } else {
                        BOOST_REQUIRE( results[j] );
                        BOOST_REQUIRE( resultsParallel[j] );
                    }
                }
            }
        }
    }
}


BOOST_AUTO_TEST_CASE( CombineShares ) {
    size_t requiredSigners = 7;
    size_t totalSigners = 10;
    size_t dataSize = 100;

    libBLS::TEDecryptSet alreadyMerged( requiredSigners, totalSigners );
    libBLS::TEDecryptSet notEnoughShares( requiredSigners, totalSigners );
    libBLS::TEDecryptSet readyToMerge( requiredSigners, totalSigners );

    libBLS::Ciphertext cipher;

    for ( size_t i = 0; i < 40; ++i ) {
        keys keys = generateKeys( requiredSigners, totalSigners );
        std::vector< uint8_t > data = randomByteVec( dataSize );
        cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );

        alreadyMerged = libBLS::TEDecryptSet( requiredSigners, totalSigners );
        readyToMerge = libBLS::TEDecryptSet( requiredSigners, totalSigners );
        notEnoughShares = libBLS::TEDecryptSet( requiredSigners, totalSigners );

        for ( const auto& cipheredKey : cipher.getKeys() ) {
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey );

            for ( size_t j = 0; j < requiredSigners; ++j ) {
                libBLS::TEDecryptionShare decrShare =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[j] );
                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, decrShare, keys.publicKeys[j] );
                alreadyMerged.addDecryptShare( decrShare );

                // only add the shares. Do not merge them - used for exception checking below
                readyToMerge.addDecryptShare( decrShare );

                // only add one share to notEnoughShares  - used for exception checking below
                if ( notEnoughShares.size() < requiredSigners - 1 ) {
                    notEnoughShares.addDecryptShare( decrShare );
                }
            }

            libBLS::AES256Key key_deciphered =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, alreadyMerged );
            libBLS::ThresholdEncryption::validateCombinedDecryption(
                cipher, key_deciphered, keys.commonPublic );
            std::vector< uint8_t > decryptedData =
                libBLS::ThresholdEncryption::decrypt( cipher, key_deciphered );

            BOOST_REQUIRE( decryptedData == data );
        }
    }

    keys keys = generateKeys( requiredSigners, totalSigners );

    // tampered TEDecryptSet
    {
        for ( const auto& cipheredKey : cipher.getKeys() )
            // already merged set
            BOOST_REQUIRE_THROW(
                libBLS::ThresholdEncryption::combineShares( cipheredKey, alreadyMerged ),
                libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        for ( const auto& cipheredKey : cipher.getKeys() )
            // not enough shares
            BOOST_REQUIRE_THROW(
                libBLS::ThresholdEncryption::combineShares( cipheredKey, notEnoughShares ),
                libBLS::ThresholdUtils::IsNotWellFormed );
    }
}

BOOST_AUTO_TEST_CASE( ValidateCombinedDecryptionAndDecrypt ) {
    size_t requiredSigners = 7;
    size_t totalSigners = 10;
    size_t dataSize = 100;

    // will all be replaced by last iteration of below for loop
    libBLS::TEDecryptSet decryptSet( requiredSigners, totalSigners );
    libBLS::Ciphertext cipher;
    libBLS::AES256Key keyDeciphered;
    keys keys = generateKeys( requiredSigners, totalSigners );

    // test normal correct behavior
    for ( size_t i = 0; i < 40; ++i ) {
        keys = generateKeys( requiredSigners, totalSigners );
        std::vector< uint8_t > data = randomByteVec( dataSize );
        cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );
        for ( const auto& cipheredKey : cipher.getKeys() ) {
            libBLS::ThresholdEncryption::validateEncryption( cipheredKey );

            decryptSet = libBLS::TEDecryptSet( requiredSigners, totalSigners );

            for ( size_t j = 0; j < requiredSigners; ++j ) {
                libBLS::TEDecryptionShare decrShare =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[j] );
                libBLS::ThresholdEncryption::validateDecryptionShare(
                    cipheredKey, decrShare, keys.publicKeys[j] );
                decryptSet.addDecryptShare( decrShare );
            }

            // validate both combined decryption and decryption
            keyDeciphered = libBLS::ThresholdEncryption::combineShares( cipheredKey, decryptSet );
            libBLS::ThresholdEncryption::validateCombinedDecryption(
                cipher, keyDeciphered, keys.commonPublic );
            std::vector< uint8_t > decryptedData =
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );

            // validate validateAndDecrypt call
            std::vector< uint8_t > decryptedData2 = libBLS::ThresholdEncryption::validateAndDecrypt(
                cipher, keyDeciphered, keys.commonPublic );

            BOOST_REQUIRE( decryptedData == data );
            BOOST_REQUIRE( decryptedData2 == data );
        }
    }

    // Exceptions

    // validateCombinedDecryption
    {
        // tampered ciphertext data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext U
        exceptionOnTamperedCiphertextU< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext W
        exceptionOnTamperedCiphertextW< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // passed public key is not the correct
        libBLS::TEPublicKey pkey = libBLS::TEPublicKey( libBLS::algebra::G2Point::random() );
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateCombinedDecryption( cipher, keyDeciphered, pkey ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // deciphered aes key is not correct
        libBLS::AES256Key keyDeciphered2;
        RAND_bytes( keyDeciphered2.data(), keyDeciphered2.size() );
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateCombinedDecryption(
                                 cipher, keyDeciphered2, keys.commonPublic ),
            std::runtime_error );
    }

    // decrypt
    {
        // passed ciphered key has tampered data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered U field
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered W field
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }

    // validateAndDecrypt
    {
        // tampered ciphertext data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext U
        exceptionOnTamperedCiphertextU< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext W
        exceptionOnTamperedCiphertextW< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // ciphertext data is short - ciphertext should have been already validated before
        libBLS::Ciphertext cipher2 = generateRandomCiphertext( dataSize, keys );
        cipher2.data->resize( libBLS::RANDOM_SECRET_SIZE_BYTES );
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateAndDecrypt(
                                 cipher2, keyDeciphered, keys.commonPublic ),
            std::runtime_error );
    }
    {
        // passed public key is not the correct
        libBLS::TEPublicKey pkey = libBLS::TEPublicKey( libBLS::algebra::G2Point::random() );
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateAndDecrypt( cipher, keyDeciphered, pkey ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // deciphered aes key is not correct
        libBLS::AES256Key keyDeciphered2;
        RAND_bytes( keyDeciphered2.data(), keyDeciphered2.size() );
        // may return one of 2 exceptions in this case: runtime_exception or IsNotWellFormed
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateAndDecrypt(
                                 cipher, keyDeciphered2, keys.commonPublic ),
            std::exception );
    }
}

BOOST_AUTO_TEST_SUITE_END()
