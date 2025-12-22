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
  @author Sidnei Teixeira
  @date 2025
 */

#include <random>

#include <threshold_encryption.h>
#include <tools/utils.h>
#include <threshold_encryption/encryptMessage.cpp>

#include <openssl/rand.h>

#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include "backends/algebra.hpp"
#include "utils.h"
#include <TEPublicKey.h>
#include <ThresholdEncryption.h>
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( EncryptMessageJS )

BOOST_AUTO_TEST_CASE( EncryptMessage ) {
    libBLS::init();
    size_t required = 10;
    size_t total = 15;

    for ( size_t i = 0; i < 50; ++i ) {
        keys keys = generateKeys( required, total );
        // random message & pKey
        std::vector< uint8_t > data( ( rand() % 1000 ) + 1 );

        // empty message case
        if ( i == 0 )
            data.clear();
        RAND_bytes( data.data(), data.size() );

        // convert key & data to string
        std::string pKeyStr = keys.commonPublic.getPublicKeyRaw().toString( libBLS::Base::HEXA );

        std::string str = libBLS::ThresholdUtils::bytesToHexString( data );
        const char* dataStr = str.c_str();

        std::vector< uint8_t > additionalAuthenticatedData = { 'a', 'd', 'd', 'i', 't', 'i', 'o',
            'n', 'a', 'l', 'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'e', 'd', 'D',
            'a', 't', 'a' };
        std::string additionalAuthenticatedDataStr =
            libBLS::ThresholdUtils::bytesToHexString( additionalAuthenticatedData );
        const char* additionalAuthenticatedDataStrC = additionalAuthenticatedDataStr.c_str();

        // call encrypt message
        const char* cipheredMessage =
            encryptMessage( dataStr, pKeyStr.c_str(), additionalAuthenticatedDataStrC );
        std::vector< uint8_t > cipheredMessageBytesActual =
            libBLS::ThresholdUtils::hexCStringToBytes( cipheredMessage );

        // encrypt message using libBLS
        libBLS::TEPublicKey publicKey( pKeyStr, libBLS::Base::HEXA );
        libBLS::Ciphertext ciphertext =
            libBLS::ThresholdEncryption::encrypt( data, publicKey, additionalAuthenticatedData );
        std::vector< uint8_t > cipheredMessageBytesTarget = ciphertext.toBytes();

        // cannot compare their contents since each has a different random secret, which results
        // in different ciphered messages - just check their lengths
        BOOST_REQUIRE( cipheredMessageBytesActual.size() == cipheredMessageBytesTarget.size() );

        // run TE process over the ciphered message from JS
        libBLS::Ciphertext cipheredMessageObj =
            libBLS::Ciphertext::fromBytes( cipheredMessageBytesActual );

        for ( const auto& cipheredKey : cipheredMessageObj.getKeys() ) {
            libBLS::TEDecryptSet decr_set( required, total );

            for ( size_t j = 0; j < required; ++j ) {
                libBLS::TEDecryptionShare share =
                    libBLS::ThresholdEncryption::partialDecrypt( cipheredKey, keys.secretKeys[j] );
                decr_set.addDecryptShare( share );
            }

            libBLS::AES256Key key_deciphered =
                libBLS::ThresholdEncryption::combineShares( cipheredKey, decr_set );
            libBLS::ThresholdEncryption::validateCombinedDecryption( cipheredMessageObj,
                key_deciphered, keys.commonPublic.getPublicKeyRaw(), additionalAuthenticatedData );
            std::vector< uint8_t > decipheredMsg = libBLS::ThresholdEncryption::decrypt(
                cipheredMessageObj, key_deciphered, additionalAuthenticatedData );

            BOOST_REQUIRE( decipheredMsg == data );
        }
    }

    for ( size_t i = 0; i < 50; ++i ) {
        std::vector< keys > keys;
        keys.push_back( generateKeys( required, total ) );
        keys.push_back( generateKeys( required, total ) );
        // random message & pKey
        std::vector< uint8_t > data( ( rand() % 1000 ) + 1 );

        // empty message case
        if ( i == 0 )
            data.clear();
        RAND_bytes( data.data(), data.size() );

        // prepare data
        std::string str = libBLS::ThresholdUtils::bytesToHexString( data );
        const char* dataStr = str.c_str();

        std::vector< std::string > publicKeysStr( 2 );
        for ( size_t j = 0; j < 2; ++j ) {
            // convert key to string
            std::string pKeyStr =
                keys[j].commonPublic.getPublicKeyRaw().toString( libBLS::Base::HEXA );
            publicKeysStr[j] = pKeyStr;
        }

        std::vector< uint8_t > additionalAuthenticatedData = { 'a', 'd', 'd', 'i', 't', 'i', 'o',
            'n', 'a', 'l', 'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'e', 'd', 'D',
            'a', 't', 'a' };
        std::string additionalAuthenticatedDataStr =
            libBLS::ThresholdUtils::bytesToHexString( additionalAuthenticatedData );
        const char* additionalAuthenticatedDataStrC = additionalAuthenticatedDataStr.c_str();

        // call encrypt message
        const char* cipheredMessage = encryptMessageDualKey( dataStr, publicKeysStr[0].c_str(),
            publicKeysStr[1].c_str(), additionalAuthenticatedDataStrC );
        std::vector< uint8_t > cipheredMessageBytesActual =
            libBLS::ThresholdUtils::hexCStringToBytes( cipheredMessage );

        // encrypt message using libBLS
        std::vector< libBLS::TEPublicKey > commonPublicKeys;
        for ( const auto& publicKey : publicKeysStr ) {
            commonPublicKeys.push_back( libBLS::TEPublicKey( publicKey, libBLS::Base::HEXA ) );
        }
        libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt(
            data, commonPublicKeys, additionalAuthenticatedData );
        std::vector< uint8_t > cipheredMessageBytesTarget = ciphertext.toBytes();

        // cannot compare their contents since each has a different random secret, which results
        // in different ciphered messages - just check their lengths
        BOOST_REQUIRE( cipheredMessageBytesActual.size() == cipheredMessageBytesTarget.size() );

        // run TE process over the ciphered message from JS
        libBLS::Ciphertext cipheredMessageObj =
            libBLS::Ciphertext::fromBytes( cipheredMessageBytesActual );

        auto cipheredKeys = cipheredMessageObj.getKeys();
        for ( size_t k = 0; k < cipheredKeys.size(); ++k ) {
            libBLS::TEDecryptSet decr_set( required, total );

            for ( size_t j = 0; j < required; ++j ) {
                libBLS::TEDecryptionShare share = libBLS::ThresholdEncryption::partialDecrypt(
                    cipheredKeys[k], keys[k].secretKeys[j] );
                decr_set.addDecryptShare( share );
            }

            libBLS::AES256Key key_deciphered =
                libBLS::ThresholdEncryption::combineShares( cipheredKeys[k], decr_set );
            libBLS::Ciphertext tempCipheredMessage(
                cipheredMessageObj.getKeys()[k], cipheredMessageObj.getData() );
            libBLS::ThresholdEncryption::validateCombinedDecryption( tempCipheredMessage,
                key_deciphered, keys[k].commonPublic.getPublicKeyRaw(),
                additionalAuthenticatedData );
            std::vector< uint8_t > decipheredMsg = libBLS::ThresholdEncryption::decrypt(
                tempCipheredMessage, key_deciphered, additionalAuthenticatedData );

            BOOST_REQUIRE( decipheredMsg == data );

            auto ciphertextCopy = cipheredMessageObj;
            BOOST_REQUIRE_THROW(
                libBLS::ThresholdEncryption::validateAndDecrypt( ciphertextCopy, key_deciphered,
                    keys[k].commonPublic, additionalAuthenticatedData ),
                libBLS::ThresholdUtils::IncorrectInput );
            ciphertextCopy.keepKey( k );
            BOOST_REQUIRE(
                libBLS::ThresholdEncryption::validateAndDecrypt( ciphertextCopy, key_deciphered,
                    keys[k].commonPublic, additionalAuthenticatedData ) == data );
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
