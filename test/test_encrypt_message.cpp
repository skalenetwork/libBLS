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

#include "utils.h"
#include <TEPublicKey.h>
#include <ThresholdEncryption.h>
#include "backends/algebra.hpp"
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( EncryptMessageJS )

BOOST_AUTO_TEST_CASE( EncryptMessage ) {
    libBLS::initCurve();
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

        // call encrypt message
        const char* cipheredMessage = encryptMessage( dataStr, pKeyStr.c_str() );
        std::vector< uint8_t > cipheredMessageBytesActual =
            libBLS::ThresholdUtils::hexCStringToBytes( cipheredMessage );

        // encrypt message using libBLS
        libBLS::TEPublicKey publicKey( pKeyStr );
        libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt( data, publicKey );
        std::vector< uint8_t > cipheredMessageBytesTarget = ciphertext.toBytes();

        // cannot compare their contents since each has a different random secret, which results
        // in different ciphered messages - just check their lengths
        BOOST_REQUIRE( cipheredMessageBytesActual.size() == cipheredMessageBytesTarget.size() );

        // run TE process over the ciphered message from JS
        libBLS::Ciphertext cipheredMessageObj =
            libBLS::Ciphertext::fromBytes( cipheredMessageBytesActual );
        libBLS::TEDecryptSet decr_set( required, total );

        for ( size_t j = 0; j < required; ++j ) {
            libBLS::TEDecryptionShare share = libBLS::ThresholdEncryption::partialDecrypt(
                cipheredMessageObj.key, keys.secretKeys[j] );
            decr_set.addDecryptShare( share );
        }

        libBLS::AES256Key key_deciphered =
            libBLS::ThresholdEncryption::combineShares( cipheredMessageObj.key, decr_set );
        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cipheredMessageObj, key_deciphered, keys.commonPublic.getPublicKeyRaw() );
        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cipheredMessageObj, key_deciphered );

        BOOST_REQUIRE( decipheredMsg == data );

        // delete cipheredMessage;
    }
}

BOOST_AUTO_TEST_SUITE_END()
