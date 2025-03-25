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
#include <threshold_encryption/encryptMessage.h>
#include <tools/utils.h>

#include <openssl/rand.h>

#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <TEPublicKey.h>
#include <ThresholdEncryption.h>
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( EncryptMessageJS )

BOOST_AUTO_TEST_CASE( EncryptMessage ) {
    libBLS::TEBase::initializeIfNecessary();
    // random message & pKey
    libff::alt_bn128_G2 pKey = libff::alt_bn128_G2::random_element();
    std::vector< uint8_t > data( rand() % 1000 + 1 );
    RAND_bytes( data.data(), data.size() );

    // convert both to strings
    std::vector< std::string > pKeyVec =
        libBLS::ThresholdUtils::G2ToString( pKey, libBLS::BASE_HEXA );
    std::string pKeyStr;
    for ( auto& str : pKeyVec ) {
        pKeyStr += str;
    }

    char* dataStr = libBLS::ThresholdUtils::bytesToHexCString( data );

    // call encrypt message
    const char* cipheredMessage = encryptMessage( dataStr, pKeyStr.c_str() );
    std::vector< uint8_t > cipheredMessageBytesActual =
        libBLS::ThresholdUtils::hexCStringToBytes( cipheredMessage );

    // encrypt message using libBLS
    libBLS::TEPublicKey publicKey( pKeyStr );
    libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt( data, publicKey );
    std::vector< uint8_t > cipheredMessageBytesTarget = ciphertext.toBytes();

    // cannot compare their contents since each has a different random secret, which results
    // in different ciphered messages
    BOOST_REQUIRE( cipheredMessageBytesActual.size() == cipheredMessageBytesTarget.size() );
}

BOOST_AUTO_TEST_SUITE_END()