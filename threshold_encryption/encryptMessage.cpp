/*
Copyright (C) 2021- SKALE Labs

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

@file encryptMessage.cpp
@author Oleh Nikolaiev
@date 2021
*/

#include "ThresholdEncryption.h"
#include <threshold_encryption.h>
#include <tools/utils.h>
#include <mutex>
#include <iostream>

static std::once_flag initFlag;
static void ensureInit() {
    std::call_once(initFlag, [](){ libBLS::init(); });
}

extern "C" {

const char* encryptMessage( const char* data, const char* key,
    const char* additionalAuthenticatedDataAES, const char* additionalAuthenticatedDataTE ) {
    thread_local std::string cipheredMessageStr;

    try {
        ensureInit();

    // convert from char into vector of bytes
    std::vector< uint8_t > messageBytes = libBLS::ThresholdUtils::hexCStringToBytes( data );

    // build public key
    std::string keyStr( key );
    libBLS::TEPublicKey commonPublic( keyStr, libBLS::Base::HEXA );

    // build encrypt meta data
    libBLS::EncryptMetaData metaData;

    // set AAD AES if not empty
    if ( additionalAuthenticatedDataAES != nullptr && additionalAuthenticatedDataAES[0] != '\0' ) {
        metaData.associatedDataAesCbc =
            libBLS::ThresholdUtils::hexCStringToBytes( additionalAuthenticatedDataAES );
    }

    // set AAD TE if not empty
    if ( additionalAuthenticatedDataTE != nullptr && additionalAuthenticatedDataTE[0] != '\0' ) {
        metaData.associatedDataTE =
            libBLS::ThresholdUtils::hexCStringToBytes( additionalAuthenticatedDataTE );
    }

    // encrypt message
    libBLS::Ciphertext cipheredMessage =
        libBLS::ThresholdEncryption::encrypt( messageBytes, commonPublic, metaData );

    std::vector< uint8_t > cipheredMessageBytes = cipheredMessage.toBytes();

    cipheredMessageStr = libBLS::ThresholdUtils::bytesToHexString( cipheredMessageBytes );

    return cipheredMessageStr.c_str();

    } catch ( const std::exception& e ) {
        std::cerr << "C++ exception in encryptMessage: " << e.what() << std::endl;
        return nullptr;
    } catch ( ... ) {
        std::cerr << "Unknown C++ exception in encryptMessage" << std::endl;
        return nullptr;
    }
}

const char* encryptMessageDualKey( const char* data, const char* firstKey, const char* secondKey,
    const char* additionalAuthenticatedDataAES, const char* additionalAuthenticatedDataTE ) {
    thread_local std::string cipheredMessageStr;

    try {
        ensureInit();

    // convert from char into vector of bytes
    std::vector< uint8_t > messageBytes = libBLS::ThresholdUtils::hexCStringToBytes( data );

    std::vector< libBLS::TEPublicKey > commonPublicKeys;
    // build public keys
    std::string firstKeyStr( firstKey );
    libBLS::TEPublicKey firstCommonPublic( firstKeyStr, libBLS::Base::HEXA );
    std::string secondKeyStr( secondKey );
    libBLS::TEPublicKey secondCommonPublic( secondKeyStr, libBLS::Base::HEXA );
    commonPublicKeys.push_back( firstCommonPublic );
    commonPublicKeys.push_back( secondCommonPublic );

    // Build metadata
    libBLS::EncryptMetaData metaData;

    // set AAD AES if not empty
    if ( additionalAuthenticatedDataAES != nullptr && additionalAuthenticatedDataAES[0] != '\0' ) {
        metaData.associatedDataAesCbc =
            libBLS::ThresholdUtils::hexCStringToBytes( additionalAuthenticatedDataAES );
    }

    // set AAD TE if not empty
    if ( additionalAuthenticatedDataTE != nullptr && additionalAuthenticatedDataTE[0] != '\0' ) {
        metaData.associatedDataTE =
            libBLS::ThresholdUtils::hexCStringToBytes( additionalAuthenticatedDataTE );
    }


    libBLS::Ciphertext cipheredMessage =
        libBLS::ThresholdEncryption::encrypt( messageBytes, commonPublicKeys, metaData );
    std::vector< uint8_t > cipheredMessageBytes = cipheredMessage.toBytes();

    cipheredMessageStr = libBLS::ThresholdUtils::bytesToHexString( cipheredMessageBytes );

    return cipheredMessageStr.c_str();

    } catch ( const std::exception& e ) {
        std::cerr << "C++ exception in encryptMessageDualKey: " << e.what() << std::endl;
        return nullptr;
    } catch ( ... ) {
        std::cerr << "Unknown C++ exception in encryptMessageDualKey" << std::endl;
        return nullptr;
    }
}

const char* encryptMessageMockup( const char* data ) {
    thread_local std::string cipheredMessageStr;

    try {
        ensureInit();

    // convert from char into vector of bytes
    std::vector< uint8_t > messageBytes = libBLS::ThresholdUtils::hexCStringToBytes( data );

    // encrypt message
    std::vector< uint8_t > cipheredMessage =
        libBLS::ThresholdEncryption::mockupEncrypt( messageBytes );

    cipheredMessageStr = libBLS::ThresholdUtils::bytesToHexString( cipheredMessage );

    return cipheredMessageStr.c_str();

    } catch ( const std::exception& e ) {
        std::cerr << "C++ exception in encryptMessageMockup: " << e.what() << std::endl;
        return nullptr;
    } catch ( ... ) {
        std::cerr << "Unknown C++ exception in encryptMessageMockup" << std::endl;
        return nullptr;
    }
}
}
