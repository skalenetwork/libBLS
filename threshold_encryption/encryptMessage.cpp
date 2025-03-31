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

extern "C" {

const char* encryptMessage( const char* data, const char* key ) {
    static std::string cipheredMessageStr;
    
    libBLS::ThresholdUtils::initCurve();

    // convert from char into vec of bytes
    std::vector< uint8_t > messageBytes = libBLS::ThresholdUtils::hexCStringToBytes( data );

    // build public key
    std::string keyStr( key );
    libBLS::TEPublicKey commonPublic( keyStr );

    // encrypt message
    libBLS::Ciphertext cipheredMessage =
        libBLS::ThresholdEncryption::encrypt( messageBytes, commonPublic );
    std::vector< uint8_t > cipheredMessageBytes = cipheredMessage.toBytes();

    cipheredMessageStr = libBLS::ThresholdUtils::bytesToHexString( cipheredMessageBytes );

    return cipheredMessageStr.c_str();
}
}