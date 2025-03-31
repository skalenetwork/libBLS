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

@file decryptMessage.cpp
@author Oleh Nikolaiev
@date 2021
*/

#include <TEDecryptSet.h>
#include <TEPrivateKeyShare.h>
#include <TEPublicKeyShare.h>
#include <ThresholdEncryption.h>
#include <threshold_encryption.h>
#include <tools/utils.h>
#include <fstream>

int main() {
    std::ifstream encryptedDataFile, secretKeyFile;
    encryptedDataFile.open( "encrypted_data.txt" );
    secretKeyFile.open( "secret_key.txt" );

    std::string encryptedData;
    encryptedDataFile >> encryptedData;

    std::cout << "Encrypted data: " << encryptedData << '\n';

    std::string secretKey;
    secretKeyFile >> secretKey;

    libBLS::ThresholdUtils::initCurve();

    auto encryptedDataBytes = libBLS::ThresholdUtils::hexCStringToBytes( encryptedData.c_str() );

    auto ciphertext = libBLS::Ciphertext::fromBytes( encryptedDataBytes );

    auto aesKeyEncrypted = ciphertext.key;
    auto encryptedMessage = ciphertext.getData();

    libBLS::ThresholdEncryption::validateEncryption( aesKeyEncrypted );

    libBLS::TEPrivateKeyShare privateKeyShare( secretKey, 0, 1, 1 );
    libBLS::TEPublicKeyShare publicKeyShare( privateKeyShare );

    libBLS::TEDecryptionShare decryptionShare =
        libBLS::ThresholdEncryption::partialDecrypt( aesKeyEncrypted, privateKeyShare );

    libBLS::ThresholdEncryption::validateDecryptionShare(
        aesKeyEncrypted, decryptionShare, publicKeyShare );

    libBLS::TEDecryptSet decryptSet( 1, 1 );
    decryptSet.addDecryptShare( decryptionShare );

    auto aesKeyDecrypted =
        libBLS::ThresholdEncryption::combineShares( aesKeyEncrypted, decryptSet );

    libBLS::TEPublicKey publicKey( publicKeyShare.getPublicKeyRaw() );

    libBLS::ThresholdEncryption::validateCombinedDecryption(
        ciphertext, aesKeyDecrypted, publicKey );

    auto decryptedMessageBytes =
        libBLS::ThresholdEncryption::decrypt( ciphertext, aesKeyDecrypted );

    auto plaintext = libBLS::ThresholdUtils::bytesToHexString( decryptedMessageBytes );

    std::ifstream messageFile;
    messageFile.open( "message.txt" );
    std::string message;
    messageFile >> message;

    assert( message == plaintext );

    return 0;
}
