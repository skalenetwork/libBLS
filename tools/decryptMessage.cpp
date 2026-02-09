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
#include <iostream>
#include <optional>

int main( int argc, char* argv[] ) {
    if ( argc < 5 || argc > 7 ) {
        std::cerr << "Usage: " << argv[0]
                  << " <encrypted_data> <secret_key> <expected_message> <key_index_to_keep> "
                     "[<aad_aes>] [<aad_te>]"
                  << std::endl;
        return 1;
    }

    std::string encryptedData = argv[1];
    std::string secretKey = argv[2];
    std::string expectedMessage = argv[3];
    size_t keyIndexToKeep = std::stoul( argv[4] );

    std::optional< std::vector< uint8_t > > aadAes;
    std::optional< std::vector< uint8_t > > aadTe;

    if ( argc >= 6 && argv[5] != nullptr && argv[5][0] != '\0' ) {
        aadAes = libBLS::ThresholdUtils::hexCStringToBytes( argv[5] );
    }

    if ( argc >= 7 && argv[6] != nullptr && argv[6][0] != '\0' ) {
        aadTe = libBLS::ThresholdUtils::hexCStringToBytes( argv[6] );
    }

    libBLS::init();

    auto encryptedDataBytes = libBLS::ThresholdUtils::hexCStringToBytes( encryptedData.c_str() );

    auto ciphertext = libBLS::Ciphertext::fromBytes( encryptedDataBytes );

    if ( ciphertext.getKeys().size() == 2 )
        ciphertext.keepKey( keyIndexToKeep );

    libBLS::CipheredKey aesKeyEncrypted = ciphertext.getTargetKey();

    auto encryptedMessage = ciphertext.getData();

    libBLS::ThresholdEncryption::validateEncryption(
        aesKeyEncrypted, aadTe.has_value() ? &aadTe.value() : nullptr );

    libBLS::TEPrivateKeyShare privateKeyShare(
        libBLS::algebra::FrScalar::fromString( secretKey, libBLS::Base::DEC ), 1, 1, 1 );
    libBLS::TEPublicKeyShare publicKeyShare( privateKeyShare );

    libBLS::TEDecryptionShare decryptionShare =
        libBLS::ThresholdEncryption::partialDecrypt( aesKeyEncrypted, privateKeyShare );

    libBLS::ThresholdEncryption::validateDecryptionShare( aesKeyEncrypted, decryptionShare,
        publicKeyShare, aadTe.has_value() ? &aadTe.value() : nullptr );

    libBLS::TEDecryptSet decryptSet( 1, 1 );
    decryptSet.addDecryptShare( decryptionShare );

    auto aesKeyDecrypted =
        libBLS::ThresholdEncryption::combineShares( aesKeyEncrypted, decryptSet );

    libBLS::TEPublicKey publicKey( publicKeyShare.getPublicKeyRaw() );

    libBLS::ThresholdEncryption::validateCombinedDecryption(
        ciphertext, aesKeyDecrypted, publicKey, aadAes );

    auto decryptedMessageBytes =
        libBLS::ThresholdEncryption::decrypt( ciphertext, aesKeyDecrypted, aadAes );

    auto plaintext = libBLS::ThresholdUtils::bytesToHexString( decryptedMessageBytes );

    assert( expectedMessage == plaintext );

    return 0;
}
