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

#include <threshold_encryption.h>
#include <tools/utils.h>
#include <fstream>

int main() {
    std::ifstream encryptedDataFile, secretKeyFile;
    encryptedDataFile.open( "encrypted_data.txt" );
    secretKeyFile.open( "secret_key.txt" );

    std::string encryptedData;
    encryptedDataFile >> encryptedData;

    std::string secretKey;
    secretKeyFile >> secretKey;

    auto te_instance = libBLS::TE( 1, 1 );

    auto ciphertext_with_aes = te_instance.aesCiphertextFromString( encryptedData );

    auto ciphertext = ciphertext_with_aes.first;
    auto encrypted_message = ciphertext_with_aes.second;

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr( secretKey.c_str() );
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    libff::alt_bn128_G2 decryption_share = te_instance.getDecryptionShare( ciphertext, secret_key );

    assert( te_instance.Verify( ciphertext, decryption_share, public_key ) );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
    shares.push_back( std::make_pair( decryption_share, size_t( 1 ) ) );

    std::string decrypted_aes_key = te_instance.CombineShares( ciphertext, shares );

    std::string plaintext =
        libBLS::ThresholdUtils::aesDecrypt( encrypted_message, decrypted_aes_key );

    std::ifstream messageFile;
    messageFile.open( "message.txt" );
    std::string message;
    messageFile >> message;

    assert( message == plaintext );

    return 0;
}