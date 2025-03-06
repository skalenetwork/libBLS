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

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/

#include <tools/utils.h>
#include "ThresholdEncryption.h"

libBLS::Ciphertext ThresholdEncryption::encrypt(const std::string& message, const TEPublicKey& common_public) {
    libBLS::TE te( common_public );

    if ( message.length() != 64 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Message length is not equal to 64" );
    }

    libBLS::Ciphertext cypher = te.getCiphertext( message, common_public.getPublicKeyRaw() );
    libBLS::TE::checkCypher( cypher );

    return cypher;
}

bool ThresholdEncryption::validateEncryption(const libBLS::Ciphertext& ciphertext, const TEPrivateKeyShare& pkey_share) {
    // return pkey_share.Verify(ciphertext);
    throw std::runtime_error("Not implemented");
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(const libBLS::Ciphertext& cyphertext, const TEPrivateKeyShare& pkey_share) {
    // return pkey_share.getDecryptionShare(cyphertext);
    throw std::runtime_error("Not implemented");
}

bool ThresholdEncryption::validateDecryptionShare(const libBLS::Ciphertext& cipherText, const TEDecryptionShare& decryption_share) {
    // return decryption_share.validate();
    throw std::runtime_error("Not implemented");
}

std::string ThresholdEncryption::combineShares(const libBLS::Ciphertext& cyphertext, const std::vector<TEDecryptionShare>& decryption_shares) {
    // return cyphertext.decrypt(decryption_shares);
    throw std::runtime_error("Not implemented");
}
