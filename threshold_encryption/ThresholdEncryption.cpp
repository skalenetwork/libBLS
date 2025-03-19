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

#include "ThresholdEncryption.h"
#include "TEBase.h"
#include "TEDecryptSet.h"
#include <tools/utils.h>
#include <valarray>

libBLS::CipherResult ThresholdEncryption::encrypt(
    const std::string& message, const TEPublicKey& commonPublic ) {
    TEBase::initializeIfNecessary();

    libBLS::CipherResult cypher =
        libBLS::TE::encryptWithAES( message, commonPublic.getPublicKeyRaw() );

    libBLS::TE::checkCypher( cypher.ciphertext->key );

    return cypher;
}

bool ThresholdEncryption::validateEncryption( const libBLS::CipheredKey& ciphertext ) {
    TEBase::initializeIfNecessary();

    auto [U, V, W] = ciphertext;

    libff::alt_bn128_G1 H = libBLS::TE::HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;

    // pairing( W, P ) == pairing( H, U )
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    return fst == snd;
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(
    const libBLS::CipheredKey& ciphertext, const TEPrivateKeyShare& pkeyShare ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( ciphertext );

    libff::alt_bn128_G2 decryption_share =
        libBLS::TE::getDecryptionShare( ciphertext, pkeyShare.getPrivateKeyRaw() );

    if ( decryption_share.is_zero() || !decryption_share.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "zero decrypt" );
    }

    TEDecryptionShare share( pkeyShare.getSignerIndex(), decryption_share );

    return share;
}

bool ThresholdEncryption::validateDecryptionShare( const libBLS::CipheredKey& cipherText,
    const TEDecryptionShare& decryptionShare, const TEPublicKeyShare& publicKey ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( cipherText );

    if ( !decryptionShare.validate() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }

    return libBLS::TE::Verify(
        cipherText, decryptionShare.getShareRaw(), publicKey.getPublicKeyRaw() );
}

std::string ThresholdEncryption::combineShares(
    const libBLS::Ciphertext& cyphertext, TEDecryptSet& decryptionSet ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( cyphertext.key );

    if ( !decryptionSet.canMerge() ) {
        auto status = decryptionSet.getMergeStatus();
        if ( status == TEDecryptSet::MergeStatus::NOT_ENOUGH_SHARES ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed(
                "Not enough elements to decrypt message" );
        } else if ( status == TEDecryptSet::MergeStatus::ALREADY_MERGED ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed( "Already merged" );
        }
    }

    libBLS::TE te( decryptionSet );
    auto aesKey = te.CombineShares( cyphertext.key, decryptionSet.getSharesRaw() );
    auto decriptedMessage = libBLS::ThresholdUtils::aesDecrypt( *cyphertext.data, aesKey );

    decryptionSet.markAsMerged();

    return decriptedMessage;
}

bool ThresholdEncryption::validateCombinedDecryption( const libBLS::Ciphertext& cyphertext,
    const std::string& message, const TEPublicKey& publicKey ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( cyphertext.key );
    
    // byte format of the cyphertext should occupy at least the same space as the message in string format
    if (cyphertext.data->size() < message.size()) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Cyphertext should be at least as big as plaintext message" );
    }

    // get random secret
    libBLS::rand_secret secret = extractRandomSecretFromMessage( message );

    // get ciphered AES key
    std::string ciphered_aes_key = cyphertext.key.V;

    // Compute G(r'Y)
    libff::alt_bn128_Fq r( libBLS::ThresholdUtils::convertHexToDec( secret ).c_str() );
    libff::alt_bn128_G2 Y = r * publicKey.getPublicKeyRaw();
    std::string hash = libBLS::TE::Hash( Y );

    // Compute V xor G(r'Y) to get M (AES key)
    std::string aes_key = xorStrings( ciphered_aes_key, hash );

    // Decrypt message with this key
    std::string decrypted_message = libBLS::ThresholdUtils::aesDecrypt( *cyphertext.data, aes_key );

    // compare decyphered message against the one given
    return decrypted_message == message;
}