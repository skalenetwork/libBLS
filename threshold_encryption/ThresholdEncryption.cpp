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
    const std::string& _message, const TEPublicKey& _commonPublic ) {
    TEBase::initializeIfNecessary();

    libBLS::CipherResult cypher =
        libBLS::TE::encryptWithAES( _message, _commonPublic.getPublicKeyRaw() );

    libBLS::TE::checkCypher( cypher.ciphertext->key );

    return cypher;
}

bool ThresholdEncryption::validateEncryption( const libBLS::CipheredKey& _ciphertext ) {
    TEBase::initializeIfNecessary();

    auto [U, V, W] = _ciphertext;

    libff::alt_bn128_G1 H = libBLS::TE::HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;

    // pairing( W, P ) == pairing( H, U )
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    return fst == snd;
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(
    const libBLS::CipheredKey& _ciphertext, const TEPrivateKeyShare& _pkeyShare ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( _ciphertext );

    libff::alt_bn128_G2 decryption_share =
        libBLS::TE::getDecryptionShare( _ciphertext, _pkeyShare.getPrivateKeyRaw() );

    if ( decryption_share.is_zero() || !decryption_share.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "zero decrypt" );
    }

    TEDecryptionShare share( _pkeyShare.getSignerIndex(), decryption_share );

    return share;
}

bool ThresholdEncryption::validateDecryptionShare( const libBLS::CipheredKey& _cipherText,
    const TEDecryptionShare& _decryptionShare, const TEPublicKeyShare& _publicKey ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( _cipherText );

    if ( !_decryptionShare.validate() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }

    return libBLS::TE::Verify(
        _cipherText, _decryptionShare.getShareRaw(), _publicKey.getPublicKeyRaw() );
}

std::string ThresholdEncryption::combineShares(
    const libBLS::Ciphertext& _cyphertext, TEDecryptSet& _decryptionSet ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( _cyphertext.key );

    switch ( _decryptionSet.getMergeStatus() ) {
    case TEDecryptSet::MergeStatus::READY_TO_MERGE:
        break;
    case TEDecryptSet::MergeStatus::ALREADY_MERGED:
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Already merged" );
    case TEDecryptSet::MergeStatus::NOT_ENOUGH_SHARES:
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Not enough shares" );
    default:
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Unknown merging status" );
    }

    libBLS::TE te( _decryptionSet );
    auto aesKey = te.CombineShares( _cyphertext.key, _decryptionSet.getSharesRaw() );
    auto decriptedMessage = libBLS::ThresholdUtils::aesDecrypt( _cyphertext.getData(), aesKey );

    _decryptionSet.markAsMerged();

    return decriptedMessage;
}

bool ThresholdEncryption::validateCombinedDecryption( const libBLS::Ciphertext& _cyphertext,
    const std::string& _message, const TEPublicKey& _publicKey ) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( _cyphertext.key );

    // byte format of the cyphertext should occupy at least the same space as the message in string
    // format
    if ( _cyphertext.getData().size() < _message.size() ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Cyphertext should be at least as big as plaintext message" );
    }

    // get random secret
    libBLS::rand_secret secret = extractRandomSecretFromMessage( _message );

    // get ciphered AES key
    std::string ciphered_aes_key = _cyphertext.key.V;

    // Compute G(r'Y)
    libff::alt_bn128_Fq r( libBLS::ThresholdUtils::convertHexToDec( secret ).c_str() );
    libff::alt_bn128_G2 Y = r * _publicKey.getPublicKeyRaw();
    std::string hash = libBLS::TE::Hash( Y );

    // Compute V xor G(r'Y) to get M (AES key)
    std::string aes_key = xorStrings( ciphered_aes_key, hash );

    // Decrypt message with this key
    std::string decrypted_message =
        libBLS::ThresholdUtils::aesDecrypt( _cyphertext.getData(), aes_key );

    // compare decyphered message against the one given
    return decrypted_message == _message;
}