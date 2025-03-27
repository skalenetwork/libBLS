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

@file ThresholdEncryption.h
@author Sidnei Teixeira
@date 2025
*/

#include "ThresholdEncryption.h"
#include "TEBase.h"
#include "TEDecryptSet.h"
#include <tools/utils.h>
#include <valarray>

namespace libBLS {

Ciphertext ThresholdEncryption::encrypt(
    const std::vector< uint8_t >& _message, const TEPublicKey& _commonPublic ) {
    TEBase::initializeIfNecessary();

    CipherResult cypher = TE::encryptWithAES( _message, _commonPublic.getPublicKeyRaw() );

    TE::checkCypher( cypher.ciphertext->key );

    if ( !cypher.ciphertext ) {
        throw ThresholdUtils::IsNotWellFormed( "ciphertext is null" );
    }

    return *cypher.ciphertext;
}

void ThresholdEncryption::validateEncryption( const CipheredKey& _ciphertext ) {
    TEBase::initializeIfNecessary();

    auto [U, V, W] = _ciphertext;
    std::string v_str = ThresholdUtils::bytesToHexCString( V );

    libff::alt_bn128_G1 H = TE::HashToGroup( U, v_str );

    libff::alt_bn128_GT fst, snd;

    // pairing( W, P ) == pairing( H, U )
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    if ( fst != snd ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid encryption" );
    }
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(
    const CipheredKey& _ciphertext, const TEPrivateKeyShare& _pkeyShare ) {
    TEBase::initializeIfNecessary();

    TE::checkCypher( _ciphertext );

    libff::alt_bn128_G2 decryption_share =
        TE::getDecryptionShare( _ciphertext, _pkeyShare.getPrivateKeyRaw() );

    if ( decryption_share.is_zero() || !decryption_share.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed( "zero decrypt" );
    }

    TEDecryptionShare share( _pkeyShare.getSignerIndex(), decryption_share );

    return share;
}

void ThresholdEncryption::validateDecryptionShare( const CipheredKey& _cipherText,
    const TEDecryptionShare& _decryptionShare, const TEPublicKeyShare& _publicKey ) {
    TEBase::initializeIfNecessary();

    TE::checkCypher( _cipherText );

    if ( !_decryptionShare.validate() ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }

    if ( !TE::Verify(
             _cipherText, _decryptionShare.getShareRaw(), _publicKey.getPublicKeyRaw() ) ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }
}

AES256Key ThresholdEncryption::combineShares(
    const CipheredKey& _cypheredKey, TEDecryptSet& _decryptionSet ) {
    TEBase::initializeIfNecessary();

    TE::checkCypher( _cypheredKey );

    switch ( _decryptionSet.getMergeStatus() ) {
    case TEDecryptSet::MergeStatus::READY_TO_MERGE:
        break;
    case TEDecryptSet::MergeStatus::ALREADY_MERGED:
        throw ThresholdUtils::IsNotWellFormed( "Already merged" );
    case TEDecryptSet::MergeStatus::NOT_ENOUGH_SHARES:
        throw ThresholdUtils::IsNotWellFormed( "Not enough shares" );
    default:
        throw ThresholdUtils::IsNotWellFormed( "Unknown merging status" );
    }

    TE te( _decryptionSet );
    AES256Key aesKey = te.CombineShares( _cypheredKey, _decryptionSet.getSharesRaw() );

    _decryptionSet.markAsMerged();

    return aesKey;
}

void ThresholdEncryption::validateCombinedDecryption(
    const Ciphertext& _cyphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey ) {
    TEBase::initializeIfNecessary();

    TE::checkCypher( _cyphertext.key );

    std::vector< uint8_t > deciphered_message =
        ThresholdUtils::aesDecrypt( _cyphertext.getData(), _aesKey );

    // cyphertext should occupy at least the same space as the message in string
    // format
    if ( _cyphertext.getData().size() < deciphered_message.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Cyphertext should be at least as big as plaintext message" );
    }

    // get random secret
    RandSecret secret = extractRandomSecretFromMessage( deciphered_message );

    // get ciphered AES key
    const AES256Key& cipheredAesKey = _cyphertext.key.V;

    // Compute G(r'Y)
    libff::alt_bn128_Fq r = ThresholdUtils::bytesToFieldElement< libff::alt_bn128_Fq >( secret );
    libff::alt_bn128_G2 Y = r * _publicKey.getPublicKeyRaw();
    std::string hash = TE::Hash( Y );

    // Compute V xor G(r'Y) to get M (AES key)
    AES256Key decipheredAesKey;
    for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
        decipheredAesKey[i] = cipheredAesKey[i] ^ static_cast< uint8_t >( hash[i] );
    }

    // compare the aes keys
    if ( decipheredAesKey != _aesKey ) {
        throw ThresholdUtils::IsNotWellFormed( "Deciphered AES key is not equal to the original" );
    }
}


std::vector< uint8_t > ThresholdEncryption::decrypt(
    const Ciphertext& _cyphertext, const AES256Key& _aesKey ) {
    TEBase::initializeIfNecessary();

    TE::checkCypher( _cyphertext.key );
    std::vector< uint8_t > data = ThresholdUtils::aesDecrypt( _cyphertext.getData(), _aesKey );
    data.resize( data.size() - RANDOM_SECRET_SIZE_BYTES );
    return data;
}


}  // namespace libBLS
