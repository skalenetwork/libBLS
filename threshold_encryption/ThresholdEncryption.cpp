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

std::vector< uint8_t > ThresholdEncryption::mockupEncrypt(
    const std::vector< uint8_t >& _message ) {
    if ( _message.empty() ) {
        throw ThresholdUtils::IncorrectInput( "Empty message" );
    }

    // Create random AES key
    AES256Key key;
    if ( RAND_bytes( key.data(), key.size() ) != 1 ) {
        throw ThresholdUtils::IsNotWellFormed( "Failed to generate random key" );
    }

    std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES >
        mockupEncryptedKey{};  // Zero-initialized

    std::copy( key.begin(), key.end(), mockupEncryptedKey.begin() );

    RandSecret random_secret{};  // Zero-initialized

    // Append random secret to end of message
    std::vector< uint8_t > message_to_cipher( _message );
    message_to_cipher.insert( message_to_cipher.end(), random_secret.begin(), random_secret.end() );

    // Cipher message + random secret using AES key
    auto encrypted_message = ThresholdUtils::aesEncrypt( message_to_cipher, key );

    // Construct result: key followed by encrypted data
    std::vector< uint8_t > result( mockupEncryptedKey.begin(), mockupEncryptedKey.end() );

    #pragma GCC diagnostic ignored "-Wstringop-overread"
    result.insert( result.end(), encrypted_message.begin(), encrypted_message.end() );
    #pragma GCC diagnostic error "-Wstringop-overread"

    return result;
}


std::vector< uint8_t > ThresholdEncryption::mockupDecrypt(
    const std::vector< uint8_t >& _encrypteData ) {
    if ( _encrypteData.size() <= CipheredKey::CIPHERED_KEY_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Encrypted data too short" );
    }

    // Extract AES key from the beginning
    AES256Key key;
    std::copy( _encrypteData.begin(), _encrypteData.begin() + AES_256_KEY_SIZE_BYTES, key.begin() );

    // Encrypted message follows the key
    std::vector< uint8_t > cipher_text(
        _encrypteData.begin() + CipheredKey::CIPHERED_KEY_SIZE_BYTES, _encrypteData.end() );

    // Decrypt the data
    std::vector< uint8_t > decrypted = ThresholdUtils::aesDecrypt( cipher_text, key );

    if ( decrypted.size() < RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IsNotWellFormed( "Decrypted message too short" );
    }

    // Remove appended random secret
    decrypted.resize( decrypted.size() - RANDOM_SECRET_SIZE_BYTES );

    return decrypted;
}


Ciphertext ThresholdEncryption::encrypt(
    const std::vector< uint8_t >& _message, const TEPublicKey& _commonPublic ) {
    TEBase::initializeIfNecessary();

    _commonPublic.validate();

    if ( _message.empty() ) {
        throw ThresholdUtils::IncorrectInput( "Empty message" );
    }

    CipherResult cypher = TE::encryptWithAES( _message, _commonPublic.getPublicKeyRaw() );

    if ( !cypher.ciphertext ) {
        throw ThresholdUtils::IsNotWellFormed( "ciphertext is null" );
    }

    cypher.ciphertext->validate();

    return *cypher.ciphertext;
}

void ThresholdEncryption::validateEncryption( const CipheredKey& _ciphertext ) {
    TEBase::initializeIfNecessary();

    _ciphertext.validate();

    auto [U, V, W] = _ciphertext;
    std::string v_str = ThresholdUtils::bytesToHexString( V );

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

    _ciphertext.validate();
    _pkeyShare.validate();

    // ciphertext is validated in getDecryptionShare
    libff::alt_bn128_G2 decryption_share =
        TE::getDecryptionShare( _ciphertext, _pkeyShare.getPrivateKeyRaw() );

    ThresholdUtils::validateG2( decryption_share );

    TEDecryptionShare share( decryption_share, _pkeyShare.getSignerIndex() );

    return share;
}

void ThresholdEncryption::validateDecryptionShare( const CipheredKey& _cipherText,
    const TEDecryptionShare& _decryptionShare, const TEPublicKeyShare& _publicKey ) {
    TEBase::initializeIfNecessary();

    _cipherText.validate();
    _decryptionShare.validate();
    _publicKey.validate();

    if ( !TE::Verify(
             _cipherText, _decryptionShare.getShareRaw(), _publicKey.getPublicKeyRaw() ) ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }
}

AES256Key ThresholdEncryption::combineShares(
    const CipheredKey& _cypheredKey, TEDecryptSet& _decryptionSet ) {
    TEBase::initializeIfNecessary();

    _cypheredKey.validate();

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

    _cyphertext.validate();

    // decipher & validate plaintext
    std::vector< uint8_t > deciphered_message = decipherAESAndValidate( _cyphertext, _aesKey );

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

    _cyphertext.validate();

    // decipher & validate plaintext
    std::vector< uint8_t > data = decipherAESAndValidate( _cyphertext, _aesKey );

    // safe - size of decipheredMessage was already validated
    data.resize( data.size() - RANDOM_SECRET_SIZE_BYTES );
    return data;
}

std::vector< uint8_t > ThresholdEncryption::validateAndDecrypt(
    const Ciphertext& _cyphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey ) {
    _cyphertext.validate();

    // decipher & validate plaintext
    std::vector< uint8_t > decipheredMessage = decipherAESAndValidate( _cyphertext, _aesKey );

    // get random secret
    RandSecret secret = extractRandomSecretFromMessage( decipheredMessage );

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

    // safe - size of decipheredMessage was already validated
    decipheredMessage.resize( decipheredMessage.size() - RANDOM_SECRET_SIZE_BYTES );
    return decipheredMessage;
}

std::vector< uint8_t > ThresholdEncryption::decipherAESAndValidate(
    const Ciphertext& _ciphertext, const AES256Key& key ) {
    std::vector< uint8_t > data = ThresholdUtils::aesDecrypt( _ciphertext.getData(), key );

    // validate output
    size_t cipherSize = _ciphertext.getData().size();
    size_t plainSize = data.size();

    // cyphertext should occupy at least the same space as the message in string
    // format
    if ( cipherSize < plainSize ) {
        throw ThresholdUtils::IncorrectInput(
            "Cyphertext should be at least as big as plaintext message" );
    }

    if ( plainSize <= RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput(
            "Message decription size is too short - cannot include random secret + at least 1 byte "
            "of data" );
    }

    return data;
}

}  // namespace libBLS
