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

#ifndef WITH_EMSCRIPTEN
#include <folly/futures/Future.h>
#endif

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
    AesGcmCipher aesGcmCipher{ key };
    auto encrypted_message = aesGcmCipher.encrypt( message_to_cipher );

    // 0x01 byte is needed for compatibility with real encryption
    // stands for the number of encrypted AES keys in the payload
    // Construct result: 0x01 byte + key + encrypted data
    std::vector< uint8_t > result = { 0x01 };
    result.insert( result.end(), mockupEncryptedKey.begin(), mockupEncryptedKey.end() );

#pragma GCC diagnostic ignored "-Wstringop-overread"
    result.insert( result.end(), encrypted_message.begin(), encrypted_message.end() );
#pragma GCC diagnostic error "-Wstringop-overread"

    return result;
}


std::vector< uint8_t > ThresholdEncryption::mockupDecrypt(
    const std::vector< uint8_t >& _encryptedData ) {
    // first byte - 0x01 stands for the number of encrypted AES keys in the payload
    // needed for compatibility with real encryption
    if ( _encryptedData.size() <= CipheredKey::CIPHERED_KEY_SIZE_BYTES + 1 ) {
        throw ThresholdUtils::IncorrectInput( "Encrypted data too short" );
    }

    // Extract AES key from the beginning
    AES256Key key;
    std::copy( _encryptedData.begin() + 1, _encryptedData.begin() + AES_256_KEY_SIZE_BYTES + 1,
        key.begin() );

    // Encrypted message follows the key
    std::vector< uint8_t > cipher_text(
        _encryptedData.begin() + CipheredKey::CIPHERED_KEY_SIZE_BYTES + 1, _encryptedData.end() );

    // Decrypt the data
    AesGcmCipher aesGcmCipher{ key };
    std::vector< uint8_t > decrypted = aesGcmCipher.decrypt( cipher_text );

    if ( decrypted.size() < RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IsNotWellFormed( "Decrypted message too short" );
    }

    // Remove appended random secret
    decrypted.resize( decrypted.size() - RANDOM_SECRET_SIZE_BYTES );

    return decrypted;
}


Ciphertext ThresholdEncryption::encrypt(
    const std::vector< uint8_t >& _message, const TEPublicKey& _commonPublic ) {
    return encrypt( _message, std::vector< TEPublicKey >{ _commonPublic } );
}


Ciphertext ThresholdEncryption::encrypt(
    const std::vector< uint8_t >& _message, const std::vector< TEPublicKey >& _commonPublic ) {
    if ( _commonPublic.size() == 0 || _commonPublic.size() > 2 )
        throw ThresholdUtils::IncorrectInput(
            "Must provide exactly 1 or 2 public keys for encryption" );

    std::vector< algebra::G2Point > rawPublicKeys;
    for ( const auto& publicKey : _commonPublic ) {
        publicKey.validate();
        rawPublicKeys.push_back( publicKey.getPublicKeyRaw() );
    }

    CipherResult cipher = TE::encryptWithAES( _message, rawPublicKeys );

    if ( !cipher.ciphertext ) {
        throw ThresholdUtils::IsNotWellFormed( "ciphertext is null" );
    }

    cipher.ciphertext->validate();

    return *cipher.ciphertext;
}

void ThresholdEncryption::validateEncryption( const CipheredKey& _ciphertext ) {
    const auto& [U, V, W] = _ciphertext;

    algebra::G1Point H = TE::HashToGroup( U, V );

    // pairing( W, P ) == pairing( H, U )
    bool validPairing = algebra::verifyPairingEq( W, algebra::G2Point::generator(), H, U );

    if ( !validPairing ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid encryption" );
    }
}

std::vector< bool > ThresholdEncryption::validateEncryptionBatch(
    const std::vector< CipheredKey >& _ciphertexts ) {
    // Store concrete values (no reference_wrapper)
    static thread_local std::vector< algebra::G1Point > g1P1s;  // W_i
    static thread_local std::vector< algebra::G1Point > g1P2s;  // H_i
    static thread_local std::vector< algebra::G2Point > g2P2s;  // U_i
    static thread_local algebra::G2Point g2P1 = algebra::G2Point::generator();

    size_t size = _ciphertexts.size();
    if ( g1P1s.size() < size ) {
        g1P1s.resize( size );
        g1P2s.resize( size );
        g2P2s.resize( size );
    }

    for ( size_t i = 0 ; i < size ; ++i ) {
        const auto& [U, V, W] = _ciphertexts.at(i);
        const algebra::G1Point H = TE::HashToGroup( U, V );

        g1P1s.at(i) = W;
        g1P2s.at(i) = H;
        g2P2s.at(i) = U;
    }

    algebra::PairingEquality1CommonBaseBatch batch( g1P1s, g1P2s, g2P1, g2P2s, size );
    batch.useOptimisticValidation();
    return algebra::verifyPairingEquality1CommonBaseBatch( batch );
}

std::vector< bool > ThresholdEncryption::validateEncryptionBatchParallel(
    const std::vector< CipheredKey >& _ciphertexts ) {

#ifdef WITH_EMSCRIPTEN
    return ThresholdEncryption::validateEncryptionBatch( _ciphertexts );
#else
    std::vector< folly::Future< std::vector< bool > > > futures;
    futures.reserve( ThresholdUtils::numThreads );

    size_t sizePerThread =
        ( _ciphertexts.size() + ThresholdUtils::numThreads - 1 ) / ThresholdUtils::numThreads;

    for ( size_t i = 0; i < ThresholdUtils::numThreads; ++i ) {
        size_t startIdx = i * sizePerThread;
        size_t endIdx = std::min( startIdx + sizePerThread, _ciphertexts.size() );

        futures.push_back( folly::via(
            ThresholdUtils::thread_pool.get(), [startIdx, endIdx, & _ciphertexts]() {
                std::vector< CipheredKey > subset(
                    _ciphertexts.begin() + startIdx, _ciphertexts.begin() + endIdx );
                return ThresholdEncryption::validateEncryptionBatch( subset );
            } 
        ));
    }

    auto results = folly::collectAll( futures ).get();
    std::vector< bool > finalResults;
    finalResults.reserve( _ciphertexts.size() );

    for (auto& r : results) {
        for (auto b : r.value()) {
            finalResults.push_back(b);
        }
    }

    return finalResults;
#endif 
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(
    const CipheredKey& _ciphertext, const TEPrivateKeyShare& _pkeyShare ) {
    algebra::G2Point decryption_share = _pkeyShare.getPrivateKeyRaw() * _ciphertext.U;
    // no need to validate G2Point - if both inputs are already valid, multiplication
    // always produces a valid point

    TEDecryptionShare share( decryption_share, _pkeyShare.getSignerIndex() );

    return share;
}

void ThresholdEncryption::validateDecryptionShare( const CipheredKey& _cipherText,
    const TEDecryptionShare& _decryptionShare, const TEPublicKeyShare& _publicKey ) {
    if ( !TE::Verify(
             _cipherText, _decryptionShare.getShareRaw(), _publicKey.getPublicKeyRaw() ) ) {
        throw ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }
}

std::vector< bool > ThresholdEncryption::validateDecryptionSharesBatch(
    const std::vector< CipheredKey >& _cipherTexts,
    const std::vector< TEDecryptionShare >& _decryptionShares,
    const std::vector< TEPublicKeyShare >& _publicKeys ) {
    // convert from keys to G points
    std::vector< algebra::G2Point > decryptionSharesRaw;
    for ( const auto& share : _decryptionShares ) {
        decryptionSharesRaw.push_back( share.getShareRaw() );
    }

    std::vector< algebra::G2Point > publicKeysRaw;
    for ( const auto& key : _publicKeys ) {
        publicKeysRaw.push_back( key.getPublicKeyRaw() );
    }

    return TE::VerifyBatch( _cipherTexts, decryptionSharesRaw, publicKeysRaw );
}

std::vector< bool > ThresholdEncryption::validateDecryptionSharesBatchParallel(
    const std::vector< CipheredKey >& _cipherTexts,
    const std::vector< TEDecryptionShare >& _decryptionShares,
    const std::vector< TEPublicKeyShare >& _publicKeys ) {

#ifdef WITH_EMSCRIPTEN
    return ThresholdEncryption::validateDecryptionSharesBatch( 
        _cipherTexts, _decryptionShares, _publicKeys );
#else

    if ( _decryptionShares.size() != _publicKeys.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Decryption shares and public keys size mismatch" );
    }

    if (_decryptionShares.size() % _cipherTexts.size() != 0) {
        throw ThresholdUtils::IncorrectInput(
            "Decryption shares size must be multiple of ciphertexts size" );
    }

    size_t sharesPerCiphertext = _decryptionShares.size() / _cipherTexts.size();

    std::vector< folly::Future< std::vector< bool > > > futures;
    futures.reserve( ThresholdUtils::numThreads );

    size_t sizePerThread =
        ( _cipherTexts.size() + ThresholdUtils::numThreads - 1 ) / ThresholdUtils::numThreads;

    for ( size_t i = 0; i < ThresholdUtils::numThreads; ++i ) {
        size_t startIdx = i * sizePerThread;
        size_t endIdx = std::min( startIdx + sizePerThread, _cipherTexts.size() );

        futures.push_back( folly::via(
            ThresholdUtils::thread_pool.get(), [startIdx, endIdx, &_cipherTexts, &_decryptionShares, &_publicKeys, sharesPerCiphertext]() {

                const std::vector< CipheredKey > ciphertexts(
                    _cipherTexts.begin() + startIdx, _cipherTexts.begin() + endIdx );
                const std::vector< TEDecryptionShare > decryptionShares(
                    _decryptionShares.begin() + startIdx * sharesPerCiphertext,
                    _decryptionShares.begin() + endIdx * sharesPerCiphertext );
                const std::vector< TEPublicKeyShare > publicKeys(
                    _publicKeys.begin() + startIdx * sharesPerCiphertext,
                    _publicKeys.begin() + endIdx * sharesPerCiphertext );
                
                return ThresholdEncryption::validateDecryptionSharesBatch( 
                    ciphertexts, decryptionShares, publicKeys
                );
            } 
        ));
    }

    auto results = folly::collectAll( futures ).get();
    std::vector< bool > finalResults;
    finalResults.reserve( _cipherTexts.size() );

    for (auto& r : results) {
        for (auto b : r.value()) {
            finalResults.push_back(b);
        }
    }

    return finalResults;

#endif
}


AES256Key ThresholdEncryption::combineShares(
    const CipheredKey& _cipheredKey, TEDecryptSet& _decryptionSet ) {
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

    auto secret = te.CombineSharesIntoAESKey( _decryptionSet.getSharesRaw() );

    AES256Key aesKey;

    for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
        aesKey[i] = secret[i] ^ _cipheredKey.V[i];
    }

    _decryptionSet.markAsMerged();

    return aesKey;
}

std::vector< std::optional< AES256Key > > ThresholdEncryption::combineSharesBatch(
    std::vector< CipheredKey >& _cipheredKeys, std::vector< TEDecryptSet >& _decryptionSets ) {

    if ( _cipheredKeys.size() != _decryptionSets.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Ciphertexts and decryption sets size mismatch" );
    }

    std::vector< std::optional< AES256Key > > results;
    results.reserve( _cipheredKeys.size() );

    for ( size_t i = 0; i < _cipheredKeys.size(); ++i ) {
        try {
            results.push_back( ThresholdEncryption::combineShares( 
                _cipheredKeys[i], _decryptionSets[i] 
            ));
        } catch ( const std::exception& e ) {
            std::cerr << "Error combining shares for ciphertext " << i << ": " << e.what() << "\n";
            results.push_back( std::nullopt );
        }
    }

    return results;
}

std::vector< std::optional< AES256Key > > ThresholdEncryption::combineSharesBatchParallel(
    std::vector< CipheredKey >& _cipheredKeys, std::vector< TEDecryptSet >& _decryptionSets
) {

#ifdef WITH_EMSCRIPTEN
    return ThresholdEncryption::combineSharesBatch( _cipheredKeys, _decryptionSets );
#else

    if ( _cipheredKeys.size() != _decryptionSets.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Ciphertexts and decryption sets size mismatch" );
    }

    std::vector< folly::Future< std::vector< std::optional< AES256Key > > > > futures;
    futures.reserve( ThresholdUtils::numThreads );

    size_t sizePerThread =
        ( _cipheredKeys.size() + ThresholdUtils::numThreads - 1 ) / ThresholdUtils::numThreads;

    for ( size_t i = 0; i < ThresholdUtils::numThreads; ++i ) {
        size_t startIdx = i * sizePerThread;
        size_t endIdx = std::min( startIdx + sizePerThread, _cipheredKeys.size() );

        futures.push_back( folly::via(
            ThresholdUtils::thread_pool.get(), [startIdx, endIdx, & _cipheredKeys, & _decryptionSets]() {
                std::vector< std::optional< AES256Key > > subset;
                subset.reserve( endIdx - startIdx );
                for ( size_t j = startIdx; j < endIdx; ++j ) {
                    try {
                        subset.push_back( ThresholdEncryption::combineShares( 
                            _cipheredKeys[j], _decryptionSets[j] 
                        ));
                    } catch ( const std::exception& e ) {
                        std::cerr << "Error combining shares for ciphertext " << j << ": " << e.what() << "\n";
                        subset.push_back( std::nullopt );
                    }
                }
                return subset;
            } 
        ));
    }

    auto results = folly::collectAll( futures ).get();
    std::vector< std::optional< AES256Key > > finalResults;
    finalResults.reserve( _cipheredKeys.size() );

    for (auto& r : results) {
        for (auto& optKey : r.value()) {
            finalResults.push_back(optKey);
        }
    }

    return finalResults;    
#endif
}

void ThresholdEncryption::validateCombinedDecryption(
    const Ciphertext& _ciphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey ) {
    // decipher & validate plaintext
    std::vector< uint8_t > decipheredMessage = decipherAESAndValidate( _ciphertext, _aesKey );

    validateDecipheredMessage( decipheredMessage, _ciphertext, _aesKey, _publicKey );
}

std::vector< bool > ThresholdEncryption::validateCombinedDecryptionBatch(
    const std::vector< Ciphertext >& _ciphertexts, const std::vector< AES256Key >& _aesKeys, const TEPublicKey& _publicKey ) {

    if ( _ciphertexts.size() != _aesKeys.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Ciphertexts and AES keys size mismatch" );
    }

    std::vector< bool > results;
    results.reserve( _ciphertexts.size() );

    for ( size_t i = 0; i < _ciphertexts.size(); ++i ) {
        try {
            std::vector< uint8_t > decipheredMessage = decipherAESAndValidate( _ciphertexts[i], _aesKeys[i] );
            validateDecipheredMessage( decipheredMessage, _ciphertexts[i], _aesKeys[i], _publicKey );
            results.push_back( true );
        } catch ( const std::exception& e ) {
            std::cerr << "Error combining shares for ciphertext " << i << ": " << e.what() << "\n";
            results.push_back( false );
        }
    }

    return results;
}

std::vector< bool > ThresholdEncryption::validateCombinedDecryptionBatchParallel(
    const std::vector< Ciphertext >& _ciphertexts, const std::vector< AES256Key >& _aesKeys, const TEPublicKey& _publicKey ) {

#ifdef WITH_EMSCRIPTEN
    return ThresholdEncryption::validateCombinedDecryptionBatch( _ciphertexts, _aesKeys, _publicKey );
#else

    if ( _ciphertexts.size() != _aesKeys.size() ) {
        throw ThresholdUtils::IncorrectInput(
            "Ciphertexts and AES keys size mismatch" );
    }

    std::vector< folly::Future< std::vector< bool > > > futures;
    futures.reserve( ThresholdUtils::numThreads );

    size_t sizePerThread =
        ( _ciphertexts.size() + ThresholdUtils::numThreads - 1 ) / ThresholdUtils::numThreads;

    for ( size_t i = 0; i < ThresholdUtils::numThreads; ++i ) {
        size_t startIdx = i * sizePerThread;
        size_t endIdx = std::min( startIdx + sizePerThread, _ciphertexts.size() );

        futures.push_back( folly::via(
            ThresholdUtils::thread_pool.get(), [startIdx, endIdx, & _ciphertexts, & _aesKeys, & _publicKey]() {
                std::vector< bool > subset;
                subset.reserve( endIdx - startIdx );
                for ( size_t j = startIdx; j < endIdx; ++j ) {
                    try {
                        std::vector< uint8_t > decipheredMessage = decipherAESAndValidate( _ciphertexts[j], _aesKeys[j] );
                        validateDecipheredMessage( decipheredMessage, _ciphertexts[j], _aesKeys[j], _publicKey );
                        subset.push_back( true );
                    } catch ( const std::exception& e ) {
                        std::cerr << "Error combining shares for ciphertext " << j << ": " << e.what() << "\n";
                        subset.push_back( false );
                    }
                }
                return subset;
            } 
        ));
    }

    auto results = folly::collectAll( futures ).get();
    std::vector< bool > finalResults;
    finalResults.reserve( _ciphertexts.size() );

    for (auto& r : results) {
        for (auto b : r.value()) {
            finalResults.push_back(b);
        }
    }

    return finalResults;   
#endif
}


std::vector< uint8_t > ThresholdEncryption::decrypt(
    const Ciphertext& _ciphertext, const AES256Key& _aesKey ) {
    // decipher & validate plaintext
    std::vector< uint8_t > data = decipherAESAndValidate( _ciphertext, _aesKey );

    // safe - size of decipheredMessage was already validated
    data.resize( data.size() - RANDOM_SECRET_SIZE_BYTES );
    return data;
}

std::vector< uint8_t > ThresholdEncryption::validateAndDecrypt(
    const Ciphertext& _ciphertext, const AES256Key& _aesKey, const TEPublicKey& _publicKey ) {
    // decipher & validate plaintext
    std::vector< uint8_t > decipheredMessage = decipherAESAndValidate( _ciphertext, _aesKey );

    validateDecipheredMessage( decipheredMessage, _ciphertext, _aesKey, _publicKey );

    // safe - size of decipheredMessage was already validated
    decipheredMessage.resize( decipheredMessage.size() - RANDOM_SECRET_SIZE_BYTES );
    return decipheredMessage;
}

void ThresholdEncryption::validateDecipheredMessage(
    const std::vector< uint8_t >& _decipheredMessage, const Ciphertext& _ciphertext,
    const AES256Key& _aesKey, const TEPublicKey& _publicKey ) {
    if ( _ciphertext.getKeys().size() != 1 )
        throw ThresholdUtils::IncorrectInput(
            "Ciphertext must include only 1 encrypted key in payload "
            "when validating against original AES key" );
    // get random secret
    RandSecret secret = extractRandomSecretFromMessage( _decipheredMessage );

    auto cipheredKey = _ciphertext.getTargetKey();
    // get ciphered AES key
    const AES256Key& cipheredAesKey = cipheredKey.V;

    // Compute G(r'Y)
    algebra::FrScalar r = algebra::FrScalar::fromBytes( secret );
    algebra::G2Point Y = r * _publicKey.getPublicKeyRaw();
    AES256Key hash = TE::Hash( Y );

    // Compute V xor G(r'Y) to get M (AES key)
    AES256Key decipheredAesKey;
    for ( size_t i = 0; i < AES_256_KEY_SIZE_BYTES; ++i ) {
        decipheredAesKey[i] = cipheredAesKey[i] ^ hash[i];
    }

    // compare the aes keys
    if ( decipheredAesKey != _aesKey ) {
        throw ThresholdUtils::IsNotWellFormed( "Deciphered AES key is not equal to the original" );
    }
}

std::vector< uint8_t > ThresholdEncryption::decipherAESAndValidate(
    const Ciphertext& _ciphertext, const AES256Key& key ) {
    AesGcmCipher aesGcmCipher{ key };
    std::vector< uint8_t > data = aesGcmCipher.decrypt( _ciphertext.getData() );

    // validate output
    size_t cipherSize = _ciphertext.getData().size();
    size_t plainSize = data.size();

    // cyphertext should occupy at least the same space as the message in string
    // format
    if ( cipherSize < plainSize ) {
        throw ThresholdUtils::IncorrectInput(
            "Cyphertext should be at least as big as plaintext message" );
    }

    if ( plainSize < RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput(
            "Message decription size is too short - cannot include random secret" );
    }

    return data;
}

}  // namespace libBLS
