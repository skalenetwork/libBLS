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
#include "TEBase.h"
#include "ThresholdEncryption.h"
#include "TEDecryptSet.h"

libBLS::Ciphertext ThresholdEncryption::encrypt(const std::string& message, const TEPublicKey& commonPublic) {
    TEBase::initializeIfNecessary();

    if ( message.length() != 64 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Message length is not equal to 64" );
    }

    libBLS::Ciphertext cypher = libBLS::TE::getCiphertext( message, commonPublic.getPublicKeyRaw() );
    libBLS::TE::checkCypher( cypher );

    return cypher;
}

bool ThresholdEncryption::validateEncryption(const libBLS::Ciphertext& ciphertext, const TEPrivateKeyShare& pkeyShare) {
    TEBase::initializeIfNecessary();

    auto [U, V, W] = ciphertext;

    libff::alt_bn128_G1 H = libBLS::TE::HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    return fst == snd;
}

TEDecryptionShare ThresholdEncryption::partialDecrypt(const libBLS::Ciphertext& ciphertext, const TEPrivateKeyShare& pkeyShare) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( ciphertext );

    libff::alt_bn128_G2 decryption_share = libBLS::TE::getDecryptionShare( ciphertext, pkeyShare.getPrivateKeyRaw() );

    if ( decryption_share.is_zero() || !decryption_share.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "zero decrypt" );
    }

    TEDecryptionShare share(pkeyShare.getSignerIndex(), decryption_share);

    return share;
}

bool ThresholdEncryption::validateDecryptionShare(const libBLS::Ciphertext& cipherText, const TEDecryptionShare& decryptionShare, const TEPublicKeyShare& publicKey) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( cipherText );

    if ( !decryptionShare.validate() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }

    return libBLS::TE::Verify( cipherText, decryptionShare.getShareRaw(), publicKey.getPublicKeyRaw() );
}

std::string ThresholdEncryption::combineShares(const libBLS::Ciphertext& cyphertext, TEDecryptSet& decryptionSet) {
    TEBase::initializeIfNecessary();

    libBLS::TE::checkCypher( cyphertext );

    if ( !decryptionSet.canMerge() ) {
        auto status = decryptionSet.getMergeStatus();
        if ( status == TEDecryptSet::MergeStatus::NOT_ENOUGH_SHARES ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed( "Not enough elements to decrypt message" );
        } else if ( status == TEDecryptSet::MergeStatus::ALREADY_MERGED ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed( "Already merged" );
        }
    }

    libBLS::TE te( decryptionSet );
    auto res = te.CombineShares( cyphertext, decryptionSet.getSharesRaw() );

    decryptionSet.markAsMerged();

    return res;
}

bool ThresholdEncryption::validateCombinedDecryption(const libBLS::Ciphertext& cyphertext, const std::string& message) {
    TEBase::initializeIfNecessary();

    throw std::runtime_error("Not implemented");
}
