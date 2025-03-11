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

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <utility>

#include <tools/utils.h>


TEDecryptSet::TEDecryptSet( size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), mergeStatus( MergeStatus::NOT_ENOUGH_SHARES ) {}

void TEDecryptSet::addDecryptShare( TEDecryptionShare _share ) {
    if ( mergeStatus == MergeStatus::ALREADY_MERGED ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Already Merged" );
    }

    if ( decrypts.find( _share ) != decrypts.end() ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Already have this secret share:" + _share.toString() );
    }

    decrypts.insert( _share );

    // only need to be set once - for the minimum amount of shares needed
    if ( decrypts.size() == requiredSigners ) {
        mergeStatus = MergeStatus::READY_TO_MERGE;
    }
}

// std::string TEDecryptSet::merge( const libBLS::Ciphertext& cyphertext ) {
//     libBLS::TE::checkCypher( cyphertext );

//     if ( decrypts.size() < requiredSigners ) {
//         throw libBLS::ThresholdUtils::IsNotWellFormed( "Not enough elements to decrypt message"
//         );
//     }

//     libBLS::TE te( *this );

//     std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
//     for ( auto&& share : decrypts ) {
//         decrypted.push_back( share );
//     }

//     auto res = te.CombineShares( cyphertext, decrypted );

//     was_merged = true;

//     return res;
// }

std::vector< uint8_t > TEDecryptSet::mergeIntoAESKey() {
    libBLS::TE te( *this );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
    for ( auto&& share : decrypts ) {
        decrypted.push_back( share );
    }

    auto res = te.CombineSharesIntoAESKey( decrypted );

    mergeStatus = MergeStatus::ALREADY_MERGED;

    return res;
}

size_t TEDecryptSet::size() const {
    return decrypts.size();
}

bool TEDecryptSet::canMerge() const {
    return mergeStatus == MergeStatus::READY_TO_MERGE;
}

void TEDecryptSet::markAsMerged() {
    mergeStatus = MergeStatus::ALREADY_MERGED;
}

TEDecryptSet::MergeStatus TEDecryptSet::getMergeStatus() const {
    return mergeStatus;
}


std::vector< std::pair< libff::alt_bn128_G2, size_t > > TEDecryptSet::getSharesRaw() const {
    std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
    for ( auto&& share : decrypts ) {
        decrypted.push_back( share );
    }

    return std::move( decrypted );
}
