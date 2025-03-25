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

namespace libBLS {

TEDecryptSet::TEDecryptSet( size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), mergeStatus( MergeStatus::NOT_ENOUGH_SHARES ) {}

void TEDecryptSet::addDecryptShare( const TEDecryptionShare& _share ) {
    if ( mergeStatus == MergeStatus::ALREADY_MERGED ) {
        throw ThresholdUtils::IncorrectInput( "Already Merged" );
    }

    if ( _share.getSignerIndex() > totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Signer index is greater than total signers" );
    }

    if ( decrypts.size() == totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Cannot add more shares than total signers" );
    }

    decrypts.insert( _share );

    // only need to be set once - for the minimum amount of shares needed
    if ( decrypts.size() == requiredSigners ) {
        mergeStatus = MergeStatus::READY_TO_MERGE;
    }
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

    return decrypted;
}

}  // namespace libBLS