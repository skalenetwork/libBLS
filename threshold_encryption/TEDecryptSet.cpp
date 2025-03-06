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

#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEBase.h>
#include <utility>

#include <tools/utils.h>


TEDecryptSet::TEDecryptSet( size_t _requiredSigners, size_t _totalSigners )
    : TEBase(_requiredSigners, _totalSigners ), was_merged( false ) {
    libff::init_alt_bn128_params();
}

void TEDecryptSet::addDecrypt( TEDecryptionShare _share ) {

    if ( was_merged ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Invalid state" );
    }

   if ( decrypts.find( _share ) != decrypts.end() ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Already have this secret share:" + _share.toString() );
    }

    decrypts.insert( _share );
}

std::string TEDecryptSet::merge( const libBLS::Ciphertext& cyphertext ) {
    libBLS::TE::checkCypher( cyphertext );

    if ( decrypts.size() < requiredSigners ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Not enough elements to decrypt message" );
    }

    libBLS::TE te( requiredSigners, totalSigners );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
    for ( auto&& share : decrypts ) {
        decrypted.push_back( share );
    }

    auto res = te.CombineShares( cyphertext, decrypted );

    was_merged = true;

    return res;
}

std::vector< uint8_t > TEDecryptSet::mergeIntoAESKey() {
    libBLS::TE te( requiredSigners, totalSigners );

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
    for ( auto&& share : decrypts ) {
        decrypted.push_back( share );
    }

    auto res = te.CombineSharesIntoAESKey( decrypted );

    was_merged = true;

    return res;
}
