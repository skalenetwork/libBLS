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
#include <threshold_encryption/utils.h>
#include <utility>

#include "../tools/utils.h"


TEDecryptSet::TEDecryptSet( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ), was_merged( false ) {
    checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();
}

void TEDecryptSet::addDecrypt( size_t _signerIndex, std::shared_ptr< libff::alt_bn128_G2 > _el ) {
    if ( decrypts.count( _signerIndex ) > 0 ) {
        throw std::runtime_error( "Already have this index:" + std::to_string( _signerIndex ) );
    }

    if ( was_merged ) {
        throw std::runtime_error( "Invalid state" );
    }

    if ( !_el ) {
        throw std::runtime_error( "try to add Null _element to decrypt set" );
    }

    if ( _el->is_zero() ) {
        throw std::runtime_error( "try to add zero _element to decrypt set" );
    }

    decrypts[_signerIndex] = _el;
}

std::string TEDecryptSet::merge( const encryption::Ciphertext& cyphertext ) {
    checkCypher( cyphertext );

    was_merged = true;

    if ( decrypts.size() < requiredSigners ) {
        throw std::runtime_error( "Not enough elements to decrypt message" );
    }

    encryption::TE te( requiredSigners, totalSigners );
    std::vector< std::pair< libff::alt_bn128_G2, size_t > > decrypted;
    for ( auto&& item : decrypts ) {
        std::pair< libff::alt_bn128_G2, size_t > encr = std::make_pair( *item.second, item.first );
        decrypted.push_back( encr );
    }

    return te.CombineShares( cyphertext, decrypted );
}
