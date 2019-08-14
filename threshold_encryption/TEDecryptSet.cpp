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
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#include "TEDecryptSet.h"
#include <utility>
#include "pbc/pbc.h"


TEDecryptSet::TEDecryptSet(size_t _requiredSigners, size_t _totalSigners) : requiredSigners(_requiredSigners),
                                                                            totalSigners(_totalSigners) {

    TEDataSingleton::checkSigners(_requiredSigners, _totalSigners);
}

void TEDecryptSet::addDecrypt (size_t _signerIndex, std::shared_ptr<encryption::element_wrapper>& _el ) {

    if ( decrypts.count( _signerIndex ) > 0 ) {
        throw std::runtime_error(
                "Already have this index:" + std::to_string(  _signerIndex ) ) ;
    }

    if ( !_el ) {
        throw std::runtime_error( "Null _element" );
    }

    decrypts[_signerIndex] = _el;
}

std::string TEDecryptSet::merge(const encryption::Ciphertext& cyphertext){

    if ( element_is0( const_cast<element_t&>(std::get<0>(cyphertext).el_) )  ||  element_is0( const_cast<element_t&>(std::get<2>(cyphertext).el_))  )
        throw std::runtime_error("zero element in cyphertext");

    if (decrypts.size() < requiredSigners)
        throw std::runtime_error("Not enough elements to decrypt message");

    encryption::TE te (requiredSigners, totalSigners);
    std::vector<std::pair<encryption::element_wrapper, size_t>> decrypted;
    for (auto&& item: decrypts){
        std::pair<encryption::element_wrapper, size_t> encr = std::make_pair(*item.second, item.first);
        decrypted.push_back(encr);
    }

    return  te.CombineShares(cyphertext, decrypted);
}
