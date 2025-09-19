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

  @file BLSSigShareSet.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <stdint.h>
#include <string>

#include "BLSSigShareSet.h"
#include <tools/utils.h>

namespace libBLS {

bool BLSSigShareSet::addSigShare( const BLSSigShare& _sigShare ) {
    _sigShare;

    if ( was_merged ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Invalid state:was already merged" );
    }

    if ( sigShares.count( _sigShare.getSignerIndex() ) > 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Already have this index:" + std::to_string( _sigShare.getSignerIndex() ) );
        return false;
    }
    
    sigShares.insert_or_assign(_sigShare.getSignerIndex(), _sigShare);

    return true;
}

size_t BLSSigShareSet::getTotalSigSharesCount() {
    return sigShares.size();
}
const BLSSigShare& BLSSigShareSet::getSigShareByIndex( size_t _index ) {
    if ( _index == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Index out of range:" + std::to_string( _index ) );
    }

    if ( sigShares.count( _index ) == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "No signature share found for index:" + std::to_string( _index ) );
    }

    return sigShares.at( _index );
}
BLSSigShareSet::BLSSigShareSet( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ), was_merged( false ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
}

bool BLSSigShareSet::isEnough() {
    return ( sigShares.size() >= requiredSigners );
}

BLSSignature BLSSigShareSet::merge() {
    if ( !isEnough() )
        throw libBLS::ThresholdUtils::IncorrectInput( "Not enough shares to create signature" );

    was_merged = true;
    libBLS::Bls obj = libBLS::Bls( requiredSigners, totalSigners );

    std::vector< size_t > participatingNodes;
    std::vector< algebra::G1Point > shares;

    for ( auto&& item : sigShares ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
        shares.push_back( item.second.getSigShare() );
    }

    std::vector< algebra::FrScalar > lagrangeCoeffs =
        algebra::lagrangeCoeffs( participatingNodes, requiredSigners );

    algebra::G1Point signature = obj.SignatureRecover( shares, lagrangeCoeffs );

    auto k = participatingNodes.at(0);
    const auto& s = sigShares.at(k);
    std::string hint = s.getHint();

    return BLSSignature( signature, hint, requiredSigners, totalSigners );
}

}  // namespace libBLS