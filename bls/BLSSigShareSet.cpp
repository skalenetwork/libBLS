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

  @file BLSSigShareSet.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <stdint.h>
#include <string>

#include <bls/BLSSigShare.h>
#include <bls/BLSSigShareSet.h>
#include <bls/BLSSignature.h>
#include <bls/BLSutils.h>


bool BLSSigShareSet::addSigShare( std::shared_ptr< BLSSigShare > _sigShare ) {
    CHECK( _sigShare );

    if ( was_merged ) {
        throw signatures::Bls::IncorrectInput( "Invalid state:was already merged" );
    }


    if ( sigShares.count( _sigShare->getSignerIndex() ) > 0 ) {
        throw signatures::Bls::IncorrectInput(
            "Already have this index:" + std::to_string( _sigShare->getSignerIndex() ) );
        return false;
    }
    sigShares[_sigShare->getSignerIndex()] = _sigShare;

    return true;
}

size_t BLSSigShareSet::getTotalSigSharesCount() {
    return sigShares.size();
}
std::shared_ptr< BLSSigShare > BLSSigShareSet::getSigShareByIndex( size_t _index ) {
    if ( _index == 0 ) {
        throw signatures::Bls::IncorrectInput( "Index out of range:" + std::to_string( _index ) );
    }


    if ( sigShares.count( _index ) == 0 ) {
        return nullptr;
    }

    return sigShares.at( _index );
}
BLSSigShareSet::BLSSigShareSet( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ), was_merged( false ) {
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    BLSutils::initBLS();
}

bool BLSSigShareSet::isEnough() {
    return ( sigShares.size() >= requiredSigners );
}


std::shared_ptr< BLSSignature > BLSSigShareSet::merge() {
    if ( !isEnough() )
        throw signatures::Bls::IncorrectInput( "Not enough shares to create signature" );

    was_merged = true;
    signatures::Bls obj = signatures::Bls( requiredSigners, totalSigners );

    std::vector< size_t > participatingNodes;
    std::vector< libff::alt_bn128_G1 > shares;

    for ( auto&& item : sigShares ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
        shares.push_back( *item.second->getSigShare() );
    }

    std::vector< libff::alt_bn128_Fr > lagrangeCoeffs = obj.LagrangeCoeffs( participatingNodes );

    libff::alt_bn128_G1 signature = obj.SignatureRecover( shares, lagrangeCoeffs );

    auto sigPtr = std::make_shared< libff::alt_bn128_G1 >( signature );

    std::string hint = sigShares[participatingNodes.at( 0 )]->getHint();

    return std::make_shared< BLSSignature >( sigPtr, hint, requiredSigners, totalSigners );
}
