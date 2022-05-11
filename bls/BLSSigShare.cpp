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

  @file BLSSigShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSSigShare.h>
#include <bls/BLSSignature.h>
#include <tools/utils.h>

#include <stdlib.h>
#include <string>

std::shared_ptr< libff::alt_bn128_G1 > BLSSigShare::getSigShare() const {
    CHECK( sigShare );
    return sigShare;
}
size_t BLSSigShare::getSignerIndex() const {
    return signerIndex;
}

std::shared_ptr< std::string > BLSSigShare::toString() {
    sigShare->to_affine_coordinates();
    std::string ret = "";
    ret += libBLS::ThresholdUtils::fieldElementToString(sigShare->X) + ':' + libBLS::ThresholdUtils::fieldElementToString(sigShare->Y) + ':' + hint;
    
    return std::make_shared< std::string >( ret );
}

BLSSigShare::BLSSigShare( std::shared_ptr< std::string > _sigShare, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( requiredSigners, totalSigners );
    libBLS::ThresholdUtils::initCurve();
    if ( _signerIndex == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Zero signer index" );
    }

    if ( !_sigShare ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Null _sigShare" );
    }


    if ( _sigShare->size() < 10 ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed(
            "Signature too short:" + std::to_string( _sigShare->size() ) );
    }

    if ( _sigShare->size() > BLS_MAX_SIG_LEN ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed(
            "Signature too long:" + std::to_string( _sigShare->size() ) );
    }


    std::shared_ptr< std::vector< std::string > > result =
        libBLS::ThresholdUtils::SplitString( _sigShare, ":" );
    if ( result->size() != 4 )
        throw libBLS::ThresholdUtils::IncorrectInput( "Misformatted signature" );
    for ( auto&& str : *result ) {
        for ( char& c : str ) {
            if ( !( c >= '0' && c <= '9' ) ) {
                throw libBLS::ThresholdUtils::IncorrectInput(
                    "Misformatted char:" + std::to_string( ( int ) c ) + " in component " + str );
            }
        }
    }

    libff::alt_bn128_Fq X( result->at( 0 ).c_str() );
    libff::alt_bn128_Fq Y( result->at( 1 ).c_str() );

    sigShare = std::make_shared< libff::alt_bn128_G1 >( X, Y, libff::alt_bn128_Fq::one() );
    hint = result->at( 2 ) + ":" + result->at( 3 );

    if ( !sigShare->is_well_formed() )
        throw libBLS::ThresholdUtils::IsNotWellFormed( "signature is not from G1" );
}

BLSSigShare::BLSSigShare( const std::shared_ptr< libff::alt_bn128_G1 >& _sigShare,
    std::string& _hint, size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : sigShare( _sigShare ),
      hint( _hint ),
      signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::initCurve();
    libBLS::ThresholdUtils::checkSigners( requiredSigners, totalSigners );
    if ( !_sigShare ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Null _s" );
    }
    if ( _sigShare->is_zero() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero signature" );
    }
    if ( _signerIndex == 0 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Zero signer index" );
    }

    if ( _hint.length() == 0 || _hint.length() > 76 ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Wrong BLS hint" );
    }

    if ( !_sigShare->is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "signature is not from G1" );
    }
}

size_t BLSSigShare::getTotalSigners() const {
    return totalSigners;
}
size_t BLSSigShare::getRequiredSigners() const {
    return requiredSigners;
}

std::string BLSSigShare::getHint() const {
    return hint;
}
