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

  @file BLSSignature.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSSignature.h>
#include <tools/utils.h>

namespace libBLS {

std::shared_ptr< algebra::G1Point > BLSSignature::getSig() const {
    CHECK( sig );
    return sig;
}
BLSSignature::BLSSignature( const std::shared_ptr< algebra::G1Point > sig, std::string& _hint,
    size_t _requiredSigners, size_t _totalSigners )
    : sig( sig ),
      hint( _hint ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    CHECK( sig );

    if ( sig->isIdentity() ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Zero BLS signature" );
    }
    if ( _hint.length() == 0 || _hint.length() > 2 * BLS_MAX_COMPONENT_LEN ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Wrong BLS hint" );
    }
}

BLSSignature::BLSSignature(
    std::shared_ptr< std::string > _sig, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    CHECK( _sig );

    libBLS::ThresholdUtils::checkSigners( requiredSigners, totalSigners );

    if ( _sig->size() < 10 ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed(
            "Signature too short:" + std::to_string( _sig->size() ) );
    }

    if ( _sig->size() > BLS_MAX_SIG_LEN ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed(
            "Signature too long:" + std::to_string( _sig->size() ) );
    }

    std::shared_ptr< std::vector< std::string > > result =
        libBLS::ThresholdUtils::SplitString( _sig, ":" );

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

    sig = std::make_shared< algebra::G1Point >(
        algebra::FqElement::fromString( result->at( 0 ), Base::DEC ),
        algebra::FqElement::fromString( result->at( 1 ), Base::DEC ) );
    hint = result->at( 2 ) + ":" + result->at( 3 );

    if ( !( sig->isWellFormed() ) ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "signature is not from G1" );
    }
}

std::shared_ptr< std::string > BLSSignature::toString() {
    sig->toAffineCoordinates();
    std::string ret = "";
    ret += sig->getX().toString( Base::DEC ) + ':' + sig->getY().toString( Base::DEC ) + ':' + hint;

    return std::make_shared< std::string >( ret );
}

std::string BLSSignature::getHint() const {
    return hint;
}

size_t BLSSignature::getTotalSigners() const {
    return totalSigners;
}
size_t BLSSignature::getRequiredSigners() const {
    return requiredSigners;
}

}  // namespace libBLS
