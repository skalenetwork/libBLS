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

  @file BLSPublicKey.cpp
  @author Sveta Rogova
  @date 2019
*/


#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <tools/utils.h>

namespace libBLS {

BLSPublicKey::BLSPublicKey( const std::shared_ptr< std::vector< std::string > > pkey_str_vect ) {
    CHECK( pkey_str_vect )

    // TODO get rid of unnecessary shared_ptr
    publicKey = std::make_shared< algebra::G2Point >(
        algebra::G2Point::fromString( *pkey_str_vect, Base::DEC ) );

    publicKey->validate();
}

BLSPublicKey::BLSPublicKey( const algebra::G2Point& pkey, size_t t, size_t n ) : t( t ), n( n ) {
    libBLS::ThresholdUtils::checkSigners( t, n );

    publicKey = std::make_shared< algebra::G2Point >( pkey );

    // TODO - maybe we should call isValid instead (?)
    if ( publicKey->isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS Public Key" );
    }
}

BLSPublicKey::BLSPublicKey( const algebra::FrScalar& skey, size_t t, size_t n ) : t( t ), n( n ) {
    libBLS::ThresholdUtils::checkSigners( t, n );

    publicKey = std::make_shared< algebra::G2Point >( skey * algebra::G2Point::generator() );
    if ( publicKey->isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
    }
}

// TODO - get rid of shared pointer no need here
bool BLSPublicKey::VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSignature > sign_ptr ) {
    if ( !hash_ptr ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "hash is null" );
    }

    if ( !sign_ptr || sign_ptr->getSig()->isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Sig share is equal to zero or corrupt" );
    }

    bool res = Bls::Verification( *hash_ptr, *( sign_ptr->getSig() ), *publicKey );
    return res;
}

bool BLSPublicKey::VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSignature > sign_ptr ) {
    if ( !hash_ptr ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "hash is null" );
    }
    if ( !sign_ptr || sign_ptr->getSig()->isIdentity() ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Sig share is equal to zero or corrupt" );
    }

    std::string hint = sign_ptr->getHint();

    std::pair< algebra::FqElement, algebra::FqElement > y_shift_x = algebra::parseHint( hint );

    algebra::FqElement x = algebra::hashToFq( *hash_ptr );
    x = x + y_shift_x.second;

    algebra::FqElement y_sqr = y_shift_x.first ^ 2;
    algebra::FqElement x3B = x ^ 3;
    x3B = x3B + algebra::AltBn128Contract::coeffB();

    if ( y_sqr != x3B )
        return false;

    algebra::G1Point hash( x.value, y_shift_x.first.value, algebra::FqElement::one().value );

    return ( algebra::pairing( *sign_ptr->getSig(), algebra::G2Point::generator() ) ==
             algebra::pairing( hash, *publicKey ) );
}

bool BLSPublicKey::AggregatedVerifySig(
    std::vector< std::shared_ptr< std::array< uint8_t, 32 > > >& hash_ptr_vec,
    std::vector< std::shared_ptr< BLSSignature > >& sign_ptr_vec ) {
    if ( hash_ptr_vec.size() != sign_ptr_vec.size() ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Number of signatures and hashes do not match" );
    }

    for ( auto& hash_ptr : hash_ptr_vec ) {
        if ( !hash_ptr ) {
            throw libBLS::ThresholdUtils::IncorrectInput( "hash is null" );
        }
    }

    std::vector< algebra::G1Point > libff_sig_vec;
    libff_sig_vec.reserve( sign_ptr_vec.size() );

    for ( auto& sign_ptr : sign_ptr_vec ) {
        if ( !sign_ptr || sign_ptr->getSig()->isIdentity() ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed(
                "Sig share is equal to zero or corrupt" );
        }

        libff_sig_vec.push_back( *( sign_ptr->getSig() ) );
    }

    bool res = libBLS::Bls::AggregatedVerification( hash_ptr_vec, libff_sig_vec, *publicKey );
    return res;
}

BLSPublicKey::BLSPublicKey(
    std::shared_ptr< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > > koefs_pkeys_map,
    size_t _requiredSigners, size_t _totalSigners )
    : t( _requiredSigners ), n( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !koefs_pkeys_map ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "map is null" );
    }

    std::vector< size_t > participatingNodes;
    std::vector< algebra::G1Point > shares;

    for ( auto&& item : *koefs_pkeys_map ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
    }

    std::vector< algebra::FrScalar > lagrangeCoeffs =
        algebra::lagrangeCoeffs( participatingNodes, _requiredSigners );

    algebra::G2Point key = algebra::G2Point::identity();
    size_t i = 0;
    for ( auto&& item : *koefs_pkeys_map ) {
        if ( i < _requiredSigners ) {
            key = key + lagrangeCoeffs.at( i ) * ( *item.second->getPublicKey() );
            i++;
        } else {
            break;
        }
    }

    publicKey = std::make_shared< algebra::G2Point >( key );
    if ( publicKey->isIdentity() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
    }
}

std::shared_ptr< std::vector< std::string > > BLSPublicKey::toString() {
    publicKey->toAffineCoordinates();
    return std::make_shared< std::vector< std::string > >(
        publicKey->toStringVector( algebra::Base::DEC ) );
}

std::shared_ptr< algebra::G2Point > BLSPublicKey::getPublicKey() const {
    return publicKey;
}

}  // namespace libBLS
