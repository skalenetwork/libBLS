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

BLSPublicKey::BLSPublicKey( const std::vector< std::string >& pkey_str_vect ) {
    // TODO get rid of unnecessary shared_ptr
    publicKey = algebra::G2Point::fromString( pkey_str_vect, Base::DEC );
    publicKey.validate();
}

BLSPublicKey::BLSPublicKey( const algebra::G2Point& pkey, size_t t, size_t n ) : t( t ), n( n ) {
    // TODO - should this be commented?
    // libBLS::ThresholdUtils::checkSigners( t, n );

    publicKey = pkey;

    if ( !publicKey.isValid() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Zero BLS Public Key" );
    }
}

BLSPublicKey::BLSPublicKey( const algebra::FrScalar& skey, size_t t, size_t n ) : t( t ), n( n ) {
    // TODO
    // libBLS::ThresholdUtils::checkSigners( t, n );

    publicKey = skey * algebra::G2Point::generator();
    if ( !publicKey.isValid() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Public Key is not valid" );
    }
}

bool BLSPublicKey::VerifySig( const std::array< uint8_t, 32 >& hash, const BLSSignature& sign ) {
    if ( !sign.getSig().isValid() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Sig share is not valid" );
    }

    bool res = Bls::Verify( hash, sign.getSig(), publicKey );
    return res;
}

bool BLSPublicKey::VerifySigWithHelper(
    const std::array< uint8_t, 32 >& hash, const BLSSignature& sign ) {
    if ( !sign.getSig().isValid() ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Sig share is not valid" );
    }

    std::string hint = sign.getHint();

    std::pair< algebra::FqElement, algebra::FqElement > y_shift_x = algebra::parseHint( hint );

    algebra::FqElement x = algebra::hashToFq( hash );
    x = x + y_shift_x.second;

    algebra::FqElement y_sqr = y_shift_x.first ^ 2;
    algebra::FqElement x3B = x ^ 3;
    x3B = x3B + algebra::AltBn128Contract::coeffB();

    if ( y_sqr != x3B )
        return false;

    algebra::G1Point hashG1( x, y_shift_x.first, algebra::FqElement::one() );

    return algebra::verifyPairingEq(
        sign.getSig(), algebra::G2Point::generator(), hashG1, publicKey );
}

bool BLSPublicKey::AggregatedVerifySig( std::vector< std::array< uint8_t, 32 > >& hash_ptr_vec,
    std::vector< BLSSignature >& sign_ptr_vec ) {
    if ( hash_ptr_vec.size() != sign_ptr_vec.size() ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "Number of signatures and hashes do not match" );
    }

    std::vector< algebra::G1Point > libff_sig_vec;
    libff_sig_vec.reserve( sign_ptr_vec.size() );

    for ( auto& sign_ptr : sign_ptr_vec ) {
        if ( !sign_ptr.getSig().isValid() ) {
            throw libBLS::ThresholdUtils::IsNotWellFormed( "Sig share is not valid" );
        }

        libff_sig_vec.push_back( sign_ptr.getSig() );
    }

    bool res = libBLS::Bls::AggregateVerify( hash_ptr_vec, libff_sig_vec, publicKey );
    return res;
}

BLSPublicKey::BLSPublicKey( const std::map< size_t, BLSPublicKeyShare >& koefs_pkeys_map,
    size_t _requiredSigners, size_t _totalSigners )
    : t( _requiredSigners ), n( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );


    std::vector< size_t > participatingNodes;
    std::vector< algebra::G1Point > shares;

    for ( auto&& item : koefs_pkeys_map ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
    }

    std::vector< algebra::FrScalar > lagrangeCoeffs =
        algebra::lagrangeCoeffs( participatingNodes, _requiredSigners );

    algebra::G2Point key = algebra::G2Point::identity();
    size_t i = 0;
    for ( auto&& item : koefs_pkeys_map ) {
        if ( i < _requiredSigners ) {
            key = key + lagrangeCoeffs.at( i ) * item.second.getPublicKey();
            i++;
        } else {
            break;
        }
    }

    publicKey = key;
    if ( !publicKey.isValid() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Public Key is not valid" );
    }
}

std::vector< std::string > BLSPublicKey::toString() {
    return publicKey.toStringVector( algebra::Base::DEC );
}

const algebra::G2Point& BLSPublicKey::getPublicKey() const {
    return publicKey;
}

}  // namespace libBLS
