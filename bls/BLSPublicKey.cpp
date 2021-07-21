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

  @file BLSPublicKey.cpp
  @author Sveta Rogova
  @date 2019
*/


#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSutils.h>


BLSPublicKey::BLSPublicKey( const std::shared_ptr< std::vector< std::string > > pkey_str_vect,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSutils::initBLS();

    CHECK( pkey_str_vect )

    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >();

    libffPublicKey->X.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 0 ).c_str() );
    libffPublicKey->X.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 1 ).c_str() );
    libffPublicKey->Y.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 2 ).c_str() );
    libffPublicKey->Y.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 3 ).c_str() );
    libffPublicKey->Z.c0 = libff::alt_bn128_Fq::one();
    libffPublicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if ( libffPublicKey->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Zero BLS public Key " );
    }

    if ( !( libffPublicKey->is_well_formed() ) ) {
        throw signatures::Bls::IsNotWellFormed( "BLS public Key is corrupt" );
    }
}

BLSPublicKey::BLSPublicKey(
    const libff::alt_bn128_G2& pkey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSutils::initBLS();

    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >( pkey );
    if ( libffPublicKey->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Zero BLS Public Key" );
    }
}

BLSPublicKey::BLSPublicKey(
    const libff::alt_bn128_Fr& skey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );
    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >( skey * libff::alt_bn128_G2::one() );
    if ( libffPublicKey->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
    }
}

size_t BLSPublicKey::getTotalSigners() const {
    return totalSigners;
}

size_t BLSPublicKey::getRequiredSigners() const {
    return requiredSigners;
}

bool BLSPublicKey::VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSignature > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    BLSutils::initBLS();

    std::shared_ptr< signatures::Bls > obj;
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    if ( !hash_ptr ) {
        throw signatures::Bls::IncorrectInput( "hash is null" );
    }

    if ( !sign_ptr || sign_ptr->getSig()->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Sig share is equal to zero or corrupt" );
    }

    obj = std::make_shared< signatures::Bls >( signatures::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification( hash_ptr, *( sign_ptr->getSig() ), *libffPublicKey );
    return res;
}

bool BLSPublicKey::VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSignature > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    std::shared_ptr< signatures::Bls > obj;
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );
    if ( !hash_ptr ) {
        throw signatures::Bls::IncorrectInput( "hash is null" );
    }
    if ( !sign_ptr || sign_ptr->getSig()->is_zero() ) {
        throw signatures::Bls::IncorrectInput( "Sig share is equal to zero or corrupt" );
    }

    std::string hint = sign_ptr->getHint();

    std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > y_shift_x = BLSutils::ParseHint( hint );

    libff::alt_bn128_Fq x = BLSutils::HashToFq( hash_ptr );
    x = x + y_shift_x.second;

    libff::alt_bn128_Fq y_sqr = y_shift_x.first ^ 2;
    libff::alt_bn128_Fq x3B = x ^ 3;
    x3B = x3B + libff::alt_bn128_coeff_b;

    if ( y_sqr != x3B )
        return false;

    libff::alt_bn128_G1 hash( x, y_shift_x.first, libff::alt_bn128_Fq::one() );

    return (
        libff::alt_bn128_ate_reduced_pairing( *sign_ptr->getSig(), libff::alt_bn128_G2::one() ) ==
        libff::alt_bn128_ate_reduced_pairing( hash, *libffPublicKey ) );
}

BLSPublicKey::BLSPublicKey(
    std::shared_ptr< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > > koefs_pkeys_map,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSutils::initBLS();

    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    signatures::Bls obj = signatures::Bls( requiredSigners, totalSigners );
    if ( !koefs_pkeys_map ) {
        throw signatures::Bls::IncorrectInput( "map is null" );
    }

    std::vector< size_t > participatingNodes;
    std::vector< libff::alt_bn128_G1 > shares;

    for ( auto&& item : *koefs_pkeys_map ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
    }

    std::vector< libff::alt_bn128_Fr > lagrangeCoeffs = obj.LagrangeCoeffs( participatingNodes );

    libff::alt_bn128_G2 key = libff::alt_bn128_G2::zero();
    size_t i = 0;
    for ( auto&& item : *koefs_pkeys_map ) {
        if ( i < _requiredSigners ) {
            key = key + lagrangeCoeffs.at( i ) * ( *item.second->getPublicKey() );
            i++;
        } else {
            break;
        }
    }

    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >( key );
    if ( libffPublicKey->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
    }
}

std::shared_ptr< std::vector< std::string > > BLSPublicKey::toString() {
    std::vector< std::string > pkey_str_vect;

    libffPublicKey->to_affine_coordinates();

    pkey_str_vect.push_back( BLSutils::ConvertToString( libffPublicKey->X.c0 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( libffPublicKey->X.c1 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( libffPublicKey->Y.c0 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( libffPublicKey->Y.c1 ) );

    return std::make_shared< std::vector< std::string > >( pkey_str_vect );
}

std::shared_ptr< libff::alt_bn128_G2 > BLSPublicKey::getPublicKey() const {
    return libffPublicKey;
}
