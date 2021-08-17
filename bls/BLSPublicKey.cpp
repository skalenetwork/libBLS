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


BLSPublicKey::BLSPublicKey( const std::shared_ptr< std::vector< std::string > > pkey_str_vect,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::initCurve();

    CHECK( pkey_str_vect )

    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >();

    libffPublicKey->X.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 0 ).c_str() );
    libffPublicKey->X.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 1 ).c_str() );
    libffPublicKey->Y.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 2 ).c_str() );
    libffPublicKey->Y.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 3 ).c_str() );
    libffPublicKey->Z.c0 = libff::alt_bn128_Fq::one();
    libffPublicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if ( libffPublicKey->is_zero() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "Zero BLS public Key " );
    }

    if ( !( libffPublicKey->is_well_formed() ) ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "BLS public Key is corrupt" );
    }
}

BLSPublicKey::BLSPublicKey(
    const libff::alt_bn128_G2& pkey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::initCurve();

    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >( pkey );
    if ( libffPublicKey->is_zero() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "Zero BLS Public Key" );
    }
}

BLSPublicKey::BLSPublicKey(
    const libff::alt_bn128_Fr& skey, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    libffPublicKey = std::make_shared< libff::alt_bn128_G2 >( skey * libff::alt_bn128_G2::one() );
    if ( libffPublicKey->is_zero() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
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
    crypto::ThresholdUtils::initCurve();

    std::shared_ptr< crypto::Bls > obj;
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !hash_ptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "hash is null" );
    }

    if ( !sign_ptr || sign_ptr->getSig()->is_zero() ) {
        throw crypto::ThresholdUtils::IsNotWellFormed( "Sig share is equal to zero or corrupt" );
    }

    obj = std::make_shared< crypto::Bls >( crypto::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification( hash_ptr, *( sign_ptr->getSig() ), *libffPublicKey );
    return res;
}

bool BLSPublicKey::VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSignature > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    std::shared_ptr< crypto::Bls > obj;
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );
    if ( !hash_ptr ) {
        throw crypto::ThresholdUtils::IncorrectInput( "hash is null" );
    }
    if ( !sign_ptr || sign_ptr->getSig()->is_zero() ) {
        throw crypto::ThresholdUtils::IncorrectInput( "Sig share is equal to zero or corrupt" );
    }

    std::string hint = sign_ptr->getHint();

    std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > y_shift_x =
        crypto::ThresholdUtils::ParseHint( hint );

    libff::alt_bn128_Fq x = crypto::ThresholdUtils::HashToFq( hash_ptr );
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

bool BLSPublicKey::AggregatedVerifySig(
    std::vector< std::shared_ptr< std::array< uint8_t, 32 > > >& hash_ptr_vec,
    std::vector< std::shared_ptr< BLSSignature > >& sign_ptr_vec, size_t _requiredSigners,
    size_t _totalSigners ) {
    crypto::ThresholdUtils::initCurve();

    std::shared_ptr< crypto::Bls > obj;
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( hash_ptr_vec.size() != sign_ptr_vec.size() ) {
        throw crypto::ThresholdUtils::IncorrectInput(
            "Number of signatures and hashes do not match" );
    }

    for ( auto& hash_ptr : hash_ptr_vec ) {
        if ( !hash_ptr ) {
            throw crypto::ThresholdUtils::IncorrectInput( "hash is null" );
        }
    }

    std::vector< libff::alt_bn128_G1 > libff_sig_vec;
    libff_sig_vec.reserve( sign_ptr_vec.size() );

    for ( auto& sign_ptr : sign_ptr_vec ) {
        if ( !sign_ptr || sign_ptr->getSig()->is_zero() ) {
            throw crypto::ThresholdUtils::IsNotWellFormed(
                "Sig share is equal to zero or corrupt" );
        }

        libff_sig_vec.push_back( *( sign_ptr->getSig() ) );
    }

    obj = std::make_shared< crypto::Bls >( crypto::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->AggregatedVerification( hash_ptr_vec, libff_sig_vec, *libffPublicKey );
    return res;
}

BLSPublicKey::BLSPublicKey(
    std::shared_ptr< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > > koefs_pkeys_map,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::initCurve();

    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !koefs_pkeys_map ) {
        throw crypto::ThresholdUtils::IncorrectInput( "map is null" );
    }

    std::vector< size_t > participatingNodes;
    std::vector< libff::alt_bn128_G1 > shares;

    for ( auto&& item : *koefs_pkeys_map ) {
        participatingNodes.push_back( static_cast< uint64_t >( item.first ) );
    }

    std::vector< libff::alt_bn128_Fr > lagrangeCoeffs =
        crypto::ThresholdUtils::LagrangeCoeffs( participatingNodes, requiredSigners );

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
        throw crypto::ThresholdUtils::IsNotWellFormed( "Public Key is equal to zero or corrupt" );
    }
}

std::shared_ptr< std::vector< std::string > > BLSPublicKey::toString() {
    std::vector< std::string > pkey_str_vect;

    libffPublicKey->to_affine_coordinates();

    pkey_str_vect.push_back( crypto::ThresholdUtils::fieldElementToString( libffPublicKey->X.c0 ) );
    pkey_str_vect.push_back( crypto::ThresholdUtils::fieldElementToString( libffPublicKey->X.c1 ) );
    pkey_str_vect.push_back( crypto::ThresholdUtils::fieldElementToString( libffPublicKey->Y.c0 ) );
    pkey_str_vect.push_back( crypto::ThresholdUtils::fieldElementToString( libffPublicKey->Y.c1 ) );

    return std::make_shared< std::vector< std::string > >( pkey_str_vect );
}

std::shared_ptr< libff::alt_bn128_G2 > BLSPublicKey::getPublicKey() const {
    return libffPublicKey;
}
