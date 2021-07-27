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

  @file BLSPublicKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSSigShare.h>
#include <bls/BLSSignature.h>
#include <bls/BLSutils.h>
#include <bls/bls.h>

BLSPublicKeyShare::BLSPublicKeyShare(
    const std::shared_ptr< std::vector< std::string > > pkey_str_vect, size_t _requiredSigners,
    size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    CHECK( pkey_str_vect );

    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    BLSutils::initBLS();

    publicKey = std::make_shared< libff::alt_bn128_G2 >();

    publicKey->X.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 0 ).c_str() );
    publicKey->X.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 1 ).c_str() );
    publicKey->Y.c0 = libff::alt_bn128_Fq( pkey_str_vect->at( 2 ).c_str() );
    publicKey->Y.c1 = libff::alt_bn128_Fq( pkey_str_vect->at( 3 ).c_str() );
    publicKey->Z.c0 = libff::alt_bn128_Fq::one();
    publicKey->Z.c1 = libff::alt_bn128_Fq::zero();

    if ( publicKey->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Zero BLS public Key share" );
    }

    if ( !( publicKey->is_well_formed() ) ) {
        throw signatures::Bls::IsNotWellFormed( "Corrupt BLS public key share" );
    }
}

BLSPublicKeyShare::BLSPublicKeyShare(
    const libff::alt_bn128_Fr& _skey, size_t _totalSigners, size_t _requiredSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    BLSutils::initBLS();
    if ( _skey.is_zero() ) {
        throw signatures::Bls::ZeroSecretKey( "Zero BLS Secret Key" );
    }
    publicKey = std::make_shared< libff::alt_bn128_G2 >( _skey * libff::alt_bn128_G2::one() );
}

std::shared_ptr< libff::alt_bn128_G2 > BLSPublicKeyShare::getPublicKey() const {
    CHECK( publicKey );
    return publicKey;
}

std::shared_ptr< std::vector< std::string > > BLSPublicKeyShare::toString() {
    std::vector< std::string > pkey_str_vect;

    publicKey->to_affine_coordinates();

    pkey_str_vect.push_back( BLSutils::ConvertToString( publicKey->X.c0 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( publicKey->X.c1 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( publicKey->Y.c0 ) );
    pkey_str_vect.push_back( BLSutils::ConvertToString( publicKey->Y.c1 ) );

    return std::make_shared< std::vector< std::string > >( pkey_str_vect );
}

bool BLSPublicKeyShare::VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    CHECK( hash_ptr );
    CHECK( sign_ptr );

    std::shared_ptr< signatures::Bls > obj;
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );

    if ( sign_ptr->getSigShare()->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Zero BLS Sig share" );
    }

    obj = std::make_shared< signatures::Bls >( signatures::Bls( _requiredSigners, _totalSigners ) );

    bool res = obj->Verification( hash_ptr, *( sign_ptr->getSigShare() ), *publicKey );
    return res;
}

bool BLSPublicKeyShare::VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
    std::shared_ptr< BLSSigShare > sign_ptr, size_t _requiredSigners, size_t _totalSigners ) {
    CHECK( sign_ptr )

    std::shared_ptr< signatures::Bls > obj;
    BLSSignature::checkSigners( _requiredSigners, _totalSigners );
    if ( !hash_ptr ) {
        throw signatures::Bls::IncorrectInput( "hash is null" );
    }
    if ( sign_ptr->getSigShare()->is_zero() ) {
        throw signatures::Bls::IsNotWellFormed( "Sig share is equal to zero" );
    }

    std::string hint = sign_ptr->getHint();

    std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > y_shift_x = BLSutils::ParseHint( hint );

    libff::alt_bn128_Fq x = BLSutils::HashToFq( hash_ptr );

    x = x + y_shift_x.second;

    libff::alt_bn128_Fq y_sqr = y_shift_x.first ^ 2;
    libff::alt_bn128_Fq x3B = x ^ 3;
    x3B = x3B + libff::alt_bn128_coeff_b;

    if ( y_sqr != x3B ) {
        return false;
    }

    libff::alt_bn128_G1 hash( x, y_shift_x.first, libff::alt_bn128_Fq::one() );

    return ( libff::alt_bn128_ate_reduced_pairing(
                 *sign_ptr->getSigShare(), libff::alt_bn128_G2::one() ) ==
             libff::alt_bn128_ate_reduced_pairing( hash, *publicKey ) );
}
