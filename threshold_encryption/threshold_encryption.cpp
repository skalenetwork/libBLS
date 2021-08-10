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

  @file threshold_encryption.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <string.h>
#include <iostream>
#include <valarray>

#include <threshold_encryption.h>
#include <tools/utils.h>

#include <libff/common/profiling.hpp>

namespace crypto {

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    libff::init_alt_bn128_params();
    libff::inhibit_profiling_info = true;
}

TE::~TE() {}

std::string TE::Hash(
    const libff::alt_bn128_G2& Y, std::string ( *hash_func )( const std::string& str ) ) {
    auto vectorCoordinates = ThresholdUtils::G2ToString( Y );

    std::string tmp = "";
    for ( const auto& coord : vectorCoordinates ) {
        tmp += coord;
    }

    const std::string sha256hex = hash_func( tmp );

    return sha256hex;
}

libff::alt_bn128_G1 TE::HashToGroup( const libff::alt_bn128_G2& U, const std::string& V,
    std::string ( *hash_func )( const std::string& str ) ) {
    // assumed that U lies in G2

    auto U_str = ThresholdUtils::G2ToString( U );

    const std::string sha256hex = hash_func( U_str[0] + U_str[1] + U_str[2] + U_str[3] + V );

    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();
    std::string hash_str = cryptlite::sha256::hash_hex( sha256hex );
    for ( size_t i = 0; i < 32; ++i ) {
        hash_bytes_arr->at( i ) = static_cast< uint8_t >( hash_str[i] );
    }

    return ThresholdUtils::HashtoG1( hash_bytes_arr );
}

Ciphertext TE::Encrypt( const std::string& message, libff::alt_bn128_G2 common_public ) {
    if ( !ThresholdUtils::checkHex(message) ) {
        throw ThresholdUtils::IncorrectInput("Input message is not hex");
    }

    if ( !ThresholdUtils::isG2( common_public ) ) {
        throw ThresholdUtils::IncorrectInput("Input common public key is corrupted");
    }

    libff::alt_bn128_Fr r = libff::alt_bn128_Fr::random_element();

    while ( r.is_zero() ) {
        r = libff::alt_bn128_Fr::random_element();
    }

    libff::alt_bn128_G2 U, Y;
    U = r * libff::alt_bn128_G2::one();
    Y = r * common_public;

    std::string hash = this->Hash( Y );

    // assuming aes_message and hash are the same size strings
    // the behaviour is undefined when the two arguments are valarrays with different sizes
    Y.to_affine_coordinates();
    std::string aes_message =
        ThresholdUtils::aesEncrypt( message, ThresholdUtils::fieldElementToString( Y.X.c0 ) );

    size_t size = std::max( aes_message.size(), hash.size() );

    std::valarray< uint8_t > lhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        lhs_to_hash[i] = i < hash.size() ? static_cast< uint8_t >( hash[i] ) : 0;
    }

    std::valarray< uint8_t > rhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        rhs_to_hash[i] = i < aes_message.size() ? static_cast< uint8_t >( aes_message[i] ) : 0;
    }

    std::valarray< uint8_t > res = lhs_to_hash ^ rhs_to_hash;

    std::string V;
    V.resize( size );
    for ( size_t i = 0; i < size; ++i ) {
        V[i] = static_cast< char >( res[i] );
    }

    libff::alt_bn128_G1 W, H;

    H = this->HashToGroup( U, V );
    W = r * H;

    return {U, V, W};
}

libff::alt_bn128_G2 TE::getDecryptionShare(
    const Ciphertext& ciphertext, const libff::alt_bn128_Fr& secret_key ) {
    ThresholdUtils::checkCypher( ciphertext );
    if ( secret_key.is_zero() )
        throw ThresholdUtils::ZeroSecretKey( "zero secret key" );

    libff::alt_bn128_G2 U = std::get< 0 >( ciphertext );

    std::string V = std::get< 1 >( ciphertext );

    libff::alt_bn128_G1 W = std::get< 2 >( ciphertext );

    libff::alt_bn128_G1 H = this->HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    if ( !res ) {
        throw ThresholdUtils::IncorrectInput( "cannot decrypt data" );
    }

    libff::alt_bn128_G2 ret_val = secret_key * U;

    return ret_val;
}

bool TE::Verify( const Ciphertext& ciphertext, const libff::alt_bn128_G2& decryptionShare,
    const libff::alt_bn128_G2& public_key ) {
    libff::alt_bn128_G2 U = std::get< 0 >( ciphertext );

    std::string V = std::get< 1 >( ciphertext );

    libff::alt_bn128_G1 W = std::get< 2 >( ciphertext );

    libff::alt_bn128_G1 H = this->HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    bool ret_val = true;

    if ( res ) {
        if ( decryptionShare.is_zero() ) {
            ret_val = false;
        } else {
            libff::alt_bn128_GT pp1, pp2;
            pp1 = libff::alt_bn128_ate_reduced_pairing( W, public_key );
            pp2 = libff::alt_bn128_ate_reduced_pairing( H, decryptionShare );

            bool check = pp1 == pp2;
            if ( !check ) {
                ret_val = false;
            }
        }
    } else {
        ret_val = false;
    }

    return ret_val;
}

std::string TE::CombineShares( const Ciphertext& ciphertext,
    const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShares ) {
    libff::alt_bn128_G2 U = std::get< 0 >( ciphertext );

    std::string V = std::get< 1 >( ciphertext );

    libff::alt_bn128_G1 W = std::get< 2 >( ciphertext );

    libff::alt_bn128_G1 H = this->HashToGroup( U, V );

    libff::alt_bn128_GT fst, snd;
    fst = libff::alt_bn128_ate_reduced_pairing( W, libff::alt_bn128_G2::one() );
    snd = libff::alt_bn128_ate_reduced_pairing( H, U );

    bool res = fst == snd;

    if ( !res ) {
        throw ThresholdUtils::IncorrectInput( "error during share combining" );
    }

    std::vector< size_t > idx( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        idx[i] = decryptionShares[i].second;
    }

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
        ThresholdUtils::LagrangeCoeffs( idx, this->t_ );

    libff::alt_bn128_G2 sum = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < this->t_; ++i ) {
        libff::alt_bn128_G2 temp = lagrange_coeffs[i] * decryptionShares[i].first;

        sum = sum + temp;
    }

    std::string hash = this->Hash( sum );
    size_t size = std::max( hash.size(), V.size() );

    std::valarray< uint8_t > lhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        lhs_to_hash[i] = i < hash.size() ? static_cast< uint8_t >( hash[i] ) : 0;
    }

    std::valarray< uint8_t > rhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        rhs_to_hash[i] = i < V.size() ? static_cast< uint8_t >( V[i] ) : 0;
    }

    std::valarray< uint8_t > xor_res = lhs_to_hash ^ rhs_to_hash;

    std::string message = "";
    for ( size_t i = 0; i < xor_res.size(); ++i ) {
        message += static_cast< char >( xor_res[i] );
    }

    sum.to_affine_coordinates();
    std::string ret =
        ThresholdUtils::aesDecrypt( message, ThresholdUtils::fieldElementToString( sum.X.c0 ) );

    return ret;
}

}  // namespace crypto
