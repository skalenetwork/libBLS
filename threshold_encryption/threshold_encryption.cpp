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

  @file threshold_encryption.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <string.h>
#include <iostream>
#include <valarray>

#include <threshold_encryption.h>
#include <threshold_encryption/utils.h>

namespace encryption {

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {}

TE::~TE() {}

std::string TE::Hash( const element_t& Y, std::string ( *hash_func )( const std::string& str ) ) {
    // assumed that Y lies in from G1

    mpz_t z;
    mpz_init( z );
    element_to_mpz( z, element_item( const_cast< element_t& >( Y ), 0 ) );

    char arr[mpz_sizeinbase( z, 10 ) + 2];
    char* tmp_c = mpz_get_str( arr, 10, z );
    std::string tmp1 = tmp_c;
    mpz_clear( z );

    mpz_init( z );
    element_to_mpz( z, element_item( const_cast< element_t& >( Y ), 1 ) );

    char arr1[mpz_sizeinbase( z, 10 ) + 2];
    char* other_tmp = mpz_get_str( arr1, 10, z );
    std::string tmp2 = other_tmp;
    mpz_clear( z );

    std::string tmp = tmp1 + tmp2;

    const std::string sha256hex = hash_func( tmp );

    return sha256hex;
}

void TE::HashToGroup( element_t ret_val, const element_t& U, const std::string& V,
    std::string ( *hash_func )( const std::string& str ) ) {
    // assumed that U lies in G1

    std::shared_ptr< std::vector< std::string > > U_str_ptr =
        ElementG1ToString( const_cast< element_t& >( U ) );

    const std::string sha256hex = hash_func( U_str_ptr->at( 0 ) + U_str_ptr->at( 1 ) + V );

    mpz_t hex;
    mpz_init( hex );
    mpz_set_str( hex, sha256hex.c_str(), 16 );

    mpz_t modulus_q;
    mpz_init( modulus_q );
    mpz_set_str( modulus_q,
        "878071079966331252243778198475404981580688319941420821102865339926647563088022295707862517"
        "9422662221423155858769582317459277713367317481324925129998224791",
        10 );

    mpz_t x_coord;
    mpz_init( x_coord );
    mpz_mod( x_coord, hex, modulus_q );

    mpz_clear( hex );

    mpz_t y_coord;
    mpz_init( y_coord );

    mpz_t one;
    mpz_init( one );
    mpz_set_ui( one, 1 );

    while ( true ) {
        mpz_t x_cubed;
        mpz_init( x_cubed );

        mpz_powm_ui( x_cubed, x_coord, 3, modulus_q );

        mpz_t sum;
        mpz_init( sum );
        mpz_add( sum, x_cubed, x_coord );
        mpz_clear( x_cubed );

        mpz_t y_squared;
        mpz_init( y_squared );
        mpz_mod( y_squared, sum, modulus_q );
        mpz_clear( sum );

        int is_square = mpz_legendre( y_squared, modulus_q );

        if ( is_square == -1 || is_square == 0 ) {
            mpz_addmul_ui( x_coord, one, 1 );
            mpz_clear( y_squared );

        } else {
            MpzSquareRoot( y_coord, y_squared );

            mpz_clear( y_squared );
            mpz_clear( one );

            break;
        }
    }

    char arr1[mpz_sizeinbase( x_coord, 10 ) + 2];
    char* coord_x = mpz_get_str( arr1, 10, x_coord );

    char arr2[mpz_sizeinbase( y_coord, 10 ) + 2];
    char* coord_y = mpz_get_str( arr2, 10, y_coord );

    std::string coords_str = "[" + std::string( coord_x ) + "," + std::string( coord_y ) + "]";


    int num = element_set_str( ret_val, coords_str.c_str(), 10 );
    if ( num == 0 ) {
        std::runtime_error( "Incorrectly formed string for G1 point" );
    }

    mpz_clear( modulus_q );
    mpz_clear( y_coord );
    mpz_clear( x_coord );
}

Ciphertext TE::Encrypt( const std::string& message, const element_t& common_public ) {
    element_t r;
    element_init_Zr( r, TEDataSingleton::getData().pairing_ );
    element_random( r );

    while ( element_is0( r ) ) {
        element_random( r );
    }

    element_t g;
    element_init_G1( g, TEDataSingleton::getData().pairing_ );
    element_set( g, TEDataSingleton::getData().generator_ );

    element_t U, Y;
    element_init_G1( U, TEDataSingleton::getData().pairing_ );
    element_init_G1( Y, TEDataSingleton::getData().pairing_ );
    element_mul_zn( U, g, r );
    element_mul_zn( Y, const_cast< element_t& >( common_public ), r );

    element_clear( g );

    std::string hash = this->Hash( Y );

    element_clear( Y );

    // assuming message and hash are the same size strings
    // the behaviour is undefined when the two arguments are valarrays with different sizes

    std::valarray< uint8_t > lhs_to_hash( hash.size() );
    for ( size_t i = 0; i < hash.size(); ++i ) {
        lhs_to_hash[i] = static_cast< uint8_t >( hash[i] );
    }

    std::valarray< uint8_t > rhs_to_hash( message.size() );
    for ( size_t i = 0; i < message.size(); ++i ) {
        rhs_to_hash[i] = static_cast< uint8_t >( message[i] );
    }


    std::valarray< uint8_t > res = lhs_to_hash ^ rhs_to_hash;

    std::string V = "";
    for ( size_t i = 0; i < res.size(); ++i ) {
        V += static_cast< char >( res[i] );
    }

    element_t W, H;
    element_init_G1( W, TEDataSingleton::getData().pairing_ );
    element_init_G1( H, TEDataSingleton::getData().pairing_ );

    this->HashToGroup( H, U, V );
    element_mul_zn( W, H, r );

    element_clear( H );
    element_clear( r );

    Ciphertext result;
    std::get< 0 >( result ) = element_wrapper( U );
    std::get< 1 >( result ) = V;
    std::get< 2 >( result ) = element_wrapper( W );

    element_clear( U );
    element_clear( W );

    return result;
}

void TE::Decrypt( element_t ret_val, const Ciphertext& ciphertext, const element_t& secret_key ) {
    checkCypher( ciphertext );
    if ( element_is0( const_cast< element_t& >( secret_key ) ) )
        throw std::runtime_error( "zero secret key" );

    element_t U;
    element_init_G1( U, TEDataSingleton::getData().pairing_ );
    element_set( U, const_cast< element_t& >( std::get< 0 >( ciphertext ).el_ ) );

    std::string V = std::get< 1 >( ciphertext );

    element_t W;
    element_init_G1( W, TEDataSingleton::getData().pairing_ );
    element_set( W, const_cast< element_t& >( std::get< 2 >( ciphertext ).el_ ) );

    element_t H;
    element_init_G1( H, TEDataSingleton::getData().pairing_ );
    this->HashToGroup( H, U, V );

    element_t fst, snd;
    element_init_GT( fst, TEDataSingleton::getData().pairing_ );
    element_init_GT( snd, TEDataSingleton::getData().pairing_ );

    pairing_apply(
        fst, TEDataSingleton::getData().generator_, W, TEDataSingleton::getData().pairing_ );
    pairing_apply( snd, U, H, TEDataSingleton::getData().pairing_ );

    bool res = element_cmp( fst, snd );

    element_clear( fst );
    element_clear( snd );

    if ( res ) {
        element_clear( U );
        element_clear( W );
        element_clear( H );
        throw std::runtime_error( "cannot decrypt data" );
    }

    element_mul_zn( ret_val, U, const_cast< element_t& >( secret_key ) );

    element_clear( U );
    element_clear( W );
    element_clear( H );
}

bool TE::Verify(
    const Ciphertext& ciphertext, const element_t& decrypted, const element_t& public_key ) {
    element_t U;
    element_init_G1( U, TEDataSingleton::getData().pairing_ );
    element_set( U, const_cast< element_t& >( std::get< 0 >( ciphertext ).el_ ) );

    std::string V = std::get< 1 >( ciphertext );

    element_t W;
    element_init_G1( W, TEDataSingleton::getData().pairing_ );
    element_set( W, const_cast< element_t& >( std::get< 2 >( ciphertext ).el_ ) );

    element_t H;
    element_init_G1( H, TEDataSingleton::getData().pairing_ );
    this->HashToGroup( H, U, V );

    element_t fst, snd;
    element_init_GT( fst, TEDataSingleton::getData().pairing_ );
    element_init_GT( snd, TEDataSingleton::getData().pairing_ );

    pairing_apply(
        fst, TEDataSingleton::getData().generator_, W, TEDataSingleton::getData().pairing_ );
    pairing_apply( snd, U, H, TEDataSingleton::getData().pairing_ );

    bool res = !element_cmp( fst, snd );

    bool ret_val = true;

    if ( res ) {
        if ( isG1Element0( const_cast< element_t& >( decrypted ) ) ) {
            ret_val = false;
        } else {
            element_t pp1, pp2;
            element_init_GT( pp1, TEDataSingleton::getData().pairing_ );
            element_init_GT( pp2, TEDataSingleton::getData().pairing_ );

            pairing_apply( pp1, TEDataSingleton::getData().generator_,
                const_cast< element_t& >( decrypted ), TEDataSingleton::getData().pairing_ );
            pairing_apply( pp2, U, const_cast< element_t& >( public_key ),
                TEDataSingleton::getData().pairing_ );

            bool check = element_cmp( pp1, pp2 );
            if ( check ) {
                ret_val = false;
            }

            element_clear( pp1 );
            element_clear( pp2 );
        }
    } else {
        ret_val = false;
    }

    element_clear( fst );
    element_clear( snd );

    element_clear( U );
    element_clear( W );
    element_clear( H );

    return ret_val;
}

std::string TE::CombineShares( const Ciphertext& ciphertext,
    const std::vector< std::pair< element_wrapper, size_t > >& decrypted ) {
    element_t U;
    element_init_G1( U, TEDataSingleton::getData().pairing_ );
    element_set( U, const_cast< element_t& >( std::get< 0 >( ciphertext ).el_ ) );

    std::string V = std::get< 1 >( ciphertext );

    element_t W;
    element_init_G1( W, TEDataSingleton::getData().pairing_ );
    element_set( W, const_cast< element_t& >( std::get< 2 >( ciphertext ).el_ ) );

    element_t H;
    element_init_G1( H, TEDataSingleton::getData().pairing_ );
    this->HashToGroup( H, U, V );

    element_t fst, snd;
    element_init_GT( fst, TEDataSingleton::getData().pairing_ );
    element_init_GT( snd, TEDataSingleton::getData().pairing_ );

    pairing_apply(
        fst, TEDataSingleton::getData().generator_, W, TEDataSingleton::getData().pairing_ );
    pairing_apply( snd, U, H, TEDataSingleton::getData().pairing_ );

    element_clear( U );
    element_clear( W );
    element_clear( H );

    bool res = element_cmp( fst, snd );

    element_clear( fst );
    element_clear( snd );

    if ( res ) {
        throw std::runtime_error( "error during share combining" );
    }

    std::vector< int > idx( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        idx[i] = decrypted[i].second;
    }


    std::vector< element_wrapper > lagrange_coeffs = this->LagrangeCoeffs( idx );

    element_t sum;
    element_init_G1( sum, TEDataSingleton::getData().pairing_ );
    element_set0( sum );
    for ( size_t i = 0; i < this->t_; ++i ) {
        element_t temp;
        element_init_G1( temp, TEDataSingleton::getData().pairing_ );
        element_mul_zn( temp,
            ( const_cast< std::vector< std::pair< element_wrapper, size_t > >& >( decrypted ) )[i]
                .first.el_,
            lagrange_coeffs[i].el_ );

        element_t tmp1;
        element_init_G1( tmp1, TEDataSingleton::getData().pairing_ );

        element_add( tmp1, sum, temp );

        element_clear( sum );
        element_init_G1( sum, TEDataSingleton::getData().pairing_ );
        element_set( sum, tmp1 );

        element_clear( temp );
        element_clear( tmp1 );
    }

    std::string hash = this->Hash( sum );

    std::valarray< uint8_t > lhs_to_hash( hash.size() );
    for ( size_t i = 0; i < hash.size(); ++i ) {
        lhs_to_hash[i] = static_cast< uint8_t >( hash[i] );
    }

    std::valarray< uint8_t > rhs_to_hash( V.size() );
    for ( size_t i = 0; i < V.size(); ++i ) {
        rhs_to_hash[i] = static_cast< uint8_t >( V[i] );
    }

    std::valarray< uint8_t > xor_res = lhs_to_hash ^ rhs_to_hash;

    std::string message = "";
    for ( size_t i = 0; i < xor_res.size(); ++i ) {
        message += static_cast< char >( xor_res[i] );
    }

    element_clear( sum );

    return message;
}

std::vector< element_wrapper > TE::LagrangeCoeffs( const std::vector< int >& idx ) {
    if ( idx.size() < this->t_ ) {
        throw std::runtime_error( "Error, not enough participants in the threshold group" );
    }

    std::vector< element_wrapper > res( this->t_ );

    element_t w;
    element_init_Zr( w, TEDataSingleton::getData().pairing_ );
    element_set1( w );

    element_t a;
    element_init_Zr( a, TEDataSingleton::getData().pairing_ );

    for ( size_t i = 0; i < this->t_; ++i ) {
        element_mul_si( a, w, idx[i] );
        element_clear( w );
        element_init_Zr( w, TEDataSingleton::getData().pairing_ );
        element_set( w, a );
    }

    element_clear( a );

    for ( size_t i = 0; i < this->t_; ++i ) {
        element_t v;
        element_init_Zr( v, TEDataSingleton::getData().pairing_ );
        element_set_si( v, idx[i] );

        for ( size_t j = 0; j < this->t_; ++j ) {
            if ( j != i ) {
                if ( idx[i] == idx[j] ) {
                    element_clear( w );
                    element_clear( v );
                    throw std::runtime_error(
                        "Error during the interpolation, have same indexes in the list of "
                        "indexes" );
                }

                element_t u;
                element_init_Zr( u, TEDataSingleton::getData().pairing_ );

                element_set_si( u, idx[j] - idx[i] );

                element_init_Zr( a, TEDataSingleton::getData().pairing_ );
                element_mul_zn( a, v, u );
                element_clear( v );
                element_init_Zr( v, TEDataSingleton::getData().pairing_ );
                element_set( v, a );

                element_clear( a );

                element_clear( u );
            }
        }

        element_init_Zr( a, TEDataSingleton::getData().pairing_ );
        element_invert( a, v );
        element_clear( v );
        element_init_Zr( v, TEDataSingleton::getData().pairing_ );
        element_set( v, a );

        element_clear( a );


        element_init_Zr( a, TEDataSingleton::getData().pairing_ );
        element_mul_zn( a, w, v );

        element_init_Zr( res[i].el_, TEDataSingleton::getData().pairing_ );
        element_set( res[i].el_, a );

        element_clear( a );

        element_clear( v );
    }

    element_clear( w );

    return res;
}

}  // namespace encryption
