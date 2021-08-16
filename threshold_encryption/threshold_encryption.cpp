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

#include <openssl/rand.h>
#include <libff/common/profiling.hpp>

namespace crypto {

TE::TE( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    libff::init_alt_bn128_params();
    libff::inhibit_profiling_info = true;
}

TE::~TE() {}

void TE::checkCypher(
    const std::tuple< libff::alt_bn128_G2, std::string, libff::alt_bn128_G1 >& cyphertext ) {
    if ( std::get< 0 >( cyphertext ).is_zero() || std::get< 2 >( cyphertext ).is_zero() )
        throw ThresholdUtils::IncorrectInput( "zero element in cyphertext" );

    if ( std::get< 1 >( cyphertext ).length() != 64 )
        throw ThresholdUtils::IncorrectInput( "wrong string length in cyphertext" );
}

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

Ciphertext TE::Encrypt( const std::string& message, const libff::alt_bn128_G2& common_public ) {
    libff::alt_bn128_Fr r = libff::alt_bn128_Fr::random_element();

    while ( r.is_zero() ) {
        r = libff::alt_bn128_Fr::random_element();
    }

    libff::alt_bn128_G2 U, Y;
    U = r * libff::alt_bn128_G2::one();
    Y = r * common_public;

    std::string hash = Hash( Y );

    size_t size = std::max( message.size(), hash.size() );
    std::valarray< uint8_t > lhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        lhs_to_hash[i] = i < hash.size() ? static_cast< uint8_t >( hash[i] ) : 0;
    }

    std::valarray< uint8_t > rhs_to_hash( size );
    for ( size_t i = 0; i < size; ++i ) {
        rhs_to_hash[i] = i < message.size() ? static_cast< uint8_t >( message[i] ) : 0;
    }

    std::valarray< uint8_t > res = lhs_to_hash ^ rhs_to_hash;

    std::string V;
    V.resize( size );
    for ( size_t i = 0; i < size; ++i ) {
        V[i] = static_cast< uint8_t >( res[i] );
    }

    libff::alt_bn128_G1 W, H;

    H = HashToGroup( U, V );
    W = r * H;

    Ciphertext result;
    std::get< 0 >( result ) = U;
    std::get< 1 >( result ) = V;
    std::get< 2 >( result ) = W;

    return result;
}

std::pair< Ciphertext, std::vector< uint8_t > > TE::encryptWithAES(
    const std::string& message, const libff::alt_bn128_G2& common_public ) {
    ThresholdUtils::initAES();
    unsigned char key_bytes[32];
    RAND_bytes( key_bytes, sizeof( key_bytes ) );
    std::string random_aes_key = std::string( ( char* ) key_bytes, sizeof( key_bytes ) );

    auto encrypted_message = ThresholdUtils::aesEncrypt( message, random_aes_key );

    auto ciphertext = Encrypt( random_aes_key, common_public );

    auto U = std::get< 0 >( ciphertext );
    auto V = std::get< 1 >( ciphertext );
    auto W = std::get< 2 >( ciphertext );

    return {{U, V, W}, encrypted_message};
}

libff::alt_bn128_G2 TE::getDecryptionShare(
    const Ciphertext& ciphertext, const libff::alt_bn128_Fr& secret_key ) {
    checkCypher( ciphertext );
    if ( secret_key.is_zero() )
        throw ThresholdUtils::ZeroSecretKey( "zero secret key" );

    libff::alt_bn128_G2 U = std::get< 0 >( ciphertext );

    std::string V = std::get< 1 >( ciphertext );

    libff::alt_bn128_G1 W = std::get< 2 >( ciphertext );

    libff::alt_bn128_G1 H = HashToGroup( U, V );

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

    libff::alt_bn128_G1 H = HashToGroup( U, V );

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

    return message;
}

std::string TE::aesCiphertextToString(
    const Ciphertext& cipher, const std::vector< uint8_t >& data ) {
    ThresholdUtils::initCurve();
    ThresholdUtils::initAES();

    auto U = std::get< 0 >( cipher );
    auto V = std::get< 1 >( cipher );
    auto W = std::get< 2 >( cipher );

    std::string v_str = ThresholdUtils::carray2Hex( ( unsigned char* ) ( V.data() ), V.size() );

    std::string encrypted_data = ThresholdUtils::carray2Hex( data.data(), data.size() );

    auto str = ThresholdUtils::G2ToString( U, 16 );
    std::string u_str = "";
    for ( auto& elem : str ) {
        while ( elem.size() < 64 ) {
            elem = "0" + elem;
        }
        u_str += elem;
    }

    W.to_affine_coordinates();
    std::string x = ThresholdUtils::fieldElementToString( W.X, 16 );
    while ( x.size() < 64 ) {
        x = "0" + x;
    }

    std::string y = ThresholdUtils::fieldElementToString( W.Y, 16 );
    while ( y.size() < 64 ) {
        y = "0" + y;
    }

    std::string w_str = x + y;

    return u_str + v_str + w_str + encrypted_data;
}

std::pair< Ciphertext, std::vector< uint8_t > > TE::aesCiphertextFromString(
    const std::string& str ) {
    ThresholdUtils::initCurve();
    ThresholdUtils::initAES();

    if ( !ThresholdUtils::checkHex( str ) ) {
        throw ThresholdUtils::IncorrectInput( "Provided string contains non-hex symbols" );
    }

    if ( str.size() < 256 + 129 + 128 + 1 ) {
        throw ThresholdUtils::IncorrectInput(
            "Incoming string to short to convert to aes ciphertext" );
    }

    std::string u_str = str.substr( 0, 256 );
    std::string v_str = str.substr( 256, 129 );
    std::string w_str = str.substr( 256 + 129, 128 );

    std::string encrypted_data = str.substr( 256 + 129 + 128, std::string::npos );

    uint64_t bin_len;
    std::vector< uint8_t > aes_cipher( encrypted_data.size() / 2 );
    if ( !ThresholdUtils::hex2carray( encrypted_data.data(), &bin_len, &aes_cipher[0] ) ) {
        throw ThresholdUtils::IncorrectInput( "Bad aes_cipher provided" );
    }

    std::vector< std::string > coords_u( 4 );
    coords_u[0] = u_str.substr( 0, 64 );
    coords_u[1] = u_str.substr( 64, 64 );
    coords_u[2] = u_str.substr( 128, 64 );
    coords_u[3] = u_str.substr( 192, std::string::npos );

    libff::alt_bn128_G2 U;
    U.Z = libff::alt_bn128_Fq2::one();
    U.X.c0 = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_u[0] ).c_str() );
    U.X.c1 = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_u[1] ).c_str() );
    U.Y.c0 = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_u[2] ).c_str() );
    U.Y.c1 = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_u[3] ).c_str() );

    std::vector< std::string > coords_w( 2 );
    coords_w[0] = w_str.substr( 0, 64 );
    coords_w[1] = w_str.substr( 64, std::string::npos );

    libff::alt_bn128_G1 W;
    W.Z = libff::alt_bn128_Fq::one();
    W.X = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_w[0] ).c_str() );
    W.Y = libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( coords_w[1] ).c_str() );

    std::string V;
    V.resize( ( v_str.size() - 1 ) / 2 );
    if ( !ThresholdUtils::hex2carray( v_str.data(), &bin_len, ( unsigned char* ) &V[0] ) ) {
        throw ThresholdUtils::IncorrectInput( "Bad encrypted aes key provided" );
    }

    return {{U, V, W}, aes_cipher};
}

}  // namespace crypto
