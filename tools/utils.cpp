/*
  Copyright (C) 2021- SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file utils.cpp
  @author Oleh Nikolaiev
  @date 2021
*/

#include <tools/utils.h>
#include <mutex>

namespace crypto {


std::atomic< bool > ThresholdUtils::is_initialized = false;

std::mutex initMutex;

void ThresholdUtils::initCurve() {
    std::lock_guard< std::mutex > lock( initMutex );
    if ( !is_initialized ) {
        libff::init_alt_bn128_params();
        is_initialized = true;
    }
}

void ThresholdUtils::checkSigners( size_t _requiredSigners, size_t _totalSigners ) {
    if ( _requiredSigners > _totalSigners ) {
        throw std::runtime_error( "_requiredSigners > _totalSigners" );
    }

    if ( _totalSigners == 0 ) {
        throw std::runtime_error( "_totalSigners == 0" );
    }

    if ( _requiredSigners == 0 ) {
        throw std::runtime_error( "_requiredSigners == 0" );
    }
}

std::vector< std::string > ThresholdUtils::G2ToString( libff::alt_bn128_G2 elem ) {
    std::vector< std::string > pkey_str_vect;

    elem.to_affine_coordinates();

    pkey_str_vect.push_back( fieldElementToString( elem.X.c0 ) );
    pkey_str_vect.push_back( fieldElementToString( elem.X.c1 ) );
    pkey_str_vect.push_back( fieldElementToString( elem.Y.c0 ) );
    pkey_str_vect.push_back( fieldElementToString( elem.Y.c1 ) );

    return pkey_str_vect;
}

std::vector< libff::alt_bn128_Fr > ThresholdUtils::LagrangeCoeffs(
    const std::vector< size_t >& idx, size_t t ) {
    if ( idx.size() < t ) {
        throw IncorrectInput( "not enough participants in the threshold group" );
    }

    std::vector< libff::alt_bn128_Fr > res( t );

    libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

    for ( size_t i = 0; i < t; ++i ) {
        w *= libff::alt_bn128_Fr( idx[i] );
    }

    for ( size_t i = 0; i < t; ++i ) {
        libff::alt_bn128_Fr v = libff::alt_bn128_Fr( idx[i] );

        for ( size_t j = 0; j < t; ++j ) {
            if ( j != i ) {
                if ( libff::alt_bn128_Fr( idx[i] ) == libff::alt_bn128_Fr( idx[j] ) ) {
                    throw IncorrectInput(
                        "during the interpolation, have same indexes in list of indexes" );
                }

                v *= ( libff::alt_bn128_Fr( idx[j] ) -
                       libff::alt_bn128_Fr( idx[i] ) );  // calculating Lagrange coefficients
            }
        }

        res[i] = w * v.invert();
    }

    return res;
}

libff::alt_bn128_Fq ThresholdUtils::HashToFq(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr ) {
    libff::bigint< libff::alt_bn128_q_limbs > from_hex;

    std::vector< uint8_t > hex( 64 );
    for ( size_t i = 0; i < 32; ++i ) {
        hex[2 * i] = static_cast< int >( hash_byte_arr->at( i ) ) / 16;
        hex[2 * i + 1] = static_cast< int >( hash_byte_arr->at( i ) ) % 16;
    }
    mpn_set_str( from_hex.data, hex.data(), 64, 16 );

    libff::alt_bn128_Fq ret_val( from_hex );

    return ret_val;
}

libff::alt_bn128_G1 ThresholdUtils::HashtoG1(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr ) {
    libff::alt_bn128_Fq x1( HashToFq( hash_byte_arr ) );

    libff::alt_bn128_G1 result;

    while ( true ) {
        libff::alt_bn128_Fq y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

        libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

        if ( euler == libff::alt_bn128_Fq::one() ||
             euler == libff::alt_bn128_Fq::zero() ) {  // if y1_sqr is a square
            result.X = x1;
            libff::alt_bn128_Fq temp_y = y1_sqr.sqrt();

            mpz_t pos_y;
            mpz_init( pos_y );

            temp_y.as_bigint().to_mpz( pos_y );

            mpz_t neg_y;
            mpz_init( neg_y );

            ( -temp_y ).as_bigint().to_mpz( neg_y );

            if ( mpz_cmp( pos_y, neg_y ) < 0 ) {
                temp_y = -temp_y;
            }

            mpz_clear( pos_y );
            mpz_clear( neg_y );

            result.Y = temp_y;
            break;
        } else {
            x1 = x1 + 1;
        }
    }
    result.Z = libff::alt_bn128_Fq::one();

    return result;
}

bool ThresholdUtils::isStringNumber( std::string& str ) {
    if ( str.at( 0 ) == '0' && str.length() > 1 )
        return false;
    for ( char& c : str ) {
        if ( !( c >= '0' && c <= '9' ) ) {
            return false;
        }
    }
    return true;
}

void ThresholdUtils::checkCypher(
    const std::tuple< libff::alt_bn128_G2, std::string, libff::alt_bn128_G1 >& cyphertext ) {
    if ( std::get< 0 >( cyphertext ).is_zero() || std::get< 2 >( cyphertext ).is_zero() )
        throw IncorrectInput( "zero element in cyphertext" );

    if ( std::get< 1 >( cyphertext ).length() != 64 )
        throw IncorrectInput( "wrong string length in cyphertext" );
}

std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > ThresholdUtils::ParseHint(
    const std::string& _hint ) {
    auto position = _hint.find( ":" );

    if ( position == std::string::npos ) {
        throw IncorrectInput( "Misformatted hint" );
    }

    libff::alt_bn128_Fq y( _hint.substr( 0, position ).c_str() );
    libff::alt_bn128_Fq shift_x( _hint.substr( position + 1 ).c_str() );

    return std::make_pair( y, shift_x );
}

std::shared_ptr< std::vector< std::string > > ThresholdUtils::SplitString(
    std::shared_ptr< std::string > str, const std::string& delim ) {
    if ( !str ) {
        throw IncorrectInput( " str pointer is null in SplitString " );
    }

    std::vector< std::string > tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str->find( delim, prev );
        if ( pos == std::string::npos )
            pos = str->length();
        std::string token = str->substr( prev, pos - prev );
        if ( !token.empty() )
            tokens.push_back( token );
        prev = pos + delim.length();
    } while ( pos < str->length() && prev < str->length() );

    return std::make_shared< std::vector< std::string > >( tokens );
}

}  // namespace crypto
