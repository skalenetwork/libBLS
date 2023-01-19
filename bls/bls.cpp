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

@file bls.cpp
@author Oleh Nikolaiev
@date 2018
*/


#include <bls/bls.h>
#include <tools/utils.h>

#include <bitset>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include <thread>

#include <boost/multiprecision/cpp_int.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/common/profiling.hpp>

namespace libBLS {

Bls::Bls( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    ThresholdUtils::initCurve();
}

std::pair< libff::alt_bn128_Fr, libff::alt_bn128_G2 > Bls::KeyGeneration() {
    // generate sample secret and public keys
    libff::alt_bn128_Fr secret_key =
        libff::alt_bn128_Fr::random_element();  // secret key generation

    while ( secret_key == libff::alt_bn128_Fr::zero() ) {
        secret_key = libff::alt_bn128_Fr::random_element();
    }

    const libff::alt_bn128_G2 public_key =
        secret_key * libff::alt_bn128_G2::one();  // public key generation

    return std::make_pair( secret_key, public_key );
}

libff::alt_bn128_G1 Bls::Hashing(
    const std::string& message, std::string ( *hash_func )( const std::string& str ) ) {
    CHECK( hash_func );

    std::string sha256hex = hash_func( message );

    boost::multiprecision::uint256_t num = 0;
    boost::multiprecision::uint256_t pow = 1;
    for ( auto sym : sha256hex ) {
        // converting from hex to bigint
        num += ( ( sym >= 'a' ) * 10 + static_cast< int >( ( sym - 'a' ) ) ) * pow;
        pow *= 16;
    }

    std::string s = num.convert_to< std::string >();

    const libff::alt_bn128_G1 hash = libff::alt_bn128_Fr( s.c_str() ) * libff::alt_bn128_G1::one();

    return hash;
}

std::pair< libff::alt_bn128_G1, std::string > Bls::HashtoG1withHint(
    std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr ) {
    CHECK( hash_byte_arr );

    libff::alt_bn128_G1 point;
    libff::alt_bn128_Fq counter = libff::alt_bn128_Fq::zero();
    libff::alt_bn128_Fq x1( ThresholdUtils::HashToFq( hash_byte_arr ) );


    while ( true ) {
        libff::alt_bn128_Fq y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

        libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

        if ( euler == libff::alt_bn128_Fq::one() ||
             euler == libff::alt_bn128_Fq::zero() ) {  // if y1_sqr is a square
            point.X = x1;
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

            point.Y = temp_y;
            break;
        } else {
            counter = counter + libff::alt_bn128_Fq::one();
            x1 = x1 + libff::alt_bn128_Fq::one();
        }
    }
    point.Z = libff::alt_bn128_Fq::one();

    return std::make_pair( point, ThresholdUtils::fieldElementToString( counter ) );
}

libff::alt_bn128_G1 Bls::HashBytes(
    const char* raw_bytes, size_t length, std::string ( *hash_func )( const std::string& str ) ) {
    CHECK( raw_bytes );
    CHECK( hash_func );

    CHECK( raw_bytes );

    std::string from_bytes( raw_bytes, length );

    libff::alt_bn128_G1 hash = Hashing( from_bytes, *hash_func );

    return hash;
}

libff::alt_bn128_G1 Bls::HashPublicKeyToG1( const libff::alt_bn128_G2& elem ) {
    auto serialized_elem_vector = ThresholdUtils::G2ToString( elem, 16 );

    std::string serialized_elem = std::accumulate(
        serialized_elem_vector.begin(), serialized_elem_vector.end(), std::string( "" ) );

    std::string hashed_pubkey = cryptlite::sha256::hash_hex( serialized_elem );

    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( hashed_pubkey.c_str(), &bin_len, hash_bytes_arr->data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return ThresholdUtils::HashtoG1( hash_bytes_arr );
}

std::pair< libff::alt_bn128_G1, std::string > Bls::HashPublicKeyToG1WithHint(
    const libff::alt_bn128_G2& elem ) {
    auto serialized_elem_vector = ThresholdUtils::G2ToString( elem, 16 );

    std::string serialized_elem = std::accumulate(
        serialized_elem_vector.begin(), serialized_elem_vector.end(), std::string( "" ) );

    std::string hashed_pubkey = cryptlite::sha256::hash_hex( serialized_elem );

    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( hashed_pubkey.c_str(), &bin_len, hash_bytes_arr->data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return Bls::HashtoG1withHint( hash_bytes_arr );
}

libff::alt_bn128_G1 Bls::Signing(
    const libff::alt_bn128_G1 hash, const libff::alt_bn128_Fr secret_key ) {
    // sign a message with its hash and secret key
    // implemented constant time signing

    if ( secret_key == libff::alt_bn128_Fr::zero() ) {
        throw ThresholdUtils::ZeroSecretKey( "failed to sign a message hash" );
    }

    std::clock_t c_start = std::clock();  // hash

    const libff::alt_bn128_G1 sign = secret_key.as_bigint() * hash;  // sign

    std::clock_t c_end = std::clock();

    std::this_thread::sleep_for(
        std::chrono::microseconds( 10000 - 1000000 * ( c_end - c_start ) / CLOCKS_PER_SEC ) );

    return sign;
}

libff::alt_bn128_G1 Bls::CoreSignAggregated(
    const std::string& message, const libff::alt_bn128_Fr secret_key ) {
    libff::alt_bn128_G1 hash = ThresholdUtils::HashtoG1( message );

    return secret_key * hash;
}

libff::alt_bn128_G1 Bls::Aggregate( const std::vector< libff::alt_bn128_G1 >& signatures ) {
    libff::alt_bn128_G1 res = libff::alt_bn128_G1::zero();

    for ( const auto& signature : signatures ) {
        if ( !ThresholdUtils::ValidateKey( signature ) ) {
            throw ThresholdUtils::IsNotWellFormed(
                "One of the signatures to be aggregated is malicious" );
        }

        res = res + signature;
    }

    return res;
}

bool Bls::CoreVerify( const libff::alt_bn128_G2& public_key, const std::string& message,
    const libff::alt_bn128_G1& signature ) {
    if ( !ThresholdUtils::ValidateKey( public_key ) || !ThresholdUtils::ValidateKey( signature ) ) {
        throw ThresholdUtils::IsNotWellFormed( "Either signature or public key is malicious" );
    }

    libff::alt_bn128_G1 hash = ThresholdUtils::HashtoG1( message );

    return libff::alt_bn128_ate_reduced_pairing( hash, public_key ) ==
           libff::alt_bn128_ate_reduced_pairing( signature, libff::alt_bn128_G2::one() );
}

bool Bls::FastAggregateVerify( const std::vector< libff::alt_bn128_G2 >& public_keys,
    const std::string& message, const libff::alt_bn128_G1& signature ) {
    libff::alt_bn128_G2 sum =
        std::accumulate( public_keys.begin(), public_keys.end(), libff::alt_bn128_G2::zero() );

    return CoreVerify( sum, message, signature );
}

bool Bls::Verification( const std::string& to_be_hashed, const libff::alt_bn128_G1 sign,
    const libff::alt_bn128_G2 public_key ) {
    // verifies that a given signature corresponds to given public key

    libff::inhibit_profiling_info = true;

    if ( !sign.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed(
            "Error, signature does not lie on the alt_bn128 curve" );
    }

    if ( !public_key.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, public key is invalid" );
    }

    if ( libff::alt_bn128_modulus_r * sign != libff::alt_bn128_G1::zero() ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, signature is not member of G1" );
    }

    libff::alt_bn128_G1 hash = Hashing( to_be_hashed );

    return ( libff::alt_bn128_ate_reduced_pairing( sign, libff::alt_bn128_G2::one() ) ==
             libff::alt_bn128_ate_reduced_pairing( hash, public_key ) );
    // there are several types of pairing, it does not matter which one is chosen for verification
}

bool Bls::Verification( std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr,
    const libff::alt_bn128_G1 sign, const libff::alt_bn128_G2 public_key ) {
    CHECK( hash_byte_arr );

    // verifies that a given signature corresponds to given public key

    libff::inhibit_profiling_info = true;

    if ( !sign.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed(
            "Error, signature does not lie on the alt_bn128 curve" );
    }

    if ( !public_key.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, public key is invalid" );
    }

    if ( libff::alt_bn128_modulus_r * sign != libff::alt_bn128_G1::zero() ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, signature is not member of G1" );
    }

    libff::alt_bn128_G1 hash = ThresholdUtils::HashtoG1( hash_byte_arr );

    return ( libff::alt_bn128_ate_reduced_pairing( sign, libff::alt_bn128_G2::one() ) ==
             libff::alt_bn128_ate_reduced_pairing( hash, public_key ) );
    // there are several types of pairing, it does not matter which one is chosen for verification
}

bool Bls::AggregatedVerification(
    std::vector< std::shared_ptr< std::array< uint8_t, 32 > > > hash_byte_arr,
    const std::vector< libff::alt_bn128_G1 > sign, const libff::alt_bn128_G2 public_key ) {
    for ( auto& hash : hash_byte_arr ) {
        CHECK( hash );
    }

    libff::inhibit_profiling_info = true;

    for ( auto& sig : sign ) {
        if ( !sig.is_well_formed() ) {
            throw ThresholdUtils::IsNotWellFormed(
                "Error, signature does not lie on the alt_bn128 curve" );
        }
        if ( libff::alt_bn128_modulus_r * sig != libff::alt_bn128_G1::zero() ) {
            throw ThresholdUtils::IsNotWellFormed( "Error, signature is not member of G1" );
        }
    }

    if ( !public_key.is_well_formed() ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, public key is invalid" );
    }

    if ( !ThresholdUtils::ValidateKey( public_key ) ) {
        throw ThresholdUtils::IsNotWellFormed( "Error, public key is not member of G2" );
    }

    libff::alt_bn128_G1 aggregated_hash = libff::alt_bn128_G1::zero();
    for ( std::shared_ptr< std::array< uint8_t, 32 > >& hash : hash_byte_arr ) {
        aggregated_hash = aggregated_hash + ThresholdUtils::HashtoG1( hash );
    }

    libff::alt_bn128_G1 aggregated_sig = libff::alt_bn128_G1::zero();
    for ( libff::alt_bn128_G1 sig : sign ) {
        aggregated_sig = aggregated_sig + sig;
    }

    return ( libff::alt_bn128_ate_reduced_pairing( aggregated_sig, libff::alt_bn128_G2::one() ) ==
             libff::alt_bn128_ate_reduced_pairing( aggregated_hash, public_key ) );
}

std::pair< libff::alt_bn128_Fr, libff::alt_bn128_G2 > Bls::KeysRecover(
    const std::vector< libff::alt_bn128_Fr >& coeffs,
    const std::vector< libff::alt_bn128_Fr >& shares ) {
    if ( shares.size() < this->t_ || coeffs.size() < this->t_ ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::zero();

    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( shares[i] == libff::alt_bn128_Fr::zero() ) {
            throw ThresholdUtils::ZeroSecretKey(
                "at least one secret key share is equal to zero in KeysRecover group" );
        }
        secret_key += coeffs[i] * shares[i];  // secret key recovering using Lagrange Interpolation
    }

    const libff::alt_bn128_G2 public_key =
        secret_key * libff::alt_bn128_G2::one();  // public key recovering

    return std::make_pair( secret_key, public_key );
}

libff::alt_bn128_G1 Bls::SignatureRecover( const std::vector< libff::alt_bn128_G1 >& shares,
    const std::vector< libff::alt_bn128_Fr >& coeffs ) {
    if ( shares.size() < this->t_ || coeffs.size() < this->t_ ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    libff::alt_bn128_G1 sign = libff::alt_bn128_G1::zero();

    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( !shares[i].is_well_formed() ) {
            throw ThresholdUtils::IsNotWellFormed( "incorrect input data to recover signature" );
        }
        sign = sign + coeffs[i] * shares[i];  // signature recovering using Lagrange Coefficients
    }

    return sign;  // first element is hash of a receiving message
}

libff::alt_bn128_G1 Bls::PopProve( const libff::alt_bn128_Fr& secret_key ) {
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();

    libff::alt_bn128_G1 hash = HashPublicKeyToG1( public_key );

    libff::alt_bn128_G1 ret = secret_key * hash;

    return ret;
}

bool Bls::PopVerify( const libff::alt_bn128_G2& public_key, const libff::alt_bn128_G1& prove ) {
    if ( !ThresholdUtils::ValidateKey( prove ) || !ThresholdUtils::ValidateKey( public_key ) ) {
        throw ThresholdUtils::IsNotWellFormed(
            "incorrect input data to verify proof of possession" );
    }

    libff::alt_bn128_G1 hash = HashPublicKeyToG1( public_key );

    return libff::alt_bn128_ate_reduced_pairing( hash, public_key ) ==
           libff::alt_bn128_ate_reduced_pairing( prove, libff::alt_bn128_G2::one() );
}

}  // namespace libBLS
