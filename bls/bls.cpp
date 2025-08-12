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

#include <gmpxx.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/common/profiling.hpp>

namespace libBLS {

Bls::Bls( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    ThresholdUtils::initCurve();
}

std::pair< algebra::FrScalar, algebra::G2Point > Bls::KeyGeneration() {
    // generate sample secret and public keys
    algebra::FrScalar secret_key = algebra::FrScalar::random();  // secret key generation

    while ( secret_key.isZero() ) {
        secret_key = algebra::FrScalar::random();
    }

    const algebra::G2Point public_key =
        secret_key * algebra::G2Point::one();  // public key generation

    return std::make_pair( secret_key, public_key );
}

// TODO move out to backends/libff/utils
algebra::G1Point Bls::Hashing(
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

    const algebra::G1Point hash =
        algebra::FrScalar::fromString( s, Base::DEC ) * algebra::G1Point::one();

    return hash;
}


algebra::G1Point Bls::HashBytes(
    const char* raw_bytes, size_t length, std::string ( *hash_func )( const std::string& str ) ) {
    CHECK( raw_bytes );
    CHECK( hash_func );

    CHECK( raw_bytes );

    std::string from_bytes( raw_bytes, length );

    algebra::G1Point hash = Hashing( from_bytes, *hash_func );

    return hash;
}

algebra::G1Point Bls::HashPublicKeyToG1( const algebra::G2Point& elem ) {
    auto serialized_elem_vector = elem.toStringArray( Base::HEXA );

    std::string serialized_elem = std::accumulate(
        serialized_elem_vector.begin(), serialized_elem_vector.end(), std::string( "" ) );

    std::string hashed_pubkey = cryptlite::sha256::hash_hex( serialized_elem );

    auto hash_bytes_arr = std::array< uint8_t, 32 >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( hashed_pubkey.c_str(), &bin_len, hash_bytes_arr.data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return algebra::G1Point::fromHash( hash_bytes_arr );
}

std::pair< algebra::G1Point, std::string > Bls::HashPublicKeyToG1WithHint(
    const algebra::G2Point& elem ) {
    auto serialized_elem_vector = elem.toStringArray( Base::HEXA );

    std::string serialized_elem = std::accumulate(
        serialized_elem_vector.begin(), serialized_elem_vector.end(), std::string( "" ) );

    std::string hashed_pubkey = cryptlite::sha256::hash_hex( serialized_elem );

    auto hash_bytes_arr = std::array< uint8_t, 32 >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( hashed_pubkey.c_str(), &bin_len, hash_bytes_arr.data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return algebra::hashtoG1withHint( hash_bytes_arr );
}

algebra::G1Point Bls::Signing( const algebra::G1Point& hash, const algebra::FrScalar& secret_key ) {
    // sign a message with its hash and secret key
    // implemented constant time signing

    if ( secret_key.isZero() ) {
        throw ThresholdUtils::ZeroSecretKey( "failed to sign a message hash" );
    }

    std::clock_t c_start = std::clock();  // hash

    // TODO using .value here. this is impl. specific - this entire function should be inside
    // backends/libff
    const algebra::G1Point sign = secret_key * hash;  // sign

    std::clock_t c_end = std::clock();

    std::this_thread::sleep_for(
        std::chrono::microseconds( 10000 - 1000000 * ( c_end - c_start ) / CLOCKS_PER_SEC ) );

    return sign;
}

algebra::G1Point Bls::CoreSignAggregated(
    const std::string& message, const algebra::FrScalar& secret_key ) {
    return secret_key * algebra::G1Point::fromHash( message );
}

algebra::G1Point Bls::Aggregate( const std::vector< algebra::G1Point >& signatures ) {
    algebra::G1Point res = algebra::G1Point::zero();

    for ( const auto& signature : signatures ) {
        signature.validate();
        res = res + signature;
    }

    return res;
}

bool Bls::CoreVerify( const algebra::G2Point& public_key, const std::string& message,
    const algebra::G1Point& signature ) {
    if ( !public_key.isValid() || !signature.isValid() ) {
        throw ThresholdUtils::IsNotWellFormed( "Either signature or public key is malicious" );
    }

    algebra::G1Point hash = algebra::G1Point::fromHash( message );

    return algebra::pairing( hash, public_key ) ==
           algebra::pairing( signature, algebra::G2Point::one() );
}

bool Bls::FastAggregateVerify( const std::vector< algebra::G2Point >& public_keys,
    const std::string& message, const algebra::G1Point& signature ) {
    algebra::G2Point sum =
        std::accumulate( public_keys.begin(), public_keys.end(), algebra::G2Point::zero() );

    return CoreVerify( sum, message, signature );
}

bool Bls::Verification( const std::string& to_be_hashed, const algebra::G1Point& sign,
    const algebra::G2Point& public_key ) {
    // verifies that a given signature corresponds to given public key

    sign.validate();
    public_key.validate();

    algebra::G1Point hash = Hashing( to_be_hashed );

    return (
        algebra::pairing( sign, algebra::G2Point::one() ) == algebra::pairing( hash, public_key ) );
    // there are several types of pairing, it does not matter which one is chosen for verification
}

bool Bls::Verification( const std::array< uint8_t, 32 >& hash_byte_arr,
    const algebra::G1Point& sign, const algebra::G2Point& public_key ) {
    // verifies that a given signature corresponds to given public key

    // TODO check for such statements throghout the codebase
    libff::inhibit_profiling_info = true;

    sign.validate();
    public_key.validate();

    algebra::G1Point hash = algebra::G1Point::fromHash( hash_byte_arr );

    return (
        algebra::pairing( sign, algebra::G2Point::one() ) == algebra::pairing( hash, public_key ) );
    // there are several types of pairing, it does not matter which one is chosen for verification
}

bool Bls::AggregatedVerification(
    const std::vector< std::shared_ptr< std::array< uint8_t, 32 > > >& hash_byte_arr,
    const std::vector< algebra::G1Point >& sign, const algebra::G2Point& public_key ) {
    for ( auto& hash : hash_byte_arr ) {
        CHECK( hash );
    }

    libff::inhibit_profiling_info = true;

    for ( auto& sig : sign ) {
        sig.validate();
    }

    public_key.validate();

    algebra::G1Point aggregated_hash = algebra::G1Point::zero();
    for ( const std::shared_ptr< std::array< uint8_t, 32 > >& hash : hash_byte_arr ) {
        aggregated_hash = aggregated_hash + algebra::G1Point::fromHash( *hash );
    }

    algebra::G1Point aggregated_sig = algebra::G1Point::zero();
    for ( const algebra::G1Point& sig : sign ) {
        aggregated_sig = aggregated_sig + sig;
    }

    return ( algebra::pairing( aggregated_sig, algebra::G2Point::one() ) ==
             algebra::pairing( aggregated_hash, public_key ) );
}

std::pair< algebra::FrScalar, algebra::G2Point > Bls::KeysRecover(
    const std::vector< algebra::FrScalar >& coeffs,
    const std::vector< algebra::FrScalar >& shares ) {
    if ( shares.size() < this->t_ || coeffs.size() < this->t_ ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    if ( shares.size() > this->n_ || coeffs.size() > this->n_ ) {
        throw ThresholdUtils::IncorrectInput( "too many participants in the threshold group" );
    }

    algebra::FrScalar secret_key = algebra::FrScalar::zero();

    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( shares[i].isZero() ) {
            throw ThresholdUtils::ZeroSecretKey(
                "at least one secret key share is equal to zero in KeysRecover group" );
        }
        secret_key += coeffs[i] * shares[i];  // secret key recovering using Lagrange Interpolation
    }

    const algebra::G2Point public_key =
        secret_key * algebra::G2Point::one();  // public key recovering

    return std::make_pair( secret_key, public_key );
}

algebra::G1Point Bls::SignatureRecover( const std::vector< algebra::G1Point >& shares,
    const std::vector< algebra::FrScalar >& coeffs ) {
    if ( shares.size() < this->t_ || coeffs.size() < this->t_ ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    if ( shares.size() > this->n_ || coeffs.size() > this->n_ ) {
        throw ThresholdUtils::IncorrectInput( "too many participants in the threshold group" );
    }

    algebra::G1Point sign = algebra::G1Point::zero();

    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( !shares[i].isWellFormed() ) {
            throw ThresholdUtils::IsNotWellFormed( "incorrect input data to recover signature" );
        }
        sign = sign + coeffs[i] * shares[i];  // signature recovering using Lagrange Coefficients
    }

    return sign;  // first element is hash of a receiving message
}

algebra::G1Point Bls::PopProve( const algebra::FrScalar& secret_key ) {
    algebra::G2Point public_key = secret_key * algebra::G2Point::one();

    algebra::G1Point hash = HashPublicKeyToG1( public_key );

    algebra::G1Point ret = secret_key * hash;

    return ret;
}

bool Bls::PopVerify( const algebra::G2Point& public_key, const algebra::G1Point& prove ) {
    prove.validate();
    public_key.validate();

    algebra::G1Point hash = HashPublicKeyToG1( public_key );

    return algebra::pairing( hash, public_key ) ==
           algebra::pairing( prove, algebra::G2Point::one() );
}

}  // namespace libBLS
