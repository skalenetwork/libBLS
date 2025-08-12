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

  @file bls.h
  @author Oleh Nikolaiev
  @date 2018
*/


#pragma once

#include <third_party/cryptlite/sha256.h>

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "backends/algebra.hpp"

static constexpr size_t BLS_MAX_SIG_LEN = 240;


namespace libBLS {

class Bls {
public:
    Bls( const size_t t, const size_t n );

    static std::pair< algebra::FrScalar, algebra::G2Point > KeyGeneration();

    static algebra::G1Point Hashing( const std::string& message,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static algebra::G1Point HashBytes( const char* raw_bytes, size_t length,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static algebra::G1Point HashPublicKeyToG1( const algebra::G2Point& elem );

    static std::pair< algebra::G1Point, std::string > HashPublicKeyToG1WithHint(
        const algebra::G2Point& elem );

    static algebra::G1Point Signing(
        const algebra::G1Point& hash, const algebra::FrScalar& secret_key );

    static algebra::G1Point CoreSignAggregated(
        const std::string& message, const algebra::FrScalar& secret_key );

    static algebra::G1Point Aggregate( const std::vector< algebra::G1Point >& signatures );

    static bool CoreVerify( const algebra::G2Point& public_key, const std::string& message,
        const algebra::G1Point& signature );

    static bool FastAggregateVerify( const std::vector< algebra::G2Point >& public_keys,
        const std::string& message, const algebra::G1Point& signature );

    static bool Verification( const std::string& to_be_hashed, const algebra::G1Point& sign,
        const algebra::G2Point& public_key );

    static bool Verification( const std::array< uint8_t, 32 >& hash_byte_arr,
        const algebra::G1Point& sign, const algebra::G2Point& public_key );

    static bool AggregatedVerification(
        const std::vector< std::shared_ptr< std::array< uint8_t, 32 > > >& hash_byte_arr,
        const std::vector< algebra::G1Point >& sign, const algebra::G2Point& public_key );

    std::pair< algebra::FrScalar, algebra::G2Point > KeysRecover(
        const std::vector< algebra::FrScalar >& coeffs,
        const std::vector< algebra::FrScalar >& shares );

    algebra::G1Point SignatureRecover( const std::vector< algebra::G1Point >& shares,
        const std::vector< algebra::FrScalar >& coeffs );

    static algebra::G1Point PopProve( const algebra::FrScalar& secret_key );

    static bool PopVerify( const algebra::G2Point& public_key, const algebra::G1Point& prove );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS


#define CHECK( _EXPRESSION_ )                                                                 \
    if ( !( _EXPRESSION_ ) ) {                                                                \
        auto __msg__ = std::string( "Check failed:" ) + #_EXPRESSION_ + "\n" + __FUNCTION__ + \
                       +" " + std::string( __FILE__ ) + ":" + std::to_string( __LINE__ );     \
        throw libBLS::ThresholdUtils::IncorrectInput( __msg__ );                              \
    }
