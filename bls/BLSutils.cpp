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

@file BLSUtils.cpp
@author Sveta Rogova
@date 2019
*/

#include "bls.h"
#include <bls/BLSutils.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <algorithm>

#include <bitset>
#include <mutex>

std::atomic< bool > BLSutils::is_initialized = false;

std::mutex initMutex;

void BLSutils::initBLS() {
    std::lock_guard< std::mutex > lock( initMutex );
    if ( !is_initialized ) {
        libff::init_alt_bn128_params();
        is_initialized = true;
    }
}

std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > BLSutils::ParseHint( std::string& _hint ) {
    auto position = _hint.find( ":" );

    if ( position == std::string::npos ) {
        throw std::runtime_error( "Misformatted hint" );
    }

    libff::alt_bn128_Fq y( _hint.substr( 0, position ).c_str() );
    libff::alt_bn128_Fq shift_x( _hint.substr( position + 1 ).c_str() );

    return std::make_pair( y, shift_x );
}

libff::alt_bn128_Fq BLSutils::HashToFq(
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

std::shared_ptr< std::vector< std::string > > BLSutils::SplitString(
    std::shared_ptr< std::string > str, const std::string& delim ) {
    CHECK( str );

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
