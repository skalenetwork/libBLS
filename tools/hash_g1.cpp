/*
  Copyright (C) 2018-2019 SKALE Labs
​
  This file is part of libBLS.
​
  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
​
  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.
​
  You should have received a copy of the GNU Affero General Public License
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.
​
  @file hash_g1.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <bls/BLSPublicKey.h>
#include <bls/BLSutils.h>
#include <bls/bls.h>
#include <boost/program_options.hpp>
#include <fstream>
#include <libff/common/profiling.hpp>
#include <third_party/json.hpp>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_b_verbose_mode = false;

static bool g_b_rehash = false;

int char2int( char _input ) {
    if ( _input >= '0' && _input <= '9' )
        return _input - '0';
    if ( _input >= 'A' && _input <= 'F' )
        return _input - 'A' + 10;
    if ( _input >= 'a' && _input <= 'f' )
        return _input - 'a' + 10;
    return -1;
}

bool hex2carray( const char* _hex, uint64_t* _bin_len, uint8_t* _bin ) {
    int len = strnlen( _hex, 2 * 1024 );

    if ( len == 0 && len % 2 == 1 )
        return false;
    *_bin_len = len / 2;
    for ( int i = 0; i < len / 2; i++ ) {
        int high = char2int( ( char ) _hex[i * 2] );
        int low = char2int( ( char ) _hex[i * 2 + 1] );
        if ( high < 0 || low < 0 ) {
            return false;
        }
        _bin[i] = ( unsigned char ) ( high * 16 + low );
    }
    return true;
}

void hash_g1( const size_t t, const size_t n ) {
    libff::inhibit_profiling_info = true;
    signatures::Bls bls_instance = signatures::Bls( t, n );

    nlohmann::json hash_in;

    std::ifstream hash_file( "hash.json" );
    hash_file >> hash_in;

    std::string to_be_hashed = hash_in["message"].get< std::string >();

    auto hash_bytes_arr = std::make_shared< std::array< uint8_t, 32 > >();
    if ( g_b_rehash ) {
        std::string hash_str = cryptlite::sha256::hash_hex( to_be_hashed );
        for ( size_t i = 0; i < 32; i++ ) {
            hash_bytes_arr->at( i ) = static_cast< uint8_t >( hash_str[i] );
        }
    } else {
        uint64_t bin_len;
        if ( !hex2carray( to_be_hashed.c_str(), &bin_len, hash_bytes_arr->data() ) ) {
            throw std::runtime_error( "Invalid hash" );
        }
    }

    std::pair< libff::alt_bn128_G1, std::string > p2vals;
    p2vals = bls_instance.HashtoG1withHint( hash_bytes_arr );  // original, what we really need

    nlohmann::json joG1 = nlohmann::json::object();
    joG1["g1"] = nlohmann::json::object();
    joG1["g1"]["hashPoint"] = nlohmann::json::object();
    joG1["g1"]["hashPoint"]["X"] = BLSutils::ConvertToString( p2vals.first.X );
    joG1["g1"]["hashPoint"]["Y"] = BLSutils::ConvertToString( p2vals.first.Y );
    joG1["g1"]["hint"] = p2vals.second;

    std::ofstream g1_file( "g1.json" );
    g1_file << joG1.dump() << "\n";

    if ( g_b_verbose_mode ) {
        std::cout << "G1.x " << p2vals.first.X << '\n';
        std::cout << "G1.y " << p2vals.first.Y << '\n';
        std::cout << "hint " << p2vals.second << '\n';
    }
}

int main( int argc, const char* argv[] ) {
    int r = 1;
    try {
        boost::program_options::options_description desc( "Options" );
        desc.add_options()( "help", "Show this help screen" )( "version", "Show version number" )(
            "t", boost::program_options::value< size_t >(), "Threshold" )( "n",
            boost::program_options::value< size_t >(),
            "Number of participants" )( "v", "Verbose mode (optional)" )(
            "rehash", "if not specified, then do not hash input message" );

        boost::program_options::variables_map vm;
        boost::program_options::store(
            boost::program_options::parse_command_line( argc, argv, desc ), vm );
        boost::program_options::notify( vm );

        if ( vm.count( "help" ) || argc <= 1 ) {
            std::cout << "BLS signature verification tool, version " << EXPAND_AS_STR( BLS_VERSION )
                      << '\n'
                      << "Usage:\n"
                      << "   " << argv[0]
                      << " --t <threshold> --n <num_participants> [--input <path>] [--v]" << '\n'
                      << desc << '\n';
            return 0;
        }
        if ( vm.count( "version" ) ) {
            std::cout << EXPAND_AS_STR( BLS_VERSION ) << '\n';
            return 0;
        }

        if ( vm.count( "t" ) == 0 ) {
            throw std::runtime_error( "--t is missing (see --help)" );
        }

        if ( vm.count( "n" ) == 0 ) {
            throw std::runtime_error( "--n is missing (see --help)" );
        }

        if ( vm.count( "v" ) ) {
            g_b_verbose_mode = true;
        }

        if ( vm.count( "rehash" ) ) {
            g_b_rehash = true;
        }

        size_t t = vm["t"].as< size_t >();
        size_t n = vm["n"].as< size_t >();
        if ( g_b_verbose_mode )
            std::cout << "t = " << t << '\n' << "n = " << n << '\n' << '\n';

        hash_g1( t, n );
        r = 0;  // success
    } catch ( std::exception& ex ) {
        r = 1;
        std::string str_what = ex.what();
        if ( str_what.empty() )
            str_what = "exception without description";
        std::cerr << "exception: " << str_what << "\n";
    } catch ( ... ) {
        r = 2;
        std::cerr << "unknown exception\n";
    }
    return r;
}
