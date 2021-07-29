/*
  Copyright (C) 2018-2020 SKALE Labs

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

  @file generate_key_system.cpp
  @author Oleh Nikolaiev
  @date 2020
*/


#include <fstream>

#include <bls/bls.h>
#include <tools/utils.h>

#include <dkg/dkg.h>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_b_verbose_mode = false;

void GenerateKeys( const size_t t, const size_t n, std::ostream& outfile ) {
    crypto::Bls bls_instance = crypto::Bls( t, n );
    crypto::Dkg dkg_instance = crypto::Dkg( t, n );

    auto polynomial = dkg_instance.GeneratePolynomial();

    std::vector< libff::alt_bn128_Fr > secret_keys( n );
    for ( size_t i = 0; i < n; ++i ) {
        secret_keys[i] = dkg_instance.PolynomialValue( polynomial, i + 1 );
    }

    std::vector< libff::alt_bn128_G2 > public_keys( n );
    for ( size_t i = 0; i < n; ++i ) {
        public_keys[i] = dkg_instance.GetPublicKeyFromSecretKey( secret_keys[i] );
        public_keys[i].to_affine_coordinates();
    }

    std::vector< size_t > idx( n );
    for ( size_t i = 0; i < n; ++i ) {
        idx[i] = i + 1;
    }
    auto lagrange_coeffs = ThresholdUtils::LagrangeCoeffs( idx, t );

    auto common_keys = bls_instance.KeysRecover( lagrange_coeffs, secret_keys );
    common_keys.second.to_affine_coordinates();

    nlohmann::json outdata;

    outdata["commonBLSPublicKey"]["0"] =
        ThresholdUtils::fieldElementToString( common_keys.second.X.c0 );
    outdata["commonBLSPublicKey"]["1"] =
        ThresholdUtils::fieldElementToString( common_keys.second.X.c1 );
    outdata["commonBLSPublicKey"]["2"] =
        ThresholdUtils::fieldElementToString( common_keys.second.Y.c0 );
    outdata["commonBLSPublicKey"]["3"] =
        ThresholdUtils::fieldElementToString( common_keys.second.Y.c1 );

    for ( size_t i = 0; i < n; ++i ) {
        outdata["privateKey"][std::to_string( i )] =
            ThresholdUtils::fieldElementToString( secret_keys[i] );

        outdata["BLSPublicKey"][std::to_string( i )]["0"] =
            ThresholdUtils::fieldElementToString( public_keys[i].X.c0 );
        outdata["BLSPublicKey"][std::to_string( i )]["1"] =
            ThresholdUtils::fieldElementToString( public_keys[i].X.c1 );
        outdata["BLSPublicKey"][std::to_string( i )]["2"] =
            ThresholdUtils::fieldElementToString( public_keys[i].Y.c0 );
        outdata["BLSPublicKey"][std::to_string( i )]["3"] =
            ThresholdUtils::fieldElementToString( public_keys[i].Y.c1 );
    }

    outfile << outdata.dump( 4 ) << '\n';
}

int main( int argc, const char* argv[] ) {
    std::ostream* p_out = &std::cout;
    int r = 1;
    try {
        boost::program_options::options_description desc( "Options" );
        desc.add_options()( "help", "Show this help screen" )( "version", "Show version number" )(
            "t", boost::program_options::value< size_t >(), "Threshold" )(
            "n", boost::program_options::value< size_t >(), "Number of participants" )( "output",
            boost::program_options::value< std::string >(),
            "Output file path; if not specified then use standard output" )(
            "v", "Verbose mode (optional)" );

        boost::program_options::variables_map vm;
        boost::program_options::store(
            boost::program_options::parse_command_line( argc, argv, desc ), vm );
        boost::program_options::notify( vm );

        if ( vm.count( "help" ) || argc <= 1 ) {
            std::cout << "BLS signature verification tool, version " << EXPAND_AS_STR( BLS_VERSION )
                      << '\n'
                      << "Usage:\n"
                      << "   " << argv[0]
                      << " --t <threshold> --n <num_participants> [--output <path>] [--v]" << '\n'
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

        size_t t = vm["t"].as< size_t >();
        size_t n = vm["n"].as< size_t >();

        if ( g_b_verbose_mode ) {
            std::cout << "t = " << t << '\n' << "n = " << n << '\n' << '\n';
        }

        std::string output;
        if ( vm.count( "output" ) ) {
            output = vm["output"].as< std::string >();
            if ( g_b_verbose_mode ) {
                std::cout << "output = " << output << '\n';
            }
            p_out = new std::ofstream( output, std::ofstream::binary );
        }

        GenerateKeys( t, n, *p_out );
        r = 0;
    } catch ( std::exception& ex ) {
        r = 1;
        std::string str_what = ex.what();
        if ( str_what.empty() ) {
            str_what = "exception without description";
        }
        std::cerr << "exception: " << str_what << "\n";
    } catch ( ... ) {
        r = 2;
        std::cerr << "unknown exception\n";
    }

    if ( p_out != &std::cout ) {
        delete ( std::ofstream* ) p_out;
    }

    return r;
}
