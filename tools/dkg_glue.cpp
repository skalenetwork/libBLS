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

  @file dkg_glue.cpp
  @author Oleh Nikolaiev
  @date 2019
*/


#include <dkg/dkg.h>
#include <tools/utils.h>
#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <third_party/json.hpp>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_b_verbose_mode = false;

// TODO - this entire function should be inside dkg

void GenerateSecretKeys( const size_t t, const size_t n, const std::vector< std::string >& input ) {
    libBLS::Dkg dkg_instance = libBLS::Dkg( t, n );

    std::vector< std::vector< libBLS::algebra::G2Point > > verification_vector( n );
    std::vector< std::vector< libBLS::algebra::FrScalar > > secret_key_contribution( n );

    for ( size_t i = 0; i < n; ++i ) {
        std::ifstream infile( input[i] );

        nlohmann::json data;

        infile >> data;

        size_t idx = stoi( data["idx"].get< std::string >() );

        secret_key_contribution[idx].resize( n );
        for ( size_t i = 0; i < n; ++i ) {
            secret_key_contribution[idx][i] = libBLS::algebra::FrScalar::fromString(
                data["secret_key_contribution"][std::to_string( i )].get< std::string >(),
                libBLS::Base::DEC );
        }

        verification_vector[idx].resize( t );
        for ( size_t i = 0; i < t; ++i ) {
            libBLS::algebra::FqElement first_coord_x = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["X"]["c0"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::FqElement first_coord_y = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["X"]["c1"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::Fq2Element first_coord( first_coord_x, first_coord_y );

            libBLS::algebra::FqElement second_coord_x = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["Y"]["c0"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::FqElement second_coord_y = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["Y"]["c1"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::Fq2Element second_coord( second_coord_x, second_coord_y );

            libBLS::algebra::FqElement third_coord_x = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["Z"]["c0"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::FqElement third_coord_y = libBLS::algebra::FqElement::fromString(
                data["verification_vector"][std::to_string( i )]["Z"]["c1"].get< std::string >(),
                libBLS::Base::DEC );
            libBLS::algebra::Fq2Element third_coord( third_coord_x, third_coord_y );


            verification_vector[idx][i] =
                libBLS::algebra::G2Point( first_coord, second_coord, third_coord );
        }
    }

    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = i; j < n; ++j ) {
            std::swap( secret_key_contribution[j][i], secret_key_contribution[i][j] );
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_key( n, libBLS::algebra::FrScalar::zero() );
    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = 0; j < n; ++j ) {
            if ( !dkg_instance.Verification(
                     i, secret_key_contribution[i][j], verification_vector[j] ) ) {
                throw std::runtime_error( std::to_string( j ) + "-th node was not verified by " +
                                          std::to_string( i ) + "-th node" );
            }
        }
    }

    std::vector< libBLS::algebra::G2Point > public_keys( n );
    libBLS::algebra::G2Point common_public_key = libBLS::algebra::G2Point::identity();
    for ( size_t i = 0; i < n; ++i ) {
        secret_key[i] = dkg_instance.SecretKeyShareCreate( secret_key_contribution[i] );
        public_keys[i] = verification_vector[i][0];
        common_public_key = common_public_key + public_keys[i];
    }

    for ( size_t i = 0; i < n; ++i ) {
        nlohmann::json BLS_key_file;

        BLS_key_file["insecureBLSPrivateKey"] = secret_key[i].toString( libBLS::Base::DEC );

        std::string str_file_name = "BLS_keys" + std::to_string( i ) + ".json";
        std::ofstream out( str_file_name.c_str() );

        libBLS::algebra::G2Point publ_key = dkg_instance.GetPublicKeyFromSecretKey( secret_key[i] );
        auto string_components = publ_key.toStringArray( libBLS::Base::DEC );
        BLS_key_file["BLSPublicKey0"] = string_components[0];
        BLS_key_file["BLSPublicKey1"] = string_components[1];
        BLS_key_file["BLSPublicKey2"] = string_components[2];
        BLS_key_file["BLSPublicKey3"] = string_components[3];

        if ( g_b_verbose_mode ) {
            std::cout << str_file_name << " file:\n" << BLS_key_file.dump( 4 ) << "\n\n";
        }
        out << BLS_key_file.dump( 4 ) << '\n';
    }


    nlohmann::json public_key_json;
    auto string_components = common_public_key.toStringArray( libBLS::Base::DEC );
    public_key_json["commonBLSPublicKey0"] = string_components[0];
    public_key_json["commonBLSPublicKey1"] = string_components[1];
    public_key_json["commonBLSPublicKey2"] = string_components[2];
    public_key_json["commonBLSPublicKey3"] = string_components[3];

    std::ofstream outfile_pk( "common_public_key.json" );
    outfile_pk << public_key_json.dump( 4 ) << "\n";
}


int main( int argc, const char* argv[] ) {
    try {
        boost::program_options::options_description desc( "Options" );
        desc.add_options()( "help", "Show this help screen" )( "version", "Show version number" )(
            "t", boost::program_options::value< size_t >(), "Threshold" )(
            "n", boost::program_options::value< size_t >(), "Number of participants" )( "input",
            boost::program_options::value< std::vector< std::string > >(),
            "Input file path with participants' data to create secret keys" )(
            "v", "Verbose mode (optional)" );

        boost::program_options::variables_map vm;
        boost::program_options::store(
            boost::program_options::parse_command_line( argc, argv, desc ), vm );
        boost::program_options::notify( vm );

        if ( vm.count( "help" ) || argc <= 1 ) {
            std::cout << "Distributed key generator, version " << EXPAND_AS_STR( BLS_VERSION )
                      << '\n'
                      << "Usage:\n"
                      << "   " << argv[0]
                      << " --t <threshold> --n <num_participants> [--input <path>] [--v]" << '\n'
                      << desc << "Output is set of secret_key<j>.json files where 0 <= j < n.\n";
            return 0;
        }
        if ( vm.count( "version" ) ) {
            std::cout << EXPAND_AS_STR( BLS_VERSION ) << '\n';
            return 0;
        }

        if ( vm.count( "t" ) == 0 )
            throw std::runtime_error( "--t is missing (see --help)" );
        if ( vm.count( "n" ) == 0 )
            throw std::runtime_error( "--n is missing (see --help)" );

        if ( vm.count( "v" ) )
            g_b_verbose_mode = true;

        size_t t = vm["t"].as< size_t >();
        size_t n = vm["n"].as< size_t >();
        if ( g_b_verbose_mode )
            std::cout << "t = " << t << '\n' << "n = " << n << '\n' << '\n';

        std::vector< std::string > input;
        if ( vm.count( "input" ) ) {
            input = vm["input"].as< std::vector< std::string > >();
            if ( g_b_verbose_mode ) {
                std::cout << "input =\n";
                for ( auto& elem : input )
                    std::cout << elem << '\n';
            }
        }

        GenerateSecretKeys( t, n, input );
        return 0;  // success
    } catch ( std::exception& ex ) {
        std::string str_what = ex.what();
        if ( str_what.empty() )
            str_what = "exception without description";
        std::cerr << "exception: " << str_what << "\n";
    } catch ( ... ) {
        std::cerr << "unknown exception\n";
    }
    return 1;
}
