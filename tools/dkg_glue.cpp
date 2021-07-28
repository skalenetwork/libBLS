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

#include <fstream>

#include <third_party/json.hpp>

#include <boost/program_options.hpp>

#define EXPAND_AS_STR( x ) __EXPAND_AS_STR__( x )
#define __EXPAND_AS_STR__( x ) #x

static bool g_b_verbose_mode = false;


void GenerateSecretKeys( const size_t t, const size_t n, const std::vector< std::string >& input ) {
    signatures::Dkg dkg_instance = signatures::Dkg( t, n );

    std::vector< std::vector< libff::alt_bn128_G2 > > verification_vector( n );
    std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_contribution( n );

    for ( size_t i = 0; i < n; ++i ) {
        std::ifstream infile( input[i] );

        nlohmann::json data;

        infile >> data;

        size_t idx = stoi( data["idx"].get< std::string >() );

        secret_key_contribution[idx].resize( n );
        for ( size_t i = 0; i < n; ++i ) {
            secret_key_contribution[idx][i] = libff::alt_bn128_Fr(
                data["secret_key_contribution"][std::to_string( i )].get< std::string >().c_str() );
        }

        verification_vector[idx].resize( t );
        for ( size_t i = 0; i < t; ++i ) {
            libff::alt_bn128_Fq first_coord_x =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["X"]["c0"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq first_coord_y =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["X"]["c1"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq2 first_coord = libff::alt_bn128_Fq2( first_coord_x, first_coord_y );

            libff::alt_bn128_Fq second_coord_x =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["Y"]["c0"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq second_coord_y =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["Y"]["c1"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq2 second_coord =
                libff::alt_bn128_Fq2( second_coord_x, second_coord_y );

            libff::alt_bn128_Fq third_coord_x =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["Z"]["c0"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq third_coord_y =
                libff::alt_bn128_Fq( data["verification_vector"][std::to_string( i )]["Z"]["c1"]
                                         .get< std::string >()
                                         .c_str() );
            libff::alt_bn128_Fq2 third_coord = libff::alt_bn128_Fq2( third_coord_x, third_coord_y );


            verification_vector[idx][i] =
                libff::alt_bn128_G2( first_coord, second_coord, third_coord );
        }
    }

    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = i; j < n; ++j ) {
            std::swap( secret_key_contribution[j][i], secret_key_contribution[i][j] );
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_key( n, libff::alt_bn128_Fr::zero() );
    for ( size_t i = 0; i < n; ++i ) {
        for ( size_t j = 0; j < n; ++j ) {
            if ( !dkg_instance.Verification(
                     i, secret_key_contribution[i][j], verification_vector[j] ) ) {
                throw std::runtime_error( std::to_string( j ) + "-th node was not verified by " +
                                          std::to_string( i ) + "-th node" );
            }
        }
    }

    std::vector< libff::alt_bn128_G2 > public_keys( n );
    libff::alt_bn128_G2 common_public_key = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < n; ++i ) {
        secret_key[i] = dkg_instance.SecretKeyShareCreate( secret_key_contribution[i] );
        public_keys[i] = verification_vector[i][0];
        common_public_key = common_public_key + public_keys[i];
    }

    for ( size_t i = 0; i < n; ++i ) {
        nlohmann::json BLS_key_file;

        BLS_key_file["insecureBLSPrivateKey"] =
            ThresholdUtils::fieldElementToString( secret_key[i] );

        std::string str_file_name = "BLS_keys" + std::to_string( i ) + ".json";
        std::ofstream out( str_file_name.c_str() );

        libff::alt_bn128_G2 publ_key = dkg_instance.GetPublicKeyFromSecretKey( secret_key[i] );
        publ_key.to_affine_coordinates();
        BLS_key_file["BLSPublicKey0"] = ThresholdUtils::fieldElementToString( publ_key.X.c0 );
        BLS_key_file["BLSPublicKey1"] = ThresholdUtils::fieldElementToString( publ_key.X.c1 );
        BLS_key_file["BLSPublicKey2"] = ThresholdUtils::fieldElementToString( publ_key.Y.c0 );
        BLS_key_file["BLSPublicKey3"] = ThresholdUtils::fieldElementToString( publ_key.Y.c1 );

        if ( g_b_verbose_mode ) {
            std::cout << str_file_name << " file:\n" << BLS_key_file.dump( 4 ) << "\n\n";
        }
        out << BLS_key_file.dump( 4 ) << '\n';
    }

    common_public_key.to_affine_coordinates();
    nlohmann::json public_key_json;
    public_key_json["commonBLSPublicKey0"] =
        ThresholdUtils::fieldElementToString( common_public_key.X.c0 );
    public_key_json["commonBLSPublicKey1"] =
        ThresholdUtils::fieldElementToString( common_public_key.X.c1 );
    public_key_json["commonBLSPublicKey2"] =
        ThresholdUtils::fieldElementToString( common_public_key.Y.c0 );
    public_key_json["commonBLSPublicKey3"] =
        ThresholdUtils::fieldElementToString( common_public_key.Y.c1 );

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
