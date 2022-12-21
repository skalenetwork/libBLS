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

  @file unit_tests_bls.cpp
  @author Oleh Nikolaiev
  @date 2019
 */


#include <bls/bls.h>
#include <tools/utils.h>

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( libBls )

BOOST_AUTO_TEST_CASE( zeroSecretKey ) {
    std::cout << "Testing zeroSecretKey\n";

    libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::zero();

    libBLS::Bls obj = libBLS::Bls( 1, 1 );

    std::string message = "Waiting for exception";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_REQUIRE_THROW( obj.Signing( hash, secret_key ), libBLS::ThresholdUtils::ZeroSecretKey );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( singleBlsrun ) {
    std::cout << "Testing singleBlsrun\n";

    libBLS::Bls obj = libBLS::Bls( 1, 1 );

    std::pair< libff::alt_bn128_Fr, libff::alt_bn128_G2 > keys = obj.KeyGeneration();

    libff::alt_bn128_Fr secret_key = keys.first;
    libff::alt_bn128_G2 public_key = keys.second;

    std::string message = "testingSKALE";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_CHECK( hash.is_well_formed() );  // is hash belongs to group G1

    libff::alt_bn128_G1 signature = obj.Signing( hash, secret_key );

    BOOST_CHECK( signature.is_well_formed() );  // is signature belongs to group G1

    BOOST_REQUIRE( obj.Verification( message, signature, public_key ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( SimillarHashes ) {
    std::cout << "Testing SimillarHashes\n";

    libBLS::Bls obj = libBLS::Bls( 1, 1 );

    const char message[5] = { 104, 101, 108, 108, 111 };

    BOOST_REQUIRE( obj.HashBytes( message, 5 ) == obj.Hashing( "hello" ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( BlsThresholdSignatures ) {
    std::cout << "Testing BlsThresholdSignatures\n";

    libBLS::Bls obj = libBLS::Bls( 2, 2 );

    libff::alt_bn128_Fr fst_secret = libff::alt_bn128_Fr(
        "4160780231445160889237664391382223604184857153814275770598791864649971919844" );
    libff::alt_bn128_Fr snd_secret = libff::alt_bn128_Fr(
        "1242918195122561069654878094438043001503525111785440814423171735067409748785" );

    std::vector< libff::alt_bn128_Fr > secret_keys = { fst_secret, snd_secret };

    // correct public key for this pair of secret keys
    libff::alt_bn128_Fq first_coord_x = libff::alt_bn128_Fq(
        "3587726236349347862079704257548861220640944168911165295818761560004029551650" );
    libff::alt_bn128_Fq first_coord_y = libff::alt_bn128_Fq(
        "19787254980733313985916848161712839039049583927978588316450905648226551363679" );
    libff::alt_bn128_Fq2 first_coord = libff::alt_bn128_Fq2( first_coord_x, first_coord_y );

    libff::alt_bn128_Fq second_coord_x = libff::alt_bn128_Fq(
        "6758417170296194890394379186698826295431221115224861568917420522501294769196" );
    libff::alt_bn128_Fq second_coord_y = libff::alt_bn128_Fq(
        "1055763161413596692895291379377477236343960686086193159772574402659834140867" );
    libff::alt_bn128_Fq2 second_coord = libff::alt_bn128_Fq2( second_coord_x, second_coord_y );

    libff::alt_bn128_G2 public_key =
        libff::alt_bn128_G2( first_coord, second_coord, libff::alt_bn128_Fq2::one() );

    std::string message = "testingSKALE";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_CHECK( hash.is_well_formed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes = { 1, 2 };

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
        libBLS::ThresholdUtils::LagrangeCoeffs( testing_nodes, 2 );

    auto recovered_keys = obj.KeysRecover( lagrange_coeffs, secret_keys );

    libff::alt_bn128_G2 common_public = recovered_keys.second;

    BOOST_REQUIRE( public_key == common_public );

    libff::alt_bn128_G1 fst_signature = obj.Signing( hash, fst_secret );
    libff::alt_bn128_G1 snd_signature = obj.Signing( hash, snd_secret );

    std::vector< libff::alt_bn128_G1 > single_signatures = { fst_signature, snd_signature };

    libff::alt_bn128_G1 common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_REQUIRE( obj.Verification( message, common_signature, common_public ) );

    std::cout << "DONE\n";
}


BOOST_AUTO_TEST_CASE( BlsThresholdSignaturesFalse ) {
    std::cout << "Testing BlsThresholdSignaturesFalse\n";

    libBLS::Bls obj = libBLS::Bls( 2, 2 );

    //  the last digit was changed
    libff::alt_bn128_Fr fst_secret = libff::alt_bn128_Fr(
        "4160780231445160889237664391382223604184857153814275770598791864649971919843" );
    libff::alt_bn128_Fr snd_secret = libff::alt_bn128_Fr(
        "1242918195122561069654878094438043001503525111785440814423171735067409748785" );

    std::vector< libff::alt_bn128_Fr > secret_keys = { fst_secret, snd_secret };

    // correct public key for secret keys from previous test
    libff::alt_bn128_Fq first_coord_x = libff::alt_bn128_Fq(
        "3587726236349347862079704257548861220640944168911165295818761560004029551650" );
    libff::alt_bn128_Fq first_coord_y = libff::alt_bn128_Fq(
        "19787254980733313985916848161712839039049583927978588316450905648226551363679" );
    libff::alt_bn128_Fq2 first_coord = libff::alt_bn128_Fq2( first_coord_x, first_coord_y );

    libff::alt_bn128_Fq second_coord_x = libff::alt_bn128_Fq(
        "6758417170296194890394379186698826295431221115224861568917420522501294769196" );
    libff::alt_bn128_Fq second_coord_y = libff::alt_bn128_Fq(
        "1055763161413596692895291379377477236343960686086193159772574402659834140867" );
    libff::alt_bn128_Fq2 second_coord = libff::alt_bn128_Fq2( second_coord_x, second_coord_y );

    libff::alt_bn128_G2 public_key =
        libff::alt_bn128_G2( first_coord, second_coord, libff::alt_bn128_Fq2::one() );

    std::string message = "testingSKALE";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_CHECK( hash.is_well_formed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes = { 1, 2 };

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
        libBLS::ThresholdUtils::LagrangeCoeffs( testing_nodes, 2 );

    libff::alt_bn128_G1 fst_signature = obj.Signing( hash, fst_secret );
    libff::alt_bn128_G1 snd_signature = obj.Signing( hash, snd_secret );

    std::vector< libff::alt_bn128_G1 > single_signatures = { fst_signature, snd_signature };

    libff::alt_bn128_G1 common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_REQUIRE( obj.Verification( message, common_signature, public_key ) == false );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( BlsThresholdSignaturesReal ) {
    std::cout << "Testing BlsThresholdSignaturesReal\n";

    libBLS::Bls obj = libBLS::Bls( 11, 16 );

    // creating a polynomial
    std::vector< libff::alt_bn128_Fr > coeffs( 11 );

    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();

        while ( elem == 0 ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        secret_keys[i] = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            secret_keys[i] =
                secret_keys[i] +
                coeffs[j] *
                    libff::power( libff::alt_bn128_Fr( std::to_string( i + 1 ).c_str() ), j );
        }
    }

    std::string message = "testingSKALE";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_CHECK( hash.is_well_formed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        testing_nodes[i] = i + 1;
    }

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
        libBLS::ThresholdUtils::LagrangeCoeffs( testing_nodes, 11 );

    auto recovered_keys = obj.KeysRecover( lagrange_coeffs, secret_keys );

    libff::alt_bn128_Fr common_secret = recovered_keys.first;
    libff::alt_bn128_G2 common_public = recovered_keys.second;

    BOOST_REQUIRE( common_secret == coeffs[0] );

    BOOST_CHECK( common_public.is_well_formed() );

    std::vector< libff::alt_bn128_G1 > single_signatures( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        single_signatures[i] = obj.Signing( hash, secret_keys[i] );
    }

    libff::alt_bn128_G1 common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_CHECK( common_signature == obj.Signing( hash, common_secret ) );

    BOOST_REQUIRE( obj.Verification( message, common_signature, common_public ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( simillarSignatures ) {
    std::cout << "Testing simillarSignatures\n";

    libBLS::Bls obj = libBLS::Bls( 11, 16 );

    // creating a polynomial
    std::vector< libff::alt_bn128_Fr > coeffs( 11 );

    for ( auto& elem : coeffs ) {
        elem = libff::alt_bn128_Fr::random_element();

        while ( elem == 0 ) {
            elem = libff::alt_bn128_Fr::random_element();
        }
    }

    std::vector< libff::alt_bn128_Fr > secret_keys( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        secret_keys[i] = libff::alt_bn128_Fr::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            secret_keys[i] =
                secret_keys[i] +
                coeffs[j] *
                    libff::power( libff::alt_bn128_Fr( std::to_string( i + 1 ).c_str() ), j );
        }
    }

    std::string message = "testingSKALE";

    libff::alt_bn128_G1 hash = obj.Hashing( message );

    BOOST_CHECK( hash.is_well_formed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes_fst( 11 );  // first group - nodes from 1 up to 12
    for ( size_t i = 0; i < 11; ++i ) {
        testing_nodes_fst[i] = i + 1;
    }

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs_fst =
        libBLS::ThresholdUtils::LagrangeCoeffs( testing_nodes_fst, 11 );

    auto recovered_keys_fst = obj.KeysRecover( lagrange_coeffs_fst, secret_keys );

    libff::alt_bn128_Fr common_secret_fst = recovered_keys_fst.first;
    libff::alt_bn128_G2 common_public_fst = recovered_keys_fst.second;

    BOOST_CHECK( common_public_fst.is_well_formed() );

    std::vector< libff::alt_bn128_G1 > single_signatures_fst( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        single_signatures_fst[i] = obj.Signing( hash, secret_keys[i] );
    }

    libff::alt_bn128_G1 common_signature_fst =
        obj.SignatureRecover( single_signatures_fst, lagrange_coeffs_fst );

    std::map< size_t, libff::alt_bn128_Fr > nodes;
    // initializing map
    for ( size_t i = 0; i < 16; ++i ) {
        nodes[i] = secret_keys[i];
    }

    std::srand( unsigned( std::time( 0 ) ) );
    std::vector< size_t > testing_nodes_snd;  // the second group - random nodes
    while ( testing_nodes_snd.size() < 11 ) {
        int random_node = std::rand() % 16;
        if ( nodes.find( random_node ) != nodes.end() ) {
            testing_nodes_snd.push_back( random_node + 1 );
            nodes.erase( random_node );
        }
    }

    std::vector< libff::alt_bn128_Fr > lagrange_coeffs_snd =
        libBLS::ThresholdUtils::LagrangeCoeffs( testing_nodes_snd, 11 );

    std::vector< libff::alt_bn128_Fr > secret_keys_for_random_subgroup( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        secret_keys_for_random_subgroup[i] = secret_keys[testing_nodes_snd[i] - 1];
    }

    auto recovered_keys_snd =
        obj.KeysRecover( lagrange_coeffs_snd, secret_keys_for_random_subgroup );

    libff::alt_bn128_Fr common_secret_snd = recovered_keys_snd.first;
    libff::alt_bn128_G2 common_public_snd = recovered_keys_snd.second;

    BOOST_CHECK( common_public_snd.is_well_formed() );


    std::vector< libff::alt_bn128_G1 > single_signatures_snd( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        single_signatures_snd[i] = obj.Signing( hash, secret_keys_for_random_subgroup[i] );
    }

    libff::alt_bn128_G1 common_signature_snd =
        obj.SignatureRecover( single_signatures_snd, lagrange_coeffs_snd );

    BOOST_REQUIRE( common_signature_snd == common_signature_fst );
    BOOST_REQUIRE( common_public_snd == common_public_fst );
    BOOST_REQUIRE( common_secret_fst == common_secret_snd );

    std::cout << "DONE\n";
}

/*
running this test takes more than 2 days(48 hours) for this moment

BOOST_AUTO_TEST_CASE(differentMessages) {
  std::cout << "Testing different message length\n";

  libBLS::Bls obj = libBLS::Bls(11, 16);

  std::vector<size_t> testing_nodes(11);  // first group - nodes from 1 up to 12
  for (size_t i = 0; i < 11; ++i) {
    testing_nodes[i] = i + 1;
  }

  std::vector<libff::alt_bn128_Fr> lagrange_coeffs = obj.LagrangeCoeffs(testing_nodes);

  // creating a polynomial
  std::vector<libff::alt_bn128_Fr> coeffs(11);

  for (auto& elem : coeffs) {
    elem = libff::alt_bn128_Fr::random_element();

    while (elem == 0) {
      elem = libff::alt_bn128_Fr::random_element();
    }
  }


  std::vector<libff::alt_bn128_Fr> secret_keys(16);
  for (size_t i = 0; i < 16; ++i) {
    secret_keys[i] = libff::alt_bn128_Fr::zero();

    for (size_t j = 0; j < 11; ++j) {
      secret_keys[i] = secret_keys[i] + coeffs[j] *
                              libff::power(libff::alt_bn128_Fr(std::to_string(i + 1).c_str()), j);
    }
  }

  auto recovered_keys = obj.KeysRecover(lagrange_coeffs, secret_keys);
  libff::alt_bn128_G2 common_public = recovered_keys.second;


  std::srand(unsigned(std::time(0)));

  std::string message = "";
  for (size_t length = 1; length < 1000000; ++length) {
    message += char(std::rand() % 2);

    libff::alt_bn128_G1 hash = obj.Hashing(message);

    BOOST_CHECK(hash.is_well_formed());  // hash belongs to group G1

    std::vector<libff::alt_bn128_G1> single_signatures(16);
    for (size_t i = 0; i < 16; ++i) {
      single_signatures[i] = obj.Signing(hash, secret_keys[i]);
    }

    libff::alt_bn128_G1 common_signature = obj.SignatureRecover(single_signatures, lagrange_coeffs);

    BOOST_REQUIRE(obj.Verification(message, common_signature, common_public));
  }
}*/

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( Exceptions )


BOOST_AUTO_TEST_CASE( SignVerification ) {
    std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % ( num_all - 1 ) + 2;
    libBLS::Bls obj( num_signed, num_all );
    libBLS::Bls obj_2_2( 2, 2 );

    libff::alt_bn128_G1 sign;
    sign.X = libff::alt_bn128_Fq( "123" );
    sign.Y = libff::alt_bn128_Fq( "234" );
    sign.Z = libff::alt_bn128_Fq( "345" );

    BOOST_REQUIRE_THROW(
        obj.Verification( "bla-bla-bla", sign, libff::alt_bn128_G2::random_element() ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    libff::alt_bn128_G2 pkey = libff::alt_bn128_G2::random_element();
    pkey.X.c1 = 123;

    BOOST_REQUIRE_THROW(
        obj.Verification( "bla-bla-bla", libff::alt_bn128_G1::random_element(), pkey ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    std::vector< libff::alt_bn128_Fr > coeffs;
    coeffs.push_back( libff::alt_bn128_Fr::random_element() );
    std::vector< libff::alt_bn128_Fr > shares;
    shares.push_back( libff::alt_bn128_Fr::random_element() );

    BOOST_REQUIRE_THROW(
        obj.KeysRecover( coeffs, shares ), libBLS::ThresholdUtils::IncorrectInput );

    coeffs.clear();
    shares.clear();

    coeffs.push_back( libff::alt_bn128_Fr::random_element() );
    coeffs.push_back( libff::alt_bn128_Fr::random_element() );

    shares.push_back( libff::alt_bn128_Fr::random_element() );
    shares.push_back( libff::alt_bn128_Fr::zero() );

    BOOST_REQUIRE_THROW(
        obj_2_2.KeysRecover( coeffs, shares ), libBLS::ThresholdUtils::ZeroSecretKey );

    coeffs.clear();
    coeffs.push_back( libff::alt_bn128_Fr::random_element() );

    std::vector< libff::alt_bn128_G1 > sig_shares;
    sig_shares.push_back( libff::alt_bn128_G1::random_element() );

    BOOST_REQUIRE_THROW(
        obj.SignatureRecover( sig_shares, coeffs ), libBLS::ThresholdUtils::IncorrectInput );

    coeffs.clear();
    sig_shares.clear();

    coeffs.push_back( libff::alt_bn128_Fr::random_element() );
    coeffs.push_back( libff::alt_bn128_Fr::random_element() );

    sig_shares.push_back( libff::alt_bn128_G1::random_element() );
    libff::alt_bn128_G1 g1_spoiled = libff::alt_bn128_G1::random_element();
    g1_spoiled.Y = 257;
    sig_shares.push_back( g1_spoiled );

    BOOST_REQUIRE_THROW(
        obj_2_2.SignatureRecover( sig_shares, coeffs ), libBLS::ThresholdUtils::IsNotWellFormed );

    std::vector< size_t > idx = { 1 };

    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::LagrangeCoeffs( idx, num_signed ),
        libBLS::ThresholdUtils::IncorrectInput );

    idx.clear();
    idx = { 1, 1 };

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::LagrangeCoeffs( idx, 2 ), libBLS::ThresholdUtils::IncorrectInput );

    std::cerr << "Exceptions test passed" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
