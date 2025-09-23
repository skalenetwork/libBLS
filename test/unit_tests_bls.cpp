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


#include "test/utils.h"
#include <bls/bls.h>
#include <tools/utils.h>

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>
#include <random>

std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );

BOOST_TEST_GLOBAL_CONFIGURATION( GlobalConfig );

std::string rand32HexStr() {
    std::array< char, 16 > s = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c',
        'd', 'e', 'f' };

    std::string res = "";
    for ( size_t i = 0; i < 32; ++i ) {
        res.push_back( *( s.begin() + rand_gen() % 16 ) );
    }

    return res;
}

BOOST_AUTO_TEST_SUITE( libBls )

BOOST_AUTO_TEST_CASE( zeroSecretKey ) {
    std::cout << "Testing zeroSecretKey\n";

    libBLS::algebra::FrScalar secret_key = libBLS::algebra::FrScalar::zero();

    libBLS::Bls obj = libBLS::Bls( 1, 1 );

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::random();

    BOOST_REQUIRE_THROW( obj.Signing( hash, secret_key ), libBLS::ThresholdUtils::ZeroSecretKey );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( singleBlsrun ) {
    std::cout << "Testing singleBlsrun\n";

    libBLS::Bls obj = libBLS::Bls( 1, 1 );

    std::pair< libBLS::algebra::FrScalar, libBLS::algebra::G2Point > keys = obj.KeyGeneration();

    libBLS::algebra::FrScalar secret_key = keys.first;
    libBLS::algebra::G2Point public_key = keys.second;

    auto message = randomByteArray< 32 >();

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::fromHash( message );

    BOOST_CHECK( hash.isWellFormed() );  // is hash belongs to group G1

    libBLS::algebra::G1Point signature = obj.Signing( hash, secret_key );

    BOOST_CHECK( signature.isWellFormed() );  // is signature belongs to group G1

    BOOST_REQUIRE( obj.Verify( message, signature, public_key ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( BlsThresholdSignatures ) {
    std::cout << "Testing BlsThresholdSignatures\n";

    libBLS::Bls obj = libBLS::Bls( 2, 2 );

    libBLS::algebra::FrScalar fst_secret = libBLS::algebra::FrScalar::fromString(
        "4160780231445160889237664391382223604184857153814275770598791864649971919844",
        libBLS::Base::DEC );
    libBLS::algebra::FrScalar snd_secret = libBLS::algebra::FrScalar::fromString(
        "1242918195122561069654878094438043001503525111785440814423171735067409748785",
        libBLS::Base::DEC );

    std::vector< libBLS::algebra::FrScalar > secret_keys = { fst_secret, snd_secret };

    // correct public key for this pair of secret keys
    libBLS::algebra::FqElement first_coord_x = libBLS::algebra::FqElement::fromString(
        "3587726236349347862079704257548861220640944168911165295818761560004029551650",
        libBLS::Base::DEC );
    libBLS::algebra::FqElement first_coord_y = libBLS::algebra::FqElement::fromString(
        "19787254980733313985916848161712839039049583927978588316450905648226551363679",
        libBLS::Base::DEC );
    libBLS::algebra::Fq2Element first_coord =
        libBLS::algebra::Fq2Element( first_coord_x, first_coord_y );

    libBLS::algebra::FqElement second_coord_x = libBLS::algebra::FqElement::fromString(
        "6758417170296194890394379186698826295431221115224861568917420522501294769196",
        libBLS::Base::DEC );
    libBLS::algebra::FqElement second_coord_y = libBLS::algebra::FqElement::fromString(
        "1055763161413596692895291379377477236343960686086193159772574402659834140867",
        libBLS::Base::DEC );
    libBLS::algebra::Fq2Element second_coord =
        libBLS::algebra::Fq2Element( second_coord_x, second_coord_y );

    libBLS::algebra::G2Point public_key =
        libBLS::algebra::G2Point( first_coord, second_coord, libBLS::algebra::Fq2Element::one() );

    auto message = randomByteArray< 32 >();

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::fromHash( message );

    BOOST_CHECK( hash.isWellFormed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes = { 1, 2 };

    std::vector< libBLS::algebra::FrScalar > lagrange_coeffs =
        libBLS::algebra::lagrangeCoeffs( testing_nodes, 2 );

    auto recovered_keys = obj.KeysRecover( lagrange_coeffs, secret_keys );

    libBLS::algebra::G2Point common_public = recovered_keys.second;

    BOOST_REQUIRE( public_key == common_public );

    libBLS::algebra::G1Point fst_signature = obj.Signing( hash, fst_secret );
    libBLS::algebra::G1Point snd_signature = obj.Signing( hash, snd_secret );

    std::vector< libBLS::algebra::G1Point > single_signatures = { fst_signature, snd_signature };

    libBLS::algebra::G1Point common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_REQUIRE( obj.Verify( message, common_signature, common_public ) );

    std::cout << "DONE\n";
}


BOOST_AUTO_TEST_CASE( BlsThresholdSignaturesFalse ) {
    std::cout << "Testing BlsThresholdSignaturesFalse\n";

    libBLS::Bls obj = libBLS::Bls( 2, 2 );

    //  the last digit was changed
    libBLS::algebra::FrScalar fst_secret = libBLS::algebra::FrScalar::fromString(
        "4160780231445160889237664391382223604184857153814275770598791864649971919843",
        libBLS::Base::DEC );
    libBLS::algebra::FrScalar snd_secret = libBLS::algebra::FrScalar::fromString(
        "1242918195122561069654878094438043001503525111785440814423171735067409748785",
        libBLS::Base::DEC );

    std::vector< libBLS::algebra::FrScalar > secret_keys = { fst_secret, snd_secret };

    // correct public key for secret keys from previous test
    libBLS::algebra::FqElement first_coord_x = libBLS::algebra::FqElement::fromString(
        "3587726236349347862079704257548861220640944168911165295818761560004029551650",
        libBLS::Base::DEC );
    libBLS::algebra::FqElement first_coord_y = libBLS::algebra::FqElement::fromString(
        "19787254980733313985916848161712839039049583927978588316450905648226551363679",
        libBLS::Base::DEC );
    libBLS::algebra::Fq2Element first_coord =
        libBLS::algebra::Fq2Element( first_coord_x, first_coord_y );

    libBLS::algebra::FqElement second_coord_x = libBLS::algebra::FqElement::fromString(
        "6758417170296194890394379186698826295431221115224861568917420522501294769196",
        libBLS::Base::DEC );
    libBLS::algebra::FqElement second_coord_y = libBLS::algebra::FqElement::fromString(
        "1055763161413596692895291379377477236343960686086193159772574402659834140867",
        libBLS::Base::DEC );
    libBLS::algebra::Fq2Element second_coord =
        libBLS::algebra::Fq2Element( second_coord_x, second_coord_y );

    libBLS::algebra::G2Point public_key =
        libBLS::algebra::G2Point( first_coord, second_coord, libBLS::algebra::Fq2Element::one() );

    auto message = randomByteArray< 32 >();

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::fromHash( message );

    BOOST_CHECK( hash.isWellFormed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes = { 1, 2 };

    std::vector< libBLS::algebra::FrScalar > lagrange_coeffs =
        libBLS::algebra::lagrangeCoeffs( testing_nodes, 2 );

    libBLS::algebra::G1Point fst_signature = obj.Signing( hash, fst_secret );
    libBLS::algebra::G1Point snd_signature = obj.Signing( hash, snd_secret );

    std::vector< libBLS::algebra::G1Point > single_signatures = { fst_signature, snd_signature };

    libBLS::algebra::G1Point common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_REQUIRE( obj.Verify( message, common_signature, public_key ) == false );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( BlsThresholdSignaturesReal ) {
    std::cout << "Testing BlsThresholdSignaturesReal\n";

    libBLS::Bls obj = libBLS::Bls( 11, 16 );

    // creating a polynomial
    std::vector< libBLS::algebra::FrScalar > coeffs( 11 );

    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();

        while ( elem == 0 ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        secret_keys[i] = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            secret_keys[i] =
                secret_keys[i] + coeffs[j] * libBLS::algebra::power(
                                                 libBLS::algebra::FrScalar::fromString(
                                                     std::to_string( i + 1 ), libBLS::Base::DEC ),
                                                 j );
        }
    }

    auto message = randomByteArray< 32 >();

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::fromHash( message );

    BOOST_CHECK( hash.isWellFormed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        testing_nodes[i] = i + 1;
    }

    std::vector< libBLS::algebra::FrScalar > lagrange_coeffs =
        libBLS::algebra::lagrangeCoeffs( testing_nodes, 11 );

    auto recovered_keys = obj.KeysRecover( lagrange_coeffs, secret_keys );

    libBLS::algebra::FrScalar common_secret = recovered_keys.first;
    libBLS::algebra::G2Point common_public = recovered_keys.second;

    BOOST_REQUIRE( common_secret == coeffs[0] );

    BOOST_CHECK( common_public.isWellFormed() );

    std::vector< libBLS::algebra::G1Point > single_signatures( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        single_signatures[i] = obj.Signing( hash, secret_keys[i] );
    }

    libBLS::algebra::G1Point common_signature =
        obj.SignatureRecover( single_signatures, lagrange_coeffs );

    BOOST_CHECK( common_signature == obj.Signing( hash, common_secret ) );

    BOOST_REQUIRE( obj.Verify( message, common_signature, common_public ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_CASE( simillarSignatures ) {
    std::cout << "Testing simillarSignatures\n";

    libBLS::Bls obj = libBLS::Bls( 11, 16 );

    // creating a polynomial
    std::vector< libBLS::algebra::FrScalar > coeffs( 11 );

    for ( auto& elem : coeffs ) {
        elem = libBLS::algebra::FrScalar::random();

        while ( elem == 0 ) {
            elem = libBLS::algebra::FrScalar::random();
        }
    }

    std::vector< libBLS::algebra::FrScalar > secret_keys( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        secret_keys[i] = libBLS::algebra::FrScalar::zero();

        for ( size_t j = 0; j < 11; ++j ) {
            secret_keys[i] =
                secret_keys[i] + coeffs[j] * libBLS::algebra::power(
                                                 libBLS::algebra::FrScalar::fromString(
                                                     std::to_string( i + 1 ), libBLS::Base::DEC ),
                                                 j );
        }
    }

    auto message = randomByteArray< 32 >();

    libBLS::algebra::G1Point hash = libBLS::algebra::G1Point::fromHash( message );

    BOOST_CHECK( hash.isWellFormed() );  // hash belongs to group G1

    std::vector< size_t > testing_nodes_fst( 11 );  // first group - nodes from 1 up to 12
    for ( size_t i = 0; i < 11; ++i ) {
        testing_nodes_fst[i] = i + 1;
    }

    std::vector< libBLS::algebra::FrScalar > lagrange_coeffs_fst =
        libBLS::algebra::lagrangeCoeffs( testing_nodes_fst, 11 );

    auto recovered_keys_fst = obj.KeysRecover( lagrange_coeffs_fst, secret_keys );

    libBLS::algebra::FrScalar common_secret_fst = recovered_keys_fst.first;
    libBLS::algebra::G2Point common_public_fst = recovered_keys_fst.second;

    BOOST_CHECK( common_public_fst.isWellFormed() );

    std::vector< libBLS::algebra::G1Point > single_signatures_fst( 16 );
    for ( size_t i = 0; i < 16; ++i ) {
        single_signatures_fst[i] = obj.Signing( hash, secret_keys[i] );
    }

    libBLS::algebra::G1Point common_signature_fst =
        obj.SignatureRecover( single_signatures_fst, lagrange_coeffs_fst );

    std::map< size_t, libBLS::algebra::FrScalar > nodes;
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

    std::vector< libBLS::algebra::FrScalar > lagrange_coeffs_snd =
        libBLS::algebra::lagrangeCoeffs( testing_nodes_snd, 11 );

    std::vector< libBLS::algebra::FrScalar > secret_keys_for_random_subgroup( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        secret_keys_for_random_subgroup[i] = secret_keys[testing_nodes_snd[i] - 1];
    }

    auto recovered_keys_snd =
        obj.KeysRecover( lagrange_coeffs_snd, secret_keys_for_random_subgroup );

    libBLS::algebra::FrScalar common_secret_snd = recovered_keys_snd.first;
    libBLS::algebra::G2Point common_public_snd = recovered_keys_snd.second;

    BOOST_CHECK( common_public_snd.isWellFormed() );


    std::vector< libBLS::algebra::G1Point > single_signatures_snd( 11 );
    for ( size_t i = 0; i < 11; ++i ) {
        single_signatures_snd[i] = obj.Signing( hash, secret_keys_for_random_subgroup[i] );
    }

    libBLS::algebra::G1Point common_signature_snd =
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

  std::vector<libBLS::algebra::FrScalar> lagrange_coeffs = obj.LagrangeCoeffs(testing_nodes);

  // creating a polynomial
  std::vector<libBLS::algebra::FrScalar> coeffs(11);

  for (auto& elem : coeffs) {
    elem = libBLS::algebra::FrScalar::random();

    while (elem == 0) {
      elem = libBLS::algebra::FrScalar::random();
    }
  }


  std::vector<libBLS::algebra::FrScalar> secret_keys(16);
  for (size_t i = 0; i < 16; ++i) {
    secret_keys[i] = libBLS::algebra::FrScalar::zero();

    for (size_t j = 0; j < 11; ++j) {
      secret_keys[i] = secret_keys[i] + coeffs[j] *
                              libff::power(libBLS::algebra::FrScalar(std::to_string(i + 1).c_str()),
j);
    }
  }

  auto recovered_keys = obj.KeysRecover(lagrange_coeffs, secret_keys);
  libBLS::algebra::G2Point common_public = recovered_keys.second;


  std::srand(unsigned(std::time(0)));

  std::string message = "";
  for (size_t length = 1; length < 1000000; ++length) {
    message += char(std::rand() % 2);

    libBLS::algebra::G1Point hash = obj.Hashing(message);

    BOOST_CHECK(hash.isWellFormed());  // hash belongs to group G1

    std::vector<libBLS::algebra::G1Point> single_signatures(16);
    for (size_t i = 0; i < 16; ++i) {
      single_signatures[i] = obj.Signing(hash, secret_keys[i]);
    }

    libBLS::algebra::G1Point common_signature = obj.SignatureRecover(single_signatures,
lagrange_coeffs);

    BOOST_REQUIRE(obj.Verify(message, common_signature, common_public));
  }
}*/

BOOST_AUTO_TEST_CASE( blsAggregatedSignatures ) {
    std::cout << "Testing blsAggregatedSignatures\n";

    auto first_key = libBLS::Bls::KeyGeneration();
    auto second_key = libBLS::Bls::KeyGeneration();

    std::string hex_message = rand32HexStr();  // random hex

    libBLS::algebra::G1Point first_signature =
        libBLS::Bls::CoreSignAggregated( hex_message, first_key.first );
    libBLS::algebra::G1Point second_signature =
        libBLS::Bls::CoreSignAggregated( hex_message, second_key.first );

    BOOST_REQUIRE( libBLS::Bls::CoreVerify( first_key.second, hex_message, first_signature ) );
    BOOST_REQUIRE( libBLS::Bls::CoreVerify( second_key.second, hex_message, second_signature ) );

    libBLS::algebra::G1Point aggregated_signature =
        libBLS::Bls::Aggregate( { first_signature, second_signature } );

    BOOST_REQUIRE( libBLS::Bls::FastAggregateVerify(
        { first_key.second, second_key.second }, hex_message, aggregated_signature ) );

    auto malicious_key = libBLS::Bls::KeyGeneration();

    libBLS::algebra::G1Point malicious_signature =
        libBLS::Bls::CoreSignAggregated( hex_message, malicious_key.first );

    auto malicious_aggregated_signature =
        libBLS::Bls::Aggregate( { first_signature, malicious_signature } );

    BOOST_REQUIRE( !libBLS::Bls::FastAggregateVerify(
        { first_key.second, second_key.second }, hex_message, malicious_aggregated_signature ) );

    std::cout << "DONE\n";
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( Exceptions )


BOOST_AUTO_TEST_CASE( SignVerification ) {
    std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % ( num_all - 1 ) + 2;
    libBLS::Bls obj( num_signed, num_all );
    libBLS::Bls obj_2_2( 2, 2 );

    libBLS::algebra::G1Point sign(
        libBLS::algebra::FqElement::fromString( "123", libBLS::Base::DEC ),
        libBLS::algebra::FqElement::fromString( "234", libBLS::Base::DEC ),
        libBLS::algebra::FqElement::fromString( "345", libBLS::Base::DEC ) );

    auto rndMsg = randomByteArray< 32 >();
    BOOST_REQUIRE_THROW( obj.Verify( rndMsg, sign, libBLS::algebra::G2Point::random() ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    libBLS::algebra::G2Point pkey = libBLS::algebra::G2Point::random();
    pkey.setXC0( libBLS::algebra::FqElement::fromString( "123", libBLS::Base::DEC ) );

    BOOST_REQUIRE_THROW( obj.Verify( rndMsg, libBLS::algebra::G1Point::random(), pkey ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    std::vector< libBLS::algebra::FrScalar > coeffs;
    coeffs.push_back( libBLS::algebra::FrScalar::random() );
    std::vector< libBLS::algebra::FrScalar > shares;
    shares.push_back( libBLS::algebra::FrScalar::random() );

    BOOST_REQUIRE_THROW(
        obj.KeysRecover( coeffs, shares ), libBLS::ThresholdUtils::IncorrectInput );

    coeffs.clear();
    shares.clear();

    coeffs.push_back( libBLS::algebra::FrScalar::random() );
    coeffs.push_back( libBLS::algebra::FrScalar::random() );

    shares.push_back( libBLS::algebra::FrScalar::random() );
    shares.push_back( libBLS::algebra::FrScalar::zero() );

    BOOST_REQUIRE_THROW(
        obj_2_2.KeysRecover( coeffs, shares ), libBLS::ThresholdUtils::ZeroSecretKey );

    coeffs.clear();
    coeffs.push_back( libBLS::algebra::FrScalar::random() );

    std::vector< libBLS::algebra::G1Point > sig_shares;
    sig_shares.push_back( libBLS::algebra::G1Point::random() );

    BOOST_REQUIRE_THROW(
        obj.SignatureRecover( sig_shares, coeffs ), libBLS::ThresholdUtils::IncorrectInput );

    coeffs.clear();
    sig_shares.clear();

    coeffs.push_back( libBLS::algebra::FrScalar::random() );
    coeffs.push_back( libBLS::algebra::FrScalar::random() );

    sig_shares.push_back( libBLS::algebra::G1Point::random() );
    libBLS::algebra::G1Point g1_spoiled = libBLS::algebra::G1Point::random();
    g1_spoiled.setY( libBLS::algebra::FqElement::fromString( "257", libBLS::Base::DEC ) );
    sig_shares.push_back( g1_spoiled );

    BOOST_REQUIRE_THROW(
        obj_2_2.SignatureRecover( sig_shares, coeffs ), libBLS::ThresholdUtils::IsNotWellFormed );

    std::vector< size_t > idx = { 1 };

    BOOST_REQUIRE_THROW( libBLS::algebra::lagrangeCoeffs( idx, num_signed ),
        libBLS::ThresholdUtils::IncorrectInput );

    idx.clear();
    idx = { 1, 1 };

    BOOST_REQUIRE_THROW(
        libBLS::algebra::lagrangeCoeffs( idx, 2 ), libBLS::ThresholdUtils::IncorrectInput );

    std::cerr << "Exceptions test passed" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
