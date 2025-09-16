#define BOOST_TEST_MODULE BLS_Bench
#include <boost/test/included/unit_test.hpp>
#include <iomanip>
#include <iostream>
#include <tuple>

#include "backend_info.hpp"
#include "bench_util.hpp"
#include "test/utils.h"

#include "bls/BLSPrivateKey.h"
#include "bls/BLSPrivateKeyShare.h"
#include "bls/BLSSigShareSet.h"

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWrappers ) {
    auto& ts = boost::unit_test::framework::master_test_suite();
    BenchArgs args = parse_args( ts.argc, ts.argv );
    BOOST_REQUIRE( args.t >= 2 && args.t <= args.n );

    double partialSignature = 0.0;
    double signatureMerge = 0.0;
    double addingSigShare = 0.0;
    double verifySig = 0.0;

    libBLS::init();

    // initial setup
    size_t numAll = args.n;
    size_t numSigned = args.t;
    const keys keys = generateKeys( numSigned, numAll );

    auto message = make_msg( args.msg_bytes );

    std::vector< size_t > participants( numAll );
    for ( size_t i = 0; i < numSigned; ++i )
        participants.at( i ) = i + 1;  // set participants indices 1,2,3

    std::shared_ptr< std::vector< std::shared_ptr< libBLS::BLSPrivateKeyShare > > > Skeys =
        libBLS::BLSPrivateKeyShare::generateSampleKeys( numSigned, numAll )->first;

    std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );
    std::array< uint8_t, 32 > hash_byte_arr;
    for ( size_t i = 0; i < 32; i++ ) {  // generate random hash
        hash_byte_arr.at( i ) = rand_gen() % 255;
    }

    std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
        std::make_shared< std::array< uint8_t, 32 > >( hash_byte_arr );

    for ( size_t i = 0; i < args.numTxs; i++ ) {
        // actual work
        libBLS::BLSSigShareSet sigSet( numSigned, numAll );

        for ( size_t j = 0; j < numSigned; ++j ) {
            std::shared_ptr< libBLS::BLSPrivateKeyShare > skey = Skeys->at( j );

            // create signature share for each participant
            std::shared_ptr< libBLS::BLSSigShare > sigShare = [&]() {
                if ( i == 0 ) {  // only time one participant
                    ScopedTimer timer( partialSignature );
                    return skey->sign( hash_ptr, participants.at( j ) );
                } else {
                    return skey->sign( hash_ptr, participants.at( j ) );
                }
            }();

            {
                ScopedTimer timer( addingSigShare );
                sigSet.addSigShare( sigShare );
            }
        }

        std::shared_ptr< libBLS::BLSSignature > common_sig_ptr = [&]() {
            ScopedTimer timer( signatureMerge );
            return sigSet.merge();
        }();

        // create common private key from private keys of each participant
        libBLS::BLSPrivateKey common_skey(
            Skeys, std::make_shared< std::vector< size_t > >( participants ), numSigned, numAll );

        // create common public key from common private key
        libBLS::BLSPublicKey common_pkey( *( common_skey.getPrivateKey() ), numSigned, numAll );


        // verify common signature with common public key
        bool sigIsValid = [&]() {
            ScopedTimer timer( verifySig );
            return common_pkey.VerifySig( hash_ptr, common_sig_ptr );
        }();

        BOOST_REQUIRE( sigIsValid );

        print_progress( i, args.numTxs );
    }

    // print results
    print_args( args );
    std::cout << "Average partial signature time: " << ( partialSignature / args.numTxs )
              << " ms\n";
    std::cout << "Average signature merge time: " << ( signatureMerge / args.numTxs ) << " ms\n";
    std::cout << "Average adding signature share time: " << ( addingSigShare / args.numTxs )
              << " ms\n";
    std::cout << "Average signature verification time: " << ( verifySig / args.numTxs ) << " ms\n";
    std::cout << "Average full cycle time: "
              << ( ( partialSignature + signatureMerge + addingSigShare + verifySig ) /
                     args.numTxs )
              << " ms\n";
}