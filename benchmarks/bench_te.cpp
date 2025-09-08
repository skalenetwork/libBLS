#define BOOST_TEST_MODULE TE_Bench
#include <boost/test/included/unit_test.hpp>
#include <iomanip>
#include <iostream>
#include <tuple>

#include "backend_info.hpp"
#include "bench_util.hpp"
#include "test/utils.h"

#include "threshold_encryption/ThresholdEncryption.h"

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWrappers ) {
    auto& ts = boost::unit_test::framework::master_test_suite();
    BenchArgs args = parse_args( ts.argc, ts.argv );
    BOOST_REQUIRE( args.t >= 2 && args.t <= args.n );

    double encryption_total_ms = 0.0;
    double validate_encryption_total_ms = 0.0;
    double partial_decrypt_total_ms = 0.0;
    double validate_decryption_share_total_ms = 0.0;
    double combine_shares_total_ms = 0.0;
    double validate_combined_decryption_total_ms = 0.0;
    double decrypt_total_ms = 0.0;

    libBLS::init();

    // initial setup
    size_t numAll = args.n;
    size_t numSigned = args.t;
    const keys keys = generateKeys( numSigned, numAll );

    auto message = make_msg( args.msg_bytes );

    for ( size_t i = 0; i < args.rounds; i++ ) {
        // encrypt
        libBLS::Ciphertext cypher = [&]() {
            ScopedTimer timer( encryption_total_ms );
            return libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );
        }();

        {  // validate encryption
            ScopedTimer timer( validate_encryption_total_ms );
            libBLS::ThresholdEncryption::validateEncryption( cypher.keys[0] );
        }


        // ============ WITH BATCHING ================

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        std::vector< libBLS::TEDecryptionShare > shares;

        for ( size_t i = 0; i < numSigned; i++ ) {
            // partial decrypt - only count the time for one (myself)
            libBLS::TEDecryptionShare decr_share = [&]() {
                if ( i == 0 ) {
                    ScopedTimer timer( partial_decrypt_total_ms );
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        cypher.keys[0], keys.secretKeys[i] );
                } else {
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        cypher.keys[0], keys.secretKeys[i] );
                }
            }();

            shares.push_back( decr_share );
        }

        auto validated = [&]() {
            ScopedTimer t( validate_decryption_share_total_ms );

            std::vector< std::shared_ptr< libBLS::TEDecryptionShare > > sharesRefs;
            std::vector< std::shared_ptr< libBLS::TEPublicKeyShare > > publicKeysRefs;

            for ( size_t i = 0; i < numSigned; ++i ) {
                sharesRefs.push_back( std::make_shared< libBLS::TEDecryptionShare >( shares[i] ) );
                publicKeysRefs.push_back(
                    std::make_shared< libBLS::TEPublicKeyShare >( keys.publicKeys[i] ) );
            }

            return libBLS::ThresholdEncryption::validateDecryptionSharesBatch(
                cypher.keys[0], sharesRefs, publicKeysRefs );
        }();

        for ( size_t i = 0; i < numSigned; ++i ) {
            if ( !validated[i] ) {
                throw libBLS::ThresholdUtils::IncorrectInput( "not validated" );
            }

            // TODO - check if maybe we can set the entire set of shares at once..?
            decrSet.addDecryptShare( shares[i] );
        }


        // ============ WITHOUT BATCHING ================

        // libBLS::TEDecryptSet decrSet( numSigned, numAll );
        // for ( size_t i = 0; i < numSigned; i++ ) {
        //     // partial decrypt - only count the time for one (myself)
        //     libBLS::TEDecryptionShare decr_share = [&]() {
        //         if ( i == 0 ) {
        //             ScopedTimer timer( partial_decrypt_total_ms );
        //             return libBLS::ThresholdEncryption::partialDecrypt(
        //                 cypher.keys[0], keys.secretKeys[i] );
        //         } else {
        //             return libBLS::ThresholdEncryption::partialDecrypt(
        //                 cypher.keys[0], keys.secretKeys[i] );
        //         }
        //     }();


        //     {  // validate share - still need to validate all received shares
        //         ScopedTimer timer( validate_decryption_share_total_ms );
        //         libBLS::ThresholdEncryption::validateDecryptionShare(
        //             cypher.keys[0], decr_share, keys.publicKeys[i] );
        //     }

        //     decrSet.addDecryptShare( decr_share );
        // }


        // combine shares
        libBLS::AES256Key key_deciphered = [&]() {
            ScopedTimer timer( combine_shares_total_ms );
            return libBLS::ThresholdEncryption::combineShares( cypher.keys[0], decrSet );
        }();

        {  // validate combined decryption
            ScopedTimer timer( validate_combined_decryption_total_ms );
            libBLS::ThresholdEncryption::validateCombinedDecryption(
                cypher, key_deciphered, keys.commonPublic );
        }

        std::vector< uint8_t > decipheredMsg;

        {  // decrypt
            ScopedTimer timer( decrypt_total_ms );
            decipheredMsg = libBLS::ThresholdEncryption::decrypt( cypher, key_deciphered );
        }

        // check correctness
        BOOST_REQUIRE( decipheredMsg == message );

        print_progress( i, args.rounds );
    }

    // print results
    print_args( args );
    std::cout << "Average encryption time: " << ( encryption_total_ms / args.rounds ) << " ms\n";
    std::cout << "Average validation encryption time: "
              << ( validate_encryption_total_ms / args.rounds ) << " ms\n";
    std::cout << "Average partial decryption time: " << ( partial_decrypt_total_ms / args.rounds )
              << " ms\n";
    std::cout << "Average validation decryption share time: "
              << ( validate_decryption_share_total_ms / args.rounds ) << " ms\n";
    std::cout << "Average combine shares time: " << ( combine_shares_total_ms / args.rounds )
              << " ms\n";
    std::cout << "Average validation combined decryption time: "
              << ( validate_combined_decryption_total_ms / args.rounds ) << " ms\n";
    std::cout << "Average decryption time: " << ( decrypt_total_ms / args.rounds ) << " ms\n";
    std::cout << "Average full cycle time: "
              << ( ( encryption_total_ms + validate_encryption_total_ms + partial_decrypt_total_ms +
                       validate_decryption_share_total_ms + combine_shares_total_ms +
                       validate_combined_decryption_total_ms + decrypt_total_ms ) /
                     args.rounds )
              << " ms\n";
}