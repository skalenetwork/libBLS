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

    // keep all ciphered keys stored in a vector
    std::vector< std::shared_ptr< libBLS::Ciphertext > > ciphertexts;
    std::vector< std::shared_ptr< libBLS::CipheredKey > > cipheredKeys;

    std::vector< std::shared_ptr< libBLS::TEDecryptionShare > > decryptionShares;
    std::vector< std::shared_ptr< libBLS::TEPublicKeyShare > > publicKeys;

    std::cout << "Encryption + validate encryption + partial decrypt: \n";
    for ( size_t i = 0; i < args.numTxs; i++ ) {
        // encrypt
        {
            ScopedTimer timer( encryption_total_ms );
            libBLS::Ciphertext cypher =
                libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );
            ciphertexts.push_back( std::make_shared< libBLS::Ciphertext >( cypher ) );
            cipheredKeys.push_back( std::make_shared< libBLS::CipheredKey >( cypher.keys[0] ) );
        }

        {  // validate encryption
            ScopedTimer timer( validate_encryption_total_ms );
            libBLS::ThresholdEncryption::validateEncryption( ciphertexts[i]->keys[0] );
        }

        for ( size_t j = 0; j < numSigned; j++ ) {
            // partial decrypt - only count the time for one (myself)
            libBLS::TEDecryptionShare decr_share = [&]() {
                if ( j == 0 ) {
                    ScopedTimer timer( partial_decrypt_total_ms );
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        ciphertexts[i]->keys[0], keys.secretKeys[j] );
                } else {
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        ciphertexts[i]->keys[0], keys.secretKeys[j] );
                }
            }();

            decryptionShares.push_back(
                std::make_shared< libBLS::TEDecryptionShare >( decr_share ) );
            publicKeys.push_back(
                std::make_shared< libBLS::TEPublicKeyShare >( keys.publicKeys[j] ) );
        }

        print_progress( i, args.numTxs );
    }

    std::cout << "ValidateDecryptionSharesBatch: \n";
    // validate entire batch of shares
    std::vector< bool > validated = [&]() {
        ScopedTimer t( validate_decryption_share_total_ms );

        return libBLS::ThresholdEncryption::validateDecryptionSharesBatch(
            cipheredKeys, decryptionShares, publicKeys );
    }();

    std::cout << "merge shares + validate combined shares + decrypt: \n";
    for ( size_t i = 0; i < args.numTxs; i++ ) {
        libBLS::TEDecryptSet decrSet( numSigned, numAll );

        for ( size_t j = 0; j < numSigned; ++j ) {
            size_t idx = i * numSigned + j;
            if ( !validated[idx] ) {
                throw libBLS::ThresholdUtils::IncorrectInput( "not validated" );
            }

            decrSet.addDecryptShare( *decryptionShares[idx] );
        }

        // combine shares
        libBLS::AES256Key key_deciphered = [&]() {
            ScopedTimer timer( combine_shares_total_ms );
            return libBLS::ThresholdEncryption::combineShares( ciphertexts[i]->keys[0], decrSet );
        }();

        {  // validate combined decryption
            ScopedTimer timer( validate_combined_decryption_total_ms );
            libBLS::ThresholdEncryption::validateCombinedDecryption(
                *ciphertexts[i], key_deciphered, keys.commonPublic );
        }

        std::vector< uint8_t > decipheredMsg;

        {  // decrypt
            ScopedTimer timer( decrypt_total_ms );
            decipheredMsg = libBLS::ThresholdEncryption::decrypt( *ciphertexts[i], key_deciphered );
        }

        // check correctness
        BOOST_REQUIRE( decipheredMsg == message );


        print_progress( i, args.numTxs );
    }

    // print results
    print_args( args );
    std::cout << "Total encryption time: " << encryption_total_ms << " ms\n";
    std::cout << "Total validation encryption time: " << validate_encryption_total_ms << " ms\n";
    std::cout << "Total partial decryption time: " << partial_decrypt_total_ms << " ms\n";
    std::cout << "Total validation decryption share time: " << validate_decryption_share_total_ms
              << " ms\n";
    std::cout << "Total combine shares time: " << combine_shares_total_ms << " ms\n";
    std::cout << "Total validation combined decryption time: "
              << validate_combined_decryption_total_ms << " ms\n";
    std::cout << "Total decryption time: " << decrypt_total_ms << " ms\n";
    std::cout << "Total full cycle time: "
              << ( encryption_total_ms + validate_encryption_total_ms + partial_decrypt_total_ms +
                     validate_decryption_share_total_ms + combine_shares_total_ms +
                     validate_combined_decryption_total_ms + decrypt_total_ms )
              << " ms\n";
}