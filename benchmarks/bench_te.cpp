#define BOOST_TEST_MODULE TE_Bench
#include <boost/test/included/unit_test.hpp>
#include <iomanip>
#include <iostream>
#include <tuple>

#include "backend_info.hpp"
#include "bench_util.hpp"
#include "test/utils.h"

#include "threshold_encryption/ThresholdEncryption.h"

BOOST_AUTO_TEST_CASE( EncryptionValidation ) {
    auto& ts = boost::unit_test::framework::master_test_suite();
    BenchArgs args = parse_args( ts.argc, ts.argv );
    BOOST_REQUIRE( args.t >= 2 && args.t <= args.n );

    // Success cases only
    double pessimistic_validation_ms = 0.0;
    double batched_validation_ms = 0.0;
    double concurrent_validation_ms = 0.0;

    libBLS::init();

    // initial setup
    size_t numAll = args.n;
    size_t numSigned = args.t;
    const keys keys = generateKeys( numSigned, numAll );

    auto message = make_msg( args.msg_bytes );

    // keep all ciphered keys stored in a vector
    std::vector< libBLS::CipheredKey > cipheredKeys;

    for ( size_t i = 0; i < args.numTxs; i++ ) {
        // encrypt
        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );
        cipheredKeys.push_back( cypher.keys[0] );

        {  // validate encryption
            ScopedTimer timer( pessimistic_validation_ms );
            libBLS::ThresholdEncryption::validateEncryption( cipheredKeys[i] );
        }
    }

    {
        ScopedTimer timer( batched_validation_ms );
        libBLS::ThresholdEncryption::validateEncryptionBatch( cipheredKeys );
    }

    {
        ScopedTimer timer( concurrent_validation_ms );
        libBLS::ThresholdEncryption::validateEncryptionBatchParallel( cipheredKeys );
    }

    print_args( args );
    std::cout << "Encryption validation (single, pessimistic) took " << pessimistic_validation_ms
              << " ms\n";
    std::cout << "Encryption validation (batched) took " << batched_validation_ms << " ms\n";
    std::cout << "Encryption validation (batched, multi-threaded) took "
              << concurrent_validation_ms << " ms\n";
}

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
    std::vector< libBLS::Ciphertext > ciphertexts;
    std::vector< libBLS::CipheredKey > cipheredKeys;

    std::vector< libBLS::TEDecryptionShare > decryptionShares;
    std::vector< libBLS::TEPublicKeyShare > publicKeys;

    for ( size_t i = 0; i < args.numTxs; i++ ) {
        // encrypt
        {
            ScopedTimer timer( encryption_total_ms );
            libBLS::Ciphertext cypher =
                libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );
            ciphertexts.push_back( cypher );
            cipheredKeys.push_back( cypher.keys[0] );
        }

        for ( size_t j = 0; j < numSigned; j++ ) {
            // partial decrypt - only count the time for one (myself)
            libBLS::TEDecryptionShare decr_share = [&]() {
                if ( j == 0 ) {
                    ScopedTimer timer( partial_decrypt_total_ms );
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        ciphertexts[i].keys[0], keys.secretKeys[j] );
                } else {
                    return libBLS::ThresholdEncryption::partialDecrypt(
                        ciphertexts[i].keys[0], keys.secretKeys[j] );
                }
            }();

            decryptionShares.push_back( decr_share );
            publicKeys.push_back( keys.publicKeys[j] );
        }

        print_progress( i, args.numTxs );
    }

    {  // validate encryption
        ScopedTimer timer( validate_encryption_total_ms );
        libBLS::ThresholdEncryption::validateEncryptionBatchParallel( cipheredKeys );
    }


    // validate entire batch of shares
    std::vector< bool > validated = [&]() {
        ScopedTimer t( validate_decryption_share_total_ms );

        return libBLS::ThresholdEncryption::validateDecryptionSharesBatchParallel(
            cipheredKeys, decryptionShares, publicKeys );
    }();

    std::vector< libBLS::TEDecryptSet > decryptSets;
    for ( size_t i = 0; i < args.numTxs; i++ ) {
        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        decryptSets.push_back( decrSet );

        for ( size_t j = 0; j < numSigned; ++j ) {
            size_t idx = i * numSigned + j;
            if ( !validated[idx] ) {
                throw libBLS::ThresholdUtils::IncorrectInput( "not validated" );
            }

            decryptSets[i].addDecryptShare( decryptionShares[idx] );
        }
        print_progress( i, args.numTxs );
    }

    // combine shares
    std::vector< std::optional< libBLS::AES256Key > > keys_deciphered = [&]() {
        ScopedTimer timer( combine_shares_total_ms );
        return libBLS::ThresholdEncryption::combineSharesBatchParallel( cipheredKeys, decryptSets );
    }();

    std::vector< libBLS::AES256Key > combinedSharesValidation;
    for ( size_t i = 0; i < keys_deciphered.size(); i++ ) {
        if ( !keys_deciphered[i].has_value() ) {
            throw libBLS::ThresholdUtils::IncorrectInput( "not all sets were merged" );
        }
        combinedSharesValidation.push_back( keys_deciphered[i].value() );
    }

    {  // validate combined decryption
        ScopedTimer timer( validate_combined_decryption_total_ms );
        libBLS::ThresholdEncryption::validateCombinedDecryptionBatchParallel(
            ciphertexts, combinedSharesValidation, keys.commonPublic );
    }

    for ( size_t i = 0; i < args.numTxs; i++ ) {
        std::vector< uint8_t > decipheredMsg;
        {  // decrypt
            ScopedTimer timer( decrypt_total_ms );
            decipheredMsg = libBLS::ThresholdEncryption::decrypt( ciphertexts[i], combinedSharesValidation[i] );
        }

        // check correctness
        BOOST_REQUIRE( decipheredMsg == message );
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
