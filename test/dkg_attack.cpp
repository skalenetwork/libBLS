#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSSigShare.h>
#include <bls/BLSSigShareSet.h>
#include <bls/BLSSignature.h>
#include <bls/BLSutils.h>
#include <bls/bls.h>
#include <dkg/DKGBLSWrapper.h>
#include <dkg/dkg.h>

#include <fstream>
#include <third_party/json.hpp>

int main() {
    // Initialize paring parameters
    libff::alt_bn128_pp::init_public_params();

    // (num_signed, num_all)=(11,13)
    size_t num_signed = 11;
    size_t num_all = 16;

    // Initialize dkgs, secret_shares, public_shares, common_public_key_point,
    // private_keys, public_keys
    std::vector< DKGBLSWrapper > dkgs;
    std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
    std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
    libff::alt_bn128_G2 common_public_key_point;
    std::vector< BLSPrivateKeyShare > private_keys;
    std::vector< BLSPublicKeyShare > public_keys;

    // Create ifstream from 'parameters.json'
    std::ifstream* malicious_parameters_if =
        new std::ifstream( "parameters.json", std::ifstream::binary );
    // Initialize malicious_parameters json, malicious_polynomial, subgroupPoint
    nlohmann::json malicious_parameters;
    std::vector< libff::alt_bn128_Fr > malicious_polynomial;
    libff::alt_bn128_G2 subgroupPoint;

    // Read 'parameters.json' stream into malicious_parameters
    *malicious_parameters_if >> malicious_parameters;

    // Write json into stdout
    std::cout << malicious_parameters;

    // Load malicious polynomial coefficients into malicious_polynomial
    for ( size_t i = 0; i < num_signed; i++ ) {
        malicious_polynomial.push_back( libff::alt_bn128_Fr(
            malicious_parameters["polynomial"][i].get< std::string >().c_str() ) );
    }

    // Initialize subgroupPoint with coordinates
    subgroupPoint = libff::alt_bn128_G2(
        libff::alt_bn128_Fq2(
            libff::alt_bn128_Fq(
                malicious_parameters["point"]["x"][0].get< std::string >().c_str() ),
            libff::alt_bn128_Fq(
                malicious_parameters["point"]["x"][1].get< std::string >().c_str() ) ),
        libff::alt_bn128_Fq2(
            libff::alt_bn128_Fq(
                malicious_parameters["point"]["y"][0].get< std::string >().c_str() ),
            libff::alt_bn128_Fq(
                malicious_parameters["point"]["y"][1].get< std::string >().c_str() ) ),
        libff::alt_bn128_Fq2( libff::alt_bn128_Fq( 1 ), libff::alt_bn128_Fq( 0 ) ) );

    // Check that the subgroupPoint is in the correct subgroup
    // and passes the is_well_formed check
    std::cout << "\nChecking that subgroupPoint is in subgroup of order 10069: "
              << ( libff::alt_bn128_Fr( 10069 ) * subgroupPoint ).is_zero()
              << "\nChecking that the point passes `is_well_formed`: "
              << subgroupPoint.is_well_formed() << "\n";

    // Create dkgs, secret shares and public shares of honest participants (num_singed - 1)
    for ( size_t i = 0; i < num_signed - 1; i++ ) {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        dkgs.push_back( dkg_wrap );

        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
            dkg_wrap.createDKGSecretShares();

        std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
            dkg_wrap.createDKGPublicShares();

        secret_shares_all.push_back( *secret_shares_ptr );
        public_shares_all.push_back( *public_shares_ptr );
    }

    // Create dkg, secret shares and public shares of the active adversary

    DKGBLSWrapper malicious_dkg_wrap( num_signed, num_all );

    // Set active adversary's polynomial to loaded malicious polynomial
    malicious_dkg_wrap.setDKGSecret(
        std::make_shared< std::vector< libff::alt_bn128_Fr > >( malicious_polynomial ) );

    dkgs.push_back( malicious_dkg_wrap );

    std::shared_ptr< std::vector< libff::alt_bn128_Fr > > malicious_secret_shares =
        malicious_dkg_wrap.createDKGSecretShares();
    std::shared_ptr< std::vector< libff::alt_bn128_G2 > > malicious_public_shares =
        malicious_dkg_wrap.createDKGPublicShares();

    // Add subgroupPoint*k_i to the i-th public share of the active adversary
    for ( size_t i = 0; i < num_signed; i++ ) {
        ( *malicious_public_shares )[i] =
            ( *malicious_public_shares )[i] + malicious_polynomial[i] * subgroupPoint;
    }

    secret_shares_all.push_back( *malicious_secret_shares );
    public_shares_all.push_back( *malicious_public_shares );

    // Create dkgs, secret and public shares for passive adversaries
    for ( size_t i = num_signed; i < num_all; i++ ) {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        dkgs.push_back( dkg_wrap );

        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
            dkg_wrap.createDKGSecretShares();

        std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
            dkg_wrap.createDKGPublicShares();

        secret_shares_all.push_back( *secret_shares_ptr );
        public_shares_all.push_back( *public_shares_ptr );
    }

    // First verify secret shares of all the honest members and all passive adversaries
    for ( size_t i = 0; i < num_all; i++ ) {
        if ( i == ( num_signed - 1 ) )
            continue;  // Skip checking active adversary's share
        for ( size_t j = 0; j < num_all; j++ ) {
            assert( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                std::make_shared< std::vector< libff::alt_bn128_G2 > >(
                    public_shares_all.at( i ) ) ) );
        }
    }

    // Then only honest participants verify the active adversary's secret shares
    // modified by SKALE
    size_t verified = 0;
    for ( size_t i = 0; i < num_signed - 1; i++ ) {
        verified += dkgs.at( num_signed - 1 )
                        .VerifyDKGShare( i, secret_shares_all.at( num_signed - 1 ).at( i ),
                            std::make_shared< std::vector< libff::alt_bn128_G2 > >(
                                public_shares_all.at( num_signed - 1 ) ) );

        if ( verified == 0 ) {
            // SKALE fixed
            std::cout << "ATTACK TEST PASSED\n";
            return 0;
        }
    }


    // Uncomment this to see that the check fails if adversaries start checking active adversary's
    // shares
    /*
    for (size_t i=num_signed-1; i<num_all; i++) {
        assert(dkgs.at(num_signed-1).VerifyDKGShare(i,secret_shares_all.at(num_signed-1).at(i),
            std::make_shared<std::vector<libff::alt_bn128_G2>>(public_shares_all.at(num_signed-1))));

    }
    */

    // // Compute common_public_key_point
    // common_public_key_point = libff::alt_bn128_G2::zero();
    // for ( size_t i = 0; i < num_all; i++ )
    //     common_public_key_point = common_public_key_point + public_shares_all.at( i ).at( 0 );

    // // Initialize common_public_key
    // BLSPublicKey common_public_key = BLSPublicKey( common_public_key_point, num_signed, num_all
    // );

    // // Check that the public key is corrputed (it is not in G2)
    // std::cout << "Let's check if public key is in G2: "
    //           << ( libff::alt_bn128_G2::order() * ( *common_public_key.getPublicKey() )
    //           ).is_zero()
    //           << "\n";

    // // Initialize secret_key_shares
    // std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_shares;

    // // Construct secret_key_shares
    // for ( size_t i = 0; i < num_all; i++ ) {
    //     std::vector< libff::alt_bn128_Fr > secret_key_contribution;
    //     for ( size_t j = 0; j < num_all; j++ ) {
    //         secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
    //     }
    //     secret_key_shares.push_back( secret_key_contribution );
    // }

    // // Compute public and private key shares
    // for ( size_t i = 0; i < num_all; i++ ) {
    //     BLSPrivateKeyShare private_key_share = dkgs.at( i ).CreateBLSPrivateKeyShare(
    //         std::make_shared< std::vector< libff::alt_bn128_Fr > >( secret_key_shares.at( i ) )
    //         );
    //     BLSPublicKeyShare public_key_share =
    //         BLSPublicKeyShare( *private_key_share.getPrivateKey(), num_signed, num_all );

    //     private_keys.push_back( private_key_share );
    //     public_keys.push_back( public_key_share );
    // }

    // // Let's try to sign some message
    // // Initialize a hash array and set all bytes to 0xff
    // std::array< uint8_t, 32 > hash_byte_arr;
    // for ( size_t i = 0; i < 32; i++ )
    //     hash_byte_arr[i] = 0xff;
    // std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
    //     std::make_shared< std::array< uint8_t, 32 > >( hash_byte_arr );

    // // Create signature shares
    // std::vector< BLSSigShare > signature_shares;
    // for ( size_t i = 0; i < num_all; i++ ) {
    //     if ( i == num_signed - 1 )
    //         continue;  // Active adversary doesn't have to sign, passive advesaries behave
    //     signature_shares.push_back( *private_keys.at( i ).sign( hash_ptr, i + 1 ) );
    // }

    // // Construct signature share set (active adversary didn't take part)
    // BLSSigShareSet signature_share_set = BLSSigShareSet( num_signed, num_all );
    // for ( size_t i = 0; i < num_all && !signature_share_set.isEnough(); i++ ) {
    //     signature_share_set.addSigShare(
    //         std::make_shared< BLSSigShare >( signature_shares.at( i ) ) );
    // }

    // // Construct the final signature
    // std::shared_ptr< BLSSignature > signature = signature_share_set.merge();

    // std::cout << "isG2:" << signatures::Dkg::isG2( *( common_public_key.getPublicKey() ) );

    // // This assertion will fail
    // assert( common_public_key.VerifySig( hash_ptr, signature, num_signed, num_all ) );
    // delete ( std::ifstream* ) malicious_parameters_if;
    // return 0;
}
