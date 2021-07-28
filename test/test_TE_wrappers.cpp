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

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/


#define BOOST_TEST_MODULE

#include "../tools/utils.h"
#include <dkg/dkg_te.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/threshold_encryption.h>
#include <threshold_encryption/utils.h>
#include <boost/test/included/unit_test.hpp>

#include <dkg/DKGTEWrapper.h>
#include <stdio.h>
#include <stdlib.h>
#include <random>


std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );

std::string spoilMessage( std::string& message ) {
    std::string mes = message;
    size_t ind = rand_gen() % message.length();
    char ch = rand_gen() % 128;
    while ( mes[ind] == ch )
        ch = rand_gen() % 128;
    mes[ind] = ch;
    return mes;
}

BOOST_AUTO_TEST_SUITE( ThresholdEncryptionWrappers )

BOOST_AUTO_TEST_CASE( TEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        encryption::DkgTe dkg_te( num_signed, num_all );

        std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();
        
        libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

        libff::alt_bn128_Fr common_skey = dkg_te.ComputePolynomialValue( poly, zero_el );
        BOOST_REQUIRE( common_skey == poly.at( 0 ) );

        TEPrivateKey common_private( common_skey, num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        TEPublicKey common_public( common_private, num_signed, num_all );
        auto msg_ptr = std::make_shared< std::string >( message );
        encryption::Ciphertext cypher = common_public.encrypt( msg_ptr );

        std::vector< libff::alt_bn128_Fr > skeys = dkg_te.CreateSecretKeyContribution( poly );
        std::vector< TEPrivateKeyShare > skey_shares;
        std::vector< TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            skey_shares.emplace_back(
                TEPrivateKeyShare( skeys[i], i + 1, num_signed, num_all ) );
            public_key_shares.emplace_back(
                TEPublicKeyShare( skey_shares[i], num_signed, num_all ) );
        }

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % skey_shares.size();
            auto pos4del = skey_shares.begin();
            advance( pos4del, ind4del );
            skey_shares.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libff::alt_bn128_G2 decrypt = skey_shares[i].getDecryptionShare( cypher );
            BOOST_REQUIRE( public_key_shares[i].Verify( cypher, decrypt ) );
            auto decr_ptr = std::make_shared< libff::alt_bn128_G2 >( decrypt );
            decr_set.addDecrypt( skey_shares[i].getSignerIndex(), decr_ptr );
        }
        std::string message_decrypted = decr_set.merge( cypher );
        BOOST_REQUIRE( message == message_decrypted );

        encryption::Ciphertext bad_cypher = cypher;  // corrupt V in cypher
        std::get< 1 >( bad_cypher ) = spoilMessage( std::get< 1 >( cypher ) );
        bool is_exception_caught = false;
        try {
            decr_set.merge( bad_cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            // cannot add after merge
            decr_set.addDecrypt( num_signed, nullptr );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        bad_cypher = cypher;  // corrupt U in cypher
        libff::alt_bn128_G2 rand_el = libff::alt_bn128_G2::random_element();
        std::get< 0 >( bad_cypher ) = rand_el;

        is_exception_caught = false;
        try {
            decr_set.merge( bad_cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        bad_cypher = cypher;  // corrupt W in cypher
        libff::alt_bn128_G1 rand_el2 = libff::alt_bn128_G1::random_element();
        std::get< 2 >( bad_cypher ) = rand_el2;
        is_exception_caught = false;
        try {
            decr_set.merge( bad_cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        size_t ind = rand_gen() % num_signed;  // corrupt random private key share

        libff::alt_bn128_Fr bad_pkey = libff::alt_bn128_Fr::random_element();
        TEPrivateKeyShare bad_key( bad_pkey, skey_shares[ind].getSignerIndex(), num_signed, num_all );
        skey_shares[ind] = bad_key;

        TEDecryptSet bad_decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libff::alt_bn128_G2 decrypt = skey_shares[i].getDecryptionShare( cypher );
            if ( i == ind )
                BOOST_REQUIRE( !public_key_shares[i].Verify( cypher, decrypt ) );
            auto decr_ptr = std::make_shared< libff::alt_bn128_G2 >( decrypt );
            bad_decr_set.addDecrypt( skey_shares[i].getSignerIndex(), decr_ptr );
        }

        std::string bad_message_decrypted = bad_decr_set.merge( cypher );
        BOOST_REQUIRE( message != bad_message_decrypted );
    }
}

BOOST_AUTO_TEST_CASE( ShortTEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        encryption::DkgTe dkg_te( num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
            std::shared_ptr< TEPublicKey > >
            keys = TEPrivateKeyShare::generateSampleKeys( num_signed, num_all );


        auto msg_ptr = std::make_shared< std::string >( message );
        encryption::Ciphertext cypher = keys.second->encrypt( msg_ptr );

        std::vector< TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            public_key_shares.emplace_back(
                TEPublicKeyShare( *keys.first->at( i ), num_signed, num_all ) );
        }

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % ( *keys.first ).size();
            auto pos4del = ( *keys.first ).begin();
            advance( pos4del, ind4del );
            ( *keys.first ).erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libff::alt_bn128_G2 decrypt = ( *keys.first->at( i ) ).getDecryptionShare( cypher );
            BOOST_REQUIRE( public_key_shares.at( i ).Verify( cypher, decrypt ) );
            auto decr_ptr = std::make_shared< libff::alt_bn128_G2 >( decrypt );
            decr_set.addDecrypt( ( *keys.first->at( i ) ).getSignerIndex(), decr_ptr );
        }
        std::string message_decrypted = decr_set.merge( cypher );
        BOOST_REQUIRE( message == message_decrypted );
    }
}

BOOST_AUTO_TEST_CASE( WrappersFromString ) {
    for ( size_t i = 0; i < 100; i++ ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libff::alt_bn128_G2 test0 = libff::alt_bn128_G2::random_element();
        TEPublicKey common_pkey( test0, num_signed, num_all );

        TEPublicKey common_pkey_from_str( common_pkey.toString(), num_signed, num_all );
        BOOST_REQUIRE( common_pkey.getPublicKey() == common_pkey_from_str.getPublicKey() );

        libff::alt_bn128_Fr test = libff::alt_bn128_Fr::random_element();
        TEPrivateKey private_key( test, num_signed, num_all );

        TEPrivateKey private_key_from_str(
            std::make_shared< std::string >( private_key.toString() ), num_signed, num_all );
        BOOST_REQUIRE( private_key.getPrivateKey() == private_key_from_str.getPrivateKey() );

        libff::alt_bn128_Fr test2 = libff::alt_bn128_Fr::random_element();
        size_t signer = rand_gen() % num_all;
        TEPrivateKeyShare pr_key_share( test2, signer, num_signed, num_all );

        TEPrivateKeyShare pr_key_share_from_str(
            std::make_shared< std::string >( pr_key_share.toString() ), signer, num_signed,
            num_all );
        BOOST_REQUIRE( pr_key_share.getPrivateKey() == pr_key_share_from_str.getPrivateKey() );

        TEPublicKeyShare pkey( pr_key_share, num_signed, num_all );
        TEPublicKeyShare pkey_from_str(
            pkey.toString(), pr_key_share.getSignerIndex(), num_signed, num_all );
        BOOST_REQUIRE( pkey.getPublicKey() == pkey_from_str.getPublicKey() );
    }
    std::cerr << "TE wrappers tests finished" << std::endl;
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWithDKG ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % num_all + 1;
        std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
        std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
        std::vector< DKGTEWrapper > dkgs;
        std::vector< TEPrivateKeyShare > skeys;
        std::vector< TEPublicKeyShare > pkeys;

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGTEWrapper dkg_wrap( num_signed, num_all );

            encryption::DkgTe dkg_te( num_signed, num_all );
            std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();
            auto shared_poly =
                std::make_shared< std::vector< libff::alt_bn128_Fr > >( poly );
            dkg_wrap.setDKGSecret( shared_poly );

            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }


        for ( size_t i = 0; i < num_all; i++ )
            for ( size_t j = 0; j < num_all; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< libff::alt_bn128_G2 > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_shares;

        for ( size_t i = 0; i < num_all; i++ ) {
            std::vector< libff::alt_bn128_Fr > secret_key_contribution;
            for ( size_t j = 0; j < num_all; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < num_all; i++ ) {
            TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
                i + 1, std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                           secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
            pkeys.push_back( TEPublicKeyShare( pkey_share, num_signed, num_all ) );
        }

        /* element_t public_key;
         element_init_G1(public_key, TEDataSingleton::getData().pairing_);
         element_set0(public_key);

         for (size_t i = 0; i < num_all; i++) {

           element_t temp;
           element_init_G1(temp, TEDataSingleton::getData().pairing_);
           element_set(temp, public_shares_all.at(i).at(0).el_);

           element_t value;
           element_init_G1(value, TEDataSingleton::getData().pairing_);
           element_add(value, public_key, temp);

           element_clear(temp);
           element_clear(public_key);
           element_init_G1(public_key, TEDataSingleton::getData().pairing_);

           element_set(public_key, value);

           element_clear(value);
         }

         TEPublicKey common_public(encryption::element_wrapper(public_key), num_signed, num_all);
         element_clear(public_key);*/

        TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
            std::make_shared< std::vector< std::vector< libff::alt_bn128_G2 > > >(
                public_shares_all ),
            num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        auto msg_ptr = std::make_shared< std::string >( message );
        encryption::Ciphertext cypher = common_public.encrypt( msg_ptr );

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % secret_shares_all.size();
            auto pos4del = secret_shares_all.begin();
            advance( pos4del, ind4del );
            secret_shares_all.erase( pos4del );
            auto pos2 = public_shares_all.begin();
            advance( pos2, ind4del );
            public_shares_all.erase( pos2 );
        }

        TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libff::alt_bn128_G2 decrypt = skeys[i].getDecryptionShare( cypher );
            BOOST_REQUIRE( pkeys[i].Verify( cypher, decrypt ) );
            auto decr_ptr = std::make_shared< libff::alt_bn128_G2 >( decrypt );
            decr_set.addDecrypt( skeys[i].getSignerIndex(), decr_ptr );
        }

        std::string message_decrypted = decr_set.merge( cypher );
        BOOST_REQUIRE( message == message_decrypted );
    }
}

BOOST_AUTO_TEST_CASE( ExceptionsTest ) {
    for ( size_t i = 0; i < 1; i++ ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % num_all + 1;

        bool is_exception_caught = false;
        try {
            checkSigners( 0, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            checkSigners( 0, 0 );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null public key share
        try {
            TEPublicKeyShare( nullptr, 1, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // 1 coord of public key share is not digit
        try {
            std::vector< std::string > pkey_str( {"123", "abc"} );
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero public key share
        try {
            std::vector< std::string > pkey_str( {"0", "0"} );
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // one component public key share
        try {
            std::vector< std::string > pkey_str( {"1232450"} );
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // one zero component in cypher
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
            TEPublicKeyShare pkey(
                TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );

            libff::alt_bn128_G2 U = libff::alt_bn128_G2::zero();

            libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U;
            std::get< 1 >( cypher ) = "tra-la-la";
            std::get< 2 >( cypher ) = W;

            pkey.Verify( cypher, U );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );


        is_exception_caught = false;  // wrong string length in cypher
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();

            TEPublicKeyShare pkey(
                TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );
            libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

            libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U;
            std::get< 1 >( cypher ) = "tra-la-la";
            std::get< 2 >( cypher ) = W;

            pkey.Verify( cypher, U );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero decrypted
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
            TEPublicKeyShare pkey( TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );

            libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

            libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U;
            std::get< 1 >( cypher ) = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = W;

            libff::alt_bn128_G2 decrypt = libff::alt_bn128_G2::zero();

            pkey.Verify( cypher, decrypt );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null private key share
        try {
            TEPrivateKeyShare( nullptr, 1, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero private key share
        try {
            std::string zero_str = "0";
            TEPrivateKeyShare(
                std::make_shared< std::string >( zero_str ), 1, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero private key share
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
            TEPrivateKeyShare( el, 1, num_signed, num_all );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null public key
        try {
            TEPublicKey( nullptr, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero public key
        try {
            std::vector< std::string > pkey_str( {"0", "0"} );
            TEPublicKey(
                std::make_shared< std::vector< std::string > >( pkey_str ), num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero public key
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
            TEPublicKey pkey( TEPrivateKey( el, num_signed, num_all ), num_signed, num_all );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero public key
        try {
            libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
            TEPublicKey pkey( el, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null message
        try {
            libff::alt_bn128_G2 el = libff::alt_bn128_G2::random_element();

            TEPublicKey pkey( el, num_signed, num_all );

            pkey.encrypt( nullptr );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // message length is not 64
        try {
            libff::alt_bn128_G2 el = libff::alt_bn128_G2::random_element();

            TEPublicKey pkey( el, num_signed, num_all );

            pkey.encrypt( std::make_shared< std::string >( "tra-la-la" ) );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null private key
        try {
            TEPrivateKey( nullptr, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero private key
        try {
            std::string zero_str = "0";
            TEPrivateKey( std::make_shared< std::string >( zero_str ), num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero private key
        try {
            libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
            TEPrivateKey( el, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_all + 1, num_signed );  //_requiredSigners > _totalSigners
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // same indices in decrypt set

            libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();
            auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );

            libff::alt_bn128_G2 el2 = libff::alt_bn128_G2::random_element();
            auto el_ptr2 = std::make_shared< libff::alt_bn128_G2 >( el2 );

            decr_set.addDecrypt( 1, el_ptr1 );
            decr_set.addDecrypt( 1, el_ptr2 );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // zero element in decrypt set

            libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::zero();
            auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );

            decr_set.addDecrypt( 1, el_ptr1 );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // null element in decrypt set
            libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::zero();

            auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );
            el_ptr1 = nullptr;
            decr_set.addDecrypt( 1, el_ptr1 );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // not enough elements in decrypt set
            libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();

            auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );
            decr_set.addDecrypt( 1, el_ptr1 );

            libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

            libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U;
            std::get< 1 >( cypher ) =
                "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = W;

            decr_set.merge( cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( 1, 1 );  // cannot combine shares
            libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();
            auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );
            decr_set.addDecrypt( 1, el_ptr1 );

            libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

            libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U;
            std::get< 1 >( cypher ) =
                "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = W;

            decr_set.merge( cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );
    }
}

BOOST_AUTO_TEST_CASE( ExceptionsDKGWrappersTest ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % num_all + 1;

    bool is_exception_caught = false;
    try {
        // zero share
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();

        dkg_te.VerifyDKGShare( 1, el, dkg_te.createDKGPublicShares() );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        // null verification vector
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        dkg_te.VerifyDKGShare( 1, el, nullptr );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();

        std::vector< libff::alt_bn128_G2 > pub_shares = *dkg_te.createDKGPublicShares();
        pub_shares.erase( pub_shares.begin() );

        dkg_te.VerifyDKGShare( 1, el,
            std::make_shared< std::vector< libff::alt_bn128_G2 > >( pub_shares ) );

    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares =
            dkg_te.createDKGSecretShares();
        shares = nullptr;
        dkg_te.setDKGSecret( shares );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares =
            dkg_te.createDKGSecretShares();
        shares->erase( shares->begin() + shares->size() - 2 );
        shares->shrink_to_fit();
        dkg_te.setDKGSecret( shares );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        dkg_te.CreateTEPrivateKeyShare( 1, nullptr );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        auto wrong_size_vector = std::make_shared< std::vector< libff::alt_bn128_Fr > >();
        wrong_size_vector->resize( num_signed - 1 );
        dkg_te.CreateTEPrivateKeyShare( 1, wrong_size_vector );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares;
        dkg_te.setDKGSecret( shares );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        dkg_te.CreateTEPublicKey( nullptr, num_signed, num_all );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );
}

BOOST_AUTO_TEST_SUITE_END()
