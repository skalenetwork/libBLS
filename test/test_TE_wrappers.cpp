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

BOOST_AUTO_TEST_CASE( testSqrt ) {
    for ( size_t i = 0; i < 100; i++ ) {
        gmp_randstate_t state;
        gmp_randinit_default( state );

        mpz_t rand;
        mpz_init( rand );

        mpz_t num_limbs_mpz;
        mpz_init( num_limbs_mpz );
        mpz_set_si( num_limbs_mpz, num_limbs );

        mpz_urandomm( rand, state, num_limbs_mpz );

        mpz_clear( num_limbs_mpz );

        mpz_t modulus_q;
        mpz_init( modulus_q );
        mpz_set_str( modulus_q,
            "87807107996633125224377819847540498158068831994142082110286533992664756308802229570786"
            "25179422662221423155858769582317459277713367317481324925129998224791",
            10 );

        mpz_t sqr_mod;
        mpz_init( sqr_mod );
        mpz_powm_ui( sqr_mod, rand, 2, modulus_q );

        mpz_t mpz_sqrt0;
        mpz_init( mpz_sqrt0 );
        mpz_mod( mpz_sqrt0, rand, modulus_q );

        mpz_clear( rand );

        mpz_t mpz_sqrt;
        mpz_init( mpz_sqrt );

        MpzSquareRoot( mpz_sqrt, sqr_mod );

        mpz_t sum;
        mpz_init( sum );

        mpz_add( sum, mpz_sqrt0, mpz_sqrt );

        BOOST_REQUIRE( mpz_cmp( mpz_sqrt0, mpz_sqrt ) == 0 || mpz_cmp( sum, modulus_q ) == 0 );

        mpz_clears( mpz_sqrt0, mpz_sqrt, sqr_mod, sum, modulus_q, 0 );
        gmp_randclear( state );
    }
}

BOOST_AUTO_TEST_CASE( TEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        encryption::DkgTe dkg_te( num_signed, num_all );

        std::vector< encryption::element_wrapper > poly = dkg_te.GeneratePolynomial();
        element_t zero;
        element_init_Zr( zero, TEDataSingleton::getData().pairing_ );
        element_set0( zero );
        encryption::element_wrapper zero_el( zero );

        element_clear( zero );

        encryption::element_wrapper common_skey = dkg_te.ComputePolynomialValue( poly, zero_el );
        BOOST_REQUIRE( element_cmp( common_skey.el_, poly.at( 0 ).el_ ) == 0 );

        TEPrivateKey common_private( common_skey, num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        TEPublicKey common_public( common_private, num_signed, num_all );
        std::shared_ptr msg_ptr = std::make_shared< std::string >( message );
        encryption::Ciphertext cypher = common_public.encrypt( msg_ptr );

        std::vector< encryption::element_wrapper > skeys =
            dkg_te.CreateSecretKeyContribution( poly );
        std::vector< TEPrivateKeyShare > skey_shares;
        std::vector< TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            skey_shares.emplace_back(
                TEPrivateKeyShare( skeys[i].el_, i + 1, num_signed, num_all ) );
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
            encryption::element_wrapper decrypt = skey_shares[i].decrypt( cypher );
            BOOST_REQUIRE( public_key_shares[i].Verify( cypher, decrypt.el_ ) );
            std::shared_ptr decr_ptr = std::make_shared< encryption::element_wrapper >( decrypt );
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
        element_t rand_el;
        element_init_G1( rand_el, TEDataSingleton::getData().pairing_ );
        std::get< 0 >( bad_cypher ) = rand_el;

        is_exception_caught = false;
        try {
            decr_set.merge( bad_cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        bad_cypher = cypher;  // corrupt W in cypher
        element_t rand_el2;
        element_init_G1( rand_el2, TEDataSingleton::getData().pairing_ );
        std::get< 2 >( bad_cypher ) = rand_el2;
        is_exception_caught = false;
        try {
            decr_set.merge( bad_cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        size_t ind = rand_gen() % num_signed;  // corrupt random private key share

        element_t bad_pkey;
        element_init_Zr( bad_pkey, TEDataSingleton::getData().pairing_ );
        element_random( bad_pkey );
        TEPrivateKeyShare bad_key( encryption::element_wrapper( bad_pkey ),
            skey_shares[ind].getSignerIndex(), num_signed, num_all );
        skey_shares[ind] = bad_key;
        element_clear( bad_pkey );

        TEDecryptSet bad_decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            encryption::element_wrapper decrypt = skey_shares[i].decrypt( cypher );
            if ( i == ind )
                BOOST_REQUIRE( !public_key_shares[i].Verify( cypher, decrypt.el_ ) );
            std::shared_ptr decr_ptr = std::make_shared< encryption::element_wrapper >( decrypt );
            bad_decr_set.addDecrypt( skey_shares[i].getSignerIndex(), decr_ptr );
        }

        std::string bad_message_decrypted = bad_decr_set.merge( cypher );
        BOOST_REQUIRE( message != bad_message_decrypted );

        element_clear( rand_el );
        element_clear( rand_el2 );
    }
}

BOOST_AUTO_TEST_CASE( ShortTEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
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


        std::shared_ptr msg_ptr = std::make_shared< std::string >( message );
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
            encryption::element_wrapper decrypt = ( *keys.first->at( i ) ).decrypt( cypher );
            BOOST_REQUIRE( public_key_shares.at( i ).Verify( cypher, decrypt.el_ ) );
            std::shared_ptr decr_ptr = std::make_shared< encryption::element_wrapper >( decrypt );
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

        element_t test0;
        element_init_G1( test0, TEDataSingleton::getData().pairing_ );
        element_random( test0 );
        TEPublicKey common_pkey( encryption::element_wrapper( test0 ), num_signed, num_all );

        element_clear( test0 );

        TEPublicKey common_pkey_from_str( common_pkey.toString(), num_signed, num_all );
        BOOST_REQUIRE( element_cmp( common_pkey.getPublicKey().el_,
                           common_pkey_from_str.getPublicKey().el_ ) == 0 );

        element_t test;
        element_init_Zr( test, TEDataSingleton::getData().pairing_ );
        element_random( test );
        TEPrivateKey private_key( encryption::element_wrapper( test ), num_signed, num_all );

        element_clear( test );

        TEPrivateKey private_key_from_str(
            std::make_shared< std::string >( private_key.toString() ), num_signed, num_all );
        BOOST_REQUIRE( element_cmp( private_key.getPrivateKey().el_,
                           private_key_from_str.getPrivateKey().el_ ) == 0 );

        element_t test2;
        element_init_Zr( test2, TEDataSingleton::getData().pairing_ );
        element_random( test2 );
        size_t signer = rand_gen() % num_all;
        TEPrivateKeyShare pr_key_share(
            encryption::element_wrapper( test2 ), signer, num_signed, num_all );

        element_clear( test2 );

        TEPrivateKeyShare pr_key_share_from_str(
            std::make_shared< std::string >( pr_key_share.toString() ), signer, num_signed,
            num_all );
        BOOST_REQUIRE( element_cmp( pr_key_share.getPrivateKey().el_,
                           pr_key_share_from_str.getPrivateKey().el_ ) == 0 );

        TEPublicKeyShare pkey( pr_key_share, num_signed, num_all );
        TEPublicKeyShare pkey_from_str(
            pkey.toString(), pr_key_share.getSignerIndex(), num_signed, num_all );
        BOOST_REQUIRE(
            element_cmp( pkey.getPublicKey().el_, pkey_from_str.getPublicKey().el_ ) == 0 );
    }
    std::cerr << "TE wrappers tests finished" << std::endl;
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWithDKG ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % num_all + 1;
        std::vector< std::vector< encryption::element_wrapper > > secret_shares_all;
        std::vector< std::vector< encryption::element_wrapper > > public_shares_all;
        std::vector< DKGTEWrapper > dkgs;
        std::vector< TEPrivateKeyShare > skeys;
        std::vector< TEPublicKeyShare > pkeys;

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGTEWrapper dkg_wrap( num_signed, num_all );

            encryption::DkgTe dkg_te( num_signed, num_all );
            std::vector< encryption::element_wrapper > poly = dkg_te.GeneratePolynomial();
            auto shared_poly =
                std::make_shared< std::vector< encryption::element_wrapper > >( poly );
            dkg_wrap.setDKGSecret( shared_poly );

            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< encryption::element_wrapper > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< encryption::element_wrapper > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }


        for ( size_t i = 0; i < num_all; i++ )
            for ( size_t j = 0; j < num_all; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< encryption::element_wrapper > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< encryption::element_wrapper > > secret_key_shares;

        for ( size_t i = 0; i < num_all; i++ ) {
            std::vector< encryption::element_wrapper > secret_key_contribution;
            for ( size_t j = 0; j < num_all; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < num_all; i++ ) {
            TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
                i + 1, std::make_shared< std::vector< encryption::element_wrapper > >(
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
            std::make_shared< std::vector< std::vector< encryption::element_wrapper > > >(
                public_shares_all ),
            num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        std::shared_ptr msg_ptr = std::make_shared< std::string >( message );
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
            encryption::element_wrapper decrypt = skeys[i].decrypt( cypher );
            BOOST_REQUIRE( pkeys[i].Verify( cypher, decrypt.el_ ) );
            std::shared_ptr decr_ptr = std::make_shared< encryption::element_wrapper >( decrypt );
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
            TEDataSingleton::checkSigners( 0, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDataSingleton::checkSigners( 0, 0 );
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
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_random( el );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );
            TEPublicKeyShare pkey(
                TEPrivateKeyShare( el_wrap, 1, num_signed, num_all ), num_signed, num_all );

            element_t U;
            element_init_G1( U, TEDataSingleton::getData().pairing_ );
            element_set_str( U, "[0, 0]", 10 );
            encryption::element_wrapper U_wrap( U );
            element_clear( U );


            element_t W;
            element_init_G1( W, TEDataSingleton::getData().pairing_ );
            element_random( W );
            encryption::element_wrapper W_wrap( W );
            element_clear( W );

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U_wrap;
            std::get< 1 >( cypher ) = "tra-la-la";
            std::get< 2 >( cypher ) = W_wrap;

            pkey.Verify( cypher, el );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );


        is_exception_caught = false;  // wrong string length in cypher
        try {
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_random( el );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );

            TEPublicKeyShare pkey(
                TEPrivateKeyShare( el_wrap, 1, num_signed, num_all ), num_signed, num_all );
            element_t U;
            element_init_G1( U, TEDataSingleton::getData().pairing_ );
            element_random( U );

            element_t W;
            element_init_G1( W, TEDataSingleton::getData().pairing_ );
            element_random( W );

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = encryption::element_wrapper( U );
            std::get< 1 >( cypher ) = "tra-la-la";
            std::get< 2 >( cypher ) = encryption::element_wrapper( W );

            element_clear( U );
            element_clear( W );

            pkey.Verify( cypher, el );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero decrypted
        try {
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_random( el );
            TEPublicKeyShare pkey(
                TEPrivateKeyShare( encryption::element_wrapper( el ), 1, num_signed, num_all ),
                num_signed, num_all );

            element_t U;
            element_init_G1( U, TEDataSingleton::getData().pairing_ );
            element_random( U );

            element_t W;
            element_init_G1( W, TEDataSingleton::getData().pairing_ );
            element_random( W );

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = encryption::element_wrapper( U );
            std::get< 1 >( cypher ) =
                "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = encryption::element_wrapper( W );

            element_t decr;
            element_init_G1( decr, TEDataSingleton::getData().pairing_ );
            element_set_str( decr, "[0, 0]", 10 );
            encryption::element_wrapper decrypt( decr );
            element_clear( decr );

            element_clear( el );
            element_clear( U );
            element_clear( W );

            pkey.Verify( cypher, decrypt.el_ );


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
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_set0( el );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );
            TEPrivateKeyShare( el_wrap, 1, num_signed, num_all );

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
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_set_si( el, 0 );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );
            TEPublicKey pkey( TEPrivateKey( el_wrap, num_signed, num_all ), num_signed, num_all );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // zero public key
        try {
            element_t el;
            element_init_G1( el, TEDataSingleton::getData().pairing_ );
            element_set_str( el, "[0, 0]", 10 );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );
            TEPublicKey pkey( el_wrap, num_signed, num_all );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // null message
        try {
            element_t el;
            element_init_G1( el, TEDataSingleton::getData().pairing_ );
            element_random( el );

            TEPublicKey pkey( el, num_signed, num_all );
            element_clear( el );

            pkey.encrypt( nullptr );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;  // message length is not 64
        try {
            element_t el;
            element_init_G1( el, TEDataSingleton::getData().pairing_ );
            element_random( el );

            TEPublicKey pkey( el, num_signed, num_all );
            element_clear( el );

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
            element_t el;
            element_init_Zr( el, TEDataSingleton::getData().pairing_ );
            element_set0( el );
            encryption::element_wrapper el_wrap( el );
            element_clear( el );
            TEPrivateKey( el_wrap, num_signed, num_all );
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

            element_t el1;
            element_init_G1( el1, TEDataSingleton::getData().pairing_ );
            element_random( el1 );
            std::shared_ptr el_ptr1 = std::make_shared< encryption::element_wrapper >( el1 );
            element_clear( el1 );

            element_t el2;
            element_init_G1( el2, TEDataSingleton::getData().pairing_ );
            element_random( el2 );
            std::shared_ptr el_ptr2 = std::make_shared< encryption::element_wrapper >( el2 );
            element_clear( el2 );

            decr_set.addDecrypt( 1, el_ptr1 );
            decr_set.addDecrypt( 1, el_ptr2 );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // zero element in decrypt set

            element_t el1;
            element_init_G1( el1, TEDataSingleton::getData().pairing_ );
            element_set_str( el1, "[0, 0]", 10 );
            std::shared_ptr el_ptr1 = std::make_shared< encryption::element_wrapper >( el1 );
            element_clear( el1 );

            decr_set.addDecrypt( 1, el_ptr1 );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // null element in decrypt set
            element_t el1;
            element_init_G1( el1, TEDataSingleton::getData().pairing_ );
            element_set_str( el1, "[0, 0]", 10 );
            encryption::element_wrapper el_wrap( el1 );
            std::shared_ptr el_ptr1 = std::make_shared< encryption::element_wrapper >( el_wrap );
            el_ptr1 = nullptr;
            element_clear( el1 );
            decr_set.addDecrypt( 1, el_ptr1 );

        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( num_signed, num_all );  // not enough elements in decrypt set
            element_t el1;
            element_init_G1( el1, TEDataSingleton::getData().pairing_ );
            element_random( el1 );
            encryption::element_wrapper el_wrap( el1 );
            element_clear( el1 );
            std::shared_ptr el_ptr1 = std::make_shared< encryption::element_wrapper >( el_wrap );
            decr_set.addDecrypt( 1, el_ptr1 );

            element_t U;
            element_init_G1( U, TEDataSingleton::getData().pairing_ );
            element_random( U );
            encryption::element_wrapper U_wrap( U );
            element_clear( U );

            element_t W;
            element_init_G1( W, TEDataSingleton::getData().pairing_ );
            element_random( W );
            encryption::element_wrapper W_wrap( W );
            element_clear( W );

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U_wrap;
            std::get< 1 >( cypher ) =
                "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = W_wrap;

            decr_set.merge( cypher );
        } catch ( std::runtime_error& ) {
            is_exception_caught = true;
        }
        BOOST_REQUIRE( is_exception_caught );

        is_exception_caught = false;
        try {
            TEDecryptSet decr_set( 1, 1 );  // cannot combine shares
            element_t el1;
            element_init_G1( el1, TEDataSingleton::getData().pairing_ );
            element_random( el1 );
            std::shared_ptr el_ptr1 = std::make_shared< encryption::element_wrapper >( el1 );
            element_clear( el1 );
            decr_set.addDecrypt( 1, el_ptr1 );

            element_t U;
            element_init_G1( U, TEDataSingleton::getData().pairing_ );
            element_random( U );
            encryption::element_wrapper U_wrap( U );
            element_clear( U );

            element_t W;
            element_init_G1( W, TEDataSingleton::getData().pairing_ );
            element_random( W );
            encryption::element_wrapper W_wrap( W );
            element_clear( W );

            encryption::Ciphertext cypher;
            std::get< 0 >( cypher ) = U_wrap;
            std::get< 1 >( cypher ) =
                "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
            std::get< 2 >( cypher ) = W_wrap;

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

        element_t el1;
        element_init_Zr( el1, TEDataSingleton::getData().pairing_ );
        element_set0( el1 );
        encryption::element_wrapper el_wrap( el1 );
        element_clear( el1 );

        dkg_te.VerifyDKGShare( 1, el_wrap, dkg_te.createDKGPublicShares() );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        // null verification vector
        DKGTEWrapper dkg_te( num_signed, num_all );

        element_t el1;
        element_init_Zr( el1, TEDataSingleton::getData().pairing_ );
        element_random( el1 );
        encryption::element_wrapper el_wrap( el1 );
        element_clear( el1 );
        dkg_te.VerifyDKGShare( 1, el_wrap, nullptr );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );

        element_t el1;
        element_init_Zr( el1, TEDataSingleton::getData().pairing_ );
        element_random( el1 );
        encryption::element_wrapper el_wrap( el1 );
        element_clear( el1 );

        std::vector< encryption::element_wrapper > pub_shares = *dkg_te.createDKGPublicShares();
        pub_shares.erase( pub_shares.begin() );

        dkg_te.VerifyDKGShare( 1, el_wrap,
            std::make_shared< std::vector< encryption::element_wrapper > >( pub_shares ) );

    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< encryption::element_wrapper > > shares =
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
        std::shared_ptr< std::vector< encryption::element_wrapper > > shares =
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
        auto wrong_size_vector = std::make_shared< std::vector< encryption::element_wrapper > >();
        wrong_size_vector->resize( num_signed - 1 );
        dkg_te.CreateTEPrivateKeyShare( 1, wrong_size_vector );
    } catch ( std::runtime_error& ) {
        is_exception_caught = true;
    }
    BOOST_REQUIRE( is_exception_caught );

    is_exception_caught = false;
    try {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< encryption::element_wrapper > > shares;
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
