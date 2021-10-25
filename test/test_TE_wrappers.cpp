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
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <dkg/dkg.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>
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

        libBLS::Dkg dkg_te( num_signed, num_all );

        std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();

        libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

        libff::alt_bn128_Fr common_skey = dkg_te.PolynomialValue( poly, zero_el );
        BOOST_REQUIRE( common_skey == poly.at( 0 ) );

        TEPrivateKey common_private( common_skey, num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        TEPublicKey common_public( common_private, num_signed, num_all );
        auto msg_ptr = std::make_shared< std::string >( message );
        libBLS::Ciphertext cypher = common_public.encrypt( msg_ptr );

        std::vector< libff::alt_bn128_Fr > skeys = dkg_te.SecretKeyContribution( poly );
        std::vector< TEPrivateKeyShare > skey_shares;
        std::vector< TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            skey_shares.emplace_back( TEPrivateKeyShare( skeys[i], i + 1, num_signed, num_all ) );
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

        libBLS::Ciphertext bad_cypher = cypher;  // corrupt V in cypher
        std::get< 1 >( bad_cypher ) = spoilMessage( std::get< 1 >( cypher ) );

        BOOST_REQUIRE_THROW( decr_set.merge( bad_cypher ), libBLS::ThresholdUtils::IncorrectInput );

        // cannot add after merge
        BOOST_REQUIRE_THROW(
            decr_set.addDecrypt( num_signed, nullptr ), libBLS::ThresholdUtils::IncorrectInput );

        bad_cypher = cypher;  // corrupt U in cypher
        libff::alt_bn128_G2 rand_el = libff::alt_bn128_G2::random_element();
        std::get< 0 >( bad_cypher ) = rand_el;

        BOOST_REQUIRE_THROW( decr_set.merge( bad_cypher ), libBLS::ThresholdUtils::IncorrectInput );

        bad_cypher = cypher;  // corrupt W in cypher
        libff::alt_bn128_G1 rand_el2 = libff::alt_bn128_G1::random_element();
        std::get< 2 >( bad_cypher ) = rand_el2;

        BOOST_REQUIRE_THROW( decr_set.merge( bad_cypher ), libBLS::ThresholdUtils::IncorrectInput );

        size_t ind = rand_gen() % num_signed;  // corrupt random private key share

        libff::alt_bn128_Fr bad_pkey = libff::alt_bn128_Fr::random_element();
        TEPrivateKeyShare bad_key(
            bad_pkey, skey_shares[ind].getSignerIndex(), num_signed, num_all );
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

        libBLS::Dkg dkg_te( num_signed, num_all );

        std::string message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }

        std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
            std::shared_ptr< TEPublicKey > >
            keys = TEPrivateKeyShare::generateSampleKeys( num_signed, num_all );


        auto msg_ptr = std::make_shared< std::string >( message );
        libBLS::Ciphertext cypher = keys.second->encrypt( msg_ptr );

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

            libBLS::Dkg dkg_te( num_signed, num_all );
            std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();
            auto shared_poly = std::make_shared< std::vector< libff::alt_bn128_Fr > >( poly );
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
        libBLS::Ciphertext cypher = common_public.encrypt( msg_ptr );

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
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % num_all + 1;

    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::checkSigners( 0, num_all ),
        libBLS::ThresholdUtils::IncorrectInput );

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, 0 ), libBLS::ThresholdUtils::IncorrectInput );

    // null public key share
    BOOST_REQUIRE_THROW( TEPublicKeyShare( nullptr, 1, num_signed, num_all ),
        libBLS::ThresholdUtils::IncorrectInput );

    {
        // 1 coord of public key share is not a number
        std::vector< std::string > pkey_str( {"123", "abc"} );
        BOOST_REQUIRE_THROW(
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // wrong formated public key share
        std::vector< std::string > pkey_str( {"0", "0", "0", "0"} );
        BOOST_REQUIRE_THROW(
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // one component public key share
        std::vector< std::string > pkey_str( {"1232450"} );
        BOOST_REQUIRE_THROW(
            TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // one zero component in cypher
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        TEPublicKeyShare pkey(
            TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::zero();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::Ciphertext cypher;
        std::get< 0 >( cypher ) = U;
        std::get< 1 >( cypher ) = "tra-la-la";
        std::get< 2 >( cypher ) = W;

        BOOST_REQUIRE_THROW( pkey.Verify( cypher, U ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // wrong string length in cypher
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();

        TEPublicKeyShare pkey(
            TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );
        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::Ciphertext cypher;
        std::get< 0 >( cypher ) = U;
        std::get< 1 >( cypher ) = "tra-la-la";
        std::get< 2 >( cypher ) = W;

        BOOST_REQUIRE_THROW( pkey.Verify( cypher, U ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // zero decrypted
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        TEPublicKeyShare pkey(
            TEPrivateKeyShare( el, 1, num_signed, num_all ), num_signed, num_all );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::Ciphertext cypher;
        std::get< 0 >( cypher ) = U;
        std::get< 1 >( cypher ) =
            "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
        std::get< 2 >( cypher ) = W;

        libff::alt_bn128_G2 decrypt = libff::alt_bn128_G2::zero();

        BOOST_REQUIRE_THROW(
            pkey.Verify( cypher, decrypt ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // null private key share
        BOOST_REQUIRE_THROW( TEPrivateKeyShare( nullptr, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // zero private key share
        std::string zero_str = "0";
        BOOST_REQUIRE_THROW( TEPrivateKeyShare( std::make_shared< std::string >( zero_str ), 1,
                                 num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        // zero private key share
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW( TEPrivateKeyShare( el, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        // wrong signer index
        BOOST_REQUIRE_THROW( TEPrivateKeyShare( libff::alt_bn128_Fr::random_element(), num_all + 1,
                                 num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // null public key
        BOOST_REQUIRE_THROW(
            TEPublicKey( nullptr, num_signed, num_all ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // wrong formated public key
        std::vector< std::string > pkey_str( {"0", "0", "0", "0"} );
        BOOST_REQUIRE_THROW(
            TEPublicKey(
                std::make_shared< std::vector< std::string > >( pkey_str ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // zero public key
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW(
            TEPublicKey pkey( TEPrivateKey( el, num_signed, num_all ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // zero public key
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW(
            TEPublicKey pkey( el, num_signed, num_all ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // null message
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::random_element();

        TEPublicKey pkey( el, num_signed, num_all );

        BOOST_REQUIRE_THROW( pkey.encrypt( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // message length is not 64
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::random_element();

        TEPublicKey pkey( el, num_signed, num_all );

        BOOST_REQUIRE_THROW( pkey.encrypt( std::make_shared< std::string >( "tra-la-la" ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // null private key
        BOOST_REQUIRE_THROW(
            TEPrivateKey( nullptr, num_signed, num_all ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // zero private key
        std::string zero_str = "0";
        BOOST_REQUIRE_THROW(
            TEPrivateKey( std::make_shared< std::string >( zero_str ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // zero private key
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW(
            TEPrivateKey( el, num_signed, num_all ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        //_requiredSigners > _totalSigners
        BOOST_REQUIRE_THROW( TEDecryptSet decr_set( num_all + 1, num_signed ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // same indices in decrypt set
        TEDecryptSet decr_set( num_signed, num_all );

        libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();
        auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );

        libff::alt_bn128_G2 el2 = libff::alt_bn128_G2::random_element();
        auto el_ptr2 = std::make_shared< libff::alt_bn128_G2 >( el2 );

        decr_set.addDecrypt( 1, el_ptr1 );
        BOOST_REQUIRE_THROW(
            decr_set.addDecrypt( 1, el_ptr2 ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // zero element in decrypt set
        TEDecryptSet decr_set( num_signed, num_all );

        libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::zero();
        auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );

        BOOST_REQUIRE_THROW(
            decr_set.addDecrypt( 1, el_ptr1 ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // null element in decrypt set
        TEDecryptSet decr_set( num_signed, num_all );

        std::shared_ptr< libff::alt_bn128_G2 > el_ptr1 = nullptr;
        BOOST_REQUIRE_THROW(
            decr_set.addDecrypt( 1, el_ptr1 ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // not enough elements in decrypt set
        TEDecryptSet decr_set( num_signed, num_all );
        libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();

        auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );
        decr_set.addDecrypt( 1, el_ptr1 );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::Ciphertext cypher;
        std::get< 0 >( cypher ) = U;
        std::get< 1 >( cypher ) =
            "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
        std::get< 2 >( cypher ) = W;

        BOOST_REQUIRE_THROW( decr_set.merge( cypher ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // cannot combine shares
        TEDecryptSet decr_set( 1, 1 );
        libff::alt_bn128_G2 el1 = libff::alt_bn128_G2::random_element();
        auto el_ptr1 = std::make_shared< libff::alt_bn128_G2 >( el1 );
        decr_set.addDecrypt( 1, el_ptr1 );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::Ciphertext cypher;
        std::get< 0 >( cypher ) = U;
        std::get< 1 >( cypher ) =
            "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";
        std::get< 2 >( cypher ) = W;
        BOOST_REQUIRE_THROW( decr_set.merge( cypher ), libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_CASE( ExceptionsDKGWrappersTest ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % num_all + 1;

    {
        // zero share
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();

        BOOST_REQUIRE_THROW( dkg_te.VerifyDKGShare( 1, el, dkg_te.createDKGPublicShares() ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        // null verification vector
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare( 1, el, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();

        std::vector< libff::alt_bn128_G2 > pub_shares = *dkg_te.createDKGPublicShares();
        pub_shares.erase( pub_shares.begin() );

        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare(
                1, el, std::make_shared< std::vector< libff::alt_bn128_G2 > >( pub_shares ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares =
            dkg_te.createDKGSecretShares();
        shares = nullptr;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        dkg_te.createDKGSecretShares();

        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > v;

        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( v ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_te.CreateTEPrivateKeyShare( 1, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        auto wrong_size_vector = std::make_shared< std::vector< libff::alt_bn128_Fr > >();
        wrong_size_vector->resize( num_signed - 1 );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPrivateKeyShare( 1, wrong_size_vector ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( num_signed, num_all );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPublicKey( nullptr, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_SUITE_END()
