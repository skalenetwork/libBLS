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

@file libBLS::TEPublicKey.h
@author Sveta Rogova
@date 2019
*/


#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>

#include <dkg/dkg.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/ThresholdEncryption.h>
#include <threshold_encryption/threshold_encryption.h>
#include <tools/utils.h>

#include "utils.h"
#include <dkg/DKGTEWrapper.h>
#include <openssl/rand.h>
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

// initialize before each test
class TestFixture {
public:
    TestFixture() { libBLS::TEBase::initializeIfNecessary(); }

    ~TestFixture() {}
};

BOOST_FIXTURE_TEST_SUITE( ThresholdEncryptionWrappers, TestFixture )

BOOST_AUTO_TEST_CASE( TEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libBLS::Dkg dkg_te( num_signed, num_all );

        std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();

        libff::alt_bn128_Fr zero_el = libff::alt_bn128_Fr::zero();

        libff::alt_bn128_Fr common_skey = dkg_te.PolynomialValue( poly, zero_el );
        BOOST_REQUIRE( common_skey == poly.at( 0 ) );

        libBLS::TEPrivateKey common_private( common_skey );

        std::vector< uint8_t > message;
        size_t msg_length = 64;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message.push_back( rand_gen() % 256 );
        }

        libBLS::TEPublicKey common_public( common_private );
        libBLS::Ciphertext cypher = libBLS::ThresholdEncryption::encrypt( message, common_public );

        std::vector< libff::alt_bn128_Fr > skeys = dkg_te.SecretKeyContribution( poly );
        std::vector< libBLS::TEPrivateKeyShare > skey_shares;
        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            skey_shares.emplace_back(
                libBLS::TEPrivateKeyShare( skeys[i], i + 1, num_signed, num_all ) );
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( skey_shares[i] ) );
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

        libBLS::TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libBLS::TEDecryptionShare share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, skey_shares[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, share, public_key_shares[i] );
            decr_set.addDecryptShare( share );
        }
        // each can only combine the shares once - thus several copies
        libBLS::TEDecryptSet decr_set2 = decr_set;
        libBLS::TEDecryptSet decr_set3 = decr_set;
        libBLS::TEDecryptSet decr_set4 = decr_set;

        libBLS::AES256Key key = libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set );

        libBLS::ThresholdEncryption::validateCombinedDecryption( cypher, key, common_public );

        std::vector< uint8_t > decipheredMsg = libBLS::ThresholdEncryption::decrypt( cypher, key );
        BOOST_REQUIRE( decipheredMsg == message );


        libBLS::CipheredKey bad_cyphered_key = cypher.key;  // corrupt V in cypher

        // spoil 2 random consecutive bytes
        size_t ind4del = rand_gen() % libBLS::AES_256_KEY_SIZE_BYTES;
        bad_cyphered_key.V[ind4del] = rand_gen() % 256;
        bad_cyphered_key.V[( ind4del + 1 ) % libBLS::AES_256_KEY_SIZE_BYTES] = rand_gen() % 256;

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set2 ),
            libBLS::ThresholdUtils::IncorrectInput );

        // cannot add after merge
        BOOST_REQUIRE_THROW( decr_set.addDecryptShare( libBLS::TEDecryptionShare(
                                 1, libff::alt_bn128_G2::random_element() ) ),
            libBLS::ThresholdUtils::IncorrectInput );

        bad_cyphered_key = cypher.key;  // corrupt U in cypher
        libff::alt_bn128_G2 rand_el = libff::alt_bn128_G2::random_element();
        bad_cyphered_key.U = rand_el;

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set3 ),
            libBLS::ThresholdUtils::IncorrectInput );

        bad_cyphered_key = cypher.key;  // corrupt W in cypher
        libff::alt_bn128_G1 rand_el2 = libff::alt_bn128_G1::random_element();
        bad_cyphered_key.W = rand_el2;

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::combineShares( bad_cyphered_key, decr_set4 ),
            libBLS::ThresholdUtils::IncorrectInput );

        size_t ind = rand_gen() % num_signed;  // corrupt random private key share

        libff::alt_bn128_Fr bad_pkey = libff::alt_bn128_Fr::random_element();
        libBLS::TEPrivateKeyShare bad_key(
            bad_pkey, skey_shares[ind].getSignerIndex(), num_signed, num_all );
        skey_shares[ind] = bad_key;

        libBLS::TEDecryptSet bad_decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, skey_shares[i] );
            if ( i == ind )
                BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                         cypher.key, decr_share, public_key_shares[i] ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
            bad_decr_set.addDecryptShare( decr_share );
        }

        libBLS::AES256Key bad_key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cypher.key, bad_decr_set );
        BOOST_REQUIRE( key != bad_key_decrypted );
    }
}

BOOST_AUTO_TEST_CASE( ShortTEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libBLS::Dkg dkg_te( num_signed, num_all );

        std::vector< uint8_t > message = randomByteVec( 64 );

        keys keys = generateKeys( num_signed, num_all );

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, public_key_shares.at( i ) );
            decr_set.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set );

        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cypher, key_decrypted, keys.commonPublic );

        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}


BOOST_AUTO_TEST_CASE( TEFailingValidation ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libBLS::Dkg dkg_te( num_signed, num_all );

        std::vector< uint8_t > message = randomByteVec( 100 );

        keys keys = generateKeys( num_signed, num_all );

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        libBLS::CipheredKey bad_key = cypher.key;
        bad_key.V[0] = 0xAA;  // spoil the ciphered key
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateEncryption( bad_key ),
            libBLS::ThresholdUtils::IsNotWellFormed );
        libBLS::ThresholdEncryption::validateEncryption( cypher.key );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < num_all; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, public_key_shares.at( i ) );

            decr_set.addDecryptShare( decr_share );
        }
        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set );

        // change some bytes from key_decrypted
        libBLS::AES256Key copy = key_decrypted;
        copy[0] = ( key_decrypted[0] + 1 ) % 256;
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateCombinedDecryption(
                                 cypher, copy, keys.commonPublic ),
            std::runtime_error );

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::decrypt( cypher, copy ), std::runtime_error );
    }
}


BOOST_AUTO_TEST_CASE( WrappersFromString ) {
    libBLS::TEBase::initializeIfNecessary();

    for ( size_t i = 0; i < 100; i++ ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libff::alt_bn128_G2 test0 = libff::alt_bn128_G2::random_element();
        libBLS::TEPublicKey common_pkey( test0 );

        libBLS::TEPublicKey common_pkey_from_str( common_pkey.toString() );
        BOOST_REQUIRE( common_pkey.getPublicKeyRaw() == common_pkey_from_str.getPublicKeyRaw() );

        libff::alt_bn128_Fr test = libff::alt_bn128_Fr::random_element();
        libBLS::TEPrivateKey private_key( test );

        libBLS::TEPrivateKey private_key_from_str(
            std::make_shared< std::string >( private_key.toString() ) );
        BOOST_REQUIRE( private_key.getPrivateKeyRaw() == private_key_from_str.getPrivateKeyRaw() );

        libff::alt_bn128_Fr test2 = libff::alt_bn128_Fr::random_element();
        size_t signer = rand_gen() % num_all;
        libBLS::TEPrivateKeyShare pr_key_share( test2, signer, num_signed, num_all );

        std::string a( pr_key_share.toStringHex() );
        libBLS::TEPrivateKeyShare pr_key_share_from_str( a, signer, num_signed, num_all );
        BOOST_REQUIRE(
            pr_key_share.getPrivateKeyRaw() == pr_key_share_from_str.getPrivateKeyRaw() );

        libBLS::TEPublicKeyShare pkey( pr_key_share );
        libBLS::TEPublicKeyShare pkey_from_str(
            pkey.toString(), pr_key_share.getSignerIndex(), num_signed, num_all );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey_from_str.getPublicKeyRaw() );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWithDKG ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % num_all + 1;
        std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
        std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
        std::vector< DKGTEWrapper > dkgs;
        std::vector< libBLS::TEPrivateKeyShare > skeys;
        std::vector< libBLS::TEPublicKeyShare > pkeys;

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
            libBLS::TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
                i + 1, std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                           secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
            pkeys.push_back( libBLS::TEPublicKeyShare( pkey_share ) );
        }

        libBLS::TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
            std::make_shared< std::vector< std::vector< libff::alt_bn128_G2 > > >(
                public_shares_all ),
            num_signed, num_all );

        std::vector< uint8_t > message;
        size_t msg_length = rand_gen() % 800;

        for ( size_t length = 0; length < msg_length; ++length ) {
            message.push_back( rand_gen() % 256 );
        }

        libBLS::Ciphertext cypher = libBLS::ThresholdEncryption::encrypt( message, common_public );

        libBLS::ThresholdEncryption::validateEncryption( cypher.key );

        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % secret_shares_all.size();
            auto pos4del = secret_shares_all.begin();
            advance( pos4del, ind4del );
            secret_shares_all.erase( pos4del );
            auto pos2 = public_shares_all.begin();
            advance( pos2, ind4del );
            public_shares_all.erase( pos2 );
        }

        libBLS::TEDecryptSet decr_set( num_signed, num_all );
        for ( size_t i = 0; i < num_signed; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, skeys[i] );

            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, pkeys[i] );

            decr_set.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_deciphered =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set );

        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cypher, key_deciphered, common_public );

        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_deciphered );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( ExceptionsTest ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % num_all + 1;

    BOOST_REQUIRE_THROW( libBLS::ThresholdUtils::checkSigners( 0, num_all ),
        libBLS::ThresholdUtils::IncorrectInput );

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, 0 ), libBLS::ThresholdUtils::IncorrectInput );

    {
        // null public key share
        std::shared_ptr< std::vector< std::string > > share_ptr = nullptr;
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare( share_ptr, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // wrong signer index public key share
        std::shared_ptr< std::vector< std::string > > share_ptr = nullptr;
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKeyShare( share_ptr, num_all + 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // 1 coord of public key share is not a number
        std::vector< std::string > pkey_str( { "123", "abc" } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // wrong formated public key share
        std::vector< std::string > pkey_str( { "0", "0", "0", "0" } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // one component public key share
        std::vector< std::string > pkey_str( { "1232450" } );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKeyShare( std::make_shared< std::vector< std::string > >( pkey_str ), 1,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // one zero component in cypher
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        libBLS::TEPublicKeyShare pkey( libBLS::TEPrivateKeyShare( el, 1, num_signed, num_all ) );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::zero();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::AES256Key V_random;
        RAND_bytes( V_random.data(), V_random.size() );

        libBLS::CipheredKey cypher = { U, V_random, W };

        libBLS::TEDecryptionShare decr_share( 1, libff::alt_bn128_G2::random_element() );

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateDecryptionShare( cypher, decr_share, pkey ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // decryption share built with zero decrypted share
        libff::alt_bn128_G2 secr_share = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare decr_share( 1, secr_share ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // null private key
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // zero private key
        std::string zero_str = "0";
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKey( std::make_shared< std::string >( zero_str ) ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // zero private key
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pKey( el ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // DecryptSet _requiredSigners > _totalSigners
        BOOST_REQUIRE_THROW( libBLS::TEDecryptSet decr_set( num_all + 1, num_signed ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // signer index is too high
        libBLS::TEDecryptSet decr_set( num_signed, num_all );

        libBLS::TEDecryptionShare decr_share( num_all + 1, libff::alt_bn128_G2::random_element() );

        BOOST_REQUIRE_THROW(
            decr_set.addDecryptShare( decr_share ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // trying to add more shares than total signers - can only happen if signer index starts
        // at 0
        libBLS::TEDecryptSet decr_set( num_signed, num_all );

        for ( size_t i = 0; i < num_all; i++ ) {
            libBLS::TEDecryptionShare decr_share( i, libff::alt_bn128_G2::random_element() );
            decr_set.addDecryptShare( decr_share );
        }

        libBLS::TEDecryptionShare decr_share( num_all, libff::alt_bn128_G2::random_element() );
        BOOST_REQUIRE_THROW(
            decr_set.addDecryptShare( decr_share ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // not enough elements in decrypt set
        libBLS::TEDecryptSet decr_set( num_signed, num_all );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::AES256Key random;
        RAND_bytes( random.data(), random.size() );

        libBLS::CipheredKey key;
        key.U = U;
        key.V = random;
        key.W = W;

        std::vector< uint8_t > data;
        libBLS::Ciphertext cypher = libBLS::Ciphertext( key, data );


        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // cannot combine shares - wrong cypher
        libBLS::TEDecryptSet decr_set( 1, 1 );
        libBLS::TEDecryptionShare decr_share( 1, libff::alt_bn128_G2::random_element() );
        decr_set.addDecryptShare( decr_share );

        libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();

        libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();

        libBLS::AES256Key random;
        RAND_bytes( random.data(), random.size() );

        libBLS::CipheredKey key;
        key.U = U;
        key.V = random;
        key.W = W;

        std::vector< uint8_t > data;
        libBLS::Ciphertext cypher = libBLS::Ciphertext( key, data );

        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::combineShares( cypher.key, decr_set ),
            libBLS::ThresholdUtils::IncorrectInput );
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

        BOOST_REQUIRE_THROW( dkg_te.setDKGSecret( v ), libBLS::ThresholdUtils::IncorrectInput );
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

BOOST_AUTO_TEST_CASE( TEPublicKey ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 30; ++i ) {
        libff::alt_bn128_Fr priv = libff::alt_bn128_Fr::random_element();
        libff::alt_bn128_G2 pub = priv * libff::alt_bn128_G2::one();

        // consruct from field element
        libBLS::TEPublicKey pkey( pub );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pub );

        // construct from vec of hexadecimal strings
        std::vector< std::string > vecOfStrings =
            libBLS::ThresholdUtils::G2ToString( pub, libBLS::BASE_HEXA );
        libBLS::TEPublicKey pkey2( vecOfStrings );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey2.getPublicKeyRaw() );

        // Convert To and From concatenated string
        std::string concatenatedPubKey;
        for ( const auto& str : vecOfStrings ) {
            concatenatedPubKey += str;
        }
        libBLS::TEPublicKey pkey3( concatenatedPubKey );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey3.getPublicKeyRaw() );
        std::string concatenatedPubKey2 = pkey3.toString();
        libBLS::TEPublicKey pkey4( concatenatedPubKey2 );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey4.getPublicKeyRaw() );

        // construct from private key
        libBLS::TEPrivateKey privKey( priv );
        libBLS::TEPublicKey pkey5( privKey );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey5.getPublicKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > pubKeyBytes =
            libBLS::ThresholdUtils::G2ToBytes( pub );
        libBLS::TEPublicKey pkey6( pubKeyBytes );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey6.getPublicKeyRaw() );
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > bytes6 = pkey6.toBytesArray();
        BOOST_REQUIRE( pubKeyBytes == bytes6 );

        // convert To and From vec of bytes
        std::vector< uint8_t > pubKeyBytesVec( pubKeyBytes.begin(), pubKeyBytes.end() );
        libBLS::TEPublicKey pkey7( pubKeyBytesVec );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey7.getPublicKeyRaw() );
        std::vector< uint8_t > bytes7 = pkey7.toBytesVec();
        BOOST_REQUIRE( pubKeyBytesVec == bytes7 );
    }
}

BOOST_AUTO_TEST_CASE( TEPublicKeyExceptions ) {
    // From G2
    {
        // zero public key
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey pkey( el ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    // From vec of strings
    {
        // Vec has incorrect length
        std::vector< std::string > pkey_str( { "0", "0", "0" } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkey_str ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not 64-char length
        std::vector< std::string > pkey_str( { "0", "0", "0", "0" } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkey_str ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not hexadecimal
        std::vector< std::string > pkey_str(
            { "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP",
                randomHexaString( 64 ), randomHexaString( 64 ), randomHexaString( 64 ) } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkey_str ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From string
    {
        // string has wrong length
        std::string pkey = "a";
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( pkey ), libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 256 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( hexa ), libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length + 1
        std::vector< uint8_t > randBytes = randomByteVec( libBLS::G2_SIZE_BYTES + 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes ), libBLS::ThresholdUtils::IncorrectInput );
        // necessary length - 1
        std::vector< uint8_t > randBytes2 = randomByteVec( libBLS::G2_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes2 ), libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey p( randBytes3 ), libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKeyShare ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 30; ++i ) {
        libff::alt_bn128_Fr priv = libff::alt_bn128_Fr::random_element();
        size_t signer = 1;
        size_t num_signed = 10;
        size_t num_all = 15;

        // consruct from field element
        libBLS::TEPrivateKeyShare share( priv, signer, num_signed, num_all );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == priv );

        // construct from hexadecimal string
        std::string stringField =
            libBLS::ThresholdUtils::fieldElementToString( priv, libBLS::BASE_HEXA );
        libBLS::TEPrivateKeyShare share2( stringField, signer, num_signed, num_all );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share2.getPrivateKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes =
            libBLS::ThresholdUtils::fieldElementToBytesArray( priv );
        libBLS::TEPrivateKeyShare share3( privBytes, signer, num_signed, num_all );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share3.getPrivateKeyRaw() );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes3 = share3.toBytesArray();
        BOOST_REQUIRE( privBytes == bytes3 );

        // convert To and From vec of bytes
        std::vector< uint8_t > privKeyBytesVec( privBytes.begin(), privBytes.end() );
        libBLS::TEPrivateKeyShare share4( privKeyBytesVec, signer, num_signed, num_all );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share4.getPrivateKeyRaw() );
        std::vector< uint8_t > bytes4 = share4.toBytesVec();
        BOOST_REQUIRE( privKeyBytesVec == bytes4 );
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKeyShareExceptions ) {
    // From field element
    {
        // zero private key
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 10, 15 ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }
    {
        // signer index > total signers
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 11, 10, 10 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required signers > total signers
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 12, 11 ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // zero required signer & total signers
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( el, 1, 0, 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From string
    {
        // string has wrong length
        std::string priv = "a";
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( priv, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 64 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( hexa, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // signer index > total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( hexa, 11, 10, 10 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required signers > total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( hexa, 1, 12, 11 ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // zero required signer & total signers
        std::string hexa = randomHexaString( 64 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare share( hexa, 1, 0, 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length - 1
        std::vector< uint8_t > randBytes2 =
            randomByteVec( libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( randBytes2, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW( libBLS::TEPrivateKeyShare p( randBytes3, 1, 10, 15 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_SUITE_END()
