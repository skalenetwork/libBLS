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

#include <dkg/DKGTEWrapper.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <test/utils.h>
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

BOOST_AUTO_TEST_CASE( TEMockupEncryption ) {
    std::vector< uint8_t > message;
    size_t msg_length = 64;
    for ( size_t length = 0; length < msg_length; ++length ) {
        message.push_back( rand_gen() % 256 );
    }

    auto encryptedMsg = libBLS::ThresholdEncryption::mockupEncrypt( message );
    auto decryptedMsg = libBLS::ThresholdEncryption::mockupDecrypt( encryptedMsg );

    BOOST_REQUIRE( message == decryptedMsg );
}

BOOST_AUTO_TEST_CASE( TEProcessWithWrappers ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

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
        for ( size_t i = 0; i < numAll; i++ ) {
            skey_shares.emplace_back(
                libBLS::TEPrivateKeyShare( skeys[i], i + 1, numSigned, numAll ) );
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( skey_shares[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % skey_shares.size();
            auto pos4del = skey_shares.begin();
            advance( pos4del, ind4del );
            skey_shares.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, skey_shares[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, share, public_key_shares[i] );
            decrSet.addDecryptShare( share );
        }
        // each can only combine the shares once - thus several copies
        libBLS::TEDecryptSet decr_set2 = decrSet;
        libBLS::TEDecryptSet decr_set3 = decrSet;
        libBLS::TEDecryptSet decr_set4 = decrSet;

        libBLS::AES256Key key = libBLS::ThresholdEncryption::combineShares( cypher.key, decrSet );

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
        BOOST_REQUIRE_THROW( decrSet.addDecryptShare( libBLS::TEDecryptionShare(
                                 libff::alt_bn128_G2::random_element(), 1 ) ),
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

        size_t ind = rand_gen() % numSigned;  // corrupt random private key share

        libff::alt_bn128_Fr bad_pkey = libff::alt_bn128_Fr::random_element();
        libBLS::TEPrivateKeyShare bad_key(
            bad_pkey, skey_shares[ind].getSignerIndex(), numSigned, numAll );
        skey_shares[ind] = bad_key;

        libBLS::TEDecryptSet bad_decr_set( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
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
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

        std::vector< uint8_t > message = randomByteVec( 64 );

        keys keys = generateKeys( numSigned, numAll );

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < numAll; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, public_key_shares.at( i ) );
            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decrSet );

        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cypher, key_decrypted, keys.commonPublic );

        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_decrypted );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}


BOOST_AUTO_TEST_CASE( TEFailingValidation ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libBLS::Dkg dkg_te( numSigned, numAll );

        std::vector< uint8_t > message = randomByteVec( 100 );

        keys keys = generateKeys( numSigned, numAll );

        libBLS::Ciphertext cypher =
            libBLS::ThresholdEncryption::encrypt( message, keys.commonPublic );

        libBLS::CipheredKey bad_key = cypher.key;
        bad_key.V[0] = ( bad_key.V[0] + 1 ) % 256;  // spoil the ciphered key
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateEncryption( bad_key ),
            libBLS::ThresholdUtils::IsNotWellFormed );
        libBLS::ThresholdEncryption::validateEncryption( cypher.key );

        std::vector< libBLS::TEPublicKeyShare > public_key_shares;
        for ( size_t i = 0; i < numAll; i++ ) {
            public_key_shares.emplace_back( libBLS::TEPublicKeyShare( keys.secretKeys[i] ) );
        }

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % keys.secretKeys.size();
            auto pos4del = keys.secretKeys.begin();
            advance( pos4del, ind4del );
            keys.secretKeys.erase( pos4del );
            auto pos2 = public_key_shares.begin();
            advance( pos2, ind4del );
            public_key_shares.erase( pos2 );
        }

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, keys.secretKeys[i] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, public_key_shares.at( i ) );

            decrSet.addDecryptShare( decr_share );
        }
        libBLS::AES256Key key_decrypted =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decrSet );

        // change some bytes from key_decrypted
        libBLS::AES256Key copy = key_decrypted;
        copy[0] = ( key_decrypted[0] + 1 ) % 256;
        // this can throw either runtime_exception OR IsNotWellFormed. depends on AES content
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateCombinedDecryption(
                                 cypher, copy, keys.commonPublic ),
            std::exception );

        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::decrypt( cypher, copy ), std::runtime_error );
    }
}


BOOST_AUTO_TEST_CASE( WrappersFromString ) {
    libBLS::TEBase::initializeIfNecessary();

    for ( size_t i = 0; i < 100; i++ ) {
        size_t numAll = rand_gen() % 16 + 1;
        size_t numSigned = rand_gen() % numAll + 1;

        libff::alt_bn128_G2 test0 = libff::alt_bn128_G2::random_element();
        libBLS::TEPublicKey common_pkey( test0 );

        libBLS::TEPublicKey common_pkey_from_str( common_pkey.toString() );
        BOOST_REQUIRE( common_pkey.getPublicKeyRaw() == common_pkey_from_str.getPublicKeyRaw() );

        libff::alt_bn128_Fr test = libff::alt_bn128_Fr::random_element();
        libBLS::TEPrivateKey private_key( test );

        libff::alt_bn128_Fr test2 = libff::alt_bn128_Fr::random_element();
        size_t signer = rand_gen() % numAll;
        libBLS::TEPrivateKeyShare pr_key_share( test2, signer, numSigned, numAll );

        std::string a( pr_key_share.toStringHex() );
        libBLS::TEPrivateKeyShare pr_key_share_from_str( a, signer, numSigned, numAll );
        BOOST_REQUIRE(
            pr_key_share.getPrivateKeyRaw() == pr_key_share_from_str.getPrivateKeyRaw() );
    }
}

BOOST_AUTO_TEST_CASE( ThresholdEncryptionWithDKG ) {
    for ( size_t i = 0; i < 10; i++ ) {
        size_t numAll = rand_gen() % 15 + 2;
        size_t numSigned = rand_gen() % numAll + 1;
        std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
        std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
        std::vector< DKGTEWrapper > dkgs;
        std::vector< libBLS::TEPrivateKeyShare > skeys;
        std::vector< libBLS::TEPublicKeyShare > pkeys;

        for ( size_t i = 0; i < numAll; i++ ) {
            DKGTEWrapper dkg_wrap( numSigned, numAll );

            libBLS::Dkg dkg_te( numSigned, numAll );
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

        for ( size_t i = 0; i < numAll; i++ )
            for ( size_t j = 0; j < numAll; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< libff::alt_bn128_G2 > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< libff::alt_bn128_Fr > > secret_key_shares;

        for ( size_t i = 0; i < numAll; i++ ) {
            std::vector< libff::alt_bn128_Fr > secret_key_contribution;
            for ( size_t j = 0; j < numAll; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < numAll; i++ ) {
            libBLS::TEPrivateKeyShare pkey_share = dkgs.at( i ).CreateTEPrivateKeyShare(
                i + 1, std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                           secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
            pkeys.push_back( libBLS::TEPublicKeyShare( pkey_share ) );
        }

        libBLS::TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
            std::make_shared< std::vector< std::vector< libff::alt_bn128_G2 > > >(
                public_shares_all ),
            numSigned, numAll );

        std::vector< uint8_t > message;
        size_t msg_length = rand_gen() % 800;

        for ( size_t length = 0; length < msg_length; ++length ) {
            message.push_back( rand_gen() % 256 );
        }

        libBLS::Ciphertext cypher = libBLS::ThresholdEncryption::encrypt( message, common_public );

        libBLS::ThresholdEncryption::validateEncryption( cypher.key );

        for ( size_t i = 0; i < numAll - numSigned; ++i ) {
            size_t ind4del = rand_gen() % secret_shares_all.size();
            auto pos4del = secret_shares_all.begin();
            advance( pos4del, ind4del );
            secret_shares_all.erase( pos4del );
            auto pos2 = public_shares_all.begin();
            advance( pos2, ind4del );
            public_shares_all.erase( pos2 );
        }

        libBLS::TEDecryptSet decrSet( numSigned, numAll );
        for ( size_t i = 0; i < numSigned; i++ ) {
            libBLS::TEDecryptionShare decr_share =
                libBLS::ThresholdEncryption::partialDecrypt( cypher.key, skeys[i] );

            libBLS::ThresholdEncryption::validateDecryptionShare(
                cypher.key, decr_share, pkeys[i] );

            decrSet.addDecryptShare( decr_share );
        }

        libBLS::AES256Key key_deciphered =
            libBLS::ThresholdEncryption::combineShares( cypher.key, decrSet );

        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cypher, key_deciphered, common_public );

        std::vector< uint8_t > decipheredMsg =
            libBLS::ThresholdEncryption::decrypt( cypher, key_deciphered );
        BOOST_REQUIRE( decipheredMsg == message );
    }
}

BOOST_AUTO_TEST_CASE( CheckSigners ) {
    size_t numAll = rand_gen() % 15 + 2;

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, numAll ), libBLS::ThresholdUtils::IncorrectInput );

    BOOST_REQUIRE_THROW(
        libBLS::ThresholdUtils::checkSigners( 0, 0 ), libBLS::ThresholdUtils::IncorrectInput );
}

BOOST_AUTO_TEST_CASE( ExceptionsDKGWrappersTest ) {
    size_t numAll = rand_gen() % 15 + 2;
    size_t numSigned = rand_gen() % numAll + 1;

    {
        // zero share
        DKGTEWrapper dkg_te( numSigned, numAll );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();

        BOOST_REQUIRE_THROW( dkg_te.VerifyDKGShare( 1, el, dkg_te.createDKGPublicShares() ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        // null verification vector
        DKGTEWrapper dkg_te( numSigned, numAll );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();
        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare( 1, el, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );

        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::random_element();

        std::vector< libff::alt_bn128_G2 > pub_shares = *dkg_te.createDKGPublicShares();
        pub_shares.erase( pub_shares.begin() );

        BOOST_REQUIRE_THROW(
            dkg_te.VerifyDKGShare(
                1, el, std::make_shared< std::vector< libff::alt_bn128_G2 > >( pub_shares ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares =
            dkg_te.createDKGSecretShares();
        shares = nullptr;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        dkg_te.createDKGSecretShares();

        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > v;

        BOOST_REQUIRE_THROW( dkg_te.setDKGSecret( v ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        BOOST_REQUIRE_THROW(
            dkg_te.CreateTEPrivateKeyShare( 1, nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        auto wrong_size_vector = std::make_shared< std::vector< libff::alt_bn128_Fr > >();
        wrong_size_vector->resize( numSigned - 1 );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPrivateKeyShare( 1, wrong_size_vector ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        std::shared_ptr< std::vector< libff::alt_bn128_Fr > > shares;
        BOOST_REQUIRE_THROW(
            dkg_te.setDKGSecret( shares ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGTEWrapper dkg_te( numSigned, numAll );
        BOOST_REQUIRE_THROW( dkg_te.CreateTEPublicKey( nullptr, numSigned, numAll ),
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
            libBLS::ThresholdUtils::G2ToBytesArray( pub );
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

    // Exceptions

    // From G2
    {
        // zero public key
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEPublicKey pkey( el ), libBLS::ThresholdUtils::IncorrectInput );
    }

    // From vec of strings
    {
        // Vec has incorrect length
        std::vector< std::string > pkeyStr( { "0", "0", "0" } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not 64-char length
        std::vector< std::string > pkeyStr( { "0", "0", "0", "0" } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // Components are not hexadecimal
        std::vector< std::string > pkeyStr(
            { "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP",
                randomHexaString( 64 ), randomHexaString( 64 ), randomHexaString( 64 ) } );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKey( std::vector< std::string >( pkeyStr ) ),
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


BOOST_AUTO_TEST_CASE( TEPublicKeyShare ) {
    size_t signer = 1;
    size_t numSigned = 10;
    size_t numAll = 15;

    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libff::alt_bn128_Fr priv = libff::alt_bn128_Fr::random_element();
        libff::alt_bn128_G2 pub = priv * libff::alt_bn128_G2::one();

        // construct from field element
        libBLS::TEPublicKeyShare pkey( pub, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pub );

        // construct from private key
        libBLS::TEPrivateKeyShare privKey( priv, signer, numSigned, numAll );
        libBLS::TEPublicKeyShare pkey2( privKey );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey2.getPublicKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > pubKeyBytes =
            libBLS::ThresholdUtils::G2ToBytesArray( pub );
        libBLS::TEPublicKeyShare pkey6( pubKeyBytes, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey6.getPublicKeyRaw() );
        std::array< uint8_t, libBLS::G2_SIZE_BYTES > bytes6 = pkey6.toBytesArray();
        BOOST_REQUIRE( pubKeyBytes == bytes6 );

        // convert To and From vec of bytes
        std::vector< uint8_t > pubKeyBytesVec( pubKeyBytes.begin(), pubKeyBytes.end() );
        libBLS::TEPublicKeyShare pkey7( pubKeyBytesVec, signer, numSigned, numAll );
        BOOST_REQUIRE( pkey.getPublicKeyRaw() == pkey7.getPublicKeyRaw() );
        std::vector< uint8_t > bytes7 = pkey7.toBytesVec();
        BOOST_REQUIRE( pubKeyBytesVec == bytes7 );
    }

    // Exceptions

    // From G2
    {
        // zero public key
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare pkey( el, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length + 1
        std::vector< uint8_t > randBytes = randomByteVec( libBLS::G2_SIZE_BYTES + 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
        // necessary length - 1
        std::vector< uint8_t > randBytes2 = randomByteVec( libBLS::G2_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes2, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW( libBLS::TEPublicKeyShare p( randBytes3, signer, numSigned, numAll ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKey ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libff::alt_bn128_Fr priv = libff::alt_bn128_Fr::random_element();

        // consruct from field element
        libBLS::TEPrivateKey pkey( priv );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == priv );

        // construct from hexadecimal string
        std::string stringField =
            libBLS::ThresholdUtils::fieldElementToString( priv, libBLS::BASE_HEXA );
        libBLS::TEPrivateKey pkey2( stringField );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey2.getPrivateKeyRaw() );

        // to and from string
        std::string stringField2 = pkey.toString();
        libBLS::TEPrivateKey pkey3( stringField2 );
        BOOST_REQUIRE( pkey3.getPrivateKeyRaw() == pkey2.getPrivateKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes =
            libBLS::ThresholdUtils::fieldElementToBytesArray( priv );
        libBLS::TEPrivateKey pkey4( privBytes );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey4.getPrivateKeyRaw() );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes4 = pkey4.toBytesArray();
        BOOST_REQUIRE( privBytes == bytes4 );

        // convert To and From vec of bytes
        std::vector< uint8_t > privKeyBytesVec( privBytes.begin(), privBytes.end() );
        libBLS::TEPrivateKey pkey5( privKeyBytesVec );
        BOOST_REQUIRE( pkey.getPrivateKeyRaw() == pkey5.getPrivateKeyRaw() );
        std::vector< uint8_t > bytes5 = pkey5.toBytesVec();
        BOOST_REQUIRE( privKeyBytesVec == bytes5 );
    }


    // Exceptions
    // From field element
    {
        // zero private key
        libff::alt_bn128_Fr el = libff::alt_bn128_Fr::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( el ), libBLS::ThresholdUtils::ZeroSecretKey );
    }

    // From string
    {
        // string has wrong length
        std::string priv = "aadwad";
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( priv ), libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // not hexa
        std::string hexa = randomHexaString( 64 );
        spoilRandomChar( hexa, 1, 'U' );
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( hexa ), libBLS::ThresholdUtils::IncorrectInput );
    }

    // From byte vector
    {
        // wrong size
        // necessary length - 1
        std::vector< uint8_t > randBytes2 =
            randomByteVec( libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES - 1 );
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( randBytes2 ), libBLS::ThresholdUtils::IncorrectInput );
        // length 0
        std::vector< uint8_t > randBytes3;
        BOOST_REQUIRE_THROW(
            libBLS::TEPrivateKey pkey( randBytes3 ), libBLS::ThresholdUtils::IncorrectInput );
        // no problem if length is higher
    }
}


BOOST_AUTO_TEST_CASE( TEPrivateKeyShare ) {
    // Well constructed inputs
    for ( size_t i = 0; i < 30; ++i ) {
        libff::alt_bn128_Fr priv = libff::alt_bn128_Fr::random_element();
        size_t signer = 1;
        size_t numSigned = 10;
        size_t numAll = 15;

        // consruct from field element
        libBLS::TEPrivateKeyShare share( priv, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == priv );

        // construct from hexadecimal string
        std::string stringField =
            libBLS::ThresholdUtils::fieldElementToString( priv, libBLS::BASE_HEXA );
        libBLS::TEPrivateKeyShare share2( stringField, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share2.getPrivateKeyRaw() );

        // convert To and From array of bytes
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > privBytes =
            libBLS::ThresholdUtils::fieldElementToBytesArray( priv );
        libBLS::TEPrivateKeyShare share3( privBytes, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share3.getPrivateKeyRaw() );
        std::array< uint8_t, libBLS::MAX_FIELD_ELEMENT_SIZE_BYTES > bytes3 = share3.toBytesArray();
        BOOST_REQUIRE( privBytes == bytes3 );

        // convert To and From vec of bytes
        std::vector< uint8_t > privKeyBytesVec( privBytes.begin(), privBytes.end() );
        libBLS::TEPrivateKeyShare share4( privKeyBytesVec, signer, numSigned, numAll );
        BOOST_REQUIRE( share.getPrivateKeyRaw() == share4.getPrivateKeyRaw() );
        std::vector< uint8_t > bytes4 = share4.toBytesVec();
        BOOST_REQUIRE( privKeyBytesVec == bytes4 );
    }


    // Exceptions

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


BOOST_AUTO_TEST_CASE( TEDecryptionShare ) {
    size_t signer = 1;

    // Well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        libff::alt_bn128_G2 priv = libff::alt_bn128_G2::random_element();

        // consruct from field element
        libBLS::TEDecryptionShare share( priv, signer );
        BOOST_REQUIRE( share.getShareRaw() == priv );

        // construct from hexadecimal string
        std::vector< std::string > stringField =
            libBLS::ThresholdUtils::G2ToString( priv, libBLS::BASE_HEXA );
        std::string str;
        for ( const auto& s : stringField ) {
            str += s;
        }
        libBLS::TEDecryptionShare share2( str, signer );
        BOOST_REQUIRE( share.getShareRaw() == share2.getShareRaw() );

        std::string str2 = share2.toString();
        libBLS::TEDecryptionShare share3( str2, signer );
        BOOST_REQUIRE( share.getShareRaw() == share3.getShareRaw() );
    }

    // Exceptions
    // From G2
    {
        // zero key
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::zero();
        BOOST_REQUIRE_THROW(
            libBLS::TEDecryptionShare share( el, signer ), libBLS::ThresholdUtils::IncorrectInput );
    }
    // From string
    {
        // tampered string - not hexadecimal
        libff::alt_bn128_G2 el = libff::alt_bn128_G2::random_element();
        std::vector< std::string > stringField =
            libBLS::ThresholdUtils::G2ToString( el, libBLS::BASE_HEXA );
        stringField[0][0] = 'U';
        std::string str;
        for ( const auto& s : stringField ) {
            str += s;
        }
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str, signer ),
            libBLS::ThresholdUtils::IncorrectInput );

        // string has wrong length
        str[0] = 'A';  // make it hexa again
        str.resize( str.size() - 1 );
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str, signer ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // zero element
        libff::alt_bn128_G2 el2 = libff::alt_bn128_G2::zero();
        std::vector< std::string > stringField2 =
            libBLS::ThresholdUtils::G2ToString( el2, libBLS::BASE_HEXA );
        std::string str2;
        for ( const auto& s : stringField2 ) {
            str2 += s;
        }
        BOOST_REQUIRE_THROW( libBLS::TEDecryptionShare share( str2, signer ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}

BOOST_AUTO_TEST_CASE( TEDecryptSet ) {
    libBLS::TEDecryptSet decrSet( 1, 1 );
    // well constructed inputs
    for ( size_t i = 0; i < 10; ++i ) {
        size_t numAll = rand_gen() % 15 + 2;
        size_t numSigned = rand_gen() % numAll + 1;

        keys keys = generateKeys( numSigned, numAll );

        decrSet = libBLS::TEDecryptSet( numSigned, numAll );
        BOOST_REQUIRE( decrSet.getRequiredSigners() == numSigned );
        BOOST_REQUIRE( decrSet.getTotalSigners() == numAll );


        std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares;
        for ( size_t i = 0; i < numSigned; ++i ) {
            libff::alt_bn128_G2 group = libff::alt_bn128_G2::random_element();
            libBLS::TEDecryptionShare share( group, i );
            decrSet.addDecryptShare( share );
            shares.push_back( std::make_pair( group, i ) );
        }

        BOOST_REQUIRE( decrSet.size() == numSigned );
        BOOST_REQUIRE( decrSet.canMerge() );

        decrSet.markAsMerged();
        BOOST_REQUIRE( decrSet.canMerge() == false );

        std::vector< std::pair< libff::alt_bn128_G2, size_t > > shares2 = decrSet.getSharesRaw();
        for ( size_t i = 0; i < shares2.size(); ++i ) {
            BOOST_REQUIRE( std::find( shares.begin(), shares.end(), shares2[i] ) != shares.end() );
        }
    }

    // Exceptions
    {
        // already merged
        BOOST_REQUIRE_THROW( decrSet.addDecryptShare( libBLS::TEDecryptionShare(
                                 libff::alt_bn128_G2::random_element(), 1 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // required > all
        BOOST_REQUIRE_THROW(
            libBLS::TEDecryptSet decrSet( 2, 1 ), libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // share signer index > total signers
        libBLS::TEDecryptSet decrSet( 1, 1 );
        libBLS::TEDecryptionShare decr_share( libff::alt_bn128_G2::random_element(), 2 );
        BOOST_REQUIRE_THROW(
            decrSet.addDecryptShare( decr_share ), libBLS::ThresholdUtils::IncorrectInput );
    }
    {
        // set is full
        libBLS::TEDecryptSet decrSet( 1, 1 );
        libBLS::TEDecryptionShare decr_share( libff::alt_bn128_G2::random_element(), 0 );
        decrSet.addDecryptShare( decr_share );
        libBLS::TEDecryptionShare decr_share2( libff::alt_bn128_G2::random_element(), 1 );
        BOOST_REQUIRE_THROW(
            decrSet.addDecryptShare( decr_share2 ), libBLS::ThresholdUtils::IncorrectInput );
    }
}


// Helper function to test a function call against the exception, when ciphertext data is tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextData(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
    tamperCipheredKeyV( cipher.key );

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}

// Helper function to test a function call against the exception, when ciphertext U field is
// tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextU(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
    cipher.key.U = libff::alt_bn128_G2::random_element();

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}

// Helper function to test a function call against the exception, when ciphertext W field is
// tampered
template < typename ExceptionType >
void exceptionOnTamperedCiphertextW(
    std::function< void( libBLS::Ciphertext& ) > testFunc, size_t dataSize, keys& keys ) {
    libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
    cipher.key.W = libff::alt_bn128_G1::random_element();

    BOOST_REQUIRE_THROW( testFunc( cipher ), ExceptionType );
}


BOOST_AUTO_TEST_CASE( Encryption ) {
    keys keys = generateKeys( 1, 1 );
    size_t dataSize = 100;
    for ( size_t i = 0; i < 20; ++i ) {
        std::vector< uint8_t > data = randomByteVec( dataSize );
        libBLS::Ciphertext cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );

        // should be big enough to contain message and random secret
        BOOST_REQUIRE( cipher.getData().size() >= data.size() + libBLS::RANDOM_SECRET_SIZE_BYTES );

        libBLS::ThresholdEncryption::validateEncryption( cipher.key );
    }

    // Exceptions
    for ( size_t i = 0; i < 40; ++i ) {
        {
            // should not pass pairing validation
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateEncryption( cipher.key );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered U field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateEncryption( cipher.key );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered W field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                []( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateEncryption( cipher.key );
                },
                dataSize, keys );
        }
    }
}

BOOST_AUTO_TEST_CASE( PartialDecrypt ) {
    keys keys = generateKeys( 1, 1 );
    size_t dataSize = 100;
    for ( size_t i = 0; i < 20; ++i ) {
        libBLS::Ciphertext cipher = generateRandomCiphertext( dataSize, keys );
        // should not throw any exception
        libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[0] );
    }

    // Exceptions
    for ( size_t i = 0; i < 40; ++i ) {
        {
            // passed ciphered key has tampered data
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IncorrectInput >(
                [&keys]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered U field
            exceptionOnTamperedCiphertextU< libBLS::ThresholdUtils::IncorrectInput >(
                [&keys]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered W field
            exceptionOnTamperedCiphertextW< libBLS::ThresholdUtils::IncorrectInput >(
                [&keys]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[0] );
                },
                dataSize, keys );
        }
    }
}

BOOST_AUTO_TEST_CASE( ValidateDecryptionShare ) {
    size_t requiredSigners = 2;
    size_t totalSigners = 4;
    keys keys = generateKeys( requiredSigners, totalSigners );
    size_t dataSize = 100;
    libBLS::TEDecryptionShare decrShare( libff::alt_bn128_G2::random_element(), 1 );
    libBLS::Ciphertext cipher;

    for ( size_t i = 0; i < 40; ++i ) {
        cipher = generateRandomCiphertext( dataSize, keys );
        decrShare = libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[0] );

        libBLS::TEDecryptionShare decrShare2 =
            libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[1] );

        // should not throw
        libBLS::ThresholdEncryption::validateDecryptionShare(
            cipher.key, decrShare, keys.publicKeys[0] );
        libBLS::ThresholdEncryption::validateDecryptionShare(
            cipher.key, decrShare2, keys.publicKeys[1] );
    }

    libBLS::TEDecryptionShare original = decrShare;

    // Exceptions
    for ( size_t i = 0; i < 40; ++i ) {
        // tampered ciphertext
        {
            // passed ciphered key has tampered data field
            exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &original]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateDecryptionShare(
                        cipher.key, original, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered U field
            exceptionOnTamperedCiphertextU< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &decrShare]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateDecryptionShare(
                        cipher.key, decrShare, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        {
            // passed ciphered key has tampered W field
            exceptionOnTamperedCiphertextW< libBLS::ThresholdUtils::IsNotWellFormed >(
                [&keys, &decrShare]( libBLS::Ciphertext& cipher ) {
                    libBLS::ThresholdEncryption::validateDecryptionShare(
                        cipher.key, decrShare, keys.publicKeys[0] );
                },
                dataSize, keys );
        }
        // tampered TEDecryptionShare
        {
            // wrong decription share
            libBLS::TEDecryptionShare decrShare2( libff::alt_bn128_G2::random_element(), 1 );
            BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                     cipher.key, decrShare2, keys.publicKeys[0] ),
                libBLS::ThresholdUtils::IsNotWellFormed );
        }
        {
            // wrong te public key share should not pass pairing validation
            libBLS::TEPublicKeyShare pKeyShare(
                libff::alt_bn128_G2::random_element(), 1, requiredSigners, totalSigners );
            BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateDecryptionShare(
                                     cipher.key, original, pKeyShare ),
                libBLS::ThresholdUtils::IsNotWellFormed );
        }
    }
}

BOOST_AUTO_TEST_CASE( CombineShares ) {
    size_t requiredSigners = 7;
    size_t totalSigners = 10;
    size_t dataSize = 100;

    libBLS::TEDecryptSet alreadyMerged( requiredSigners, totalSigners );
    libBLS::TEDecryptSet notEnoughShares( requiredSigners, totalSigners );
    libBLS::TEDecryptSet readyToMerge( requiredSigners, totalSigners );

    libBLS::Ciphertext cipher;

    for ( size_t i = 0; i < 40; ++i ) {
        keys keys = generateKeys( requiredSigners, totalSigners );
        std::vector< uint8_t > data = randomByteVec( dataSize );
        cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );
        libBLS::ThresholdEncryption::validateEncryption( cipher.key );

        alreadyMerged = libBLS::TEDecryptSet( requiredSigners, totalSigners );
        readyToMerge = libBLS::TEDecryptSet( requiredSigners, totalSigners );
        notEnoughShares = libBLS::TEDecryptSet( requiredSigners, totalSigners );


        for ( size_t j = 0; j < requiredSigners; ++j ) {
            libBLS::TEDecryptionShare decrShare =
                libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[j] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipher.key, decrShare, keys.publicKeys[j] );
            alreadyMerged.addDecryptShare( decrShare );

            // only add the shares. Do not merge them - used for exception checking below
            readyToMerge.addDecryptShare( decrShare );

            // only add one share to notEnoughShares  - used for exception checking below
            if ( notEnoughShares.size() < requiredSigners - 1 ) {
                notEnoughShares.addDecryptShare( decrShare );
            }
        }

        libBLS::AES256Key key_deciphered =
            libBLS::ThresholdEncryption::combineShares( cipher.key, alreadyMerged );
        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cipher, key_deciphered, keys.commonPublic );
        std::vector< uint8_t > decryptedData =
            libBLS::ThresholdEncryption::decrypt( cipher, key_deciphered );

        BOOST_REQUIRE( decryptedData == data );
    }

    keys keys = generateKeys( requiredSigners, totalSigners );


    // Exceptions
    // tampered ciphertext
    {
        exceptionOnTamperedCiphertextData< libBLS::ThresholdUtils::IncorrectInput >(
            [&readyToMerge]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::combineShares( cipher.key, readyToMerge );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered U field
        exceptionOnTamperedCiphertextU< libBLS::ThresholdUtils::IncorrectInput >(
            [&readyToMerge]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::combineShares( cipher.key, readyToMerge );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered W field
        exceptionOnTamperedCiphertextW< libBLS::ThresholdUtils::IncorrectInput >(
            [&readyToMerge]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::combineShares( cipher.key, readyToMerge );
            },
            dataSize, keys );
    }
    // tampered TEDecryptSet
    {
        // already merged set
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::combineShares( cipher.key, alreadyMerged ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // not enough shares
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::combineShares( cipher.key, notEnoughShares ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
}

BOOST_AUTO_TEST_CASE( ValidateCombinedDecryptionAndDecrypt ) {
    size_t requiredSigners = 7;
    size_t totalSigners = 10;
    size_t dataSize = 100;

    // will all be replaced by last iteration of below for loop
    libBLS::TEDecryptSet decryptSet( requiredSigners, totalSigners );
    libBLS::Ciphertext cipher;
    libBLS::AES256Key keyDeciphered;
    keys keys = generateKeys( requiredSigners, totalSigners );

    // test normal correct behavior
    for ( size_t i = 0; i < 40; ++i ) {
        keys = generateKeys( requiredSigners, totalSigners );
        std::vector< uint8_t > data = randomByteVec( dataSize );
        cipher = libBLS::ThresholdEncryption::encrypt( data, keys.commonPublic );
        libBLS::ThresholdEncryption::validateEncryption( cipher.key );

        decryptSet = libBLS::TEDecryptSet( requiredSigners, totalSigners );

        for ( size_t j = 0; j < requiredSigners; ++j ) {
            libBLS::TEDecryptionShare decrShare =
                libBLS::ThresholdEncryption::partialDecrypt( cipher.key, keys.secretKeys[j] );
            libBLS::ThresholdEncryption::validateDecryptionShare(
                cipher.key, decrShare, keys.publicKeys[j] );
            decryptSet.addDecryptShare( decrShare );
        }

        // validate both combined decryption and decryption
        keyDeciphered = libBLS::ThresholdEncryption::combineShares( cipher.key, decryptSet );
        libBLS::ThresholdEncryption::validateCombinedDecryption(
            cipher, keyDeciphered, keys.commonPublic );
        std::vector< uint8_t > decryptedData =
            libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );

        // validate validateAndDecrypt call
        std::vector< uint8_t > decryptedData2 = libBLS::ThresholdEncryption::validateAndDecrypt(
            cipher, keyDeciphered, keys.commonPublic );

        BOOST_REQUIRE( decryptedData == data );
        BOOST_REQUIRE( decryptedData2 == data );
    }

    // Exceptions

    // validateCombinedDecryption
    {
        // tampered ciphertext data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext U
        exceptionOnTamperedCiphertextU< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext W
        exceptionOnTamperedCiphertextW< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateCombinedDecryption(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // passed public key is not the correct
        libBLS::TEPublicKey pkey = libBLS::TEPublicKey( libff::alt_bn128_G2::random_element() );
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateCombinedDecryption( cipher, keyDeciphered, pkey ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // deciphered aes key is not correct
        libBLS::AES256Key keyDeciphered2;
        RAND_bytes( keyDeciphered2.data(), keyDeciphered2.size() );
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateCombinedDecryption(
                                 cipher, keyDeciphered2, keys.commonPublic ),
            std::runtime_error );
    }

    // decrypt
    {
        // passed ciphered key has tampered data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered U field
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }
    {
        // passed ciphered key has tampered W field
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::decrypt( cipher, keyDeciphered );
            },
            dataSize, keys );
    }
    {
        // ciphertext data is short
        libBLS::Ciphertext cipher2 = generateRandomCiphertext( dataSize, keys );
        cipher2.data->resize( libBLS::RANDOM_SECRET_SIZE_BYTES );
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::decrypt( cipher2, keyDeciphered ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    // validateAndDecrypt
    {
        // tampered ciphertext data
        exceptionOnTamperedCiphertextData< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext U
        exceptionOnTamperedCiphertextU< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // tampered ciphertext W
        exceptionOnTamperedCiphertextW< std::runtime_error >(
            [&keyDeciphered, &keys]( libBLS::Ciphertext& cipher ) {
                libBLS::ThresholdEncryption::validateAndDecrypt(
                    cipher, keyDeciphered, keys.commonPublic );
            },
            dataSize, keys );
    }
    {
        // ciphertext data is short
        libBLS::Ciphertext cipher2 = generateRandomCiphertext( dataSize, keys );
        cipher2.data->resize( libBLS::RANDOM_SECRET_SIZE_BYTES );
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateAndDecrypt(
                                 cipher2, keyDeciphered, keys.commonPublic ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // passed public key is not the correct
        libBLS::TEPublicKey pkey = libBLS::TEPublicKey( libff::alt_bn128_G2::random_element() );
        BOOST_REQUIRE_THROW(
            libBLS::ThresholdEncryption::validateAndDecrypt( cipher, keyDeciphered, pkey ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }
    {
        // deciphered aes key is not correct
        libBLS::AES256Key keyDeciphered2;
        RAND_bytes( keyDeciphered2.data(), keyDeciphered2.size() );
        // may return one of 2 exceptions in this case: runtime_exception or IsNotWellFormed
        BOOST_REQUIRE_THROW( libBLS::ThresholdEncryption::validateAndDecrypt(
                                 cipher, keyDeciphered2, keys.commonPublic ),
            std::exception );
    }
}


BOOST_AUTO_TEST_SUITE_END()
