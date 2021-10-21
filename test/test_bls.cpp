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
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file test_bls.cpp
  @author Sveta Rogova
  @date 2019
*/

#include <bls/bls.h>
#include <dkg/dkg.h>
#include <ctime>

#include <bls/BLSPrivateKey.h>
#include <bls/BLSPrivateKeyShare.h>
#include <bls/BLSPublicKey.h>
#include <bls/BLSPublicKeyShare.h>
#include <bls/BLSSigShare.h>
#include <bls/BLSSigShareSet.h>
#include <bls/BLSSignature.h>
#include <tools/utils.h>

#include <map>

#include <dkg/DKGBLSWrapper.h>

#include <fstream>
#include <third_party/json.hpp>

#define BOOST_TEST_MODULE
#ifdef EMSCRIPTEN
#define BOOST_TEST_DISABLE_ALT_STACK
#endif  // EMSCRIPTEN

#include <boost/test/included/unit_test.hpp>
#include <libff/common/profiling.hpp>


BOOST_AUTO_TEST_SUITE( Bls )

std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );

libff::alt_bn128_Fq SpoilSignCoord( libff::alt_bn128_Fq& sign_coord ) {
    libff::alt_bn128_Fq bad_coord = sign_coord;
    do {
        size_t n_bad_bit = rand_gen() % ( bad_coord.size_in_bits() ) + 1;

        mpz_t was_coord;
        mpz_init( was_coord );
        bad_coord.as_bigint().to_mpz( was_coord );

        mpz_t mask;
        mpz_init( mask );
        mpz_set_si( mask, n_bad_bit );

        mpz_t badCoord;
        mpz_init( badCoord );
        mpz_xor( badCoord, was_coord, mask );

        bad_coord = libff::alt_bn128_Fq( badCoord );
        mpz_clears( badCoord, was_coord, mask, 0 );
    } while ( bad_coord == libff::alt_bn128_Fq::zero() );

    return bad_coord;
}

libff::alt_bn128_G1 SpoilSignature( libff::alt_bn128_G1& sign ) {
    libff::alt_bn128_G1 bad_sign = sign;
    while ( bad_sign.is_well_formed() ) {
        size_t bad_coord_num = rand_gen() % 3;
        switch ( bad_coord_num ) {
        case 0:
            bad_sign.X = SpoilSignCoord( sign.X );
            break;
        case 1:
            bad_sign.Y = SpoilSignCoord( sign.Y );
            break;
        case 2:
            bad_sign.Z = SpoilSignCoord( sign.Z );
            break;
        }
    }
    return bad_sign;
}

std::array< uint8_t, 32 > GenerateRandHash() {
    // generates random hexadermical hash
    std::array< uint8_t, 32 > hash_byte_arr;
    for ( size_t i = 0; i < 32; i++ ) {
        hash_byte_arr.at( i ) = rand_gen() % 256;
    }

    return hash_byte_arr;
}

BOOST_AUTO_TEST_CASE( libBls ) {
    libff::inhibit_profiling_info = true;
    std::cerr << "STARTING LIBBLS TESTS" << std::endl;
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libBLS::Dkg dkg_obj = libBLS::Dkg( num_signed, num_all );
        const std::vector< libff::alt_bn128_Fr > pol = dkg_obj.GeneratePolynomial();
        std::vector< libff::alt_bn128_Fr > skeys = dkg_obj.SecretKeyContribution( pol );

        std::vector< libff::alt_bn128_G1 > signatures( num_signed );

        libBLS::Bls obj = libBLS::Bls( num_signed, num_all );

        for ( size_t i = 0; i < 10; ++i ) {
            std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );
            libff::alt_bn128_G1 hash = libBLS::ThresholdUtils::HashtoG1( hash_ptr );

            for ( size_t i = 0; i < num_signed; ++i )
                signatures.at( i ) = obj.Signing( hash, skeys.at( i ) );

            std::vector< size_t > participants( num_all );
            for ( size_t i = 0; i < num_all; ++i )
                participants.at( i ) = i + 1;
            for ( size_t i = 0; i < num_all - num_signed; ++i ) {
                size_t ind4del = rand_gen() % participants.size();
                participants.erase( participants.begin() + ind4del );
            }

            for ( size_t i = 0; i < num_signed; ++i ) {
                auto pkey = skeys.at( i ) * libff::alt_bn128_G2::one();
                BOOST_REQUIRE( obj.Verification( hash_ptr, signatures.at( i ), pkey ) );
                BOOST_REQUIRE_THROW(
                    obj.Verification( hash_ptr, SpoilSignature( signatures.at( i ) ), pkey ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
            }

            std::vector< libff::alt_bn128_Fr > lagrange_coeffs =
                libBLS::ThresholdUtils::LagrangeCoeffs( participants, num_signed );
            libff::alt_bn128_G1 signature = obj.SignatureRecover( signatures, lagrange_coeffs );

            auto recovered_keys = obj.KeysRecover( lagrange_coeffs, skeys );
            BOOST_REQUIRE( obj.Verification( hash_ptr, signature, recovered_keys.second ) );
            BOOST_REQUIRE_THROW(
                obj.Verification( hash_ptr, SpoilSignature( signature ), recovered_keys.second ),
                libBLS::ThresholdUtils::IsNotWellFormed );

            recovered_keys.second.X.c0 = SpoilSignCoord( recovered_keys.second.X.c0 );
            BOOST_REQUIRE_THROW( obj.Verification( hash_ptr, signature, recovered_keys.second ),
                libBLS::ThresholdUtils::IsNotWellFormed );
        }
    }

    std::cerr << "BLS TESTS completed successfully" << std::endl;
}

BOOST_AUTO_TEST_CASE( libBlsAPI ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all )->first;

        for ( size_t i = 0; i < 10; ++i ) {
            BLSSigShareSet sigSet( num_signed, num_all );

            std::vector< size_t > participants( num_all );  // choosing random participants
            for ( size_t i = 0; i < num_all; ++i )
                participants.at( i ) = i + 1;
            for ( size_t i = 0; i < num_all - num_signed; ++i ) {
                size_t ind4del = rand_gen() % participants.size();
                participants.erase( participants.begin() + ind4del );
            }

            std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );

            for ( size_t i = 0; i < num_signed; ++i ) {
                std::shared_ptr< BLSPrivateKeyShare > skey = Skeys->at( participants.at( i ) - 1 );
                std::shared_ptr< BLSSigShare > sigShare =
                    skey->sign( hash_ptr, participants.at( i ) );
                sigSet.addSigShare( sigShare );
            }

            for ( size_t i = 0; i < num_signed; ++i ) {
                BLSPublicKeyShare pkey_share(
                    *Skeys->at( participants.at( i ) - 1 )->getPrivateKey(), num_signed, num_all );
                std::shared_ptr< BLSSigShare > sig_share_ptr =
                    sigSet.getSigShareByIndex( participants.at( i ) );
                BOOST_REQUIRE(
                    pkey_share.VerifySig( hash_ptr, sig_share_ptr, num_signed, num_all ) );
                std::shared_ptr< libff::alt_bn128_G1 > bad_sig =
                    std::make_shared< libff::alt_bn128_G1 >(
                        SpoilSignature( *sig_share_ptr->getSigShare() ) );
                std::string hint = sig_share_ptr->getHint();

                BOOST_REQUIRE_THROW(
                    BLSSigShare( bad_sig, hint, participants.at( i ), num_signed, num_all ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
            }

            BOOST_REQUIRE( sigSet.getTotalSigSharesCount() == num_signed );

            std::shared_ptr< BLSSignature > common_sig_ptr = sigSet.merge();  // verifying signature
            BLSPrivateKey common_skey( Skeys,
                std::make_shared< std::vector< size_t > >( participants ), num_signed, num_all );
            BLSPublicKey common_pkey( *( common_skey.getPrivateKey() ) );
            BOOST_REQUIRE( common_pkey.VerifySig( hash_ptr, common_sig_ptr ) );
            std::shared_ptr< libff::alt_bn128_G1 > bad_sig =
                std::make_shared< libff::alt_bn128_G1 >(
                    SpoilSignature( *common_sig_ptr->getSig() ) );
            std::string hint = common_sig_ptr->getHint();
            BLSSignature bad_sign( bad_sig, hint, num_signed, num_all );

            BOOST_REQUIRE_THROW(
                common_pkey.VerifySig( hash_ptr, std::make_shared< BLSSignature >( bad_sign ) ),
                libBLS::ThresholdUtils::IsNotWellFormed );

            std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > pkeys_map1;
            for ( size_t i = 0; i < num_signed; ++i ) {
                BLSPublicKeyShare cur_pkey(
                    *Skeys->at( participants.at( i ) - 1 )->getPrivateKey(), num_signed, num_all );
                pkeys_map1[participants.at( i )] =
                    std::make_shared< BLSPublicKeyShare >( cur_pkey );
            }

            BLSPublicKey common_pkey1(
                std::make_shared< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > >(
                    pkeys_map1 ),
                num_signed, num_all );

            BOOST_REQUIRE( common_pkey1.getRequiredSigners() == num_signed );
            BOOST_REQUIRE( common_pkey1.getTotalSigners() == num_all );

            BOOST_REQUIRE( common_pkey1.VerifySig( hash_ptr, common_sig_ptr ) );

            std::vector< size_t > participants1( num_all );  // use the whole set of participants
            for ( size_t i = 0; i < num_all; ++i )
                participants1.at( i ) = i + 1;

            std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > pkeys_map2;
            for ( size_t i = 0; i < num_all; ++i ) {
                BLSPublicKeyShare cur_pkey(
                    *Skeys->at( participants1.at( i ) - 1 )->getPrivateKey(), num_signed, num_all );
                pkeys_map2[participants1.at( i )] =
                    std::make_shared< BLSPublicKeyShare >( cur_pkey );
            }

            BLSPublicKey common_pkey2(
                std::make_shared< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > >(
                    pkeys_map2 ),
                num_signed, num_all );

            BOOST_REQUIRE( common_pkey2.VerifySig( hash_ptr, common_sig_ptr ) );
        }
    }
    std::cerr << "BLS API TEST END" << std::endl;
}

BOOST_AUTO_TEST_CASE( libffObjsToString ) {
    libff::inhibit_profiling_info = true;

    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all )->first;

        std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
            std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );

        BLSSigShareSet sigSet( num_signed, num_all );

        std::vector< size_t > participants( num_all );  // choosing random participants
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            std::shared_ptr< BLSPrivateKeyShare > skey = Skeys->at( participants.at( i ) - 1 );
            std::shared_ptr< std::string > skey_str_ptr = skey->toString();
            std::shared_ptr< BLSPrivateKeyShare > skey_from_str =
                std::make_shared< BLSPrivateKeyShare >( *skey_str_ptr, num_signed, num_all );
            BOOST_REQUIRE( *skey_from_str->getPrivateKey() == *skey->getPrivateKey() );

            std::shared_ptr< BLSSigShare > sigShare =
                skey->signWithHelper( hash_ptr, participants.at( i ) );
            std::shared_ptr< std::string > sig_str_ptr = sigShare->toString();
            std::shared_ptr< BLSSigShare > sigShare_from_str = std::make_shared< BLSSigShare >(
                sig_str_ptr, participants.at( i ), num_signed, num_all );
            BOOST_REQUIRE( *sigShare->getSigShare() == *sigShare_from_str->getSigShare() );
            BOOST_REQUIRE( sigShare->getHint() == sigShare_from_str->getHint() );
            BOOST_REQUIRE(
                sigShare->getRequiredSigners() == sigShare_from_str->getRequiredSigners() );
            BOOST_REQUIRE( sigShare->getTotalSigners() == sigShare_from_str->getTotalSigners() );
            sigSet.addSigShare( sigShare );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare pkey_share(
                *Skeys->at( participants.at( i ) - 1 )->getPrivateKey(), num_signed, num_all );
            std::shared_ptr< std::vector< std::string > > pkey_str_vect = pkey_share.toString();
            BLSPublicKeyShare pkey_from_str( pkey_str_vect, num_signed, num_all );
            BOOST_REQUIRE( *pkey_share.getPublicKey() == *pkey_from_str.getPublicKey() );
            BOOST_REQUIRE( pkey_share.VerifySigWithHelper( hash_ptr,
                sigSet.getSigShareByIndex( participants.at( i ) ), num_signed, num_all ) );
        }

        std::shared_ptr< BLSSignature > common_sig_ptr = sigSet.merge();
        BLSPrivateKey common_skey(
            Skeys, std::make_shared< std::vector< size_t > >( participants ), num_signed, num_all );
        std::shared_ptr< std::string > common_skey_str = common_skey.toString();
        BLSPrivateKey common_skey_from_str( common_skey_str, num_signed, num_all );
        BOOST_REQUIRE( *common_skey_from_str.getPrivateKey() == *common_skey.getPrivateKey() );

        BLSSignature common_sig_from_str( common_sig_ptr->toString(), num_signed, num_all );
        BOOST_REQUIRE( *common_sig_from_str.getSig() == *common_sig_ptr->getSig() );
        BOOST_REQUIRE( common_sig_from_str.getHint() == common_sig_ptr->getHint() );
        BOOST_REQUIRE(
            common_sig_from_str.getRequiredSigners() == common_sig_ptr->getRequiredSigners() );
        BOOST_REQUIRE( common_sig_from_str.getTotalSigners() == common_sig_ptr->getTotalSigners() );

        BLSPublicKey common_pkey( *( common_skey.getPrivateKey() ) );
        std::shared_ptr< std::vector< std::string > > common_pkey_str_vect = common_pkey.toString();
        BLSPublicKey common_pkey_from_str( common_pkey_str_vect );
        BOOST_REQUIRE( *common_pkey.getPublicKey() == *common_pkey_from_str.getPublicKey() );
        BOOST_REQUIRE( common_pkey.VerifySigWithHelper( hash_ptr, common_sig_ptr ) );

        std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > pkeys_map;
        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare cur_pkey(
                *Skeys->at( participants[i] - 1 )->getPrivateKey(), num_signed, num_all );
            pkeys_map[participants.at( i )] = std::make_shared< BLSPublicKeyShare >( cur_pkey );
        }

        BLSPublicKey common_pkey1(
            std::make_shared< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > >(
                pkeys_map ),
            num_signed, num_all );
        std::shared_ptr< std::vector< std::string > > common_pkey_str_vect1 =
            common_pkey.toString();
        BLSPublicKey common_pkey_from_str1( common_pkey_str_vect1 );

        BOOST_REQUIRE( *common_pkey1.getPublicKey() == *common_pkey_from_str1.getPublicKey() );
        BOOST_REQUIRE( *common_pkey1.getPublicKey() == *common_pkey.getPublicKey() );
    }
    std::cerr << "BLS libffObjsToString TEST END" << std::endl;
}

std::shared_ptr< std::vector< size_t > > choose_rand_signers( size_t num_signed, size_t num_all ) {
    std::vector< size_t > participants( num_all );
    for ( size_t i = 0; i < num_all; ++i )
        participants.at( i ) = i + 1;
    for ( size_t i = 0; i < num_all - num_signed; ++i ) {
        size_t ind4del = rand_gen() % participants.size();
        participants.erase( participants.begin() + ind4del );
    }
    return std::make_shared< std::vector< size_t > >( participants );
}

BOOST_AUTO_TEST_CASE( threshold_signs_equality ) {
    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        std::shared_ptr< std::vector< std::shared_ptr< BLSPrivateKeyShare > > > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all )->first;

        std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
            std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );

        BLSSigShareSet sigSet( num_signed, num_all );
        BLSSigShareSet sigSet1( num_signed, num_all );

        std::string message;
        size_t msg_length = rand_gen() % 1000 + 2;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }
        std::shared_ptr< std::string > msg_ptr = std::make_shared< std::string >( message );

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );
        std::shared_ptr< std::vector< size_t > > participants1 =
            choose_rand_signers( num_signed, num_all );

        for ( size_t i = 0; i < num_signed; ++i ) {
            std::shared_ptr< BLSPrivateKeyShare > skey = Skeys->at( participants->at( i ) - 1 );
            std::shared_ptr< BLSSigShare > sigShare = skey->sign( hash_ptr, participants->at( i ) );
            sigSet.addSigShare( sigShare );

            std::shared_ptr< BLSPrivateKeyShare > skey1 = Skeys->at( participants1->at( i ) - 1 );
            std::shared_ptr< BLSSigShare > sigShare1 =
                skey1->sign( hash_ptr, participants1->at( i ) );
            sigSet1.addSigShare( sigShare1 );
        }

        std::shared_ptr< BLSSignature > common_sig_ptr = sigSet.merge();
        std::shared_ptr< BLSSignature > common_sig_ptr1 = sigSet1.merge();

        BOOST_REQUIRE( *common_sig_ptr->getSig() == *common_sig_ptr1->getSig() );
    }
}

BOOST_AUTO_TEST_CASE( private_keys_equality ) {
    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        libBLS::Dkg dkg_obj = libBLS::Dkg( num_signed, num_all );
        const std::vector< libff::alt_bn128_Fr > pol = dkg_obj.GeneratePolynomial();
        std::vector< libff::alt_bn128_Fr > skeys = dkg_obj.SecretKeyContribution( pol );

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );

        std::vector< libff::alt_bn128_Fr > lagrange_koefs =
            libBLS::ThresholdUtils::LagrangeCoeffs( *participants, num_signed );
        libff::alt_bn128_Fr common_skey = libff::alt_bn128_Fr::zero();
        for ( size_t i = 0; i < num_signed; ++i ) {
            common_skey =
                common_skey + lagrange_koefs.at( i ) * skeys.at( participants->at( i ) - 1 );
        }

        BOOST_REQUIRE( common_skey == pol.at( 0 ) );
    }
}

BOOST_AUTO_TEST_CASE( public_keys_equality ) {
    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        libBLS::Dkg dkg_obj = libBLS::Dkg( num_signed, num_all );
        const std::vector< libff::alt_bn128_Fr > pol = dkg_obj.GeneratePolynomial();
        std::vector< libff::alt_bn128_Fr > skeys = dkg_obj.SecretKeyContribution( pol );
        libff::alt_bn128_G2 common_pkey = dkg_obj.GetPublicKeyFromSecretKey( pol.at( 0 ) );

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );

        std::vector< libff::alt_bn128_Fr > lagrange_koefs =
            libBLS::ThresholdUtils::LagrangeCoeffs( *participants, num_signed );
        libff::alt_bn128_G2 common_pkey1 = libff::alt_bn128_G2::zero();
        for ( size_t i = 0; i < num_signed; ++i ) {
            common_pkey1 = common_pkey1 + lagrange_koefs.at( i ) *
                                              skeys.at( participants->at( i ) - 1 ) *
                                              libff::alt_bn128_G2::one();
        }
        BOOST_REQUIRE( common_pkey == common_pkey1 );
    }
}

BOOST_AUTO_TEST_CASE( BLSWITHDKG ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
        std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
        std::vector< DKGBLSWrapper > dkgs;
        std::vector< BLSPrivateKeyShare > skeys;

        libff::alt_bn128_G2 common_public = libff::alt_bn128_G2::zero();

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGBLSWrapper dkg_wrap( num_signed, num_all );
            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            common_public = common_public + public_shares_ptr->at( 0 );
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }

        BLSPublicKey dkg_common_pkey( common_public );

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
            BLSPrivateKeyShare pkey_share = dkgs.at( i ).CreateBLSPrivateKeyShare(
                std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                    secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
        }

        std::vector< size_t > participants( num_all );  // choosing random participants
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
            std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );

        BLSSigShareSet sigSet( num_signed, num_all );

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPrivateKeyShare skey = skeys.at( participants.at( i ) - 1 );
            std::shared_ptr< BLSSigShare > sigShare = skey.sign( hash_ptr, participants.at( i ) );
            sigSet.addSigShare( sigShare );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare pkey_share(
                *skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
            std::shared_ptr< BLSSigShare > sig_share_ptr =
                sigSet.getSigShareByIndex( participants.at( i ) );
            BOOST_REQUIRE( pkey_share.VerifySig( hash_ptr, sig_share_ptr, num_signed, num_all ) );
        }

        std::vector< std::shared_ptr< BLSPrivateKeyShare > > ptr_skeys;
        for ( size_t i = 0; i < num_all; i++ ) {
            ptr_skeys.push_back( std::make_shared< BLSPrivateKeyShare >( skeys.at( i ) ) );
        }

        libff::alt_bn128_Fr common_secret = libff::alt_bn128_Fr::zero();
        for ( size_t i = 0; i < num_all; i++ ) {
            common_secret = common_secret + dkgs.at( i ).getValueAt0();
        }

        std::shared_ptr< BLSSignature > common_sig_ptr = sigSet.merge();  // verifying signature

        std::string common_secret_str =
            libBLS::ThresholdUtils::fieldElementToString( common_secret );
        BLSPrivateKey common_skey(
            std::make_shared< std::string >( common_secret_str ), num_signed, num_all );

        BLSPrivateKey common_skey2(
            std::make_shared< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >( ptr_skeys ),
            std::make_shared< std::vector< size_t > >( participants ), num_signed, num_all );
        BOOST_REQUIRE( *common_skey.getPrivateKey() == *common_skey2.getPrivateKey() );
        BOOST_REQUIRE( common_secret * libff::alt_bn128_G2::one() == common_public );
        BLSPublicKey common_pkey( *( common_skey2.getPrivateKey() ) );
        BOOST_REQUIRE( *common_pkey.getPublicKey() == *dkg_common_pkey.getPublicKey() );
        BOOST_REQUIRE( common_pkey.VerifySig( hash_ptr, common_sig_ptr ) );

        std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > pkeys_map;
        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare cur_pkey(
                *skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
            pkeys_map[participants.at( i )] = std::make_shared< BLSPublicKeyShare >( cur_pkey );
        }

        BLSPublicKey common_pkey1(
            std::make_shared< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > >(
                pkeys_map ),
            num_signed, num_all );

        BOOST_REQUIRE( common_pkey1.VerifySig( hash_ptr, common_sig_ptr ) );
    }
    std::cerr << "BLS WITH DKG TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( BLSAGGREGATEDVERIFICATION ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;
        size_t batch_size = rand_gen() % 5 + 1;

        bool invalid_sig = rand_gen() % 2;

        std::vector< std::vector< libff::alt_bn128_Fr > > secret_shares_all;
        std::vector< std::vector< libff::alt_bn128_G2 > > public_shares_all;
        std::vector< DKGBLSWrapper > dkgs;
        std::vector< BLSPrivateKeyShare > skeys;

        libff::alt_bn128_G2 common_public = libff::alt_bn128_G2::zero();

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGBLSWrapper dkg_wrap( num_signed, num_all );
            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< libff::alt_bn128_Fr > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< libff::alt_bn128_G2 > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            common_public = common_public + public_shares_ptr->at( 0 );
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }

        BLSPublicKey dkg_common_pkey( common_public );

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
            BLSPrivateKeyShare pkey_share = dkgs.at( i ).CreateBLSPrivateKeyShare(
                std::make_shared< std::vector< libff::alt_bn128_Fr > >(
                    secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
        }

        std::vector< size_t > participants( num_all );
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        std::vector< std::shared_ptr< std::array< uint8_t, 32 > > > hash_ptrs;
        hash_ptrs.reserve( batch_size );
        for ( size_t i = 0; i < batch_size; i++ ) {
            std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );
            hash_ptrs.push_back( std::move( hash_ptr ) );
        }

        std::vector< BLSSigShareSet > sigSets;
        sigSets.reserve( batch_size );
        for ( size_t i = 0; i < batch_size; i++ ) {
            BLSSigShareSet sigSet( num_signed, num_all );
            sigSets.push_back( std::move( sigSet ) );
        }

        for ( size_t i = 0; i < batch_size; i++ ) {
            size_t malicious_signer = rand_gen() % num_signed;
            for ( size_t j = 0; j < num_signed; j++ ) {
                BLSPrivateKeyShare skey = skeys.at( participants.at( j ) - 1 );
                // simulate a malicious signer
                if ( invalid_sig && ( j == malicious_signer ) ) {
                    std::shared_ptr< std::array< uint8_t, 32 > > bad_hash_ptr =
                        std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );
                    std::shared_ptr< BLSSigShare > sigShare =
                        skey.sign( bad_hash_ptr, participants.at( j ) );
                    sigSets.at( i ).addSigShare( sigShare );
                } else {
                    std::shared_ptr< BLSSigShare > sigShare =
                        skey.sign( hash_ptrs.at( i ), participants.at( j ) );
                    sigSets.at( i ).addSigShare( sigShare );
                }
            }
        }

        std::vector< std::shared_ptr< BLSSignature > > common_sig_ptrs;
        common_sig_ptrs.reserve( batch_size );
        for ( size_t i = 0; i < batch_size; i++ ) {
            common_sig_ptrs.push_back( sigSets.at( i ).merge() );
        }

        std::vector< std::shared_ptr< BLSPrivateKeyShare > > ptr_skeys;
        ptr_skeys.reserve( batch_size );
        for ( size_t i = 0; i < num_all; i++ ) {
            ptr_skeys.push_back( std::make_shared< BLSPrivateKeyShare >( skeys.at( i ) ) );
        }

        BLSPrivateKey common_skey(
            std::make_shared< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >( ptr_skeys ),
            std::make_shared< std::vector< size_t > >( participants ), num_signed, num_all );
        BLSPublicKey common_pkey( *( common_skey.getPrivateKey() ) );

        // individual verification
        for ( size_t i = 0; i < batch_size; i++ ) {
            if ( invalid_sig ) {
                BOOST_REQUIRE(
                    !common_pkey.VerifySig( hash_ptrs.at( i ), common_sig_ptrs.at( i ) ) );
            } else {
                BOOST_REQUIRE(
                    common_pkey.VerifySig( hash_ptrs.at( i ), common_sig_ptrs.at( i ) ) );
            }
        }

        // aggregated verification
        if ( invalid_sig ) {
            BOOST_REQUIRE( !common_pkey.AggregatedVerifySig( hash_ptrs, common_sig_ptrs ) );
        } else {
            BOOST_REQUIRE( common_pkey.AggregatedVerifySig( hash_ptrs, common_sig_ptrs ) );
        }
    }
    std::cerr << "BLS AGGREGATED VERIFICATION TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( Exceptions ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

    std::vector< size_t > participants( num_all );
    for ( size_t i = 0; i < num_all; ++i )
        participants.at( i ) = i + 1;

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey pkey( std::make_shared< std::string >( "" ), num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey( std::make_shared< std::string >( "0" ), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BOOST_REQUIRE_THROW( BLSPrivateKey skey( nullptr, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey( nullptr, std::make_shared< std::vector< size_t > >( participants ),
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey(
                BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all )->first, NULL,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // creating a polynomial
        std::vector< libff::alt_bn128_Fr > coeffs( 11 );

        for ( auto& elem : coeffs ) {
            elem = libff::alt_bn128_Fr::random_element();

            while ( elem == 0 ) {
                elem = libff::alt_bn128_Fr::random_element();
            }
        }

        // make free element zero so the common secret is zero
        coeffs[0] = libff::alt_bn128_Fr::zero();

        std::vector< std::shared_ptr< BLSPrivateKeyShare > > secret_keys( 16 );
        std::vector< size_t > ids( 11 );
        for ( size_t i = 0; i < 16; ++i ) {
            if ( i < 11 ) {
                ids[i] = i + 1;
            }

            libff::alt_bn128_Fr tmp = libff::alt_bn128_Fr::zero();

            for ( size_t j = 0; j < 11; ++j ) {
                tmp = tmp +
                      coeffs[j] *
                          libff::power( libff::alt_bn128_Fr( std::to_string( i + 1 ).c_str() ), j );
            }
            secret_keys[i] =
                std::make_shared< BLSPrivateKeyShare >( BLSPrivateKeyShare( tmp, 11, 16 ) );
        }

        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey(
                std::make_shared< std::vector< std::shared_ptr< BLSPrivateKeyShare > > >(
                    secret_keys ),
                std::make_shared< std::vector< size_t > >( ids ), 11, 16 ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BOOST_REQUIRE_THROW( BLSPrivateKeyShare skey( "", num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW( BLSPrivateKeyShare skey( "0", num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKeyShare skey( libff::alt_bn128_Fr::zero(), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BLSPrivateKeyShare skey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            skey.sign( std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() ), 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPrivateKeyShare skey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        BOOST_REQUIRE_THROW( skey.sign( NULL, 1 ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPrivateKeyShare skey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            skey.signWithHelper(
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() ), 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPrivateKeyShare skey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            skey.signWithHelper( NULL, 1 ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        const std::shared_ptr< std::vector< std::string > > null_vect = nullptr;
        BOOST_REQUIRE_THROW(
            BLSPublicKey pkey( null_vect ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::vector< std::string > coords = {"0", "0", "0", "0"};
        auto vector_ptr_str = std::make_shared< std::vector< std::string > >( coords );
        BOOST_REQUIRE_THROW(
            BLSPublicKey pkey( vector_ptr_str ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        const std::shared_ptr< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > > null_map =
            nullptr;
        BOOST_REQUIRE_THROW( BLSPublicKey pkey( null_map, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // creating a polynomial
        std::vector< libff::alt_bn128_Fr > coeffs( 11 );

        for ( auto& elem : coeffs ) {
            elem = libff::alt_bn128_Fr::random_element();

            while ( elem == 0 ) {
                elem = libff::alt_bn128_Fr::random_element();
            }
        }

        // make free element zero so the common secret is zero
        coeffs[0] = libff::alt_bn128_Fr::zero();

        std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > coeffs_map;
        for ( size_t i = 0; i < 16; ++i ) {
            libff::alt_bn128_Fr tmp = libff::alt_bn128_Fr::zero();

            for ( size_t j = 0; j < 11; ++j ) {
                tmp = tmp +
                      coeffs[j] *
                          libff::power( libff::alt_bn128_Fr( std::to_string( i + 1 ).c_str() ), j );
            }

            if ( i < 11 ) {
                coeffs_map[i + 1] =
                    std::make_shared< BLSPublicKeyShare >( BLSPublicKeyShare( tmp, 11, 16 ) );
            }
        }
        auto map_ptr = std::make_shared< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > >(
            coeffs_map );

        BOOST_REQUIRE_THROW(
            BLSPublicKey pkey( map_ptr, 11, 16 ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BOOST_REQUIRE_THROW( BLSPublicKey pkey( libff::alt_bn128_G2::zero() ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BOOST_REQUIRE_THROW( BLSPublicKey pkey( libff::alt_bn128_Fr::zero() ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BLSPublicKey pkey( libff::alt_bn128_Fr::random_element() );
        std::string hint = "123:1";
        BLSSignature rand_sig(
            std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::random_element() ), hint,
            num_signed, num_all );
        BOOST_REQUIRE_THROW(
            pkey.VerifySigWithHelper( nullptr, std::make_shared< BLSSignature >( rand_sig ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPublicKey pkey( libff::alt_bn128_Fr::random_element() );
        BOOST_REQUIRE_THROW(
            pkey.VerifySigWithHelper(
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() ), nullptr ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPublicKey pkey( libff::alt_bn128_Fr::random_element() );
        BOOST_REQUIRE_THROW(
            pkey.VerifySig(
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() ), nullptr ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BLSPublicKey pkey( libff::alt_bn128_Fr::random_element() );
        std::string hint = "123:1";
        BLSSignature rand_sig(
            std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::random_element() ), hint,
            num_signed, num_all );
        BOOST_REQUIRE_THROW(
            pkey.VerifySig( nullptr, std::make_shared< BLSSignature >( rand_sig ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPublicKeyShare pkey( libff::alt_bn128_Fr::zero(), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BOOST_REQUIRE_THROW( BLSPublicKeyShare pkey( nullptr, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::vector< std::string > coords = {"0", "0", "0", "0"};
        auto vector_str_ptr = std::make_shared< std::vector< std::string > >( coords );
        BOOST_REQUIRE_THROW( BLSPublicKeyShare pkey( vector_str_ptr, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BLSPublicKeyShare pkey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        std::string hint = "123:1";
        BLSSigShare rand_sig(
            std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::random_element() ), hint,
            1, num_signed, num_all );
        BOOST_REQUIRE_THROW( pkey.VerifySigWithHelper( nullptr,
                                 std::make_shared< BLSSigShare >( rand_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPublicKeyShare pkey( libff::alt_bn128_Fr::random_element(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            pkey.VerifySigWithHelper(
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() ), nullptr,
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSSignature( nullptr, num_signed, num_all ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW( BLSSignature( nullptr, hint, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string empty_hint = "";
        BOOST_REQUIRE_THROW( BLSSignature( std::make_shared< libff::alt_bn128_G1 >(
                                               libff::alt_bn128_G1::random_element() ),
                                 empty_hint, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string short_sig = "1:1:1:1";
        BOOST_REQUIRE_THROW(
            BLSSignature( std::make_shared< std::string >( short_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 3; j++ )
            for ( size_t i = 0; i < 100; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 99 && j != 2 )
                    long_sig += ":";
            }
        BOOST_REQUIRE_THROW(
            BLSSignature( std::make_shared< std::string >( long_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 3; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j < 2 )
                    long_sig += ":";
            }
        BOOST_REQUIRE_THROW(
            BLSSignature( std::make_shared< std::string >( long_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 4; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j != 3 )
                    long_sig += ":";
            }

        BOOST_REQUIRE_THROW(
            BLSSignature( std::make_shared< std::string >( long_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 4; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j != 3 )
                    long_sig += ":";
            }
        long_sig[25] = 'a';
        BOOST_REQUIRE_THROW(
            BLSSignature( std::make_shared< std::string >( long_sig ), num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        libff::alt_bn128_G1 zero_sig = libff::alt_bn128_G1::zero();
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW( BLSSignature( std::make_shared< libff::alt_bn128_G1 >( zero_sig ),
                                 hint, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW( BLSSigShare( nullptr, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW( BLSSigShare( nullptr, 0, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW( BLSSigShare( nullptr, hint, 0, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string empty_hint = "";
        BOOST_REQUIRE_THROW( BLSSigShare( std::make_shared< libff::alt_bn128_G1 >(
                                              libff::alt_bn128_G1::random_element() ),
                                 empty_hint, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::zero() ),
                hint, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW( BLSSigShare( std::make_shared< libff::alt_bn128_G1 >(
                                              libff::alt_bn128_G1::random_element() ),
                                 hint, 0, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string short_sig = "1:1:1:1";
        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< std::string >( short_sig ), 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 3; j++ ) {
            for ( size_t i = 0; i < 100; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 99 && j != 2 )
                    long_sig += ":";
            }
        }
        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< std::string >( long_sig ), 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 3; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j < 2 )
                    long_sig += ":";
            }
        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< std::string >( long_sig ), 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 4; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j != 3 ) {
                    long_sig += ":";
                }
            }

        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< std::string >( long_sig ), 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string long_sig;
        for ( size_t j = 0; j < 4; j++ )
            for ( size_t i = 0; i < 20; i++ ) {
                long_sig += std::to_string( rand_gen() % 10 );
                if ( i == 19 && j != 3 )
                    long_sig += ":";
            }
        long_sig[25] = 'a';
        BOOST_REQUIRE_THROW(
            BLSSigShare( std::make_shared< std::string >( long_sig ), 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }


    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            sig_set.addSigShare( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BLSSigShare sigShare1(
            std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::random_element() ), hint,
            1, num_signed, num_all );
        BLSSigShare sigShare2 = sigShare1;
        BLSSigShareSet sig_set( num_signed, num_all );
        sig_set.addSigShare( std::make_shared< BLSSigShare >( sigShare1 ) );
        BOOST_REQUIRE_THROW( sig_set.addSigShare( std::make_shared< BLSSigShare >( sigShare2 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BLSSigShare sigShare1(
            std::make_shared< libff::alt_bn128_G1 >( libff::alt_bn128_G1::random_element() ), hint,
            1, num_signed, num_all );
        BLSSigShareSet sig_set( 1, 1 );
        sig_set.addSigShare( std::make_shared< BLSSigShare >( sigShare1 ) );
        sig_set.merge();
        BOOST_REQUIRE_THROW( sig_set.addSigShare( std::make_shared< BLSSigShare >( sigShare1 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE_THROW( sig_set.merge(), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE( sig_set.getSigShareByIndex( 1 ) == nullptr );
    }

    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            sig_set.getSigShareByIndex( 0 ), libBLS::ThresholdUtils::IncorrectInput );
    }

    std::cerr << "EXCEPTIONS TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( DKGWrappersExceptions ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        std::vector< libff::alt_bn128_G2 > vect = {libff::alt_bn128_G2::random_element()};
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, libff::alt_bn128_Fr::zero(),
                                 std::make_shared< std::vector< libff::alt_bn128_G2 > >( vect ) ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, libff::alt_bn128_Fr::zero(), nullptr ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_wrap.VerifyDKGShare( 1, libff::alt_bn128_Fr::random_element(), nullptr ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed + 1, num_all + 1 );
        std::vector< libff::alt_bn128_G2 > vect = {libff::alt_bn128_G2::random_element()};
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, libff::alt_bn128_Fr::random_element(),
                                 std::make_shared< std::vector< libff::alt_bn128_G2 > >( vect ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_wrap.setDKGSecret( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        std::vector< libff::alt_bn128_Fr > poly;
        BOOST_REQUIRE_THROW(
            dkg_wrap.setDKGSecret( std::make_shared< std::vector< libff::alt_bn128_Fr > >( poly ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_wrap.CreateBLSPrivateKeyShare( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        std::vector< libff::alt_bn128_Fr > shares;
        BOOST_REQUIRE_THROW( dkg_wrap.CreateBLSPrivateKeyShare(
                                 std::make_shared< std::vector< libff::alt_bn128_Fr > >( shares ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}
BOOST_AUTO_TEST_SUITE_END()
