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

#include "test/utils.h"
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

#include "backends/interface/test/FqElementTestAccessor.hpp"

using namespace libBLS;
using namespace libBLS::algebra;

BOOST_AUTO_TEST_SUITE( Bls )

std::default_random_engine rand_gen( ( unsigned int ) time( 0 ) );


G1Point SpoilSignature( G1Point& sign ) {
    G1Point bad_sign = sign;
    while ( bad_sign.isWellFormed() ) {
        size_t bad_coord_num = rand_gen() % 3;
        switch ( bad_coord_num ) {
        case 0:
            bad_sign.getXRef().asBackendRef() =
                FqElementTestAccessor::spoil( sign.getXRef().asBackendRef() );
            break;
        case 1:
            bad_sign.getYRef().asBackendRef() =
                FqElementTestAccessor::spoil( sign.getYRef().asBackendRef() );
            break;
        case 2:
            bad_sign.getZRef().asBackendRef() =
                FqElementTestAccessor::spoil( sign.getZRef().asBackendRef() );
            break;
        }
    }
    return bad_sign;
}

G2Point SpoilPublicKey( G2Point& elem ) {
    G2Point bad_elem = elem;
    while ( bad_elem.isWellFormed() ) {
        size_t bad_coord_num = rand_gen() % 6;
        switch ( bad_coord_num ) {
        case 0:
            bad_elem.getXRef().getC0Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getXRef().getC0Ref().asBackendRef() );
            break;
        case 1:
            bad_elem.getXRef().getC1Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getXRef().getC1Ref().asBackendRef() );
            break;
        case 2:
            bad_elem.getYRef().getC0Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getYRef().getC0Ref().asBackendRef() );
            break;
        case 3:
            bad_elem.getYRef().getC1Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getYRef().getC1Ref().asBackendRef() );
            break;
        case 4:
            bad_elem.getZRef().getC0Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getZRef().getC0Ref().asBackendRef() );
            break;
        case 5:
            bad_elem.getZRef().getC1Ref().asBackendRef() =
                FqElementTestAccessor::spoil( elem.getZRef().getC1Ref().asBackendRef() );
            break;
        }
    }
    return bad_elem;
}

std::array< uint8_t, 32 > GenerateRandHash() {
    // generates random hexadermical hash
    std::array< uint8_t, 32 > hash_byte_arr;
    for ( size_t i = 0; i < 32; i++ ) {
        hash_byte_arr.at( i ) = rand_gen() % 256;
    }

    return hash_byte_arr;
}

std::string rand32HexStr() {
    std::array< char, 16 > s = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c',
        'd', 'e', 'f' };

    std::string res = "";
    for ( size_t i = 0; i < 32; ++i ) {
        res.push_back( *( s.begin() + rand_gen() % 16 ) );
    }

    return res;
}

BOOST_TEST_GLOBAL_CONFIGURATION( GlobalConfig );

BOOST_AUTO_TEST_CASE( libBls ) {
    std::cerr << "STARTING LIBBLS TESTS" << std::endl;
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        libBLS::Dkg dkg_obj = libBLS::Dkg( num_signed, num_all );
        const std::vector< algebra::FrScalar > pol = dkg_obj.GeneratePolynomial();
        std::vector< algebra::FrScalar > skeys = dkg_obj.SecretKeyContribution( pol );

        std::vector< algebra::G1Point > signatures( num_signed );

        libBLS::Bls obj = libBLS::Bls( num_signed, num_all );

        for ( size_t i = 0; i < 10; ++i ) {
            std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr =
                std::make_shared< std::array< uint8_t, 32 > >( GenerateRandHash() );
            G1Point hash = G1Point::fromHash( *hash_ptr );

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
                auto pkey = skeys.at( i ) * G2Point::generator();
                BOOST_REQUIRE( obj.Verify( *hash_ptr, signatures.at( i ), pkey ) );
                BOOST_REQUIRE_THROW(
                    obj.Verify( *hash_ptr, SpoilSignature( signatures.at( i ) ), pkey ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
            }

            std::vector< algebra::FrScalar > lagrange_coeffs =
                algebra::lagrangeCoeffs( participants, num_signed );
            algebra::G1Point signature = obj.SignatureRecover( signatures, lagrange_coeffs );

            auto recovered_keys = obj.KeysRecover( lagrange_coeffs, skeys );
            BOOST_REQUIRE( obj.Verify( *hash_ptr, signature, recovered_keys.second ) );
            BOOST_REQUIRE_THROW(
                obj.Verify( *hash_ptr, SpoilSignature( signature ), recovered_keys.second ),
                libBLS::ThresholdUtils::IsNotWellFormed );

            recovered_keys.second.getXRef().getC0Ref().asBackendRef() =
                FqElementTestAccessor::spoil(
                    recovered_keys.second.getXRef().getC0Ref().asBackendRef() );
            BOOST_REQUIRE_THROW( obj.Verify( *hash_ptr, signature, recovered_keys.second ),
                libBLS::ThresholdUtils::IsNotWellFormed );
        }
    }

    std::cerr << "BLS TESTS completed successfully" << std::endl;
}

BOOST_AUTO_TEST_CASE( libBlsAPI ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        std::vector< BLSPrivateKeyShare > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all ).first;

        for ( size_t i = 0; i < 10; ++i ) {
            BLSSigShareSet sigSet( num_signed, num_all );

            std::vector< size_t > participants( num_all );  // choosing random participants
            for ( size_t i = 0; i < num_all; ++i )
                participants.at( i ) = i + 1;
            for ( size_t i = 0; i < num_all - num_signed; ++i ) {
                size_t ind4del = rand_gen() % participants.size();
                participants.erase( participants.begin() + ind4del );
            }

            std::array< uint8_t, 32 > hash_ptr = GenerateRandHash();

            for ( size_t i = 0; i < num_signed; ++i ) {
                BLSPrivateKeyShare skey = Skeys.at( participants.at( i ) - 1 );
                BLSSigShare sigShare =
                    skey.sign( hash_ptr, participants.at( i ) );
                sigSet.addSigShare( sigShare );
            }

            for ( size_t i = 0; i < num_signed; ++i ) {
                BLSPublicKeyShare pkey_share(
                    Skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
                BLSSigShare sig_share =
                    sigSet.getSigShareByIndex( participants.at( i ) );
                BOOST_REQUIRE(
                    pkey_share.VerifySig( hash_ptr, sig_share, num_signed, num_all ) );
                algebra::G1Point good_sig = sig_share.getSigShare();
                algebra::G1Point bad_sig = SpoilSignature( good_sig );
                std::string hint = sig_share.getHint();

                BOOST_REQUIRE_THROW(
                    BLSSigShare( bad_sig, hint, participants.at( i ), num_signed, num_all ),
                    libBLS::ThresholdUtils::IsNotWellFormed );
            }

            BOOST_REQUIRE( sigSet.getTotalSigSharesCount() == num_signed );

            BLSSignature common_sig_ptr = sigSet.merge();  // verifying signature
            std::vector< size_t > participants_vec( participants );
            BLSPrivateKey common_skey( Skeys,
                participants_vec, num_signed, num_all );
            BLSPublicKey common_pkey( common_skey.getPrivateKey() );
            BOOST_REQUIRE( common_pkey.VerifySig( hash_ptr, common_sig_ptr ) );
            algebra::G1Point good_sig = common_sig_ptr.getSig();
            algebra::G1Point bad_sig = SpoilSignature( good_sig );
            std::string hint = common_sig_ptr.getHint();
            BLSSignature bad_sign( bad_sig, hint, num_signed, num_all );

            BOOST_REQUIRE_THROW(
                common_pkey.VerifySig( hash_ptr, BLSSignature( bad_sign ) ),
                libBLS::ThresholdUtils::IsNotWellFormed );

            std::map< size_t, BLSPublicKeyShare > pkeys_map1;
            for ( size_t i = 0; i < num_signed; ++i ) {
                BLSPublicKeyShare cur_pkey(
                    Skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
                pkeys_map1.insert_or_assign( participants.at( i ), BLSPublicKeyShare( cur_pkey ) );
            }

            auto map = std::map< size_t, BLSPublicKeyShare >(pkeys_map1 );
            BLSPublicKey common_pkey1( map, num_signed, num_all );

            BOOST_REQUIRE( common_pkey1.getRequiredSigners() == num_signed );
            BOOST_REQUIRE( common_pkey1.getTotalSigners() == num_all );

            BOOST_REQUIRE( common_pkey1.VerifySig( hash_ptr, common_sig_ptr ) );

            std::vector< size_t > participants1( num_all );  // use the whole set of participants
            for ( size_t i = 0; i < num_all; ++i )
                participants1.at( i ) = i + 1;

            std::map< size_t, BLSPublicKeyShare > pkeys_map2;
            for ( size_t i = 0; i < num_all; ++i ) {
                BLSPublicKeyShare cur_pkey(
                    Skeys.at( participants1.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
                pkeys_map2.insert_or_assign( participants1.at( i ), BLSPublicKeyShare( cur_pkey ) );
            }

            BLSPublicKey common_pkey2(
                std::map< size_t, BLSPublicKeyShare>(pkeys_map2 ),
                num_signed, num_all );

            BOOST_REQUIRE( common_pkey2.VerifySig( hash_ptr, common_sig_ptr ) );
        }
    }
    std::cerr << "BLS API TEST END" << std::endl;
}

BOOST_AUTO_TEST_CASE( libffObjsToString ) {
    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        std::vector< BLSPrivateKeyShare > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all ).first;

        std::array< uint8_t, 32 > hash_ptr = GenerateRandHash();

        BLSSigShareSet sigSet( num_signed, num_all );

        std::vector< size_t > participants( num_all );  // choosing random participants
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPrivateKeyShare skey = Skeys.at( participants.at( i ) - 1 );
            std::string skey_str_ptr = skey.toString();
            BLSPrivateKeyShare skey_from_str =
                BLSPrivateKeyShare( skey_str_ptr, num_signed, num_all );
            BOOST_REQUIRE( skey_from_str.getPrivateKey() == skey.getPrivateKey() );

            BLSSigShare sigShare =
                skey.signWithHelper( hash_ptr, participants.at( i ) );
            std::string sig_str_ptr = sigShare.toString();
            BLSSigShare sigShare_from_str = BLSSigShare( sig_str_ptr, participants.at( i ), num_signed, num_all );
            BOOST_REQUIRE( sigShare.getSigShare() == sigShare_from_str.getSigShare() );
            BOOST_REQUIRE( sigShare.getHint() == sigShare_from_str.getHint() );
            BOOST_REQUIRE(
                sigShare.getRequiredSigners() == sigShare_from_str.getRequiredSigners() );
            BOOST_REQUIRE( sigShare.getTotalSigners() == sigShare_from_str.getTotalSigners() );
            sigSet.addSigShare( sigShare );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare pkey_share(
                Skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
            std::vector< std::string > pkey_str_vect = pkey_share.toString();
            BLSPublicKeyShare pkey_from_str( pkey_str_vect, num_signed, num_all );
            BOOST_REQUIRE( pkey_share.getPublicKey() == pkey_from_str.getPublicKey() );
            BOOST_REQUIRE( pkey_share.VerifySigWithHelper( hash_ptr,
                sigSet.getSigShareByIndex( participants.at( i ) ), num_signed, num_all ) );
        }

        BLSSignature common_sig_ptr = sigSet.merge();
        BLSPrivateKey common_skey(
            Skeys, std::vector< size_t >( participants ), num_signed, num_all );
        std::string common_skey_str = common_skey.toString();
        BLSPrivateKey common_skey_from_str( common_skey_str, num_signed, num_all );
        BOOST_REQUIRE( common_skey_from_str.getPrivateKey() == common_skey.getPrivateKey() );

        BLSSignature common_sig_from_str( common_sig_ptr.toString(), num_signed, num_all );
        BOOST_REQUIRE( common_sig_from_str.getSig() == common_sig_ptr.getSig() );
        BOOST_REQUIRE( common_sig_from_str.getHint() == common_sig_ptr.getHint() );
        BOOST_REQUIRE(
            common_sig_from_str.getRequiredSigners() == common_sig_ptr.getRequiredSigners() );
        BOOST_REQUIRE( common_sig_from_str.getTotalSigners() == common_sig_ptr.getTotalSigners() );

        BLSPublicKey common_pkey( common_skey.getPrivateKey() );
        std::vector< std::string > common_pkey_str_vect = common_pkey.toString();
        BLSPublicKey common_pkey_from_str( common_pkey_str_vect );
        BOOST_REQUIRE( common_pkey.getPublicKey() == common_pkey_from_str.getPublicKey() );
        BOOST_REQUIRE( common_pkey.VerifySigWithHelper( hash_ptr, common_sig_ptr ) );

        std::map< size_t, BLSPublicKeyShare > pkeys_map;
        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare cur_pkey(
                Skeys.at( participants[i] - 1 ).getPrivateKey(), num_signed, num_all );
            pkeys_map.insert_or_assign( participants.at( i ), BLSPublicKeyShare( cur_pkey ) );
        }

        BLSPublicKey common_pkey1(
            std::map< size_t, BLSPublicKeyShare >(
                pkeys_map ),
            num_signed, num_all );
        std::vector< std::string > common_pkey_str_vect1 = common_pkey.toString();
        BLSPublicKey common_pkey_from_str1( common_pkey_str_vect1 );

        BOOST_REQUIRE( common_pkey1.getPublicKey() == common_pkey_from_str1.getPublicKey() );
        BOOST_REQUIRE( common_pkey1.getPublicKey() == common_pkey.getPublicKey() );
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

        std::vector< BLSPrivateKeyShare > Skeys =
            BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all ).first;

        std::array< uint8_t, 32 > hash_ptr = GenerateRandHash();

        BLSSigShareSet sigSet( num_signed, num_all );
        BLSSigShareSet sigSet1( num_signed, num_all );

        std::string message;
        size_t msg_length = rand_gen() % 1000 + 2;
        for ( size_t length = 0; length < msg_length; ++length ) {
            message += char( rand_gen() % 128 );
        }
        std::string msg_ptr = message;

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );
        std::shared_ptr< std::vector< size_t > > participants1 =
            choose_rand_signers( num_signed, num_all );

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPrivateKeyShare skey = Skeys.at( participants->at( i ) - 1 );
            BLSSigShare sigShare = skey.sign( hash_ptr, participants->at( i ) );
            sigSet.addSigShare( sigShare );

            BLSPrivateKeyShare skey1 = Skeys.at( participants1->at( i ) - 1 );
            BLSSigShare sigShare1 =
                skey1.sign( hash_ptr, participants1->at( i ) );
            sigSet1.addSigShare( sigShare1 );
        }

        BLSSignature common_sig_ptr = sigSet.merge();
        BLSSignature common_sig_ptr1 = sigSet1.merge();

        BOOST_REQUIRE( common_sig_ptr.getSig() == common_sig_ptr1.getSig() );
    }
}

BOOST_AUTO_TEST_CASE( private_keys_equality ) {
    for ( size_t i = 0; i < 100; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        libBLS::Dkg dkg_obj = libBLS::Dkg( num_signed, num_all );
        const std::vector< algebra::FrScalar > pol = dkg_obj.GeneratePolynomial();
        std::vector< algebra::FrScalar > skeys = dkg_obj.SecretKeyContribution( pol );

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );

        std::vector< algebra::FrScalar > lagrange_koefs =
            algebra::lagrangeCoeffs( *participants, num_signed );
        algebra::FrScalar common_skey = algebra::FrScalar::zero();
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
        const std::vector< algebra::FrScalar > pol = dkg_obj.GeneratePolynomial();
        std::vector< algebra::FrScalar > skeys = dkg_obj.SecretKeyContribution( pol );
        algebra::G2Point common_pkey = dkg_obj.GetPublicKeyFromSecretKey( pol.at( 0 ) );

        std::shared_ptr< std::vector< size_t > > participants =
            choose_rand_signers( num_signed, num_all );

        std::vector< algebra::FrScalar > lagrange_koefs =
            algebra::lagrangeCoeffs( *participants, num_signed );
        algebra::G2Point common_pkey1 = algebra::G2Point::identity();
        for ( size_t i = 0; i < num_signed; ++i ) {
            common_pkey1 = common_pkey1 + lagrange_koefs.at( i ) *
                                              skeys.at( participants->at( i ) - 1 ) *
                                              algebra::G2Point::generator();
        }
        BOOST_REQUIRE( common_pkey == common_pkey1 );
    }
}

BOOST_AUTO_TEST_CASE( BLSWITHDKG ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

        std::vector< std::vector< algebra::FrScalar > > secret_shares_all;
        std::vector< std::vector< algebra::G2Point > > public_shares_all;
        std::vector< DKGBLSWrapper > dkgs;
        std::vector< BLSPrivateKeyShare > skeys;

        algebra::G2Point common_public = algebra::G2Point::identity();

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGBLSWrapper dkg_wrap( num_signed, num_all );
            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< algebra::FrScalar > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< algebra::G2Point > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            common_public = common_public + public_shares_ptr->at( 0 );
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }

        BLSPublicKey dkg_common_pkey( common_public );

        for ( size_t i = 0; i < num_all; i++ )
            for ( size_t j = 0; j < num_all; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< algebra::G2Point > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< algebra::FrScalar > > secret_key_shares;

        for ( size_t i = 0; i < num_all; i++ ) {
            std::vector< algebra::FrScalar > secret_key_contribution;
            for ( size_t j = 0; j < num_all; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < num_all; i++ ) {
            BLSPrivateKeyShare pkey_share = dkgs.at( i ).CreateBLSPrivateKeyShare(
                std::make_shared< std::vector< algebra::FrScalar > >( secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
        }

        std::vector< size_t > participants( num_all );  // choosing random participants
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        std::array< uint8_t, 32 > hash_ptr = GenerateRandHash();

        BLSSigShareSet sigSet( num_signed, num_all );

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPrivateKeyShare skey = skeys.at( participants.at( i ) - 1 );
            BLSSigShare sigShare = skey.sign( hash_ptr, participants.at( i ) );
            sigSet.addSigShare( sigShare );
        }

        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare pkey_share(
                skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
            BLSSigShare sig_share_ptr =
                sigSet.getSigShareByIndex( participants.at( i ) );
            BOOST_REQUIRE( pkey_share.VerifySig( hash_ptr, sig_share_ptr, num_signed, num_all ) );
        }

        std::vector< BLSPrivateKeyShare > ptr_skeys;
        for ( size_t i = 0; i < num_all; i++ ) {
            ptr_skeys.push_back( BLSPrivateKeyShare( skeys.at( i ) ) );
        }

        algebra::FrScalar common_secret = algebra::FrScalar::zero();
        for ( size_t i = 0; i < num_all; i++ ) {
            common_secret = common_secret + dkgs.at( i ).getValueAt0();
        }

        BLSSignature common_sig_ptr = sigSet.merge();  // verifying signature

        std::string common_secret_str = common_secret.toString( Base::DEC );
        BLSPrivateKey common_skey( common_secret_str, num_signed, num_all );

        BLSPrivateKey common_skey2(
            std::vector< BLSPrivateKeyShare >( ptr_skeys ),
            std::vector< size_t >( participants ), num_signed, num_all );
        BOOST_REQUIRE( common_skey.getPrivateKey() == common_skey2.getPrivateKey() );
        BOOST_REQUIRE( common_secret * algebra::G2Point::generator() == common_public );
        BLSPublicKey common_pkey( common_skey2.getPrivateKey() );
        BOOST_REQUIRE( common_pkey.getPublicKey() == dkg_common_pkey.getPublicKey() );
        BOOST_REQUIRE( common_pkey.VerifySig( hash_ptr, common_sig_ptr ) );

        std::map< size_t, BLSPublicKeyShare > pkeys_map;
        for ( size_t i = 0; i < num_signed; ++i ) {
            BLSPublicKeyShare cur_pkey(
                skeys.at( participants.at( i ) - 1 ).getPrivateKey(), num_signed, num_all );
            pkeys_map.insert_or_assign( participants.at( i ), BLSPublicKeyShare( cur_pkey ) );
        }

        BLSPublicKey common_pkey1(
            std::map< size_t, BLSPublicKeyShare >(
                pkeys_map ),
            num_signed, num_all );

        BOOST_REQUIRE( common_pkey1.VerifySig( hash_ptr, common_sig_ptr ) );
    }
    std::cerr << "BLS WITH DKG TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( BLSAGGREGATEDVERIFICATIONONLY ) {
    for ( size_t i = 0; i < 10; ++i ) {
        size_t num_all = rand_gen() % 15 + 2;
        size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;
        size_t batch_size = rand_gen() % 5 + 1;

        bool invalid_sig = rand_gen() % 2;

        std::vector< std::vector< algebra::FrScalar > > secret_shares_all;
        std::vector< std::vector< algebra::G2Point > > public_shares_all;
        std::vector< DKGBLSWrapper > dkgs;
        std::vector< BLSPrivateKeyShare > skeys;

        algebra::G2Point common_public = algebra::G2Point::identity();

        for ( size_t i = 0; i < num_all; i++ ) {
            DKGBLSWrapper dkg_wrap( num_signed, num_all );
            dkgs.push_back( dkg_wrap );
            std::shared_ptr< std::vector< algebra::FrScalar > > secret_shares_ptr =
                dkg_wrap.createDKGSecretShares();
            std::shared_ptr< std::vector< algebra::G2Point > > public_shares_ptr =
                dkg_wrap.createDKGPublicShares();
            common_public = common_public + public_shares_ptr->at( 0 );
            secret_shares_all.push_back( *secret_shares_ptr );
            public_shares_all.push_back( *public_shares_ptr );
        }

        BLSPublicKey dkg_common_pkey( common_public );

        for ( size_t i = 0; i < num_all; i++ )
            for ( size_t j = 0; j < num_all; j++ ) {
                BOOST_REQUIRE( dkgs.at( i ).VerifyDKGShare( j, secret_shares_all.at( i ).at( j ),
                    std::make_shared< std::vector< algebra::G2Point > >(
                        public_shares_all.at( i ) ) ) );
            }

        std::vector< std::vector< algebra::FrScalar > > secret_key_shares;

        for ( size_t i = 0; i < num_all; i++ ) {
            std::vector< algebra::FrScalar > secret_key_contribution;
            for ( size_t j = 0; j < num_all; j++ ) {
                secret_key_contribution.push_back( secret_shares_all.at( j ).at( i ) );
            }
            secret_key_shares.push_back( secret_key_contribution );
        }

        for ( size_t i = 0; i < num_all; i++ ) {
            BLSPrivateKeyShare pkey_share = dkgs.at( i ).CreateBLSPrivateKeyShare(
                std::make_shared< std::vector< algebra::FrScalar > >( secret_key_shares.at( i ) ) );
            skeys.push_back( pkey_share );
        }

        std::vector< size_t > participants( num_all );
        for ( size_t i = 0; i < num_all; ++i )
            participants.at( i ) = i + 1;
        for ( size_t i = 0; i < num_all - num_signed; ++i ) {
            size_t ind4del = rand_gen() % participants.size();
            participants.erase( participants.begin() + ind4del );
        }

        std::vector< std::array< uint8_t, 32 > > hash_ptrs;
        hash_ptrs.reserve( batch_size );
        for ( size_t i = 0; i < batch_size; i++ ) {
            std::array< uint8_t, 32 > hash_ptr = GenerateRandHash();
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
                    std::array< uint8_t, 32 > bad_hash_ptr = GenerateRandHash();
                    BLSSigShare sigShare =
                        skey.sign( bad_hash_ptr, participants.at( j ) );
                    sigSets.at( i ).addSigShare( sigShare );
                } else {
                    BLSSigShare sigShare =
                        skey.sign( hash_ptrs.at( i ), participants.at( j ) );
                    sigSets.at( i ).addSigShare( sigShare );
                }
            }
        }

        std::vector< BLSSignature > common_sig_ptrs;
        common_sig_ptrs.reserve( batch_size );
        for ( size_t i = 0; i < batch_size; i++ ) {
            common_sig_ptrs.push_back( sigSets.at( i ).merge() );
        }

        std::vector< BLSPrivateKeyShare > ptr_skeys;
        ptr_skeys.reserve( batch_size );
        for ( size_t i = 0; i < num_all; i++ ) {
            ptr_skeys.push_back( BLSPrivateKeyShare( skeys.at( i ) ) );
        }

        BLSPrivateKey common_skey(
            std::vector< BLSPrivateKeyShare >( ptr_skeys ),
            std::vector< size_t >( participants ), num_signed, num_all );
        BLSPublicKey common_pkey( common_skey.getPrivateKey() );

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
    std::cerr << "BLS AGGREGATED VERIFICATION ONLY TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( BLSAGGREGATEDSIGNATURESSCHEME ) {
    size_t num_all = rand_gen() % 100 + 2;

    std::vector< algebra::FrScalar > private_keys( num_all );
    std::vector< algebra::G2Point > public_keys( num_all );
    for ( size_t i = 0; i < num_all; ++i ) {
        auto key_pair = libBLS::Bls::KeyGeneration();
        private_keys[i] = key_pair.first;
        public_keys[i] = key_pair.second;
    }

    std::string hex_message = rand32HexStr();

    std::vector< algebra::G1Point > signatures( num_all );
    for ( size_t i = 0; i < num_all; ++i ) {
        signatures[i] = libBLS::Bls::CoreSignAggregated( hex_message, private_keys[i] );
        BOOST_REQUIRE( libBLS::Bls::CoreVerify( public_keys[i], hex_message, signatures[i] ) );
        BOOST_REQUIRE_THROW(
            libBLS::Bls::CoreVerify( public_keys[i], hex_message, SpoilSignature( signatures[i] ) ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    for ( size_t i = 0; i < num_all; ++i ) {
        auto malicious_signatures = signatures;
        size_t rand_idx = rand_gen() % num_all;
        malicious_signatures[rand_idx] = SpoilSignature( signatures[rand_idx] );

        BOOST_REQUIRE_THROW( libBLS::Bls::Aggregate( malicious_signatures ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    auto aggregated_signature = libBLS::Bls::Aggregate( signatures );

    BOOST_REQUIRE(
        libBLS::Bls::FastAggregateVerify( public_keys, hex_message, aggregated_signature ) );

    for ( size_t i = 0; i < num_all; ++i ) {
        auto malicious_public_keys = public_keys;
        size_t rand_idx = rand_gen() % num_all;
        malicious_public_keys[rand_idx] = SpoilPublicKey( public_keys[rand_idx] );

        BOOST_REQUIRE_THROW( libBLS::Bls::FastAggregateVerify(
                                 malicious_public_keys, hex_message, aggregated_signature ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    for ( size_t i = 0; i < num_all; ++i ) {
        auto malicious_public_keys = public_keys;
        size_t rand_idx = rand_gen() % num_all;
        malicious_public_keys[rand_idx] = algebra::G2Point::random();

        BOOST_REQUIRE( !libBLS::Bls::FastAggregateVerify(
            malicious_public_keys, hex_message, aggregated_signature ) );
    }

    std::cerr << "BLS AGGREGATED SIGNATURES SCHEME TEST FINISHED" << std::endl;
}

BOOST_AUTO_TEST_CASE( BLSAGGREGATEDPOPPROVEVERIFY ) {
    auto key_pair = libBLS::Bls::KeyGeneration();

    auto pop_prove = libBLS::Bls::PopProve( key_pair.first );

    BOOST_REQUIRE( libBLS::Bls::PopVerify( key_pair.second, pop_prove ) );

    auto random_prove = algebra::G1Point::random();

    BOOST_REQUIRE( !libBLS::Bls::PopVerify( key_pair.second, random_prove ) );

    BOOST_REQUIRE( libBLS::Bls::HashPublicKeyToG1WithHint( key_pair.second ).first ==
                   libBLS::Bls::HashPublicKeyToG1( key_pair.second ) );

    auto spoiled_public_key = SpoilPublicKey( key_pair.second );
    auto spoiled_pop_prove = SpoilSignature( pop_prove );

    BOOST_REQUIRE_THROW( libBLS::Bls::PopVerify( spoiled_public_key, pop_prove ),
        libBLS::ThresholdUtils::IsNotWellFormed );
    BOOST_REQUIRE_THROW( libBLS::Bls::PopVerify( key_pair.second, spoiled_pop_prove ),
        libBLS::ThresholdUtils::IsNotWellFormed );

    std::cout << "BLS AGGREGATED POP PROVE VERIFY TEST PASSED\n";
}

BOOST_AUTO_TEST_CASE( Exceptions ) {
    size_t num_all = rand_gen() % 15 + 2;
    size_t num_signed = rand_gen() % ( num_all - 1 ) + 1;

    std::vector< size_t > participants( num_all );
    for ( size_t i = 0; i < num_all; ++i )
        participants.at( i ) = i + 1;

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey pkey( std::string( "" ), num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey( std::string( "0" ), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey(
                BLSPrivateKeyShare::generateSampleKeys( num_signed, num_all ).first, {},
                num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        // creating a polynomial
        std::vector< algebra::FrScalar > coeffs( 11 );

        for ( auto& elem : coeffs ) {
            elem = algebra::FrScalar::random();

            while ( elem == 0 ) {
                elem = algebra::FrScalar::random();
            }
        }

        // make free element zero so the common secret is zero
        coeffs[0] = algebra::FrScalar::zero();

        std::vector< BLSPrivateKeyShare > secret_keys( 16 );
        std::vector< size_t > ids( 11 );
        for ( size_t i = 0; i < 16; ++i ) {
            if ( i < 11 ) {
                ids[i] = i + 1;
            }

            algebra::FrScalar tmp = algebra::FrScalar::zero();

            for ( size_t j = 0; j < 11; ++j ) {
                tmp = tmp + coeffs[j] * algebra::power( algebra::FrScalar::fromString(
                                                            std::to_string( i + 1 ), Base::DEC ),
                                            j );
            }
            secret_keys[i] = BLSPrivateKeyShare( tmp, 11, 16 );
        }

        BOOST_REQUIRE_THROW(
            BLSPrivateKey skey(
                std::vector< BLSPrivateKeyShare >( secret_keys ),
                std::vector< size_t >( ids ), 11, 16 ),
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
            BLSPrivateKeyShare skey( algebra::FrScalar::zero(), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        BLSPrivateKeyShare skey( algebra::FrScalar::random(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            skey.sign( GenerateRandHash() , 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSPrivateKeyShare skey( algebra::FrScalar::random(), num_signed, num_all );
        BOOST_REQUIRE_THROW(
            skey.signWithHelper( GenerateRandHash(), 0 ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::vector< std::string > coords = { "0", "0", "0", "0" };
        BOOST_REQUIRE_THROW(
            BLSPublicKey pkey( coords ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        // creating a polynomial
        std::vector< algebra::FrScalar > coeffs( 11 );

        for ( auto& elem : coeffs ) {
            elem = algebra::FrScalar::random();

            while ( elem == 0 ) {
                elem = algebra::FrScalar::random();
            }
        }

        // make free element zero so the common secret is zero
        coeffs[0] = algebra::FrScalar::zero();

        std::map< size_t, BLSPublicKeyShare > coeffs_map;
        for ( size_t i = 0; i < 16; ++i ) {
            algebra::FrScalar tmp = algebra::FrScalar::zero();

            for ( size_t j = 0; j < 11; ++j ) {
                tmp = tmp + coeffs[j] * algebra::power( algebra::FrScalar::fromString(
                                                            std::to_string( i + 1 ), Base::DEC ),
                                            j );
            }

            if ( i < 11 ) {
                coeffs_map.insert_or_assign( i + 1, BLSPublicKeyShare( tmp, 11, 16 ) );
            }
        }

        BOOST_REQUIRE_THROW(
            BLSPublicKey pkey( coeffs_map, 11, 16 ), libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BOOST_REQUIRE_THROW( BLSPublicKey pkey( algebra::G2Point::identity() ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BOOST_REQUIRE_THROW( BLSPublicKey pkey( algebra::FrScalar::zero() ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        BOOST_REQUIRE_THROW(
            BLSPublicKeyShare pkey( algebra::FrScalar::zero(), num_signed, num_all ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        std::vector< std::string > coords = { "0", "0", "0", "0" };
        BOOST_REQUIRE_THROW( BLSPublicKeyShare pkey( coords, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string empty_hint = "";
        BOOST_REQUIRE_THROW(
            BLSSignature( algebra::G1Point::random(),
                empty_hint, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string short_sig = "1:1:1:1";
        BOOST_REQUIRE_THROW(
            BLSSignature( short_sig, num_signed, num_all ),
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
            BLSSignature( long_sig, num_signed, num_all ),
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
            BLSSignature( long_sig, num_signed, num_all ),
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
            BLSSignature( long_sig, num_signed, num_all ),
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
            BLSSignature( long_sig, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        algebra::G1Point zero_sig = algebra::G1Point::identity();
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW( BLSSignature( zero_sig, hint,
                                 num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string empty_hint = "";
        BOOST_REQUIRE_THROW(
            BLSSigShare( algebra::G1Point::random(),
                empty_hint, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW(
            BLSSigShare( algebra::G1Point::identity(), hint,
                1, num_signed, num_all ),
            libBLS::ThresholdUtils::IsNotWellFormed );
    }

    {
        std::string hint = "123:1";
        BOOST_REQUIRE_THROW(
            BLSSigShare( algebra::G1Point::random(), hint,
                0, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string short_sig = "1:1:1:1";
        BOOST_REQUIRE_THROW(
            BLSSigShare( short_sig, 1, num_signed, num_all ),
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
            BLSSigShare( long_sig, 1, num_signed, num_all ),
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
            BLSSigShare( long_sig, 1, num_signed, num_all ),
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
            BLSSigShare( long_sig, 1, num_signed, num_all ),
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
            BLSSigShare( long_sig, 1, num_signed, num_all ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BLSSigShare sigShare1( algebra::G1Point::random(),
            hint, 1, num_signed, num_all );
        BLSSigShare sigShare2 = sigShare1;
        BLSSigShareSet sig_set( num_signed, num_all );
        sig_set.addSigShare( BLSSigShare( sigShare1 ) );
        BOOST_REQUIRE_THROW( sig_set.addSigShare( BLSSigShare( sigShare2 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        std::string hint = "123:1";
        BLSSigShare sigShare1( algebra::G1Point::random(),
            hint, 1, num_signed, num_all );
        BLSSigShareSet sig_set( 1, 1 );
        sig_set.addSigShare( BLSSigShare( sigShare1 ) );
        sig_set.merge();
        BOOST_REQUIRE_THROW( sig_set.addSigShare( BLSSigShare( sigShare1 ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE_THROW( sig_set.merge(), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        BLSSigShareSet sig_set( num_signed, num_all );
        BOOST_REQUIRE_THROW( sig_set.getSigShareByIndex( 1 ), libBLS::ThresholdUtils::IncorrectInput );
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
        std::vector< algebra::G2Point > vect = { algebra::G2Point::random() };
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, algebra::FrScalar::zero(),
                                 std::make_shared< std::vector< algebra::G2Point > >( vect ) ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, algebra::FrScalar::zero(), nullptr ),
            libBLS::ThresholdUtils::ZeroSecretKey );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, algebra::FrScalar::random(), nullptr ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed + 1, num_all + 1 );
        std::vector< algebra::G2Point > vect = { algebra::G2Point::random() };
        BOOST_REQUIRE_THROW( dkg_wrap.VerifyDKGShare( 1, algebra::FrScalar::random(),
                                 std::make_shared< std::vector< algebra::G2Point > >( vect ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_wrap.setDKGSecret( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        std::vector< algebra::FrScalar > poly;
        BOOST_REQUIRE_THROW(
            dkg_wrap.setDKGSecret( std::make_shared< std::vector< algebra::FrScalar > >( poly ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        BOOST_REQUIRE_THROW(
            dkg_wrap.CreateBLSPrivateKeyShare( nullptr ), libBLS::ThresholdUtils::IncorrectInput );
    }

    {
        DKGBLSWrapper dkg_wrap( num_signed, num_all );
        std::vector< algebra::FrScalar > shares;
        BOOST_REQUIRE_THROW( dkg_wrap.CreateBLSPrivateKeyShare(
                                 std::make_shared< std::vector< algebra::FrScalar > >( shares ) ),
            libBLS::ThresholdUtils::IncorrectInput );
    }
}
BOOST_AUTO_TEST_SUITE_END()
