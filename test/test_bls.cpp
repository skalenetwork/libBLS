

#include <bls/bls.h>
#include <dkg/dkg.h>
#include <ctime>


#include <map>

#include "bls/BLSPrivateKeyShare.h"
#include "bls/BLSPrivateKey.h"
#include "bls/BLSSigShareSet.h"
#include "bls/BLSSigShare.h"
#include "bls/BLSSignature.h"
#include "bls/BLSPublicKey.h"
#include "bls/BLSPublicKeyShare.h"
#include "bls/BLSutils.cpp"

#include <fstream>
#include <third_party/json.hpp>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>
#include <libff/common/profiling.hpp>


BOOST_AUTO_TEST_SUITE(Bls)

    std::default_random_engine rand_gen((unsigned int) time(0));

    libff::alt_bn128_Fq SpoilSignCoord(libff::alt_bn128_Fq &sign_coord) {
        libff::alt_bn128_Fq bad_coord = sign_coord;
        size_t n_bad_bit = rand_gen() % (bad_coord.size_in_bits()) + 1;

        mpz_t was_coord;
        mpz_init(was_coord);
        bad_coord.as_bigint().to_mpz(was_coord);

        mpz_t mask;
        mpz_init(mask);
        mpz_set_si(mask, n_bad_bit);

        mpz_t badCoord;
        mpz_init(badCoord);
        mpz_xor(badCoord, was_coord, mask);

        bad_coord = libff::alt_bn128_Fq(badCoord);
        mpz_clears(badCoord, was_coord, mask, 0);

        return bad_coord;
    }

    libff::alt_bn128_G1 SpoilSignature(libff::alt_bn128_G1 &sign) {
        libff::alt_bn128_G1 bad_sign = sign;
        size_t bad_coord_num = rand_gen() % 3;
        switch (bad_coord_num) {
            case 0:
                bad_sign.X = SpoilSignCoord(sign.X);
                break;
            case 1:
                bad_sign.Y = SpoilSignCoord(sign.Y);
                break;
            case 2:
                bad_sign.Z = SpoilSignCoord(sign.Z);
                break;
        }
        return bad_sign;
    }

    BOOST_AUTO_TEST_CASE(libBls) {
        libff::inhibit_profiling_info = true;
        std::cerr << "STARTING LIBBLS TESTS" << std::endl;
        for (size_t i = 0; i < 10; ++i) {

            size_t num_all = rand_gen() % 16 + 1;
            size_t num_signed = rand_gen() % num_all + 1;

            signatures::Dkg dkg_obj = signatures::Dkg(num_signed, num_all);
            const std::vector<libff::alt_bn128_Fr> pol = dkg_obj.GeneratePolynomial();
            std::vector<libff::alt_bn128_Fr> skeys = dkg_obj.SecretKeyContribution(pol);

            std::vector<libff::alt_bn128_G1> signatures(num_signed);

            signatures::Bls obj = signatures::Bls(num_signed, num_all);

            for (size_t i = 0; i < 10; ++i) {
                std::string message;
                size_t msg_length = rand_gen() % 1000 + 2;
                for (size_t length = 0; length < msg_length; ++length) {
                    message += char(rand_gen() % 128);
                }

                libff::alt_bn128_G1 hash = obj.Hashing(message);
                for (size_t i = 0; i < num_signed; ++i) signatures.at(i) = obj.Signing(hash, skeys[i]);

                std::vector<size_t> participants(num_all);
                for (size_t i = 0; i < num_all; ++i) participants.at(i) = i + 1;
                for (size_t i = 0; i < num_all - num_signed; ++i) {
                    size_t ind4del = rand_gen() % participants.size();
                    participants.erase(participants.begin() + ind4del);
                }

                bool is_exception_caught = false;
                for (size_t i = 0; i < num_signed; ++i) {
                    auto pkey = skeys.at(i) * libff::alt_bn128_G2::one();
                    BOOST_REQUIRE(obj.Verification(message, signatures.at(i), pkey));
                    try {
                        obj.Verification(message, SpoilSignature(signatures.at(i)), pkey);
                    }
                    catch (std::runtime_error) {
                        is_exception_caught = true;
                    }
                    BOOST_REQUIRE(is_exception_caught);
                }

                std::vector<libff::alt_bn128_Fr> lagrange_coeffs = obj.LagrangeCoeffs(participants);
                libff::alt_bn128_G1 signature = obj.SignatureRecover(signatures, lagrange_coeffs);

                auto recovered_keys = obj.KeysRecover(lagrange_coeffs, skeys);
                BOOST_REQUIRE(obj.Verification(message, signature, recovered_keys.second));

                is_exception_caught = false;
                try {
                    obj.Verification(message, SpoilSignature(signature), recovered_keys.second);
                }
                catch (std::runtime_error) {
                    is_exception_caught = true;
                }

                BOOST_REQUIRE(is_exception_caught);

            }

        }

        std::cerr << "BLS TESTS completed successfully" << std::endl;


    }

    BOOST_AUTO_TEST_CASE(libBlsAPI) {

        //std::default_random_engine rand_gen((unsigned int) time(0));
        for (size_t i = 0; i < 10; ++i) {

            size_t num_all = rand_gen() % 16 + 1;
            size_t num_signed = rand_gen() % num_all + 1;

            std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> Skeys = BLSPrivateKeyShare::generateSampleKeys(
                    num_signed, num_all)->first;

            for (size_t i = 0; i < 10; ++i) {

                BLSSigShareSet sigSet(num_signed, num_all);

                std::string message;
                size_t msg_length = rand_gen() % 1000 + 2;
                for (size_t length = 0; length < msg_length; ++length) {
                    message += char(rand_gen() % 128);
                }
                std::shared_ptr<std::string> msg_ptr = std::make_shared<std::string>(message);

                std::vector<size_t> participants(num_all);                          ////choosing random participants
                for (size_t i = 0; i < num_all; ++i) participants.at(i) = i + 1;
                for (size_t i = 0; i < num_all - num_signed; ++i) {
                    size_t ind4del = rand_gen() % participants.size();
                    participants.erase(participants.begin() + ind4del);
                }

                for (size_t i = 0; i < num_signed; ++i) {
                    std::shared_ptr<BLSPrivateKeyShare> skey = Skeys->at(participants.at(i) - 1);
                    std::shared_ptr<BLSSigShare> sigShare = skey->sign(msg_ptr, participants.at(i));
                    sigSet.addSigShare(sigShare);
                }

                bool is_exception_caught = false;               //// verifying sigShare
                for (size_t i = 0; i < num_signed; ++i) {
                    BLSPublicKeyShare pkey_share(*Skeys->at(participants.at(i) - 1)->getPrivateKey(), num_signed,
                                                 num_all);
                    std::shared_ptr<BLSSigShare> sig_share_ptr = sigSet.getSigShareByIndex(participants.at(i));
                    BOOST_REQUIRE(pkey_share.VerifySig(msg_ptr, sig_share_ptr, num_signed, num_all));
                    try {
                        libff::alt_bn128_G1 bad_sig = SpoilSignature(*sig_share_ptr->getSigShare());
                        BLSSigShare bad_sig_share(std::make_shared<libff::alt_bn128_G1>(bad_sig), participants.at(i),
                                                  num_signed, num_all);
                        pkey_share.VerifySig(msg_ptr, std::make_shared<BLSSigShare>(bad_sig_share), num_signed,
                                             num_all);
                    }
                    catch (std::runtime_error) {
                        is_exception_caught = true;
                    }
                    BOOST_REQUIRE(is_exception_caught);
                }

                std::shared_ptr<BLSSignature> common_sig_ptr = sigSet.merge();                                                //// verifying signature
                BLSPrivateKey common_skey(Skeys, std::make_shared<std::vector<size_t >>(participants), num_signed,
                                          num_all);
                BLSPublicKey common_pkey(*(common_skey.getPrivateKey()), num_signed, num_all);
                BOOST_REQUIRE(common_pkey.VerifySig(msg_ptr, common_sig_ptr, num_signed, num_all));
                is_exception_caught = false;
                try {
                    BLSSignature bad_sign(
                            std::make_shared<libff::alt_bn128_G1>(SpoilSignature(*common_sig_ptr->getSig())),
                            num_signed, num_all);
                    common_pkey.VerifySig(msg_ptr, std::make_shared<BLSSignature>(bad_sign), num_signed, num_all);
                }
                catch (std::runtime_error) {
                    is_exception_caught = true;
                }
                BOOST_REQUIRE(is_exception_caught);

                std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > pkeys_map;
                for (size_t i = 0; i < num_signed; ++i) {
                    BLSPublicKeyShare cur_pkey(*Skeys->at(participants.at(i) - 1)->getPrivateKey(), num_signed,
                                               num_all);
                    pkeys_map[participants.at(i)] = std::make_shared<BLSPublicKeyShare>(cur_pkey);
                }

                BLSPublicKey common_pkey1(
                        std::make_shared<std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > >(pkeys_map), num_signed,
                        num_all);

                BOOST_REQUIRE(common_pkey1.VerifySig(msg_ptr, common_sig_ptr, num_signed, num_all));

            }

        }
        std::cerr << "BLS API TEST END" << std::endl;

    }

    BOOST_AUTO_TEST_CASE(libffObjsToString) {

        libff::inhibit_profiling_info = true;

        for (size_t i = 0; i < 100; ++i) {

            size_t num_all = rand_gen() % 16 + 1;
            size_t num_signed = rand_gen() % num_all + 1;

            std::shared_ptr<std::vector<std::shared_ptr<BLSPrivateKeyShare>>> Skeys = BLSPrivateKeyShare::generateSampleKeys(
                    num_signed, num_all)->first;

            BLSSigShareSet sigSet(num_signed, num_all);

            std::string message;
            size_t msg_length = rand_gen() % 1000 + 2;
            for (size_t length = 0; length < msg_length; ++length) {
                message += char(rand_gen() % 128);
            }
            std::shared_ptr<std::string> msg_ptr = std::make_shared<std::string>(message);


            std::vector<size_t> participants(num_all);                          ////choosing random participants
            for (size_t i = 0; i < num_all; ++i) participants.at(i) = i + 1;
            for (size_t i = 0; i < num_all - num_signed; ++i) {
                size_t ind4del = rand_gen() % participants.size();
                participants.erase(participants.begin() + ind4del);
            }

            for (size_t i = 0; i < num_signed; ++i) {
                std::shared_ptr<BLSPrivateKeyShare> skey = Skeys->at(participants.at(i) - 1);
                std::shared_ptr<std::string> skey_str_ptr = skey->toString();
                std::shared_ptr<BLSPrivateKeyShare> skey_from_str = std::make_shared<BLSPrivateKeyShare>(*skey_str_ptr,
                                                                                                         num_signed,
                                                                                                         num_all);
                BOOST_REQUIRE(*skey_from_str->getPrivateKey() == *skey->getPrivateKey());

                std::shared_ptr<BLSSigShare> sigShare = skey->sign(msg_ptr, participants.at(i));
                std::shared_ptr<std::string> sig_str_ptr = sigShare->toString();
                std::shared_ptr<BLSSigShare> sigShare_from_str = std::make_shared<BLSSigShare>(sig_str_ptr,
                                                                                               participants.at(i),
                                                                                               num_signed, num_all);
                BOOST_REQUIRE(*sigShare->getSigShare() == *sigShare_from_str->getSigShare());
                sigSet.addSigShare(sigShare);
            }


            for (size_t i = 0; i < num_signed; ++i) {
                BLSPublicKeyShare pkey_share(*Skeys->at(participants.at(i) - 1)->getPrivateKey(), num_signed, num_all);
                std::shared_ptr<std::vector<std::string>> pkey_str_vect = pkey_share.toString();
                BLSPublicKeyShare pkey_from_str(pkey_str_vect, num_signed, num_all);
                BOOST_REQUIRE(*pkey_share.getPublicKey() == *pkey_from_str.getPublicKey());
            }

            std::shared_ptr<BLSSignature> common_sig_ptr = sigSet.merge();
            BLSPrivateKey common_skey(Skeys, std::make_shared<std::vector<size_t >>(participants), num_signed, num_all);
            std::shared_ptr<std::string> common_skey_str = common_skey.toString();
            BLSPrivateKey common_skey_from_str(*common_skey_str, num_signed, num_all);
            BOOST_REQUIRE(*common_skey_from_str.getPrivateKey() == *common_skey.getPrivateKey());


            BLSPublicKey common_pkey(*(common_skey.getPrivateKey()), num_signed, num_all);
            std::shared_ptr<std::vector<std::string>> common_pkey_str_vect = common_pkey.toString();
            BLSPublicKey common_pkey_from_str(common_pkey_str_vect, num_signed, num_all);
            BOOST_REQUIRE(*common_pkey.getPublicKey() == *common_pkey_from_str.getPublicKey());


            std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > pkeys_map;
            for (size_t i = 0; i < num_signed; ++i) {
                BLSPublicKeyShare cur_pkey(*Skeys->at(participants[i] - 1)->getPrivateKey(), num_signed, num_all);
                pkeys_map[participants.at(i)] = std::make_shared<BLSPublicKeyShare>(cur_pkey);
            }

            BLSPublicKey common_pkey1(
                    std::make_shared<std::map<size_t, std::shared_ptr<BLSPublicKeyShare> > >(pkeys_map), num_signed,
                    num_all);
            std::shared_ptr<std::vector<std::string>> common_pkey_str_vect1 = common_pkey.toString();
            BLSPublicKey common_pkey_from_str1(common_pkey_str_vect1, num_signed, num_all);

            BOOST_REQUIRE(*common_pkey1.getPublicKey() == *common_pkey_from_str1.getPublicKey());
            BOOST_REQUIRE(*common_pkey1.getPublicKey() == *common_pkey.getPublicKey());
        }

        std::cerr << "BLS libffObjsToString TEST END" << std::endl;
    }

    BOOST_AUTO_TEST_CASE(jsonDataVerification) {

        std::ifstream infile("key1.json");
        nlohmann::json  json_keys;
        infile >> json_keys;
        std::string skey_str = json_keys["insecureBLSPrivateKey"];
        BLSPrivateKeyShare skey(skey_str, 2, 3);
        std::vector<std::string> pkey_str;
        for ( size_t i = 0; i < 4; i++){
            pkey_str.push_back(json_keys["insecureBLSPublicKey" + std::to_string(i+1)]);
        }
        BLSPublicKeyShare pkey_share(std::make_shared<std::vector<std::string>>(pkey_str), 2, 3);

        BOOST_REQUIRE(*skey.getPrivateKey() * libff::alt_bn128_G2::one() == *pkey_share.getPublicKey());
    }

BOOST_AUTO_TEST_SUITE_END()

