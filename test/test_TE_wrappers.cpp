//
// Created by stan on 01.08.19.
//


#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>
#include <dkg/dkg_te.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>

#include <random>

std::default_random_engine rand_gen((unsigned int) time(0));

static char aparam[] =
        "type a\n"
        "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
        "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
        "r 730750818665451621361119245571504901405976559617\n"
        "exp2 159\n"
        "exp1 107\n"
        "sign1 1\n"
        "sign0 1\n";

BOOST_AUTO_TEST_SUITE(ThresholdEncryptionWrappers)
    BOOST_AUTO_TEST_CASE(test1){
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;

        encryption:: DkgTe dkg_te (num_signed, num_all);

        element_t g;
        element_init_G1(g, dkg_te.pairing_);
        element_set(g, dkg_te.GetGenerator().el_);

        std::vector<encryption::element_wrapper> poly = dkg_te.GeneratePolynomial();
        encryption::element_wrapper zero_el;
        encryption::element_wrapper common_skey = dkg_te.ComputePolynomialValue(poly, zero_el);

        std::string message;
        size_t msg_length = rand_gen() % 1000 + 2;
        for (size_t length = 0; length < msg_length; ++length) {
             message += char(rand_gen() % 128);
        }

        element_t common_pkey;
        element_init_G1(common_pkey, dkg_te.pairing_);
        element_mul(common_pkey, common_skey.el_, g);

        TEPublicKey common_public(common_pkey, num_signed, num_all);
        encryption::Ciphertext cypher = common_public.encrypt(std::make_shared<std::string>(message));

        std::vector<encryption::element_wrapper> skeys = dkg_te.CreateSecretKeyContribution(poly);
        std::vector<TEPrivateKeyShare> skey_shares;
        for ( size_t i = 0; i < num_all; i++){
            skey_shares.push_back( TEPrivateKeyShare(skeys[i].el_, i + 1, num_signed, num_all));
        }


    }



BOOST_AUTO_TEST_SUITE_END()
