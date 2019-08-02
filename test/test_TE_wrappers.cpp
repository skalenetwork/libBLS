//
// Created by stan on 01.08.19.
//

#include <boost/test/included/unit_test.hpp>
#include "TEPublicKey.h"
#include "dkg/dkg_te.h"

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

BOOST_AUTO_TEST_SUITE(ThresholdEncryptionWrappers){
    BOOST_AUTO_TEST_CASE(test1){
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;
        DKGTE dkg_te (num_signed, num_all);
        std::vector<element_wrapper> skeys = dkg_te.CreateSecretKeyContribution(dkg_te.GeneratePolynomial());
    }
}
