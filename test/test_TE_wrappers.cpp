//
// Created by stan on 01.08.19.
//


#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>
#include <dkg/dkg_te.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/threshold_encryption.h>

#include <random>

std::default_random_engine rand_gen((unsigned int) time(0));

BOOST_AUTO_TEST_SUITE(ThresholdEncryptionWrappers)
    BOOST_AUTO_TEST_CASE(test1){
        size_t num_all = rand_gen() % 16 + 1;
        size_t num_signed = rand_gen() % num_all + 1;
        //encryption::TE te_obj(num_signed, num_all);

        encryption:: DkgTe dkg_te (num_signed, num_all);

        element_t g;
        element_init_G1(g, dkg_te.pairing_);
        element_set(g, dkg_te.GetGenerator().el_);

        std::vector<encryption::element_wrapper> poly = dkg_te.GeneratePolynomial();
        element_t zero;
        element_init_Zr(zero, dkg_te.pairing_);
        element_set0(zero);
        encryption::element_wrapper zero_el(zero);
        encryption::element_wrapper common_skey = dkg_te.ComputePolynomialValue(poly, zero_el);

        element_t common_pkey;
        element_init_G1(common_pkey, dkg_te.pairing_);
        element_mul(common_pkey, common_skey.el_, g);
        element_clear(g);


        std::string message;
        size_t msg_length = 64; //rand_gen() % 1000 + 2;
        for (size_t length = 0; length < msg_length; ++length) {
             message += char(rand_gen() % 128);
        }       

        TEPublicKey common_public(common_pkey, num_signed, num_all);
        std::shared_ptr msg_ptr = std::make_shared<std::string>(message);
        encryption::Ciphertext cypher = common_public.encrypt(msg_ptr);

        std::vector<encryption::element_wrapper> skeys = dkg_te.CreateSecretKeyContribution(poly);
        std::vector<TEPrivateKeyShare> skey_shares;
        for ( size_t i = 0; i < num_all; i++){
            skey_shares.push_back( TEPrivateKeyShare(skeys[i].el_, i + 1, num_signed, num_all));
        }

        for (size_t i = 0; i < num_all - num_signed; ++i) {
            size_t ind4del = rand_gen() % skey_shares.size();
            auto pos4del = skey_shares.begin();
            advance(pos4del, ind4del);
            skey_shares.erase(pos4del);
        }
        TEDecryptSet decr_set(num_signed, num_all);
        for (size_t i = 0; i < num_signed; i++){
            element_printf("Decrypt is  %B\n", skey_shares[i].getPrivateKey().el_);
            std::cerr << "CYPHER[1] is " <<  std::get<1>(cypher) <<std::endl;
            element_printf("CYPHER[0] is  %B\n", std::get<0>(cypher).el_);
            encryption::element_wrapper decrypt = skey_shares[i].decrypt(cypher);

            std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
            decr_set.addDecrypt(skey_shares[i].getSignerIndex(), decr_ptr);
        }
        std::string message_decrypted = decr_set.merge(cypher);
        BOOST_REQUIRE(message == message_decrypted);
    }



BOOST_AUTO_TEST_SUITE_END()
