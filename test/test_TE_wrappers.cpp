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

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/


#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>
#include <dkg/dkg_te.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <threshold_encryption/TEPrivateKey.h>
#include <threshold_encryption/threshold_encryption.h>
#include <threshold_encryption/utils.h>

#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <dkg/DKGTEWrapper.h>


std::default_random_engine rand_gen((unsigned int) time(0));

std::string spoilMessage(std::string & message){
  std::string mes = message;
  size_t ind = rand_gen() % message.length();
  char ch = rand_gen() % 128;
  while ( mes[ind] == ch)
  ch = rand_gen() % 128;
  mes[ind] = ch;
  return mes;
}

BOOST_AUTO_TEST_SUITE(ThresholdEncryptionWrappers)

BOOST_AUTO_TEST_CASE(testSqrt){
  for (size_t i = 0; i < 100; i++) {
    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpz_t rand;
    mpz_init(rand);

    mpz_random(rand, num_limbs);

    mpz_t modulus_q;
    mpz_init(modulus_q);
    mpz_set_str(modulus_q, "8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791", 10);

    mpz_t sqr_mod;
    mpz_init(sqr_mod);
    mpz_powm_ui(sqr_mod, rand, 2,  modulus_q);

    mpz_t mpz_sqrt0;
    mpz_init(mpz_sqrt0);
    mpz_mod(mpz_sqrt0, rand, modulus_q);

    mpz_clear(rand);

    mpz_t mpz_sqrt;
    mpz_init(mpz_sqrt);

    MpzSquareRoot(mpz_sqrt, sqr_mod);

    mpz_t sum;
    mpz_init(sum);

    mpz_add(sum, mpz_sqrt0, mpz_sqrt);

    BOOST_REQUIRE(mpz_cmp(mpz_sqrt0, mpz_sqrt) == 0 || mpz_cmp(sum, modulus_q) == 0);

    mpz_clears(mpz_sqrt0, mpz_sqrt, sqr_mod, sum, modulus_q, 0);
    gmp_randclear(state);
  }

}

BOOST_AUTO_TEST_CASE(TEProcessWithWrappers){
  for (size_t i = 0; i < 1; i++) {
    size_t num_all = rand_gen() % 16 + 1;
    size_t num_signed = rand_gen() % num_all + 1;

    encryption::DkgTe dkg_te (num_signed, num_all);

    std::vector<encryption::element_wrapper> poly = dkg_te.GeneratePolynomial();
    element_t zero;
    element_init_Zr(zero, TEDataSingleton::getData().pairing_);
    element_set0(zero);
    encryption::element_wrapper zero_el(zero);

    element_clear(zero);

    encryption::element_wrapper common_skey = dkg_te.ComputePolynomialValue(poly, zero_el);
    BOOST_REQUIRE( element_cmp(common_skey.el_, poly.at(0).el_) == 0 );

    TEPrivateKey common_private(common_skey, num_signed, num_all);

    std::string message;
    size_t msg_length = 64;
    for (size_t length = 0; length < msg_length; ++length) {
      message += char(rand_gen() % 128);
    }

    TEPublicKey common_public(common_private, num_signed, num_all);
    std::shared_ptr msg_ptr = std::make_shared<std::string>(message);
    encryption::Ciphertext cypher = common_public.encrypt(msg_ptr);

    std::vector<encryption::element_wrapper> skeys = dkg_te.CreateSecretKeyContribution(poly);
    std::vector<TEPrivateKeyShare> skey_shares;
    std::vector<TEPublicKeyShare> public_key_shares;
    for ( size_t i = 0; i < num_all; i++){
      skey_shares.emplace_back( TEPrivateKeyShare(skeys[i].el_, i + 1, num_signed, num_all));
      public_key_shares.emplace_back( TEPublicKeyShare(skey_shares[i],num_signed, num_all));
    }

    for (size_t i = 0; i < num_all - num_signed; ++i) {
      size_t ind4del = rand_gen() % skey_shares.size();
      auto pos4del = skey_shares.begin();
      advance(pos4del, ind4del);
      skey_shares.erase(pos4del);
      auto pos2 = public_key_shares.begin();
      advance(pos2, ind4del);
      public_key_shares.erase(pos2);
    }

    TEDecryptSet decr_set(num_signed, num_all);
    for (size_t i = 0; i < num_signed; i++){
      encryption::element_wrapper decrypt = skey_shares[i].decrypt(cypher);
      BOOST_REQUIRE(public_key_shares[i].Verify(cypher, decrypt.el_));
      std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
      decr_set.addDecrypt(skey_shares[i].getSignerIndex(), decr_ptr);

    }
    std::string message_decrypted = decr_set.merge(cypher);
    BOOST_REQUIRE(message == message_decrypted);

    encryption::Ciphertext bad_cypher = cypher; // corrupt V n cypher
    std::get<1>(bad_cypher) = spoilMessage(std::get<1>(cypher));
    bool is_exception_caught = false;
    try {
      decr_set.merge(bad_cypher);
    }
    catch (std::runtime_error&) {
      is_exception_caught = true;
    }
    BOOST_REQUIRE(is_exception_caught);

    bad_cypher = cypher;  // corrupt U in cypher
    element_t rand_el;
    element_init_G1(rand_el, TEDataSingleton::getData().pairing_);
    std::get<0>(bad_cypher) = rand_el;

    is_exception_caught = false;
    try {
      decr_set.merge(bad_cypher);
    }
    catch (std::runtime_error &) {
      is_exception_caught = true;
    }
    BOOST_REQUIRE(is_exception_caught);

    bad_cypher = cypher;  // corrupt W in cypher
    element_t rand_el2;
    element_init_G1(rand_el2, TEDataSingleton::getData().pairing_);
    std::get<2>(bad_cypher) = rand_el2;
    is_exception_caught = false;
    try {
      decr_set.merge(bad_cypher);
    }
    catch (std::runtime_error &) {
      is_exception_caught = true;
    }
    BOOST_REQUIRE(is_exception_caught);

    size_t ind = rand_gen() % num_signed;  // corrupt random private key share

    element_t bad_pkey;
    element_init_Zr(bad_pkey, TEDataSingleton::getData().pairing_);
    element_random(bad_pkey);
    TEPrivateKeyShare bad_key(encryption::element_wrapper(bad_pkey),
                                          skey_shares[ind].getSignerIndex(),  num_signed, num_all);
    skey_shares[ind] = bad_key;
    element_clear(bad_pkey);

    TEDecryptSet bad_decr_set(num_signed, num_all);
    for (size_t i = 0; i < num_signed; i++){
      encryption::element_wrapper decrypt = skey_shares[i].decrypt(cypher);
      if ( i == ind ) BOOST_REQUIRE(!public_key_shares[i].Verify(cypher, decrypt.el_));
      std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
      bad_decr_set.addDecrypt(skey_shares[i].getSignerIndex(), decr_ptr);
    }

    std::string bad_message_decrypted = bad_decr_set.merge(cypher);
    BOOST_REQUIRE(message != bad_message_decrypted);

    element_clear(rand_el);
    element_clear(rand_el2);

  }
}

BOOST_AUTO_TEST_CASE(WrappersFromString){
  for ( size_t i = 0; i < 100; i++ ) {

    size_t num_all = rand_gen() % 16 + 1;
    size_t num_signed = rand_gen() % num_all + 1;

    element_t test0;
    element_init_G1(test0, TEDataSingleton::getData().pairing_);
    element_random(test0);
    TEPublicKey common_pkey(encryption::element_wrapper(test0), num_signed, num_all);

    element_clear(test0);

    TEPublicKey common_pkey_from_str(common_pkey.toString(), num_signed, num_all);
    BOOST_REQUIRE(element_cmp(common_pkey.getPublicKey().el_,
                                                    common_pkey_from_str.getPublicKey().el_) == 0);

    element_t test;
    element_init_Zr(test, TEDataSingleton::getData().pairing_);
    element_random(test);
    TEPrivateKey private_key(encryption::element_wrapper(test), num_signed, num_all);

    element_clear(test);

    TEPrivateKey private_key_from_str(std::make_shared<std::string>(private_key.toString()),
                                                                              num_signed, num_all);
    BOOST_REQUIRE(element_cmp(private_key.getPrivateKey().el_,
                                                    private_key_from_str.getPrivateKey().el_) == 0);

    element_t test2;
    element_init_Zr(test2, TEDataSingleton::getData().pairing_);
    element_random(test2);
    size_t signer = rand_gen() % num_all;
    TEPrivateKeyShare pr_key_share(encryption::element_wrapper(test2), signer, num_signed, num_all);

    element_clear(test2);

    TEPrivateKeyShare pr_key_share_from_str(std::make_shared<std::string>(pr_key_share.toString()),
                                                                        signer, num_signed, num_all);
    BOOST_REQUIRE(element_cmp(pr_key_share.getPrivateKey().el_,
                                                  pr_key_share_from_str.getPrivateKey().el_) == 0);

    TEPublicKeyShare pkey(pr_key_share, num_signed, num_all);
    TEPublicKeyShare pkey_from_str(pkey.toString(), signer, num_signed, num_all);
    BOOST_REQUIRE(element_cmp(pkey.getPublicKey().el_, pkey_from_str.getPublicKey().el_) == 0);

  }
  std:: cerr << "TE wrappers tests finished" << std::endl;
}

BOOST_AUTO_TEST_CASE(ThresholdEncryptionWithDKG){

      size_t num_all = 2;//rand_gen() % 16 + 1;
      size_t num_signed = 2;//rand_gen() % num_all + 1;
      std::vector< std::vector<encryption::element_wrapper>> secret_shares_all;
      std::vector< std::vector<encryption::element_wrapper>> public_shares_all;
      std::vector<DKGTEWrapper> dkgs;
      std::vector<TEPrivateKeyShare> skeys;
      std::vector<TEPublicKeyShare> pkeys;

      for ( size_t i = 0; i < num_all; i++) {
        DKGTEWrapper dkg_wrap(num_signed, num_all);
        dkgs.push_back(dkg_wrap);
        std::shared_ptr<std::vector<encryption::element_wrapper>> secret_shares_ptr = dkg_wrap.createDKGSecretShares();
        std::shared_ptr<std::vector<encryption::element_wrapper>> public_shares_ptr = dkg_wrap.createDKGPublicShares();
        secret_shares_all.push_back(*secret_shares_ptr);
        public_shares_all.push_back(*public_shares_ptr);
        TEPrivateKeyShare pkey_share = dkg_wrap.CreateTEPrivateKeyShare(i+1, secret_shares_ptr);
        skeys.push_back(pkey_share);
        pkeys.push_back(TEPublicKeyShare(pkey_share,num_signed,num_all));
      }

      for ( size_t i = 0; i < num_all; i++)
        for (size_t j = 0; j < num_signed; j++){
          BOOST_REQUIRE( dkgs.at(i).VerifyDKGShare( j , secret_shares_all.at(i).at(j), public_shares_all.at(i) ));
      }

      element_t public_key;
      element_init_G1(public_key, TEDataSingleton::getData().pairing_);
      element_set0(public_key);

      for ( size_t i = 0; i < num_all; i++){

          element_t temp;
          element_init_G1(temp, TEDataSingleton::getData().pairing_);
          element_set(temp, public_shares_all.at(i).at(0).el_);

          element_t value;
          element_init_G1(value, TEDataSingleton::getData().pairing_);
          element_add(value, public_key, temp );

          element_clear(temp);
          element_clear(public_key);
          element_init_G1(public_key, TEDataSingleton::getData().pairing_);

          element_set( public_key, value);

          element_clear(value);
      }

      TEPublicKey common_public(encryption::element_wrapper(public_key), num_signed, num_all);
      element_clear(public_key);

      element_t secret_key;
      element_init_G1(secret_key, TEDataSingleton::getData().pairing_);
      element_set0(secret_key);

      for ( size_t i = 0; i < num_all; i++){

        element_t temp;
        element_init_Zr(temp, TEDataSingleton::getData().pairing_);
        element_set(temp, dkgs.at(i).getValueAt0().el_);

        element_t value;
        element_init_G1(value, TEDataSingleton::getData().pairing_);
        element_add(value, secret_key, temp );

        element_clear(temp);
        element_clear(secret_key);
        element_init_G1(secret_key, TEDataSingleton::getData().pairing_);

        element_set( secret_key, value);

        element_clear(value);
      }
      element_t test_pkey;
      element_init_G1(test_pkey, TEDataSingleton::getData().pairing_);
      element_mul_zn(test_pkey, TEDataSingleton::getData().generator_, secret_key);
      element_clear(secret_key);

      BOOST_REQUIRE( element_cmp(public_key, test_pkey) == 0);




      std::string message;
      /*size_t msg_length = 64;
      for (size_t length = 0; length < msg_length; ++length) {
        message += char(rand_gen() % 128);
      }*/
      message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!";

      std::shared_ptr msg_ptr = std::make_shared<std::string>(message);
      encryption::Ciphertext cypher = common_public.encrypt(msg_ptr);

     /* for (size_t i = 0; i < num_all - num_signed; ++i) {
        size_t ind4del = rand_gen() % secret_shares_all.size();
        auto pos4del = secret_shares_all.begin();
        advance(pos4del, ind4del);
        secret_shares_all.erase(pos4del);
        auto pos2 = public_shares_all.begin();
        advance(pos2, ind4del);
        public_shares_all.erase(pos2);
      }*/

      TEDecryptSet decr_set(num_signed, num_all);
      for (size_t i = 0; i < num_signed; i++){
        encryption::element_wrapper decrypt = skeys[i].decrypt(cypher);
        BOOST_REQUIRE(pkeys[i].Verify(cypher, decrypt.el_));
        std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
        decr_set.addDecrypt(skeys[i].getSignerIndex(), decr_ptr);
      }

      std::string message_decrypted = decr_set.merge(cypher);
      std::cerr << "MESSAGE: " << message << std::endl;
      std::cerr << "MESSAGE DECRYPTED: " << message_decrypted << std::endl;
      BOOST_REQUIRE(message == message_decrypted);
}


BOOST_AUTO_TEST_SUITE_END()
