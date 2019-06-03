/*
    Copyright (C) 2018-2019 SKALE Labs

    This file is part of libBLS.

    libBLS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libBLS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libBLS. If not, see <https://www.gnu.org/licenses/>.

    @file unit_tests_te.cpp
    @author Oleh Nikolaiev
    @date 2019
 */


#include <threshold_encryption.h>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

static char *aparam =
      "type a\n"
      "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
      "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
      "r 730750818665451621361119245571504901405976559617\n"
      "exp2 159\n"
      "exp1 107\n"
      "sign1 1\n"
      "sign0 1\n";

BOOST_AUTO_TEST_SUITE(ThresholdEncryption)

BOOST_AUTO_TEST_CASE(PairingBillinearity) {
  pairing_t pairing;

  pairing_init_set_str(pairing, aparam);

  element_t g, h;
  element_t public_key, secret_key;
  element_t sig;
  element_t temp1, temp2;

  element_init_Zr(secret_key, pairing);
  element_init_G1(h, pairing);
  element_init_G1(sig, pairing);
  element_init_G1(g, pairing);
  element_init_G1(public_key, pairing);
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);

  element_random(g);
  element_random(secret_key);
  element_pow_zn(public_key, g, secret_key);

  char* message = "abcdef";
  element_from_hash(h, message, 6);

  element_pow_zn(sig, h, secret_key);

  pairing_apply(temp1, sig, g, pairing);
  pairing_apply(temp2, h, public_key, pairing);

  BOOST_REQUIRE(!element_cmp(temp1, temp2));
}

BOOST_AUTO_TEST_CASE(SimpleEncryption) {
  encryption::TE te_instance = encryption::TE(1, 1);

  std::string message = "Hello, SKALE users and fans, gl!Hello, SKALE users and fans, gl!"; // message should be 64 length 

  element_t secret_key;
  element_init_Zr(secret_key, te_instance.pairing_);
  element_random(secret_key);

  element_t g;
  element_init_G1(g, te_instance.pairing_);
  element_random(g);

  element_t public_key;
  element_init_G1(public_key, te_instance.pairing_);
  element_pow_zn(public_key, g, secret_key);

  auto ciphertext = te_instance.Encrypt(message, public_key);

  element_t decrypted;
  element_init_G1(decrypted, te_instance.pairing_);

  te_instance.Decrypt(decrypted, ciphertext, secret_key);

  te_instance.Verify(ciphertext, decrypted, public_key);

  std::vector<std::pair<element_s, size_t>> shares;
  shares.push_back(std::make_pair(decrypted[0], size_t(0)));

  std::string res = te_instance.CombineShares(ciphertext, shares);

  element_clear(secret_key);
  element_clear(public_key);
  element_clear(g);
  element_clear(decrypted);
  
  BOOST_REQUIRE(res == message);
  std::cout << "OK\n";
}

BOOST_AUTO_TEST_SUITE_END()
