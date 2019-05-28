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

BOOST_AUTO_TEST_SUITE(ThresholdEncryption)

BOOST_AUTO_TEST_CASE(Pairing) {
  encryption::TE test_instance = encryption::TE(1, 2);

  element_t g, h;
  element_t public_key, secret_key;
  element_t sig;
  element_t temp1, temp2;

  element_init_Zr(secret_key, test_instance.pairing_);
  element_init_G1(h, test_instance.pairing_);
  element_init_G1(sig, test_instance.pairing_);
  element_init_G2(g, test_instance.pairing_);
  element_init_G2(public_key, test_instance.pairing_);
  element_init_GT(temp1, test_instance.pairing_);
  element_init_GT(temp2, test_instance.pairing_);

  element_random(g);
  element_random(secret_key);
  element_pow_zn(public_key, g, secret_key);

  char* message = "abcdef";
  element_from_hash(h, message, 6);

  element_pow_zn(sig, h, secret_key);

  pairing_apply(temp1, sig, g, test_instance.pairing_);
  pairing_apply(temp2, h, public_key, test_instance.pairing_);

  BOOST_REQUIRE(!element_cmp(temp1, temp2));
}

BOOST_AUTO_TEST_SUITE_END()
