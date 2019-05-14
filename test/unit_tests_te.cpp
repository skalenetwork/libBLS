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


#include <bls/bls.h>
#include <threshold_encryption/utils.h>

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>

#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(ThresholdEncryption)

BOOST_AUTO_TEST_CASE(TE) {
  libff::init_alt_bn128_params();

  libff::alt_bn128_G2 P = libff::alt_bn128_G2::random_element();
  libff::alt_bn128_Fq x = libff::alt_bn128_Fq::random_element();
  libff::alt_bn128_Fq y = libff::alt_bn128_Fq::random_element();
  libff::alt_bn128_G2 Q = libff::alt_bn128_G2::random_element();

  BOOST_REQUIRE(WeilPairing(x * P, y * Q) == (WeilPairing(P, Q) ^ (x * y).as_bigint()));
}

BOOST_AUTO_TEST_SUITE_END()
