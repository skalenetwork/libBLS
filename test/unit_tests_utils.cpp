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
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file unit_tests_utils.cpp
  @author Oleh Nikolaiev
  @date 2021
*/

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>

#include <tools/utils.h>


#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE( TestLagrange )

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( TestAES )

BOOST_AUTO_TEST_CASE( SimpleAES ) {
    const std::string message = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const std::string key = "bbbbbbbbbbbbbbbb";

    auto ciphertext = crypto::ThresholdUtils::aesEncrypt( message, key );
    auto decrypted_text = crypto::ThresholdUtils::aesDecrypt( ciphertext, key );

    BOOST_REQUIRE( decrypted_text == message );
}

BOOST_AUTO_TEST_SUITE_END()
