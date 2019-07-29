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

  @file bls.h
  @author Oleh Nikolaiev
  @date 2018
*/


#pragma once

#include <third_party/cryptlite/sha256.h>

#include <string>
#include <vector>
#include <utility>
#include <memory>
#include <iostream>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

static constexpr size_t BLS_MAX_COMPONENT_LEN = 80;

static constexpr size_t BLS_MAX_SIG_LEN = 240;


namespace signatures {

class Bls {
 public:
    Bls(const size_t t, const size_t n);

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> KeyGeneration();

    libff::alt_bn128_G1 Hashing(const std::string& message,
                                  std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

    libff::alt_bn128_G1 HashBytes(const char* raw_bytes, size_t length,
                                  std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

    libff::alt_bn128_G1 HashtoG1(std::shared_ptr< std::array< uint8_t, 32>>);

    std::pair<libff::alt_bn128_G1, std::string> HashtoG1withHint(std::shared_ptr< std::array< uint8_t, 32>>);

    libff::alt_bn128_G1 Signing(const libff::alt_bn128_G1 hash,
                                  const libff::alt_bn128_Fr secret_key);

    bool Verification(const std::string& to_be_hashed, const libff::alt_bn128_G1 sign,
                        const libff::alt_bn128_G2 public_key);

    bool Verification(std::shared_ptr<std::array< uint8_t, 32>>, const libff::alt_bn128_G1 sign,
                      const libff::alt_bn128_G2 public_key);

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> KeysRecover(
                                                  const std::vector<libff::alt_bn128_Fr>& coeffs,
                                                  const std::vector<libff::alt_bn128_Fr>& shares);

    libff::alt_bn128_G1 SignatureRecover(const std::vector<libff::alt_bn128_G1>& shares,
                                          const std::vector<libff::alt_bn128_Fr>& coeffs);

    std::vector<libff::alt_bn128_Fr> LagrangeCoeffs(const std::vector<size_t>& idx);

 private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace signatures
