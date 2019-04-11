/**
 * @license
 * SKALE libBLS
 * Copyright (C) 2019-Present SKALE Labs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file dkg.h
 * @date 2019
 */


#pragma once

#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp.hpp>

namespace signatures {

class Dkg {
 public:
    Dkg(const size_t t, const size_t n);

    std::vector<libff::alt_bn128_Fr> GeneratePolynomial();

    std::vector<libff::alt_bn128_G2> VerificationVector(
                                              const std::vector<libff::alt_bn128_Fr>& polynomial);

    libff::alt_bn128_Fr PolynomialValue(const std::vector<libff::alt_bn128_Fr>& pol,
                                                                        libff::alt_bn128_Fr point);

    std::vector<libff::alt_bn128_Fr> SecretKeyContribution(
                                              const std::vector<libff::alt_bn128_Fr>& polynomial);

    libff::alt_bn128_Fr SecretKeyShareCreate(
                                  const std::vector<libff::alt_bn128_Fr>& secret_key_contribution);

    bool Verification(size_t idx, libff::alt_bn128_Fr share,
                        const std::vector<libff::alt_bn128_G2>& verification_vector);

 private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace signatures
