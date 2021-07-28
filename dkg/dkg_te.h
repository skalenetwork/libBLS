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

  @file dkg_te.h
  @author Oleh Nikolaiev
  @date 2019
 */

#pragma once

#include <threshold_encryption.h>

namespace encryption {

class DkgTe {
public:
    DkgTe( const size_t t, const size_t n );

    std::vector< libff::alt_bn128_Fr > GeneratePolynomial();

    std::vector< libff::alt_bn128_G2 > CreateVerificationVector(
        const std::vector< libff::alt_bn128_Fr >& polynomial );

    libff::alt_bn128_Fr ComputePolynomialValue(
        const std::vector< libff::alt_bn128_Fr >& polynomial, const libff::alt_bn128_Fr& point );

    std::vector< libff::alt_bn128_Fr > CreateSecretKeyContribution(
        const std::vector< libff::alt_bn128_Fr >& polynomial );

    libff::alt_bn128_Fr CreateSecretKeyShare(
        const std::vector< libff::alt_bn128_Fr >& secret_key_contribution );

    bool Verify( size_t idx, const libff::alt_bn128_Fr& share,
        const std::vector< libff::alt_bn128_G2 >& verification_vector );

    static bool isG2( const libff::alt_bn128_G2& point );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace encryption
