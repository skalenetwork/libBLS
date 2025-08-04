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

  @file dkg.h
  @author Oleh Nikolaiev
  @date 2018
*/


#pragma once

#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp.hpp>

namespace libBLS {

class Dkg {
public:
    Dkg( const size_t t, const size_t n );

    std::vector< algebra::FrScalar > GeneratePolynomial();

    std::vector< algebra::G2Point > VerificationVector(
        const std::vector< algebra::FrScalar >& polynomial );

    algebra::FrScalar PolynomialValue(
        const std::vector< algebra::FrScalar >& pol, algebra::FrScalar point );

    std::vector< algebra::FrScalar > SecretKeyContribution(
        const std::vector< algebra::FrScalar >& polynomial );

    algebra::FrScalar SecretKeyShareCreate(
        const std::vector< algebra::FrScalar >& secret_key_contribution );

    bool Verification( size_t idx, algebra::FrScalar share,
        const std::vector< algebra::G2Point >& verification_vector );

    algebra::G2Point GetPublicKeyFromSecretKey( const algebra::FrScalar& secret_key );

    size_t GetT() const;

    size_t GetN() const;

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
