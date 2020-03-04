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

  @file dkg_te.h
  @author Oleh Nikolaiev
  @date 2019
 */

#pragma once

#include <TEDataSingleton.h>
#include <threshold_encryption.h>

namespace encryption {

class DkgTe {
public:
    DkgTe( const size_t t, const size_t n );

    std::vector< element_wrapper > GeneratePolynomial();

    std::vector< element_wrapper > CreateVerificationVector(
        const std::vector< element_wrapper >& polynomial );

    element_wrapper ComputePolynomialValue(
        const std::vector< element_wrapper >& polynomial, const element_wrapper& point );

    std::vector< element_wrapper > CreateSecretKeyContribution(
        const std::vector< element_wrapper >& polynomial );

    element_wrapper CreateSecretKeyShare(
        const std::vector< element_wrapper >& secret_key_contribution );

    bool Verify( size_t idx, const element_wrapper& share,
        const std::vector< element_wrapper >& verification_vector );

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace encryption
