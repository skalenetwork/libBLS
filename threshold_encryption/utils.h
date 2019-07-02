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

  @file utils.h
  @author Oleh Nikolaiev
  @date 2019
 */

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <utility>

class G2;

libff::alt_bn128_Fq CurveEquation(const libff::alt_bn128_Fq& field_elem);

bool IsQuadraticResidue(const libff::alt_bn128_Fq& field_elem);

libff::alt_bn128_Fq SquareRoot(const libff::alt_bn128_Fq& field_elem);
