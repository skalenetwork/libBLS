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

  @file utils.cpp
  @author Oleh Nikolaiev
  @date 2019
*/

#include <threshold_encryption/utils.h>

libff::bigint<num_limbs> modulus = libff::bigint<num_limbs>("8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791");

void MpzSquareRoot(mpz_t ret_val, mpz_t x) {
  type_a_Fq::s = 1;
  type_a_Fq::t = libff::bigint<num_limbs>("4390355399831656261218890992377024907903441599707104105514326699633237815440111478539312589711331110711577929384791158729638856683658740662462564999112395");
  type_a_Fq::t_minus_1_over_2 = libff::bigint<num_limbs>("4390355399831656261218890992377024907903441599707104105514326699633237815440111478539312589711331110711577929384791158729638856683658740662462564999112394");
  type_a_Fq::nqr = long(11);
  type_a_Fq::nqr_to_t = type_a_Fq::nqr ^ type_a_Fq::t;

  type_a_Fq to_find_square_root = type_a_Fq(libff::bigint<num_limbs>(x));

  type_a_Fq root = type_a_Fq(libff::bigint<num_limbs>(x)).sqrt();

  root.as_bigint().to_mpz(ret_val);
}