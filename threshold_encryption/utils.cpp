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
  type_a_Fq::Rsquared = libff::bigint<num_limbs>("7908377253245679686309230217487816474209105348333109471752408628253287194295204727324253215849716283310453246501640191319592635974636605685978512739837527");
  type_a_Fq::inv = 13978139192989384153;
  type_a_Fq::s = 1;
  type_a_Fq::t = libff::bigint<num_limbs>("4390355399831656261218890992377024907903441599707104105514326699633237815440111478539312589711331110711577929384791158729638856683658740662462564999112395");
  type_a_Fq::t_minus_1_over_2 = libff::bigint<num_limbs>("2195177699915828130609445496188512453951720799853552052757163349816618907720055739269656294855665555355788964692395579364819428341829370331231282499556197");
  type_a_Fq::nqr = type_a_Fq("11");
  type_a_Fq::nqr_to_t = type_a_Fq::nqr ^ type_a_Fq::t;

  libff::bigint<num_limbs> to_find_square_root = libff::bigint<num_limbs>("2195177699915828130609445496188512453951720799853552052757163349816618907720055739269656294855665555355788964692395579364819428341829370331231282499556198"); //type_a_Fq(libff::bigint<num_limbs>(x));

  libff::bigint<num_limbs> new_x = libff::bigint<num_limbs>(x);
  type_a_Fq base(new_x);
  type_a_Fq root = base ^ to_find_square_root;

  std::cerr << "BASE VALUE IS : " << type_a_Fq::nqr << '\n';
  std::cerr << "ROOT VALUE IS : " << root << '\n';

  root.as_bigint().to_mpz(ret_val);
}
