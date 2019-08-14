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


//#include <pbc/pbc_field.h>


libff::bigint<num_limbs> modulus = libff::bigint<num_limbs>("8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791");

void MpzSquareRoot(mpz_t ret_val, mpz_t x) {
  /*assert(type_a_Fq::modulus_is_valid());
  type_a_Fq::Rsquared = libff::bigint<num_limbs>("7908377253245679686309230217487816474209105348333109471752408628253287194295204727324253215849716283310453246501640191319592635974636605685978512739837527");
  type_a_Fq::Rcubed = libff::bigint<num_limbs>("7852932988661878723775242768845432675513004110346433075808894336018985633290560702487151366204515158699758717961115825050580193491630542543472251086224684");
  type_a_Fq::inv = 0xc1fC53896318fdd9;
  type_a_Fq::num_bits = 512;
  type_a_Fq::euler = libff::bigint<num_limbs>("4390355399831656261218890992377024907903441599707104105514326699633237815440111478539312589711331110711577929384791158729638856683658740662462564999112395");
  type_a_Fq::s = 1;
  type_a_Fq::t = libff::bigint<num_limbs>("4390355399831656261218890992377024907903441599707104105514326699633237815440111478539312589711331110711577929384791158729638856683658740662462564999112395");
  type_a_Fq::t_minus_1_over_2 = libff::bigint<num_limbs>("2195177699915828130609445496188512453951720799853552052757163349816618907720055739269656294855665555355788964692395579364819428341829370331231282499556197");
  type_a_Fq::multiplicative_generator = type_a_Fq("11");
  type_a_Fq::nqr = type_a_Fq("11");

  */libff::bigint<num_limbs> to_find_square_root = libff::bigint<num_limbs>("2195177699915828130609445496188512453951720799853552052757163349816618907720055739269656294855665555355788964692395579364819428341829370331231282499556198"); //type_a_Fq(libff::bigint<num_limbs>(x));

    /*libff::bigint<num_limbs> new_x = libff::bigint<num_limbs>(x);
    type_a_Fq base(new_x);*/
    //type_a_Fq root = base ^ to_find_square_root;

  mpz_t deg;
  mpz_init(deg);
  to_find_square_root.to_mpz(deg);

  mpz_t mode;
  mpz_init(mode);
  modulus.to_mpz(mode);

  mpz_powm(ret_val, x, deg, mode);

  mpz_clears(deg,mode,0);

  //assert(root * root == base);


  //std::cerr << "BASE VALUE IS : " << base << '\n';
  //std::cerr << "ROOT VALUE IS : " << root << '\n';

  //root.as_bigint().to_mpz(ret_val);
}

std::string ElementZrToString(element_t el ){
   std::string str = "1";
   if ( element_item_count(el)){
       str = "2";
   }
   else{
       mpz_t a;
       mpz_init(a);

       element_to_mpz(a, el);

       char arr[mpz_sizeinbase (a, 10) + 2];

       char * tmp = mpz_get_str(arr, 10, a);
       mpz_clear(a);

       str = tmp;
   }
   return str;
}

std::shared_ptr<std::vector<std::string>> ElementG1ToString(element_t el ){
    std::vector<std::string> res_str;

    for ( int i = 0;  i < element_item_count(el); i++){
        res_str.push_back(ElementZrToString(element_item(el,i)));
    }
    return std::make_shared<std::vector<std::string>>(res_str);
}