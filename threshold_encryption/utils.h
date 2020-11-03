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

#pragma once

#include <threshold_encryption.h>
#include <libff/algebra/fields/fp.hpp>

const mp_size_t bitcount = 512;
const mp_size_t num_limbs = ( bitcount + GMP_NUMB_BITS - 1 ) / GMP_NUMB_BITS;

extern libff::bigint< num_limbs > modulus;

using type_a_Fq = libff::Fp_model< num_limbs, modulus >;

void MpzSquareRoot( mpz_t ret_val, mpz_t x );

std::string ElementZrToString( element_t el );

std::shared_ptr< std::vector< std::string > > ElementG1ToString( element_t& el );

bool isStringNumber( std::string& str );

bool isG1Element0( element_t& el );

void checkCypher( const encryption::Ciphertext& cypher );
