/*
  Copyright (C) 2021- SKALE Labs

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

  @file utils.h
  @author Oleh Nikolaiev
  @date 2021
*/

#ifndef LIBBLS_UTILS_H
#define LIBBLS_UTILS_H

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

template < class T >
std::string fieldElementToString( const T& field_elem );

std::vector< std::string > G2ToString( libff::alt_bn128_G2 elem );

std::vector< libff::alt_bn128_Fr > LagrangeCoeffs( const std::vector< int >& idx, size_t t );

libff::alt_bn128_Fq HashToFq( std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr);

libff::alt_bn128_G1 HashtoG1( std::shared_ptr< std::array< uint8_t, 32 > > hash_byte_arr);

#endif // LIBBLS_UTILS_H
