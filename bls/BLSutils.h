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

@file BLSUtils.h
@author Sveta Rogova
@date 2019
*/

#include <array>
#include <memory>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

class BLSutils {
public:
    template < class T >
    static std::string ConvertToString( const T& field_elem );
    static std::pair< libff::alt_bn128_Fq, libff::alt_bn128_Fq > ParseHint( std::string& );
    static libff::alt_bn128_Fq HashToFq( std::shared_ptr< std::array< uint8_t, 32 > > );
    static std::shared_ptr< std::vector< std::string > > SplitString(
        const std::shared_ptr< std::string >, const std::string& delim );
    static void initBLS();


    static std::atomic< bool > is_initialized;
};

template < class T >
std::string BLSutils::ConvertToString( const T& field_elem ) {
    mpz_t t;
    mpz_init( t );

    field_elem.as_bigint().to_mpz( t );

    char arr[mpz_sizeinbase( t, 10 ) + 2];

    char* tmp = mpz_get_str( arr, 10, t );
    mpz_clear( t );

    std::string output = tmp;

    return output;
}
