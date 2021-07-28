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

@file dkg_te.cpp
@author Oleh Nikolaiev
@date 2019
*/

#include <dkg/dkg_te.h>

#include <iostream>

namespace encryption {

typedef std::vector< libff::alt_bn128_Fr > Polynomial;

DkgTe::DkgTe( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    libff::init_alt_bn128_params();
}

Polynomial DkgTe::GeneratePolynomial() {
    Polynomial pol( this->t_ );

    for ( size_t i = 0; i < this->t_; ++i ) {
        libff::alt_bn128_Fr g = libff::alt_bn128_Fr::random_element();

        while ( i == this->t_ - 1 && g.is_zero() ) {
            g = libff::alt_bn128_Fr::random_element();
        }

        pol[i] = g;
    }

    return pol;
}

std::vector< libff::alt_bn128_G2 > DkgTe::CreateVerificationVector(
    const std::vector< libff::alt_bn128_Fr >& polynomial ) {
    std::vector< libff::alt_bn128_G2 > verification_vector( this->t_ );

    for ( size_t i = 0; i < this->t_; ++i ) {
        verification_vector[i] = polynomial[i] * libff::alt_bn128_G2::one();
    }

    return verification_vector;
}

libff::alt_bn128_Fr DkgTe::ComputePolynomialValue(
    const std::vector< libff::alt_bn128_Fr >& polynomial, const libff::alt_bn128_Fr& point ) {
    libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

    libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( i == this->t_ - 1 && polynomial[i] == libff::alt_bn128_Fr::zero() ) {
            throw std::logic_error( "Error, incorrect degree of a polynomial" );
        }
        value += polynomial[i] * pow;
        pow *= point;
    }

    return value;
}

std::vector< libff::alt_bn128_Fr > DkgTe::CreateSecretKeyContribution(
    const std::vector< libff::alt_bn128_Fr >& polynomial ) {
    std::vector< libff::alt_bn128_Fr > secret_key_contribution( this->n_ );
    for ( size_t i = 0; i < this->n_; ++i ) {
        libff::alt_bn128_Fr point = i + 1;

        secret_key_contribution[i] = ComputePolynomialValue( polynomial, point );
    }

    return secret_key_contribution;
}

libff::alt_bn128_Fr DkgTe::CreateSecretKeyShare(
    const std::vector< libff::alt_bn128_Fr >& secret_key_contribution ) {
    libff::alt_bn128_Fr secret_key_share = libff::alt_bn128_Fr::zero();

    for ( size_t i = 0; i < this->n_; ++i ) {
        secret_key_share += secret_key_contribution[i];
    }

    if ( secret_key_share.is_zero() ) {
        throw std::runtime_error( "Error, at least one secret key share is equal to zero" );
    }

    return secret_key_share;
}

bool DkgTe::Verify( size_t idx, const libff::alt_bn128_Fr& share,
    const std::vector< libff::alt_bn128_G2 >& verification_vector ) {
    libff::alt_bn128_G2 value = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( !this->isG2( verification_vector[i] ) ) {
            return false;
        }
        value = value + power( libff::alt_bn128_Fr( idx + 1 ), i ) * verification_vector[i];
    }

    return ( value == share * libff::alt_bn128_G2::one() );
}

bool DkgTe::isG2( const libff::alt_bn128_G2& point ) {
    return point.is_well_formed() &&
           libff::alt_bn128_G2::order() * point == libff::alt_bn128_G2::zero();
}

}  // namespace encryption
