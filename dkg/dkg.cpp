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

  @file dkg.cpp
  @author Oleh Nikolaiev
  @date 2018
*/

#include <dkg/dkg.h>
#include <tools/utils.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>

namespace signatures {

typedef std::vector< libff::alt_bn128_Fr > Polynomial;

Dkg::Dkg( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    ThresholdUtils::initCurve();
}

Polynomial Dkg::GeneratePolynomial() {
    // generate polynomial of degree t for each node that takes part in DKG
    Polynomial pol( this->t_ );

    for ( size_t i = 0; i < this->t_; ++i ) {
        pol[i] = libff::alt_bn128_Fr::random_element();

        while ( i == this->t_ - 1 && pol[i] == libff::alt_bn128_Fr::zero() ) {
            pol[i] = libff::alt_bn128_Fr::random_element();
        }
    }

    return pol;
}

std::vector< libff::alt_bn128_G2 > Dkg::VerificationVector(
    const std::vector< libff::alt_bn128_Fr >& polynomial ) {
    // vector of public values that each node will broadcast
    std::vector< libff::alt_bn128_G2 > verification_vector( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        verification_vector[i] = polynomial[i] * libff::alt_bn128_G2::one();
    }

    return verification_vector;
}

libff::alt_bn128_Fr Dkg::PolynomialValue( const Polynomial& pol, libff::alt_bn128_Fr point ) {
    // calculate value of polynomial in a random integer point
    libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

    libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( i == this->t_ - 1 && pol[i] == libff::alt_bn128_Fr::zero() ) {
            throw std::logic_error( "Error, incorrect degree of a polynomial" );
        }
        value += pol[i] * pow;
        pow *= point;
    }

    return value;
}

std::vector< libff::alt_bn128_Fr > Dkg::SecretKeyContribution(
    const std::vector< libff::alt_bn128_Fr >& polynomial ) {
    // calculate for each node a list of secret values that will be used for verification
    std::vector< libff::alt_bn128_Fr > secret_key_contribution( this->n_ );
    for ( size_t i = 0; i < this->n_; ++i ) {
        secret_key_contribution[i] = PolynomialValue( polynomial, libff::alt_bn128_Fr( i + 1 ) );
    }

    return secret_key_contribution;
}

libff::alt_bn128_Fr Dkg::SecretKeyShareCreate(
    const std::vector< libff::alt_bn128_Fr >& secret_key_contribution ) {
    // create secret key share from secret key contribution
    libff::alt_bn128_Fr secret_key_share = libff::alt_bn128_Fr::zero();

    for ( size_t i = 0; i < this->n_; ++i ) {
        secret_key_share = secret_key_share + secret_key_contribution[i];
    }

    if ( secret_key_share == libff::alt_bn128_Fr::zero() ) {
        throw std::logic_error( "Error, at least one secret key share is equal to zero" );
    }

    return secret_key_share;
}

bool Dkg::Verification( size_t idx, libff::alt_bn128_Fr share,
    const std::vector< libff::alt_bn128_G2 >& verification_vector ) {
    // idx-th node verifies that share corresponds to the verification vector
    libff::alt_bn128_G2 value = libff::alt_bn128_G2::zero();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( !this->isG2( verification_vector[i] ) ) {
            return false;
        }
        value = value + power( libff::alt_bn128_Fr( idx + 1 ), i ) * verification_vector[i];
    }

    return ( value == share * libff::alt_bn128_G2::one() );
}

libff::alt_bn128_G2 Dkg::GetPublicKeyFromSecretKey( const libff::alt_bn128_Fr& secret_key ) {
    libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();
    public_key.to_affine_coordinates();

    return public_key;
}

size_t Dkg::GetT() const {
    return this->t_;
}

size_t Dkg::GetN() const {
    return this->n_;
}

bool Dkg::isG2( const libff::alt_bn128_G2& point ) {
    return point.is_well_formed() &&
           libff::alt_bn128_G2::order() * point == libff::alt_bn128_G2::zero();
}

}  // namespace signatures
