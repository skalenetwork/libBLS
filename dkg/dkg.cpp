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

namespace libBLS {

typedef std::vector< algebra::FrScalar > Polynomial;

Dkg::Dkg( const size_t t, const size_t n ) : t_( t ), n_( n ) {
    ThresholdUtils::initCurve();
}

Polynomial Dkg::GeneratePolynomial() {
    // generate polynomial of degree t for each node that takes part in DKG
    Polynomial pol( this->t_ );

    for ( size_t i = 0; i < this->t_; ++i ) {
        pol[i] = algebra::FrScalar::random();

        while ( i == this->t_ - 1 && pol[i] == algebra::FrScalar::zero() ) {
            pol[i] = algebra::FrScalar::random();
        }
    }

    return pol;
}

std::vector< algebra::G2Point > Dkg::VerificationVector(
    const std::vector< algebra::FrScalar >& polynomial ) {
    if ( polynomial.size() < t_ )
        throw ThresholdUtils::IncorrectInput( "Wrong polynomial degree: must be at least t" );
    // vector of public values that each node will broadcast
    std::vector< algebra::G2Point > verification_vector( this->t_ );
    for ( size_t i = 0; i < this->t_; ++i ) {
        verification_vector[i] = polynomial[i] * algebra::G2Point::one();
    }

    return verification_vector;
}

algebra::FrScalar Dkg::PolynomialValue( const Polynomial& pol, algebra::FrScalar point ) {
    if ( pol.size() < t_ )
        throw ThresholdUtils::IncorrectInput( "Wrong polynomial degree: must be at least t" );
    // calculate value of polynomial in a random integer point
    algebra::FrScalar value = algebra::FrScalar::zero();

    algebra::FrScalar pow = algebra::FrScalar::one();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( i == this->t_ - 1 && pol[i] == algebra::FrScalar::zero() ) {
            throw std::logic_error( "Error, incorrect degree of a polynomial" );
        }
        value += pol[i] * pow;
        pow *= point;
    }

    return value;
}

std::vector< algebra::FrScalar > Dkg::SecretKeyContribution(
    const std::vector< algebra::FrScalar >& polynomial ) {
    // calculate for each node a list of secret values that will be used for verification
    std::vector< algebra::FrScalar > secret_key_contribution( this->n_ );
    for ( size_t i = 0; i < this->n_; ++i ) {
        secret_key_contribution[i] = PolynomialValue( polynomial, algebra::FrScalar( i + 1 ) );
    }

    return secret_key_contribution;
}

algebra::FrScalar Dkg::SecretKeyShareCreate(
    const std::vector< algebra::FrScalar >& secret_key_contribution ) {
    if ( secret_key_contribution.size() < n_ )
        throw ThresholdUtils::IncorrectInput(
            "Secret key contribution must be at least of size n" );
    // create secret key share from secret key contribution
    algebra::FrScalar secret_key_share = algebra::FrScalar::zero();

    for ( size_t i = 0; i < this->n_; ++i ) {
        secret_key_share = secret_key_share + secret_key_contribution[i];
    }

    if ( secret_key_share == algebra::FrScalar::zero() ) {
        throw std::logic_error( "Error, at least one secret key share is equal to zero" );
    }

    return secret_key_share;
}

bool Dkg::Verification( size_t idx, algebra::FrScalar share,
    const std::vector< algebra::G2Point >& verification_vector ) {
    if ( verification_vector.size() < t_ )
        throw ThresholdUtils::IncorrectInput( "Verification vector must be at least of size n" );
    // idx-th node verifies that share corresponds to the verification vector
    algebra::G2Point value = algebra::G2Point::zero();
    for ( size_t i = 0; i < this->t_; ++i ) {
        if ( !ThresholdUtils::ValidateKey( verification_vector[i] ) ) {
            return false;
        }

        // TODO - can save the power value in a variable from prev. iteration to avoid recalculating it
        value = value + algebra::power( algebra::FrScalar( idx + 1 ), i ) * verification_vector[i];
    }

    return ( value == share * algebra::G2Point::one() );
}

algebra::G2Point Dkg::GetPublicKeyFromSecretKey( const algebra::FrScalar& secret_key ) {
    algebra::G2Point public_key = secret_key * algebra::G2Point::one();
    public_key.to_affine_coordinates();

    return public_key;
}

size_t Dkg::GetT() const {
    return this->t_;
}

size_t Dkg::GetN() const {
    return this->n_;
}

}  // namespace libBLS
