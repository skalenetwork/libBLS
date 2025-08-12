#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include "tools/utils.h"

namespace libBLS {
namespace algebra {

inline GTElement pairing( const G1Point& g1, const G2Point& g2 ) {
    return libff::alt_bn128_ate_reduced_pairing( g1.value, g2.value );
}

inline FrScalar power( const FrScalar& fr, int exponent ) {
    return libff::power( fr.value, exponent );
}

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t ) {
    if ( idx.size() < t ) {
        throw ThresholdUtils::IncorrectInput( "not enough participants in the threshold group" );
    }

    std::vector< libff::alt_bn128_Fr > res( t );

    libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

    for ( size_t i = 0; i < t; ++i ) {
        w *= libff::alt_bn128_Fr( idx[i] );
    }

    for ( size_t i = 0; i < t; ++i ) {
        libff::alt_bn128_Fr v = libff::alt_bn128_Fr( idx[i] );

        for ( size_t j = 0; j < t; ++j ) {
            if ( j != i ) {
                if ( libff::alt_bn128_Fr( idx[i] ) == libff::alt_bn128_Fr( idx[j] ) ) {
                    throw ThresholdUtils::IncorrectInput(
                        "during the interpolation, have same indexes in list of indexes" );
                }

                v *= ( libff::alt_bn128_Fr( idx[j] ) -
                       libff::alt_bn128_Fr( idx[i] ) );  // calculating Lagrange coefficients
            }
        }

        res[i] = w * v.invert();
    }

    std::vector< FrScalar > output;
    output.reserve( t );

    for ( size_t i = 0; i < t; ++i ) {
        output.push_back( FrScalar( res[i] ) );
    }

    return output;
}

}  // namespace algebra
}  // namespace libBLS
