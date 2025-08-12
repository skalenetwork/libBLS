#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include "tools/utils.h"

namespace libBLS {
namespace algebra {

std::pair< FqElement, FqElement > parseHint( const std::string& _hint ) {
    auto position = _hint.find( ":" );

    if ( position == std::string::npos || position > BLS_MAX_COMPONENT_LEN ||
         _hint.length() - position - 1 > BLS_MAX_COMPONENT_LEN ) {
        throw ThresholdUtils::IncorrectInput( "Misformatted hint" );
    }

    libff::alt_bn128_Fq y( _hint.substr( 0, position ).c_str() );
    libff::alt_bn128_Fq shift_x( _hint.substr( position + 1 ).c_str() );

    return std::make_pair( FqElement( y ), FqElement( shift_x ) );
}

std::pair< algebra::G1Point, std::string > hashtoG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr ) {
    libff::alt_bn128_G1 point;
    libff::alt_bn128_Fq counter = libff::alt_bn128_Fq::zero();
    libff::alt_bn128_Fq x1( algebra::FqElement::fromHash( hash_byte_arr ).value );

    while ( true ) {
        // y^2 = x^3 + b
        libff::alt_bn128_Fq y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

        libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

        if ( euler == libff::alt_bn128_Fq::one() ||
             euler == libff::alt_bn128_Fq::zero() ) {  // if y1_sqr is a square
            point.X = x1;
            libff::alt_bn128_Fq temp_y = y1_sqr.sqrt();

            mpz_class y, y_neg;
            temp_y.as_bigint().to_mpz( y.get_mpz_t() );
            // get -y in Fq first, then convert to mpz
            ( -temp_y ).as_bigint().to_mpz( y_neg.get_mpz_t() );

            if ( y < y_neg ) {
                temp_y = -temp_y;
            }

            point.Y = temp_y;
            break;
        } else {
            counter = counter + libff::alt_bn128_Fq::one();
            x1 = x1 + libff::alt_bn128_Fq::one();
        }
    }
    point.Z = libff::alt_bn128_Fq::one();

    FqElement counter_fq( counter );
    G1Point g1_point( point );
    return std::make_pair( g1_point, counter_fq.toString( Base::DEC ) );
}

}  // namespace algebra
}  // namespace libBLS
