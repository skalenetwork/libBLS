#ifdef LIBFF

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include "tools/utils.h"
#include <gmpxx.h>

namespace libBLS::algebra {

GTElement pairing( const G1Point& g1, const G2Point& g2 ) {
    return libff::alt_bn128_ate_reduced_pairing( g1.value, g2.value );
}

FrScalar power( const FrScalar& fr, size_t exponent ) {
    return libff::power( fr.value, exponent );
}

FqElement power( const FqElement& fq, const std::string& exponent ) {
    return fq.value ^ libff::bigint< libff::alt_bn128_q_limbs >( exponent.c_str() );
}

void normalizeYCoordinate( FqElement& element ) {
    mpz_class y, y_neg;
    element.value.as_bigint().to_mpz( y.get_mpz_t() );
    // get -y in Fq first, then convert to mpz
    ( -element.value ).as_bigint().to_mpz( y_neg.get_mpz_t() );

    if ( y < y_neg ) {
        element.value = -element.value;
    }
}

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr ) {
    libff::bigint< libff::alt_bn128_q_limbs > from_hex;

    std::vector< uint8_t > hex( 2 * HASH_SIZE );
    for ( size_t i = 0; i < HASH_SIZE; ++i ) {
        hex[2 * i] = static_cast< int >( hash_byte_arr.at( i ) ) / 16;
        hex[2 * i + 1] = static_cast< int >( hash_byte_arr.at( i ) ) % 16;
    }
    mpn_set_str( from_hex.data, hex.data(), 2 * HASH_SIZE, 16 );

    libff::alt_bn128_Fq ret_val( from_hex );

    return algebra::FqElement( ret_val );
}

}  // namespace libBLS::algebra

#endif  // LIBFF