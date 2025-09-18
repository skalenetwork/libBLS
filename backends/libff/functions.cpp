#ifdef LIBFF

#include "backends/interface/functions.hpp"
#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include "tools/utils.h"
#include <gmpxx.h>

namespace libBLS::algebra {

GTElement pairing( const G1Point& g1, const G2Point& g2 ) {
    return libff::alt_bn128_ate_reduced_pairing( g1.asBackendType(), g2.asBackendType() );
}

FrScalar power( const FrScalar& fr, size_t exponent ) {
    return libff::power( fr.asBackendType(), exponent );
}

FqElement power( const FqElement& fq, const std::string& exponent ) {
    return fq.asBackendType() ^ libff::bigint< libff::alt_bn128_q_limbs >( exponent.c_str() );
}

void normalizeYCoordinate( FqElement& element ) {
    mpz_class y, y_neg;
    element.asBackendType().as_bigint().to_mpz( y.get_mpz_t() );
    // get -y in Fq first, then convert to mpz
    ( -element.asBackendType() ).as_bigint().to_mpz( y_neg.get_mpz_t() );

    if ( y < y_neg ) {
        element.asBackendType() = -element.asBackendType();
    }
}

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr ) {
    libff::bigint< libff::alt_bn128_q_limbs > from_hex;

    std::vector< uint8_t > hex( 2 * HASH_SIZE );
    for ( size_t i = 0; i < HASH_SIZE; ++i ) {
        hex.at(2 * i) = static_cast< int >( hash_byte_arr.at( i ) ) / 16;
        hex.at(2 * i + 1) = static_cast< int >( hash_byte_arr.at( i ) ) % 16;
    }
    mpn_set_str( from_hex.data, hex.data(), 2 * HASH_SIZE, 16 );

    libff::alt_bn128_Fq ret_val( from_hex );

    return algebra::FqElement( ret_val );
}

bool verifyPairingEq(
    const G1Point& g1P1, const G2Point& g2P1, const G1Point& g1P2, const G2Point& g2P2 ) {
    return algebra::pairing( g1P1, g2P1 ) == algebra::pairing( g1P2, g2P2 );
}

std::vector< bool > verifyPairingEqBatch( const PairingEqualityBatch& batch ) {
    throw ThresholdUtils::IsNotWellFormed( "Batch pairing not implemented for libff backend" );
}

G2Point lagrangeInterpolateAt0( const std::vector< size_t >& idx, size_t t,
    const std::vector< std::reference_wrapper< const G2Point > >& shares ) {
    std::vector< algebra::FrScalar > lagrange_coeffs = algebra::lagrangeCoeffs( idx, t );

    G2BackendType sum = G2Point::identity().asBackendType();

    for ( size_t i = 0; i < t; ++i ) {
        G2BackendType n = lagrange_coeffs.at(i).asBackendType() * shares.at(i).get().asBackendType();
        sum = sum + n;
    }

    return sum;
}

}  // namespace libBLS::algebra

#endif  // LIBFF