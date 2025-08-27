#ifdef LIBFF

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#include <gmpxx.h>
#include "backends/interface/test/FqElementTestAccessor.hpp"


namespace libBLS::algebra {

std::default_random_engine libBLS::algebra::FqElementTestAccessor::rand_gen(
    static_cast< unsigned int >( std::time( 0 ) ) );

FqBackendType FqElementTestAccessor::spoil( FqBackendType& elem ) {
    libff::alt_bn128_Fq elem_copy = elem;  // Create a copy to avoid modifying the original element
    do {
        size_t n_bad_bit = rand_gen() % ( elem_copy.size_in_bits() ) + 1;

        mpz_class was_coord;
        elem_copy.as_bigint().to_mpz( was_coord.get_mpz_t() );

        mpz_class mask;
        mpz_set_si( mask.get_mpz_t(), n_bad_bit );

        mpz_class badCoord;
        mpz_xor( badCoord.get_mpz_t(), was_coord.get_mpz_t(), mask.get_mpz_t() );

        elem_copy = libff::alt_bn128_Fq( badCoord.get_mpz_t() );
    } while ( elem_copy == libff::alt_bn128_Fq::zero() );

    return elem_copy;
}

}  // namespace libBLS::algebra

#endif // LIBFF