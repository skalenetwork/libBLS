#ifdef MCL

#include "backends/interface/functions.hpp"

namespace libBLS::algebra {

GTElement pairing( const G1Point& g1, const G2Point& g2 ) {
    GTBackendType res;
    mcl::bn::pairing( res, g1.value, g2.value );
    return GTElement( res );
}

FrScalar power( const FrScalar& fr, size_t exponent ) {
    FrBackendType res;
    mcl::Fr::pow( res, fr.value, exponent );
    return FrScalar( res );
}

FqElement power( const FqElement& fq, const std::string& exponent ) {
#ifdef MCL_USE_GMP
    mpz_class e;
    e.set_str( exponent, 10 );
#else  // emscripten
    mcl::Vint e;
    e.setStr( exponent, 10 );
#endif

    FqBackendType out;
    mcl::Fp::pow( out, fq.value, e );
    return FqElement( out );
}

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr ) {
    FqBackendType x;
    x.setBigEndianMod( hash_byte_arr.data(), hash_byte_arr.size() );
    return FqElement( x );
}

void normalizeYCoordinate( FqElement& element ) {
#ifdef MCL_USE_GMP
    mpz_class y, y_neg;
#else  // emscripten
    mcl::Vint y, y_neg;
#endif

    element.value.getMpz( y );
    mcl::bn::Fp neg;
    mcl::bn::Fp::neg( neg, element.value );
    neg.getMpz( y_neg );

    if ( y < y_neg ) {
        mcl::bn::Fp::neg( element.value, element.value );
    }
}

}  // namespace libBLS::algebra

#endif  // MCL