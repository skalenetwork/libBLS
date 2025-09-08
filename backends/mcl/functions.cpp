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

bool verifyPairingEq(
    const G1Point& g1P1, const G2Point& g2P1, const G1Point& g1P2, const G2Point& g2P2 ) {
    // compute pairing equality for each element in the vector
    mcl::Fp12 f1, f2;

    // Two Miller loops (no final exponentiation yet)
    mcl::millerLoop( f1, g1P1.value, g2P1.value );  // f1 = ML(g1P1, g2P1)
    G1BackendType g1P2Negatted = g1P2.value;
    G1BackendType::neg( g1P2Negatted, g1P2.value );   // -g1P2
    mcl::millerLoop( f2, g1P2Negatted, g2P2.value );  // f2 = ML(-g1P2, g2P2)

    // Combine, then a single final exponentiation
    f1 *= f2;                 // f1 = ML(g1P1,g2P1) * ML(-g1P2,g2P2)
    mcl::finalExp( f1, f1 );  // f1 = FE( ... )

    return f1.isOne();  // product == 1 ?
}

std::vector< bool > verifyPairingEqBatch( const PairingEqualityBatch& batch ) {
    // negate g1P2 only once
    G1BackendType g1P2Negatted = batch.commonG1P2.get().value;
    G1BackendType::neg( g1P2Negatted, batch.commonG1P2.get().value );  // -g1P2

    std::vector< bool > isValidVec( batch.size, true );

    // Multiplies all miller loops together, and then final single exponentiation
    // If the result is 1, then all pairings must be valid.
    // Else, there is at least 1 element that is not valid.
    const auto optimisticValidation = [&]() {
        std::vector< G1BackendType > g1Points;
        std::vector< G2BackendType > g2Points;

        for ( size_t i = 0; i < batch.size; ++i ) {
            g1Points.push_back( batch.commonG1P1.get().value );
            g1Points.push_back( g1P2Negatted );  // use negated point
            g2Points.push_back( batch.g2P1s[i].get().value );
            g2Points.push_back( batch.g2P2s[i].get().value );
        }

        mcl::Fp12 f;
        mcl::millerLoopVec( f, g1Points.data(), g2Points.data(), g1Points.size() );
        mcl::finalExp( f, f );  // f1 = FE( ... )
        return f.isOne();       // product == 1 ?
    };

    // Do each pairing equality individually, and identify which ones are invalid
    const auto pessimisticValidation = [&]() {
        for ( size_t i = 0; i < batch.size; ++i ) {
            const algebra::G2Point& currentG2P1 = batch.g2P1s[i].get();
            const algebra::G2Point& currentG2P2 = batch.g2P2s[i].get();

            // compute pairing equality for each element in the vector
            mcl::Fp12 f1, f2;

            // Two Miller loops (no final exponentiation yet)
            mcl::millerLoop(
                f1, batch.commonG1P1.get().value, currentG2P1.value );  // f1 = ML(g1P1, g2P1)
            mcl::millerLoop( f2, g1P2Negatted, currentG2P2.value );     // f2 = ML(-g1P2, g2P2)

            // Combine, then a single final exponentiation
            f1 *= f2;                 // f1 = ML(g1P1,g2P1) * ML(-g1P2,g2P2)
            mcl::finalExp( f1, f1 );  // f1 = FE( ... )

            isValidVec[i] = f1.isOne();  // product == 1 ?
        }
    };

    // If optimistic validation is ON and passes -> return all true (current vector)
    // Else, set false for all invalid and return
    if ( !batch.optimisticValidation || !optimisticValidation() ) {
        pessimisticValidation();
    }

    return isValidVec;
}

}  // namespace libBLS::algebra

#endif  // MCL