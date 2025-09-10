#ifdef MCL

#include "backends/interface/functions.hpp"
#include <iostream>

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
    mcl::Fp12 f;

    G1BackendType g1P2Negatted = g1P2.value;
    G1BackendType::neg( g1P2Negatted, g1P2.value );  // -g1P2

    // Two Miller loops (no final exponentiation yet)
    std::array< G1BackendType, 2 > g1s = { g1P1.value, g1P2Negatted };
    std::array< G2BackendType, 2 > g2s = { g2P1.value, g2P2.value };
    mcl::millerLoopVec( f, g1s.data(), g2s.data(), 2 );  // f = ML(g1P1,g2P1) * ML(-g1P2,g2P2)

    // Combine, then a single final exponentiation
    mcl::finalExp( f, f );  // f1 = FE( ... )
    return f.isOne();       // product == 1 ?
}

std::vector< bool > verifyPairingEqBatch( const PairingEqualityBatch& batch ) {
    static thread_local FastRandFrScalar fastRndFr = [] {
        std::cout << "Fr size: " << sizeof( FrBackendType ) << " bytes\n";
        std::cout << "Fq size: " << sizeof( FqBackendType ) << " bytes\n";

        FastRandFrScalar r;
        std::array< uint8_t, 32 > key{};
        std::array< uint8_t, 12 > nonce{};
        if ( RAND_bytes( key.data(), key.size() ) != 1 )
            throw std::runtime_error( "RAND_bytes(key) failed" );
        if ( RAND_bytes( nonce.data(), nonce.size() ) != 1 )
            throw std::runtime_error( "RAND_bytes(nonce) failed" );
        r.seed( key.data(), nonce.data(), /*counter=*/0 );
        return r;  // constructed once per thread on first entry
    }();

    const size_t n = batch.size;

    std::vector< bool > isValidVec( n, true );

    // --- (allocated once per thread) ---
    static thread_local std::vector< FrBackendType > r_backend;
    static thread_local std::vector< G2BackendType > g2P1s;  // g2P1_i
    static thread_local std::vector< G2BackendType > g2P2s;  // g2P2_i

    // Reserve once (upper bound you expect)
    if ( r_backend.capacity() < 32 )
        r_backend.reserve( 32 );
    if ( g2P1s.capacity() < 32 )
        g2P1s.reserve( 32 );
    if ( g2P2s.capacity() < 32 )
        g2P2s.reserve( 32 );

    // clear
    r_backend.clear();
    r_backend.resize( n );
    g2P1s.clear();
    g2P1s.resize( n );
    g2P2s.clear();
    g2P2s.resize( n );

    const auto optimisticValidation = [&]() {
        // get random scalars r_i
        fastRndFr.nextFrVec( r_backend, n, /*nonZero=*/true );

        for ( size_t i = 0; i < batch.size; ++i ) {
            g2P1s[i] = batch.g2P1s[i].get().value;  // g2 for W
            g2P2s[i] = batch.g2P2s[i].get().value;  // g2 for H
        }

        // 3) MSM in G2 (Straus via mulVec)
        G2BackendType G2P1, G2P2;
        G2BackendType::mulVec( G2P1, g2P1s.data(), r_backend.data(),
            ( int ) g2P1s.size() );  // G2P1 = sum r_i * g2P1_i
        G2BackendType::mulVec( G2P2, g2P2s.data(), r_backend.data(),
            ( int ) g2P2s.size() );  // G2P2 = sum r_i * g2P2_i

        return verifyPairingEq( batch.commonG1P1.get(), G2P1, batch.commonG1P2.get(), G2P2 );
    };

    // Do each pairing equality individually, and identify which ones are invalid
    const auto pessimisticValidation = [&]() {
        // negate g1P2 only once
        G1BackendType g1P2Negatted = batch.commonG1P2.get().value;
        G1BackendType::neg( g1P2Negatted, batch.commonG1P2.get().value );  // -g1P2
        G1Point g1P2NegPoint( g1P2Negatted );

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

G2Point lagrangeInterpolateAt0( const std::vector< size_t >& idx, size_t t,
    const std::vector< std::reference_wrapper< const G2Point > >& shares ) {
    std::vector< algebra::FrScalar > lagrange_coeffs = algebra::lagrangeCoeffs( idx, t );

    std::vector< G2BackendType > shares_backend( t );
    std::vector< FrBackendType > coeffs_backend( t );

    for ( size_t i = 0; i < t; ++i ) {
        shares_backend[i] = shares[i].get().value;
        coeffs_backend[i] = lagrange_coeffs[i].value;
    }

    G2BackendType sum;
    sum.clear();
    // sum = sum{ r_i * share_i }
    G2BackendType::mulVec( sum, shares_backend.data(), coeffs_backend.data(), ( int ) t );
    return sum;
}

}  // namespace libBLS::algebra

#endif  // MCL