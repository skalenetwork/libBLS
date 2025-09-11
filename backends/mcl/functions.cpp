#ifdef MCL

#include "backends/interface/functions.hpp"
#include <iostream>

namespace libBLS::algebra {

// fast random FrScalar generator (ChaCha20-based)
inline FastRandFrScalar& fastRndFr() {
    thread_local FastRandFrScalar r = [] {
        FastRandFrScalar out;
        std::array<unsigned char, 32> key{};
        std::array<unsigned char, 12> nonce{};
        if (RAND_priv_bytes(key.data(), key.size()) != 1)  // prefer priv bytes if available
            throw std::runtime_error("RAND_priv_bytes(key) failed");
        if (RAND_priv_bytes(nonce.data(), nonce.size()) != 1)
            throw std::runtime_error("RAND_priv_bytes(nonce) failed");
        out.seed(key.data(), nonce.data(), /*counter=*/0);
        return out;
    }(); // constructed once per thread at first call; retried if it throws
    return r;
}

bool optimisticBatchPairingValidation( const PairingEqualityBatch& batch, 
    size_t startingBatch, size_t numBatches );
void pessimisticBatchPairingValidation( const PairingEqualityBatch& batch, 
    std::vector< bool >& isValidVec, size_t batchIdx);


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
    std::vector< bool > isValidVec( batch.sizeTotal, true );

    size_t startingBatch = 0;
    size_t sizeEach = batch.sizeEachBatch;
    size_t numBatches = batch.numBatches;

    // If optimistic validation is ON and passes -> return all true (current vector)
    // meaning all shares from all batches are valid.
    // Else, at least 1 share has failed
    if ( !batch.optimisticValidation || !optimisticBatchPairingValidation( batch, startingBatch, numBatches ) ) {
        // check if we are parsing batch of batches, or simple batch
        if ( batch.isMegaBatch() ) {

            // TODO - the process below could be optimized to do it in logN time instead of linear
            // Identify which batches failed (do it linearly)
            for (size_t i = 0; i < batch.numBatches; ++i) {
                // if this batch has failed - run pessimistic validation for it
                const size_t startingBatch = i;
                const size_t numBatches = 1;
                if (!optimisticBatchPairingValidation(batch, startingBatch, numBatches)) {

                    size_t startIdx = i * sizeEach;
                    size_t endIdx = startIdx + sizeEach;
                    for (size_t j = startIdx; j < endIdx; ++j) {
                        isValidVec[j] = verifyPairingEq(
                            batch.g1P1s[j], batch.g2P1s[j].get(),
                            batch.g1P2s[j], batch.g2P2s[j].get()
                        );
                    }
                }
            }
        }
        else { // simple batch - batch of shares - identify which share failed
            pessimisticBatchPairingValidation( batch, isValidVec, 0 );
        }
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

// ================= Helper Functions ================= //

/**
 * Assumes P1 and P2 in e(P1, G1) == e(P2, G2) are fixed/common for all equalities.
 * Only does pessimistic pass over a single (inner) batch.
 * 
 */
void pessimisticBatchPairingValidation( 
    const PairingEqualityBatch& batch, 
    std::vector< bool >& isValidVec,
    size_t batchIdx
) {
    if (isValidVec.size() != batch.sizeTotal ) {
        throw std::invalid_argument(
            "pessimisticBatchPairingValidation: isValidVec size mismatch with batch.sizeTotal" );
    }

    // Do pessimistic approach
    // negate g1P2 only once
    G1BackendType g1P2Negatted = batch.g1P2s.at(batchIdx).value;
    G1BackendType::neg( g1P2Negatted, batch.g1P2s.at(batchIdx).value );  // -g1P2

    size_t startingIdx = batchIdx * batch.sizeEachBatch;
    size_t endIdx = startingIdx + batch.sizeEachBatch;
    for ( size_t i = startingIdx; i < endIdx; ++i ) {
        const algebra::G2Point& currentG2P1 = batch.g2P1s[i].get();
        const algebra::G2Point& currentG2P2 = batch.g2P2s[i].get();

        // compute pairing equality for each element in the vector
        mcl::Fp12 f1, f2;

        // Two Miller loops (no final exponentiation yet)
        mcl::millerLoop(
            f1, batch.g1P1s.at(batchIdx).value, currentG2P1.value );  // f1 = ML(g1P1, g2P1)
        mcl::millerLoop( f2, g1P2Negatted, currentG2P2.value );       // f2 = ML(-g1P2, g2P2)

        // Combine, then a single final exponentiation
        f1 *= f2;                 // f1 = ML(g1P1,g2P1) * ML(-g1P2,g2P2)
        mcl::finalExp( f1, f1 );  // f1 = FE( ... )

        isValidVec[i] = f1.isOne();  // product == 1 ?
    }
}

/**
 * Optimistically validates a batch of pairing equalities.
 * Returns true if all are valid, and false if at least one is invalid.
 */
bool optimisticBatchPairingValidation( const PairingEqualityBatch& batch, 
    size_t startingBatch, size_t numBatches ) {
    // holds random scalars - sizeTotal (1 per share)
    static thread_local std::vector< FrBackendType > r_backend;
    // holds each individual share's g2P1 and g2P2 - (1 per share)
    // starts at idx 0. i.e, if startingBatch is 2, idx 0 will contain first
    // share of batch 2
    static thread_local std::vector< G2BackendType > g2P1s;  // g2P1_i
    static thread_local std::vector< G2BackendType > g2P2s;  // g2P2_i

    static thread_local std::vector< G1BackendType > millerLoopG1s;
    static thread_local std::vector< G2BackendType > millerLoopG2s;

    // amount of shares expected (15 shares * 1000 txs = 15k)
    static constexpr size_t kExpectedBatchSize = 15000;
    const size_t millerLoopPointsCapacity = 2 * numBatches;

    size_t n = batch.sizeTotal;
    size_t numSharesToProcess = batch.sizeEachBatch * numBatches;

    // Reserve once (upper bound you expect)
    if ( r_backend.capacity() < kExpectedBatchSize )
        r_backend.reserve( kExpectedBatchSize );
    if ( g2P1s.capacity() < kExpectedBatchSize )
        g2P1s.reserve( kExpectedBatchSize );
    if ( g2P2s.capacity() < kExpectedBatchSize )
        g2P2s.reserve( kExpectedBatchSize );
    if ( millerLoopG1s.capacity() < millerLoopPointsCapacity )
        millerLoopG1s.reserve( millerLoopPointsCapacity );
    if ( millerLoopG2s.capacity() < millerLoopPointsCapacity )
        millerLoopG2s.reserve( millerLoopPointsCapacity );

    // clear
    r_backend.clear(); r_backend.resize( numSharesToProcess );
    g2P1s.clear(); g2P1s.resize( numSharesToProcess );
    g2P2s.clear(); g2P2s.resize( numSharesToProcess );
    millerLoopG1s.clear(); millerLoopG1s.resize( 2 * numBatches );
    millerLoopG2s.clear(); millerLoopG2s.resize( 2 * numBatches );

    // get random scalars r_i
    fastRndFr().nextFrVec( r_backend, numSharesToProcess, /*nonZero=*/true );

    // convert from algebra::G2Point into G2BackendType
    const size_t startingIdx = startingBatch * batch.sizeEachBatch;
    for ( size_t i = 0; i < numSharesToProcess; ++i ) {
        g2P1s[i] = batch.g2P1s.at(startingIdx + i).get().value;  // g2P1s
        g2P2s[i] = batch.g2P2s.at(startingIdx + i).get().value;  // g2P2s
    }

    // convert from algebra::G1Point into G1BackendType
    for (size_t i = 0; i < numBatches; ++i) {
        // get constant G1P1 and G1P2 for this batch
        G1BackendType g1P1 = batch.g1P1s.at(startingBatch + i).value;  // g1P1
        G1BackendType g1P2 = batch.g1P2s.at(startingBatch + i).value;  // g1P2

        // sum up all G2P1 and G2P2
        size_t offset = i * batch.sizeEachBatch;
        G2BackendType G2P1, G2P2;
        G2BackendType::mulVec( G2P1, g2P1s.data() + offset, r_backend.data() + offset,
            ( int ) batch.sizeEachBatch );  // G2P1 = sum r_i * g2P1_i
        G2BackendType::mulVec( G2P2, g2P2s.data() + offset, r_backend.data() + offset,
            ( int ) batch.sizeEachBatch );  // G2P2 = sum r_i * g2P2_i

        // negate g1P2 once
        G1BackendType::neg( g1P2, g1P2 );  // -g1P2

        // pairing 1 - e(g1P1, G2P1)
        millerLoopG1s[2 * i] = g1P1;
        millerLoopG2s[2 * i] = G2P1;
        // pairing 2 - e(-g1P2, G2P2)
        millerLoopG1s[2 * i + 1] = g1P2;
        millerLoopG2s[2 * i + 1] = G2P2;
    }

    mcl::Fp12 f_batch;
    mcl::millerLoopVec( f_batch, millerLoopG1s.data(), millerLoopG2s.data(), 2 * numBatches );  // f = ML(g1P1,g2P1) * ML(-g1P2,g2P2) * ...
    mcl::finalExp( f_batch, f_batch ); 
    return f_batch.isOne();
}

}  // namespace libBLS::algebra

#endif  // MCL