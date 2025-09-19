#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <functional>
#include <limits>
#include <optional>
#include <utility>

namespace libBLS::algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

struct PairingEqualityBatch {
    // store the common G1 points per batch. I.e, for each G1Point, there are N G2Points.
    // no reference wrapper - these values usually have to be computed within a limited scope.
    // thus moving ownership to this struct works best.
    std::vector< G1Point > g1P1s;
    std::vector< G1Point > g1P2s;

    // vectors of points to be paired with the common bases (as reference_wrappers)
    std::vector< std::reference_wrapper< const G2Point > > g2P1s;
    std::vector< std::reference_wrapper< const G2Point > > g2P2s;

    // Specifies whether to optimize the verification by assuming first
    // that all shares are valid with high probability. If batch verification
    // fails, then fallback to individual verification of each share.
    bool optimisticValidation = false;

    // size cached after construction
    size_t numBatches;
    size_t sizeEachBatch;
    size_t sizeTotal;

    // Used to construct a mega-batch of M batches of N shares, where g1P1 and g1P2
    // are NOT constant across batches
    PairingEqualityBatch( const std::vector< G1Point >& p1, const std::vector< G1Point >& p2,
        const std::vector< std::reference_wrapper< const G2Point > >& v1,
        const std::vector< std::reference_wrapper< const G2Point > >& v2 )
        : g1P1s( std::move( p1 ) ),
          g1P2s( std::move( p2 ) ),
          g2P1s( std::move( v1 ) ),
          g2P2s( std::move( v2 ) ) {
        if ( g1P1s.size() == 0 ) {
            throw std::invalid_argument( "PairingEqualityBatch: no batches provided" );
        }

        if ( g2P1s.size() != g2P2s.size() ) {
            throw std::invalid_argument(
                "PairingEqualityBatch: size mismatch between g2P1s and g2P2s" );
        }
        if ( g1P1s.size() != g1P2s.size() ) {
            throw std::invalid_argument(
                "PairingEqualityBatch: size mismatch between g1P1s and g1P2s" );
        }
        if ( g2P1s.size() % g1P1s.size() != 0 ) {
            throw std::invalid_argument(
                "PairingEqualityBatch: g2P1s size is not multiple of g1P1s size" );
        }

        numBatches = g1P1s.size();
        sizeEachBatch = g2P1s.size() / g1P1s.size();
        sizeTotal = g2P1s.size();
    }

    void useOptimisticValidation() { optimisticValidation = true; }

    // Returns true if this is a mega-batch (multiple batches of sizeEach)
    bool isMegaBatch() const { return numBatches > 1; }
};

// -------------------- Backend Specific -------------------- //
// All functions below need to be re-implemented for each backend
// in the corresponding functions.cpp file

GTElement pairing( const G1Point& g1, const G2Point& g2 );

// Returns true iff e(g1P1, g2P1) == e(g1P2, g2P2)
bool verifyPairingEq(
    const G1Point& g1P1, const G2Point& g2P1, const G1Point& g1P2, const G2Point& g2P2 );

// Returns vec of bools where each bool at index i is true iff
std::vector< bool > verifyPairingEqBatch( const PairingEqualityBatch& batch );

// TODO - check why there is ^ operator and also this power function
FrScalar power( const FrScalar& fr, size_t exponent );

// Exponentiation using a big integer
FqElement power( const FqElement& fq, const std::string& exponent );

void normalizeYCoordinate( FqElement& element );

FqElement hashToFq( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr );

G2Point lagrangeInterpolateAt0( const std::vector< size_t >& idx, size_t t,
    const std::vector< std::reference_wrapper< const G2Point > >& shares );

// -------------------- Backend Agnostic -------------------- //
// These functions are implemented in functions.cpp and should
// work for any backend

std::pair< FqElement, FqElement > parseHint( const std::string& _hint );

std::pair< G1Point, std::string > hashToG1withHint(
    const std::array< uint8_t, HASH_SIZE >& hash_byte_arr );

G1Point hashToG1( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr );

G1Point hashToG1( const std::string& message );

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t );

// -------------------- Helper Class -------------------- //

// RNG using OpenSSL EVP_chacha20 as a keystream generator.
// - Seed once with a 32B key + 12B nonce.
// - Counter is 32-bit little-endian in the first 4 bytes of the IV for EVP_chacha20.
// - Generate bytes by encrypting a zero buffer (classic stream-cipher usage).
// - Allows generating single FrScalar or a vector of FrScalars in one shot.
class FastRandFrScalar {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;

private:
    EVP_CIPHER_CTX* ctx_;
    std::array< uint8_t, KEY_SIZE > key_{};
    std::array< uint8_t, NONCE_SIZE > nonce_{};
    uint32_t counter_;

public:
    FastRandFrScalar() : ctx_( EVP_CIPHER_CTX_new() ), counter_( 0 ) {
        if ( !ctx_ )
            throw std::runtime_error( "EVP_CIPHER_CTX_new failed" );
    }
    ~FastRandFrScalar() { EVP_CIPHER_CTX_free( ctx_ ); }

    // Pass a 32B key and 12B nonce.
    // Re-seeds and resets the internal counter to 'counter0' (usually 0).
    void seed( const std::array< uint8_t, KEY_SIZE >& key,
        const std::array< uint8_t, NONCE_SIZE >& nonce12, uint32_t counter0 = 0 ) {
        std::memcpy( key_.data(), key.data(), KEY_SIZE );
        std::memcpy( nonce_.data(), nonce12.data(), NONCE_SIZE );
        counter_ = counter0;
        reinit_ctx();
    }

    // Fill 'out' with 'len' bytes of ChaCha20 keystream (no syscalls).
    void fill( uint8_t* out, size_t len ) {
        constexpr size_t kMaxChunk = static_cast< size_t >( std::numeric_limits< int >::max() );
        size_t remaining = len;
        while ( remaining > 0 ) {
            const int chunk = static_cast< int >( std::min( remaining, kMaxChunk ) );
            // For a stream cipher, encrypting zeros yields raw keystream.
            // Do it in-place: zero the output slice, then XOR with keystream into itself.
            std::memset( out, 0, static_cast< size_t >( chunk ) );
            int outlen = 0;
            if ( !EVP_EncryptUpdate( ctx_, out, &outlen, out, chunk ) ) {
                throw std::runtime_error( "EVP_EncryptUpdate failed" );
            }
            if ( outlen != chunk ) {
                throw std::runtime_error( "EVP_EncryptUpdate produced partial output" );
            }
            out += chunk;
            remaining -= static_cast< size_t >( chunk );
        }
    }

    // Produce one BN254 scalar Fr (32B → Fr via hash-to-field reduction).
    // Enforce non-zero by resampling if needed.
    FrScalar nextFr( bool nonZero = false ) {
        uint8_t buf[FrScalar::SIZE_BYTES];
        FrScalar r;
        do {
            fill( buf, FrScalar::SIZE_BYTES );
            r = FrScalar::fromHashBytes( buf, sizeof( buf ) );
        } while ( nonZero && r.isZero() );
        return r;
    }

    // Produce N random scalars in one shot (single keystream call).
    // - Generates 32*N bytes once, then maps each 32B slice → FrScalar.
    // - Optional nonZero to enforce.
    void nextFrVec( std::vector< FrBackendType >& rndScalars, size_t n, bool nonZero = false ) {
        std::vector< uint8_t > buf( FrScalar::SIZE_BYTES * n );
        fill( buf.data(), buf.size() );

        const uint8_t* p = buf.data();
        for ( size_t i = 0; i < n; ++i, p += FrScalar::SIZE_BYTES ) {
            FrScalar r = FrScalar::fromHashBytes( p, FrScalar::SIZE_BYTES );
            if ( nonZero && r.isZero() ) {
                // Rare; resample a single 32B slice without redoing the whole batch.
                uint8_t tmp[FrScalar::SIZE_BYTES];
                do {
                    fill( tmp, sizeof( tmp ) );
                    r = FrScalar::fromHashBytes( tmp, sizeof( tmp ) );
                } while ( nonZero && r.isZero() );
            }
            rndScalars.at( i ) = r.asBackendType();
        }
    }

private:
    void reinit_ctx() {
        // Build IV = counter(4B LE) || nonce(12B)
        std::array< uint8_t, 16 > iv{};
        iv.at( 0 ) = ( uint8_t ) ( counter_ );
        iv.at( 1 ) = ( uint8_t ) ( counter_ >> 8 );
        iv.at( 2 ) = ( uint8_t ) ( counter_ >> 16 );
        iv.at( 3 ) = ( uint8_t ) ( counter_ >> 24 );
        std::memcpy( &iv.at( 4 ), nonce_.data(), 12 );

        // Reset + init context
        EVP_CIPHER_CTX_reset( ctx_ );
        if ( !EVP_EncryptInit_ex( ctx_, EVP_chacha20(), nullptr, key_.data(), iv.data() ) ) {
            throw std::runtime_error( "EVP_EncryptInit_ex(EVP_chacha20) failed" );
        }
    }
};


}  // namespace libBLS::algebra
