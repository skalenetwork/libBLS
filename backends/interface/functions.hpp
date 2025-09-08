#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <functional>
#include <utility>

namespace libBLS::algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

struct PairingEqualityBatch {
    // common bases (stored as reference_wrappers)
    std::reference_wrapper< const G1Point > commonG1P1;
    std::reference_wrapper< const G1Point > commonG1P2;

    // vectors of points to be paired with the common bases (as reference_wrappers)
    std::vector< std::reference_wrapper< const G2Point > > g2P1s;
    std::vector< std::reference_wrapper< const G2Point > > g2P2s;

    // Specifies whether to optimize the verification by assuming first
    // that all shares are valid with high probability. If batch verification
    // fails, then fallback to individual verification of each share.
    bool optimisticValidation = false;

    // size cached after construction
    size_t size;

    PairingEqualityBatch( const G1Point& p1, const G1Point& p2,
        std::vector< std::reference_wrapper< const G2Point > > v1,
        std::vector< std::reference_wrapper< const G2Point > > v2 )
        : commonG1P1( std::cref( p1 ) ),
          commonG1P2( std::cref( p2 ) ),
          g2P1s( std::move( v1 ) ),
          g2P2s( std::move( v2 ) ),
          size( g2P1s.size() ) {
        if ( g2P1s.size() != g2P2s.size() ) {
            throw std::invalid_argument(
                "PairingEqualityBatch: size mismatch between g2P1s and g2P2s" );
        }
    }

    void useOptimisticValidation() { optimisticValidation = true; }
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

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr );

G2Point lagrangeInterpolateAt0( const std::vector< size_t >& idx, size_t t,
    const std::vector< std::reference_wrapper< const G2Point > >& shares );

// -------------------- Backend Agnostic -------------------- //
// These functions are implemented in functions.cpp and should
// work for any backend

std::pair< FqElement, FqElement > parseHint( const std::string& _hint );

std::pair< G1Point, std::string > hashToG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::string& message );

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t );

// -------------------- Helper Class -------------------- //

// Thread-local RNG using OpenSSL EVP_chacha20 as a keystream generator.
// - Seed once with a 32B key + 12B nonce (RFC7539 style).
// - Counter is 32-bit little-endian in the first 4 bytes of the IV for EVP_chacha20.
// - Generate bytes by encrypting a zero buffer (classic stream-cipher usage).
class FastRandFrScalar {
private:
    EVP_CIPHER_CTX* ctx_;
    std::array< uint8_t, 32 > key_{};
    std::array< uint8_t, 12 > nonce_{};
    uint32_t counter_;

public:
    FastRandFrScalar() : ctx_( EVP_CIPHER_CTX_new() ), counter_( 0 ) {
        if ( !ctx_ )
            throw std::runtime_error( "EVP_CIPHER_CTX_new failed" );
    }
    ~FastRandFrScalar() { EVP_CIPHER_CTX_free( ctx_ ); }

    // Secure seeding: pass a 32B key and 12B nonce (you can get them from RAND_bytes once at
    // startup). Re-seeds and resets the internal counter to 'counter0' (usually 0).
    void seed( const uint8_t key[32], const uint8_t nonce12[12], uint32_t counter0 = 0 ) {
        std::memcpy( key_.data(), key, 32 );
        std::memcpy( nonce_.data(), nonce12, 12 );
        counter_ = counter0;
        reinit_ctx();
    }

    // Fill 'out' with 'len' bytes of keystream (no syscalls).
    void fill( uint8_t* out, size_t len ) {
        // OpenSSL's EVP_chacha20 uses a 16-byte IV: [4B counter (LE)] || [12B nonce]
        // We keep the ctx initialized; to advance the keystream, we just encrypt zero bytes.
        std::vector< uint8_t > zero( len, 0 );
        int outlen = 0;
        if ( !EVP_EncryptUpdate( ctx_, out, &outlen, zero.data(), ( int ) len ) ) {
            throw std::runtime_error( "EVP_EncryptUpdate failed" );
        }
        // outlen == len for stream ciphers; no finalization needed for pure keystream.
    }

    // Convenience: produce one BN254 scalar Fr (32B → Fr via hash-to-field reduction).
    FrScalar nextFr() {
        uint8_t buf[32];
        fill( buf, sizeof( buf ) );
        return FrScalar::fromHashBytes( buf, sizeof( buf ) );
    }

    // Bulk: fill a vector of Fr
    std::vector< FrScalar > nextFrVec( size_t n ) {
        std::vector< FrScalar > v( n );
        for ( auto& x : v )
            x = nextFr();
        return v;
    }

private:
    void reinit_ctx() {
        // Build IV = counter(4B LE) || nonce(12B)
        std::array< uint8_t, 16 > iv{};
        iv[0] = ( uint8_t ) ( counter_ );
        iv[1] = ( uint8_t ) ( counter_ >> 8 );
        iv[2] = ( uint8_t ) ( counter_ >> 16 );
        iv[3] = ( uint8_t ) ( counter_ >> 24 );
        std::memcpy( &iv[4], nonce_.data(), 12 );

        // Reset + init context
        EVP_CIPHER_CTX_reset( ctx_ );
        if ( !EVP_EncryptInit_ex( ctx_, EVP_chacha20(), nullptr, key_.data(), iv.data() ) ) {
            throw std::runtime_error( "EVP_EncryptInit_ex(EVP_chacha20) failed" );
        }
        // No padding in stream ciphers; nothing else needed.
    }
};


}  // namespace libBLS::algebra
