#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"

#include <utility>
#include <functional>

namespace libBLS::algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

struct PairingEqualityBatch {
    // common bases (stored as reference_wrappers)
    std::reference_wrapper<const G1Point> commonG1P1;
    std::reference_wrapper<const G1Point> commonG1P2;

    // vectors of points to be paired with the common bases (as reference_wrappers)
    std::vector<std::reference_wrapper<const G2Point>> g2P1s;
    std::vector<std::reference_wrapper<const G2Point>> g2P2s;

    // Specifies whether to optimize the verification by assuming first
    // that all shares are valid with high probability. If batch verification
    // fails, then fallback to individual verification of each share.
    bool optimisticValidation = false;

    // size cached after construction
    size_t size;

    PairingEqualityBatch(const G1Point& p1,
                         const G1Point& p2,
                         std::vector<std::reference_wrapper<const G2Point>> v1,
                         std::vector<std::reference_wrapper<const G2Point>> v2)
        : commonG1P1(std::cref(p1))
        , commonG1P2(std::cref(p2))
        , g2P1s(std::move(v1))
        , g2P2s(std::move(v2))
        , size(g2P1s.size())
    {
        if (g2P1s.size() != g2P2s.size()) {
            throw std::invalid_argument("PairingEqualityBatch: size mismatch between g2P1s and g2P2s");
        }
    }

    void useOptimisticValidation() { optimisticValidation = true; }
};

// -------------------- Backend Specific -------------------- //
// All functions below need to be re-implemented for each backend
// in the corresponding functions.cpp file

GTElement pairing( const G1Point& g1, const G2Point& g2 );

// Returns true iff e(g1P1, g2P1) == e(g1P2, g2P2)
bool verifyPairingEq(const G1Point& g1P1, const G2Point& g2P1, const G1Point& g1P2, const G2Point& g2P2);

// Returns vec of bools where each bool at index i is true iff
std::vector< bool > verifyPairingEqBatch(const PairingEqualityBatch& batch);

// TODO - check why there is ^ operator and also this power function
FrScalar power( const FrScalar& fr, size_t exponent );

// Exponentiation using a big integer
FqElement power( const FqElement& fq, const std::string& exponent );

void normalizeYCoordinate( FqElement& element );

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr );

// -------------------- Backend Agnostic -------------------- //
// These functions are implemented in functions.cpp and should
// work for any backend

std::pair< FqElement, FqElement > parseHint( const std::string& _hint );

std::pair< G1Point, std::string > hashToG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::string& message );

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t );


}  // namespace libBLS::algebra
